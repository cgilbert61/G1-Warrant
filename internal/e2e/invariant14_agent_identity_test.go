package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cgilbert61/G1-Warrant/db/migrations"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/extractor"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/server"
	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func personaToSignerBundle(p crypto.TestSmartcardPersona) *warrantsdk.SignerKeyBundle {
	return &warrantsdk.SignerKeyBundle{
		PrincipalID:    p.PrincipalID,
		Email:          p.Email,
		DisplayName:    p.DisplayName,
		Role:           p.Role,
		KeyID:          p.KeyID,
		Alg:            p.Alg,
		PublicKeyB64:   p.PublicKeyB64,
		PrivateKeyB64:  base64.StdEncoding.EncodeToString(p.PrivateKey),
		KeyFingerprint: p.KeyFingerprint,
	}
}

func TestInvariant14_AgentIdentityCommissioningSponsorshipIGAQuarantineAndWirePoP(t *testing.T) {
	h := setupIsolatedHarness(t)
	ctx := h.ctx
	cli := warrantsdk.NewClient(h.httpSrv.URL)

	aliceBundle := personaToSignerBundle(h.alice)
	bobBundle := personaToSignerBundle(h.bob)
	malloryBundle := personaToSignerBundle(h.mallory)

	// -------------------------------------------------------------------------
	// 1. Internal System Workload Identities & Zero Synthetic Human-Slot Strings
	// -------------------------------------------------------------------------
	initAgents, err := cli.ListAgents(ctx)
	if err != nil {
		t.Fatalf("ListAgents initial: %v", err)
	}
	if len(initAgents) < 6 {
		t.Fatalf("expected >= 6 kernel-bootstrapped internal N4 worker identities, got %d", len(initAgents))
	}
	repInit, err := cli.VerifyLedgerChains(ctx)
	if err != nil || !repInit.AllValid || len(repInit.Tables) != 6 || len(repInit.AgentAuthorityTables) != 3 {
		t.Fatalf("expected valid 6+3 WORM chains on startup, got valid=%v tables=%d agent_tables=%d err=%v detail=%s",
			repInit.AllValid, len(repInit.Tables), len(repInit.AgentAuthorityTables), err, repInit.SuperuserTamperDetail)
	}

	// Mint a governing Standing Warrant (auto-seals genesis bootstrap)
	wEnv, _, err := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:              "wrt-inv14-core",
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          []string{"payments-ledger-api", "identity-sso-gateway"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 8,
		SLABridgeMinutes:       60,
		MaxP99LatencyMs:        120,
		TTLDays:                30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceBundle.SignEnvelope(1, wEnv); err != nil {
		t.Fatal(err)
	}
	if err := bobBundle.SignEnvelope(2, wEnv); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.CreateWarrant(ctx, *wEnv); err != nil {
		t.Fatalf("CreateWarrant: %v", err)
	}

	// -------------------------------------------------------------------------
	// 2. CommissioningFunction Governance & 3-Way Builder != Commissioner SoD
	// -------------------------------------------------------------------------
	cfDraft, err := warrantsdk.DraftCommissioningFunctionEnvelope(warrantsdk.CommissioningFunction{
		FunctionID:             "fn-fin-core-remediation",
		DisplayName:            "Financial Core Remediation Function",
		OwningOrgUnit:          "FIN_PLATFORM_SEC",
		CostCenter:             "CC-FIN-900",
		PrimarySOPrincipalID:   h.alice.PrincipalID,
		SecondarySOPrincipalID: h.elena.PrincipalID,
		PrimaryAOPrincipalID:   h.bob.PrincipalID,
		SecondaryAOPrincipalID: h.marcus.PrincipalID,
		EscalationContact:      "fin-oncall@agency.gov",
		OrphanGraceHours:       1, // 1 hour (3600s) orphan grace window
	}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	_ = aliceBundle.SignEnvelope(1, cfDraft)
	_ = bobBundle.SignEnvelope(2, cfDraft)
	cfCreated, err := cli.SubmitCommissioningFunction(ctx, *cfDraft)
	if err != nil {
		t.Fatalf("SubmitCommissioningFunction: %v", err)
	}
	if cfCreated.ContinuityStatus != models.SponsorshipActive || cfCreated.ActiveSOCount != 2 || cfCreated.ActiveAOCount != 2 {
		t.Fatalf("expected ACTIVE CommissioningFunction with 2 SOs + 2 AOs, got %+v", cfCreated)
	}

	// Generate distinct Builder keypair & Agent keypairs
	builderKey, err := warrantsdk.GenerateAgentKeyBundle("bld-ci-release-attestor", "CI Artifact Builder")
	if err != nil {
		t.Fatal(err)
	}
	rootAgentKey, err := warrantsdk.GenerateAgentKeyBundle("agt-root-orchestrator", "Root Remediation Orchestrator")
	if err != nil {
		t.Fatal(err)
	}
	subAgentKey, err := warrantsdk.GenerateAgentKeyBundle("agt-sub-diff-scanner", "Sub-Agent Diff Scanner")
	if err != nil {
		t.Fatal(err)
	}

	// 2a. Attempt self-commissioning: Alice (Commissioning SO) signs builder provenance AND co-signs enrollment -> MUST FAIL!
	artDigest := "sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"
	selfSig, err := warrantsdk.SignBuilderProvenance(rootAgentKey.AgentID, artDigest, rootAgentKey.PublicKeyB64, aliceBundle.PrivateKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	badSoDEnv, err := warrantsdk.DraftAgentEnrollEnvelope(warrantsdk.AgentEnrollDraftOptions{
		AgentID:                 rootAgentKey.AgentID,
		CommissioningFunctionID: "fn-fin-core-remediation",
		KeyID:                   rootAgentKey.KeyID,
		PublicKeyB64:            rootAgentKey.PublicKeyB64,
		ArtifactDigest:          artDigest,
		BuilderPrincipalID:      h.alice.PrincipalID,
		BuilderPublicKeyB64:     h.alice.PublicKeyB64,
		BuilderKeyFingerprint:   h.alice.KeyFingerprint,
		BuilderProvenanceSigB64: selfSig,
		AllowedActions:          []string{"EXTRACT_SARIF_2_1_0", "EXTRACT_PATCH_DIFF"},
		AllowedServices:         []string{"payments-ledger-api", "identity-sso-gateway"},
		AllowedEgressProfile:    models.EgressProfileZeroIsolated,
		MaxTTLSeconds:           180,
		MaxDelegationDepth:      2,
		RecertifyDays:           30,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = aliceBundle.SignEnvelope(1, badSoDEnv)
	_ = bobBundle.SignEnvelope(2, badSoDEnv)
	if _, err := cli.EnrollAgent(ctx, *badSoDEnv); err == nil || !strings.Contains(err.Error(), "SOD_BUILDER_CANNOT_SELF_COMMISSION") {
		t.Fatalf("expected SOD_BUILDER_CANNOT_SELF_COMMISSION when Alice signs both builder provenance and commissioning, got: %v", err)
	}

	// 2b. Attempt enrolling an agent reusing a human principal's public key -> MUST FAIL!
	dupHumanSig, _ := warrantsdk.SignBuilderProvenance("agt-human-key-reuse", artDigest, h.bob.PublicKeyB64, builderKey.PrivateKeyB64)
	dupHumanEnv, _ := warrantsdk.DraftAgentEnrollEnvelope(warrantsdk.AgentEnrollDraftOptions{
		AgentID:                 "agt-human-key-reuse",
		CommissioningFunctionID: "fn-fin-core-remediation",
		PublicKeyB64:            h.bob.PublicKeyB64,
		ArtifactDigest:          artDigest,
		BuilderPrincipalID:      builderKey.AgentID,
		BuilderPublicKeyB64:     builderKey.PublicKeyB64,
		BuilderKeyFingerprint:   builderKey.KeyFingerprint,
		BuilderProvenanceSigB64: dupHumanSig,
		AllowedActions:          []string{"EXTRACT_SARIF_2_1_0"},
		AllowedServices:         []string{"payments-ledger-api"},
		RecertifyDays:           30,
	})
	_ = aliceBundle.SignEnvelope(1, dupHumanEnv)
	_ = bobBundle.SignEnvelope(2, dupHumanEnv)
	if _, err := cli.EnrollAgent(ctx, *dupHumanEnv); err == nil || !strings.Contains(err.Error(), "AGENT_KEY_COLLIDES_WITH_HUMAN_PRINCIPAL") {
		t.Fatalf("expected AGENT_KEY_COLLIDES_WITH_HUMAN_PRINCIPAL, got: %v", err)
	}

	// 2c. Valid 3-Way SoD enrollment of rootAgentKey & subAgentKey (Builder != Alice & Builder != Bob)
	enrollValidAgent := func(ak *warrantsdk.AgentKeyBundle, services []string, maxTTL int) *models.AgentIdentity {
		sig, sErr := warrantsdk.SignBuilderProvenance(ak.AgentID, artDigest, ak.PublicKeyB64, builderKey.PrivateKeyB64)
		if sErr != nil {
			t.Fatal(sErr)
		}
		env, dErr := warrantsdk.DraftAgentEnrollEnvelope(warrantsdk.AgentEnrollDraftOptions{
			AgentID:                 ak.AgentID,
			DisplayName:             ak.DisplayName,
			CommissioningFunctionID: "fn-fin-core-remediation",
			KeyID:                   ak.KeyID,
			PublicKeyB64:            ak.PublicKeyB64,
			ArtifactDigest:          artDigest,
			BuilderPrincipalID:      builderKey.AgentID,
			BuilderPublicKeyB64:     builderKey.PublicKeyB64,
			BuilderKeyFingerprint:   builderKey.KeyFingerprint,
			BuilderProvenanceSigB64: sig,
			AllowedActions:          []string{"EXTRACT_SARIF_2_1_0", "EXTRACT_PATCH_DIFF"},
			AllowedServices:         services,
			AllowedEgressProfile:    models.EgressProfileZeroIsolated,
			MaxTTLSeconds:           maxTTL,
			MaxDelegationDepth:      2,
			AllowAutonomousIntake:   true,
			RecertifyDays:           45,
		})
		if dErr != nil {
			t.Fatal(dErr)
		}
		_ = aliceBundle.SignEnvelope(1, env)
		_ = bobBundle.SignEnvelope(2, env)
		enrolled, eErr := cli.EnrollAgent(ctx, *env)
		if eErr != nil {
			t.Fatalf("EnrollAgent %s failed: %v", ak.AgentID, eErr)
		}
		return enrolled
	}

	enrollValidAgent(rootAgentKey, []string{"*"}, 240)
	enrollValidAgent(subAgentKey, []string{"payments-ledger-api", "checkout-cart-svc"}, 120)

	// -------------------------------------------------------------------------
	// 3. OPA Permission Intersection + RFC 8693 Sub-Agent `act` Attenuation
	// -------------------------------------------------------------------------
	// 3a. Root Token Exchange (depth=0) succeeds within StandingWarrant ∩ AgentCeiling
	rootXchEnv, err := warrantsdk.SignTokenExchangeRequest(rootAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeWarrantComposite,
		WarrantID:           "wrt-inv14-core",
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_PATCH_DIFF",
		RequestedTTLSeconds: 120,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rootXchRes, err := cli.ExchangeAgentToken(ctx, *rootXchEnv)
	if err != nil {
		t.Fatalf("ExchangeAgentToken root failed: %v", err)
	}
	if rootXchRes.EffectiveTTLSeconds != 120 || rootXchRes.Payload.Cnf == nil || rootXchRes.Payload.Act == nil ||
		rootXchRes.Payload.Act.AgentID != rootAgentKey.AgentID {
		t.Fatalf("unexpected root token exchange response: %+v", rootXchRes)
	}

	// 3b. Out-of-ceiling action is denied by OPA permission intersection
	badActionEnv, _ := warrantsdk.SignTokenExchangeRequest(rootAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeWarrantComposite,
		WarrantID:           "wrt-inv14-core",
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "ROLLOUT_CANARY_STAGE",
		RequestedTTLSeconds: 60,
	}, nil)
	if _, err := cli.ExchangeAgentToken(ctx, *badActionEnv); err == nil || !strings.Contains(err.Error(), "ACTION_OUTSIDE_AGENT_CAPABILITY_CEILING") {
		t.Fatalf("expected ACTION_OUTSIDE_AGENT_CAPABILITY_CEILING, got: %v", err)
	}

	// 3c. Sub-agent attenuation (depth=1): narrower TTL (45s <= 120s) succeeds and nests RFC 8693 act claim!
	subOkEnv, err := warrantsdk.SignTokenExchangeRequest(subAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeWarrantComposite,
		WarrantID:           "wrt-inv14-core",
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_PATCH_DIFF",
		RequestedTTLSeconds: 45,
		ParentTaskWarrant:   &rootXchRes.TaskWarrantDSSE,
	}, rootAgentKey)
	if err != nil {
		t.Fatal(err)
	}
	subOkRes, err := cli.ExchangeAgentToken(ctx, *subOkEnv)
	if err != nil {
		t.Fatalf("sub-agent attenuated token exchange failed: %v", err)
	}
	if subOkRes.Payload.DelegationDepth != 1 || subOkRes.Payload.Act == nil ||
		subOkRes.Payload.Act.ParentActor == nil || subOkRes.Payload.Act.ParentActor.AgentID != rootAgentKey.AgentID {
		t.Fatalf("expected depth=1 nested RFC 8693 act chain, got: %+v", subOkRes.Payload)
	}

	// 3d. Sub-agent privilege escalation (wider service or longer TTL than parent) MUST be rejected!
	subEscAssetEnv, _ := warrantsdk.SignTokenExchangeRequest(subAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeWarrantComposite,
		WarrantID:           "wrt-inv14-core",
		TargetAsset:         "checkout-cart-svc", // parent is scoped strictly to payments-ledger-api!
		RequestedAction:     "EXTRACT_PATCH_DIFF",
		RequestedTTLSeconds: 30,
		ParentTaskWarrant:   &rootXchRes.TaskWarrantDSSE,
	}, rootAgentKey)
	if _, err := cli.ExchangeAgentToken(ctx, *subEscAssetEnv); err == nil || !strings.Contains(err.Error(), "SUBAGENT_PRIVILEGE_ESCALATION_DENIED") {
		t.Fatalf("expected SUBAGENT_PRIVILEGE_ESCALATION_DENIED on asset widening, got: %v", err)
	}

	subEscTTLEnv, _ := warrantsdk.SignTokenExchangeRequest(subAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeWarrantComposite,
		WarrantID:           "wrt-inv14-core",
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_PATCH_DIFF",
		RequestedTTLSeconds: 200, // exceeds parent remaining TTL (<= 120s)!
		ParentTaskWarrant:   &rootXchRes.TaskWarrantDSSE,
	}, rootAgentKey)
	if _, err := cli.ExchangeAgentToken(ctx, *subEscTTLEnv); err == nil || !strings.Contains(err.Error(), "SUBAGENT_PRIVILEGE_ESCALATION_DENIED") {
		t.Fatalf("expected SUBAGENT_PRIVILEGE_ESCALATION_DENIED on TTL widening, got: %v", err)
	}

	// -------------------------------------------------------------------------
	// 4. Event-Driven IGA Lifecycle: Secondary Failover -> Grace TTL Clamping -> Orphan Quarantine
	// -------------------------------------------------------------------------
	// Arm a ContainmentBridge first so we verify quarantine never disarms active containment bridges
	sarifHold := server.BuildDeterministicSARIF(
		"CVE-2026-88001", "CWE-918", 9.4, true, "identity-sso-gateway",
		"sha256:b200000000000000000000000000000000000000000000000000000000000002",
		"", "ssrf_metadata_hop", "SSRF_METADATA", 8443,
	)
	if _, err := h.orch.ExecuteSARIFRemediation(ctx, sarifHold, "UPSTREAM_VENDOR_PENDING"); err != nil {
		t.Fatalf("seed active bridge for quarantine continuity check: %v", err)
	}

	// 4a. Alice (Primary SO) transfers roles via IGA -> Elena (Secondary SO) keeps agent ACTIVE_SECONDARY_CONTINUITY with zero outage!
	igaCli := warrantsdk.NewClient(h.httpSrv.URL, warrantsdk.WithSignerBundle(bobBundle))
	if _, err := igaCli.EmitIGAEvent(ctx, warrantsdk.IGAEventRequest{
		EventType:   models.IGAEventRoleTransfer,
		PrincipalID: h.alice.PrincipalID,
		ReasonCode:  "HR_INTERNAL_ORG_TRANSFER",
	}, "", ""); err != nil {
		t.Fatalf("EmitIGAEvent Alice ROLE_TRANSFER: %v", err)
	}

	secXchEnv, _ := warrantsdk.SignTokenExchangeRequest(rootAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeWarrantComposite,
		WarrantID:           "wrt-inv14-core",
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_PATCH_DIFF",
		RequestedTTLSeconds: 90,
	}, nil)
	secXchRes, err := cli.ExchangeAgentToken(ctx, *secXchEnv)
	if err != nil {
		t.Fatalf("expected zero-downtime secondary sponsor continuity after Primary SO transfer, got: %v", err)
	}
	if secXchRes.SponsorshipState != models.SponsorshipSecondaryContinuity {
		t.Fatalf("expected ACTIVE_SECONDARY_CONTINUITY, got %s", secXchRes.SponsorshipState)
	}
	transfers, err := cli.ListPendingSponsorTransfers(ctx)
	if err != nil || len(transfers) == 0 {
		t.Fatalf("expected PENDING_SPONSOR_SUCCESSION in Action Inbox, got len=%d err=%v", len(transfers), err)
	}

	// 4b. Elena (Secondary SO) ALSO transfers out -> 0 active SOs remain!
	// Set effective_time to (now - 1h + 35s) so 35 seconds of the 1h orphan grace window remain.
	effLoss := time.Now().UTC().Add(-1*time.Hour + 35*time.Second)
	if _, err := h.orch.N1Warrant.ProcessIGALifecycleEvent(ctx, models.IGAEventRequest{
		EventType:     models.IGAEventRoleTransfer,
		PrincipalID:   h.elena.PrincipalID,
		ReasonCode:    "HR_SECONDARY_SO_TRANSFER",
		EffectiveTime: &effLoss,
	}, h.bob.PrincipalID, models.LineageModePostSeal1Of2, nil); err != nil {
		t.Fatalf("ProcessIGALifecycleEvent Elena ROLE_TRANSFER: %v", err)
	}

	graceXchEnv, _ := warrantsdk.SignTokenExchangeRequest(rootAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeWarrantComposite,
		WarrantID:           "wrt-inv14-core",
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_PATCH_DIFF",
		RequestedTTLSeconds: 180, // Requesting 180s when <=35s of grace remains!
	}, nil)
	graceXchRes, err := cli.ExchangeAgentToken(ctx, *graceXchEnv)
	if err != nil {
		t.Fatalf("expected bounded grace-window token exchange to succeed before expiry, got: %v", err)
	}
	if graceXchRes.SponsorshipState != models.SponsorshipGraceEscalated || graceXchRes.EffectiveTTLSeconds > 35 || graceXchRes.EffectiveTTLSeconds <= 0 {
		t.Fatalf("expected SPONSOR_GRACE_ESCALATED with clamped TTL in (0, 35], got state=%s ttl=%d",
			graceXchRes.SponsorshipState, graceXchRes.EffectiveTTLSeconds)
	}

	// During grace, sub-agent re-delegation (depth > 0) MUST be blocked!
	subGraceEnv, _ := warrantsdk.SignTokenExchangeRequest(subAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeWarrantComposite,
		WarrantID:           "wrt-inv14-core",
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_PATCH_DIFF",
		RequestedTTLSeconds: 10,
		ParentTaskWarrant:   &graceXchRes.TaskWarrantDSSE,
	}, rootAgentKey)
	if _, err := cli.ExchangeAgentToken(ctx, *subGraceEnv); err == nil || !strings.Contains(err.Error(), "GRACE_WINDOW_BLOCKS_SUBAGENT_DELEGATION") {
		t.Fatalf("expected GRACE_WINDOW_BLOCKS_SUBAGENT_DELEGATION during sponsor grace, got: %v", err)
	}

	// 4c. Advance evaluation clock past grace_expires_at -> automatic GHOST_AGENT_ORPHAN_QUARANTINED!
	afterGrace := time.Now().UTC().Add(2 * time.Minute)
	postGracePayload := models.AgentTokenExchangePayload{
		EnvelopeID:          "xch-post-grace-" + uuid.NewString(),
		AgentID:             rootAgentKey.AgentID,
		AuthorityMode:       models.AuthorityModeWarrantComposite,
		WarrantID:           "wrt-inv14-core",
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_PATCH_DIFF",
		RequestedTTLSeconds: 60,
		IssuedAt:            afterGrace.Format(time.RFC3339),
		ExpiresAt:           afterGrace.Add(30 * time.Second).Format(time.RFC3339),
	}
	postGraceEnv, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeAgentTokenExchange, postGracePayload)
	_ = rootAgentKey.SignEnvelope(postGraceEnv)
	if _, err := h.orch.N4AgentCP.ExchangeAgentTaskToken(ctx, *postGraceEnv, afterGrace); err == nil || !strings.Contains(err.Error(), "GHOST_AGENT_ORPHAN_QUARANTINED") {
		t.Fatalf("expected GHOST_AGENT_ORPHAN_QUARANTINED once grace expires, got: %v", err)
	}

	// Verify active CiliumNetworkPolicy containment bridges remain ARMED during ghost-agent quarantine!
	bridges, _ := cli.ListBridges(ctx)
	armedCount := 0
	for _, b := range bridges {
		if b.Status == "ARMED" {
			armedCount++
		}
	}
	if armedCount == 0 {
		t.Fatalf("expected active Cilium containment bridge to remain ARMED during ghost-agent quarantine")
	}

	// 4d. Execute 2-of-2 TRANSFER_COMMISSIONING_SPONSOR re-anchoring fn-fin-core-remediation to Mallory (SO) + Bob (AO)
	transferEnv, err := warrantsdk.DraftCommissioningFunctionEnvelope(warrantsdk.CommissioningFunction{
		FunctionID:           "fn-fin-core-remediation",
		DisplayName:          "Financial Core Remediation Function",
		OwningOrgUnit:        "FIN_PLATFORM_SEC",
		CostCenter:           "CC-FIN-900",
		PrimarySOPrincipalID: h.mallory.PrincipalID,
		PrimaryAOPrincipalID: h.bob.PrincipalID,
		EscalationContact:    "fin-oncall@agency.gov",
		OrphanGraceHours:     1,
	}, true, "SUCCESSION_TO_MALLORY_SO")
	if err != nil {
		t.Fatal(err)
	}
	_ = malloryBundle.SignEnvelope(1, transferEnv)
	_ = bobBundle.SignEnvelope(2, transferEnv)
	cfTransferred, err := cli.TransferCommissioningSponsor(ctx, "fn-fin-core-remediation", *transferEnv)
	if err != nil || cfTransferred.ContinuityStatus != models.SponsorshipActive {
		t.Fatalf("expected 2-of-2 sponsor transfer to restore ACTIVE continuity, got %+v err=%v", cfTransferred, err)
	}

	// -------------------------------------------------------------------------
	// 5. Immediate 0s Cutoff on 1-of-2 Kill-Switch & KEY_COMPROMISE (Bypassing Grace)
	// -------------------------------------------------------------------------
	// 5a. 1-of-2 REVOKE_AGENT_IDENTITY kill-switch on subAgentKey
	revAgentEnv, err := warrantsdk.DraftAgentRevokeEnvelope(subAgentKey.AgentID, "ANOMALOUS_SUBAGENT_BEHAVIOR")
	if err != nil {
		t.Fatal(err)
	}
	_ = bobBundle.SignEnvelope(1, revAgentEnv)
	revokedSub, err := cli.RevokeAgent(ctx, *revAgentEnv)
	if err != nil || !revokedSub.Revoked || revokedSub.SponsorshipState != models.SponsorshipRevokedKillSwitch {
		t.Fatalf("expected immediate REVOKED_KILL_SWITCH, got %+v err=%v", revokedSub, err)
	}
	deadSubXch, _ := warrantsdk.SignTokenExchangeRequest(subAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeAutonomousSponsored,
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_SARIF_2_1_0",
		RequestedTTLSeconds: 30,
	}, nil)
	if _, err := cli.ExchangeAgentToken(ctx, *deadSubXch); err == nil || !strings.Contains(err.Error(), "AGENT_REVOKED_KILL_SWITCH") {
		t.Fatalf("expected immediate AGENT_REVOKED_KILL_SWITCH denial, got: %v", err)
	}

	// 5b. KEY_COMPROMISE on Mallory (Primary SO of fn-fin-core-remediation) -> 0s cutoff bypassing the 1h grace window!
	if _, err := igaCli.EmitIGAEvent(ctx, warrantsdk.IGAEventRequest{
		EventType:   models.IGAEventKeyCompromise,
		PrincipalID: h.mallory.PrincipalID,
		ReasonCode:  "PIV_PRIVATE_KEY_COMPROMISE_DETECTED",
	}, "", ""); err != nil {
		t.Fatalf("EmitIGAEvent KEY_COMPROMISE: %v", err)
	}
	compXchEnv, _ := warrantsdk.SignTokenExchangeRequest(rootAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeAutonomousSponsored,
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_SARIF_2_1_0",
		RequestedTTLSeconds: 30,
	}, nil)
	if _, err := cli.ExchangeAgentToken(ctx, *compXchEnv); err == nil || !strings.Contains(err.Error(), "SPONSOR_KEY_COMPROMISED_IMMEDIATE_KILL") {
		t.Fatalf("expected immediate 0s SPONSOR_KEY_COMPROMISED_IMMEDIATE_KILL bypassing grace, got: %v", err)
	}

	// -------------------------------------------------------------------------
	// 6. Wire-Level Gateway Enforcement on warrant-extractor (X-Warrant-Task-DSSE + X-Warrant-Agent-PoP)
	// -------------------------------------------------------------------------
	kernelPub := ed25519.PublicKey(h.orch.N5Ledger.KernelPublicKey().PublicKeyBytes)
	govExtSrv := httptest.NewServer(extractor.NewGovernedHTTPHandler(
		"sha256-governed-extractor",
		func() []ed25519.PublicKey { return []ed25519.PublicKey{kernelPub} },
		true,
	))
	defer govExtSrv.Close()

	sampleSARIF := server.BuildDeterministicSARIF(
		"CVE-2026-77100", "CWE-400", 9.8, true, "payments-ledger-api",
		"sha256:a100000000000000000000000000000000000000000000000000000000000001",
		"sha256:a199999999999999999999999999999999999999999999999999999999999901",
		"", "HTTP2_RAPID_RESET", 8443,
	)

	// 6a. Missing X-Warrant-Task-DSSE -> HTTP 401
	respNoHdr, err := http.Post(govExtSrv.URL+"/extract/sarif", "application/json", bytes.NewReader(sampleSARIF))
	if err != nil {
		t.Fatal(err)
	}
	_ = respNoHdr.Body.Close()
	if respNoHdr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected HTTP 401 on missing X-Warrant-Task-DSSE, got %d", respNoHdr.StatusCode)
	}

	// Re-anchor fn-fin-core-remediation to Elena + Marcus (re-enrolled via fresh function fn-fin-wire-test) to mint a clean live token
	wireCFEnv, _ := warrantsdk.DraftCommissioningFunctionEnvelope(warrantsdk.CommissioningFunction{
		FunctionID:           "fn-fin-wire-test",
		DisplayName:          "Wire PoP Verification Function",
		OwningOrgUnit:        "SEC_WIRE_GATEWAY",
		PrimarySOPrincipalID: h.alice.PrincipalID,
		PrimaryAOPrincipalID: h.bob.PrincipalID,
		EscalationContact:    "wire@agency.gov",
		OrphanGraceHours:     24,
	}, false, "")
	_ = aliceBundle.SignEnvelope(1, wireCFEnv)
	_ = bobBundle.SignEnvelope(2, wireCFEnv)
	if _, err := cli.SubmitCommissioningFunction(ctx, *wireCFEnv); err != nil {
		t.Fatalf("SubmitCommissioningFunction wire: %v", err)
	}
	wireAgentKey, _ := warrantsdk.GenerateAgentKeyBundle("agt-wire-caller", "Wire PoP Agent")
	wireSig, _ := warrantsdk.SignBuilderProvenance(wireAgentKey.AgentID, artDigest, wireAgentKey.PublicKeyB64, builderKey.PrivateKeyB64)
	wireAgEnv, _ := warrantsdk.DraftAgentEnrollEnvelope(warrantsdk.AgentEnrollDraftOptions{
		AgentID:                 wireAgentKey.AgentID,
		CommissioningFunctionID: "fn-fin-wire-test",
		KeyID:                   wireAgentKey.KeyID,
		PublicKeyB64:            wireAgentKey.PublicKeyB64,
		ArtifactDigest:          artDigest,
		BuilderPrincipalID:      builderKey.AgentID,
		BuilderPublicKeyB64:     builderKey.PublicKeyB64,
		BuilderKeyFingerprint:   builderKey.KeyFingerprint,
		BuilderProvenanceSigB64: wireSig,
		AllowedActions:          []string{"EXTRACT_SARIF_2_1_0"},
		AllowedServices:         []string{"*"},
		AllowAutonomousIntake:   true,
		RecertifyDays:           30,
	})
	_ = aliceBundle.SignEnvelope(1, wireAgEnv)
	_ = bobBundle.SignEnvelope(2, wireAgEnv)
	if _, err := cli.EnrollAgent(ctx, *wireAgEnv); err != nil {
		t.Fatalf("EnrollAgent wire: %v", err)
	}

	wireXchReq, _ := warrantsdk.SignTokenExchangeRequest(wireAgentKey, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       models.AuthorityModeAutonomousSponsored,
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_SARIF_2_1_0",
		RequestedTTLSeconds: 60,
	}, nil)
	wireXchRes, err := cli.ExchangeAgentToken(ctx, *wireXchReq)
	if err != nil {
		t.Fatalf("ExchangeAgentToken wire: %v", err)
	}

	// 6b. Forged X-Warrant-Agent-PoP (signed by wrong agent key) -> HTTP 403
	rogueHolder, _ := warrantsdk.GenerateAgentKeyBundle("agt-rogue-impersonator", "Rogue Impersonator")
	forgedReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, govExtSrv.URL+"/extract/sarif", bytes.NewReader(sampleSARIF))
	_ = warrantsdk.SignAgentHTTPRequest(forgedReq, sampleSARIF, &wireXchRes.TaskWarrantDSSE, rogueHolder)
	respForgedPoP, err := http.DefaultClient.Do(forgedReq)
	if err != nil {
		t.Fatal(err)
	}
	forgedBody, _ := io.ReadAll(respForgedPoP.Body)
	_ = respForgedPoP.Body.Close()
	if respForgedPoP.StatusCode != http.StatusForbidden || !strings.Contains(string(forgedBody), "AGENT_POP_VERIFICATION_FAILED") {
		t.Fatalf("expected HTTP 403 AGENT_POP_VERIFICATION_FAILED on forged PoP, got %d: %s", respForgedPoP.StatusCode, string(forgedBody))
	}

	// 6c. Expired X-Warrant-Task-DSSE -> HTTP 403
	expPayload := wireXchRes.Payload
	expPayload.IssuedUnix = time.Now().UTC().Add(-10 * time.Minute).Unix()
	expPayload.ExpiresUnix = time.Now().UTC().Add(-5 * time.Minute).Unix()
	expEnv, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeTaskWarrant, expPayload)
	_ = h.orch.N5Ledger.Signer().SignEnvelope(ctx, 1, expEnv)
	expReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, govExtSrv.URL+"/extract/sarif", bytes.NewReader(sampleSARIF))
	_ = warrantsdk.SignAgentHTTPRequest(expReq, sampleSARIF, expEnv, wireAgentKey)
	respExp, err := http.DefaultClient.Do(expReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = respExp.Body.Close()
	if respExp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 on expired X-Warrant-Task-DSSE, got %d", respExp.StatusCode)
	}

	// 6d. Forged Kernel Signature on X-Warrant-Task-DSSE -> HTTP 403
	_, rogueKernelPriv, _ := ed25519.GenerateKey(rand.Reader)
	forgedKernelEnv, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeTaskWarrant, wireXchRes.Payload)
	_ = forgedKernelEnv.SignEd25519(1, crypto.PrincipalKey{KeyID: "forged-kernel", Alg: crypto.AlgEd25519}, rogueKernelPriv)
	fkReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, govExtSrv.URL+"/extract/sarif", bytes.NewReader(sampleSARIF))
	_ = warrantsdk.SignAgentHTTPRequest(fkReq, sampleSARIF, forgedKernelEnv, wireAgentKey)
	respFK, err := http.DefaultClient.Do(fkReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = respFK.Body.Close()
	if respFK.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 on forged kernel DSSE signature, got %d", respFK.StatusCode)
	}

	// 6e. Authentic X-Warrant-Task-DSSE + X-Warrant-Agent-PoP -> HTTP 200 OK!
	validWireReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, govExtSrv.URL+"/extract/sarif", bytes.NewReader(sampleSARIF))
	_ = warrantsdk.SignAgentHTTPRequest(validWireReq, sampleSARIF, &wireXchRes.TaskWarrantDSSE, wireAgentKey)
	respOK, err := http.DefaultClient.Do(validWireReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = respOK.Body.Close()
	if respOK.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 on authentic X-Warrant-Task-DSSE + X-Warrant-Agent-PoP, got %d", respOK.StatusCode)
	}

	// -------------------------------------------------------------------------
	// 7. OSCAL 1.1.2 Agent Lineage Observation & v1.0.x -> v1.1.0 Ledger Upgrade Continuity
	// -------------------------------------------------------------------------
	if _, err := h.orch.ExecuteSARIFRemediation(ctx, sampleSARIF, "STATELESS_CLEAN"); err != nil {
		t.Fatalf("ExecuteSARIFRemediation for OSCAL lineage check: %v", err)
	}
	atts, err := cli.ListAttestations(ctx)
	if err != nil || len(atts) == 0 {
		t.Fatalf("expected minted OSCAL attestation, got len=%d err=%v", len(atts), err)
	}
	rawOSCAL, err := cli.ExportOSCALBundle(ctx, atts[0].AttestationID)
	if err != nil {
		t.Fatal(err)
	}
	oscalStr := string(rawOSCAL)
	for _, mustContain := range []string{
		"commissioning-function-id",
		"builder-artifact-digest",
		"sponsorship-continuity-state",
		"act-delegation-lineage",
	} {
		if !strings.Contains(oscalStr, mustContain) {
			t.Fatalf("expected minted OSCAL 1.1.2 POA&M to embed %q", mustContain)
		}
	}

	// Verify clean v1.0.x (migrations 001..007 + MerkleVersion=2 checkpoint) -> v1.1.0 (008 + MerkleVersion=3) upgrade!
	verifyV104ToV110LedgerUpgradeAndLineageGuard(t, ctx)
}

func verifyV104ToV110LedgerUpgradeAndLineageGuard(t *testing.T, ctx context.Context) {
	t.Helper()
	adminDSN := os.Getenv("TEST_DATABASE_URL")
	if adminDSN == "" {
		adminDSN = os.Getenv("DATABASE_URL")
	}
	if adminDSN == "" {
		adminDSN = "postgres://warrant:warrant@localhost:5432/postgres?sslmode=disable"
	}
	adminConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin DSN: %v", err)
	}
	upgDB := "warrant_upg110_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, upgDB)); err != nil {
		_ = adminConn.Close(ctx)
		t.Fatal(err)
	}
	_ = adminConn.Close(ctx)
	t.Cleanup(func() {
		c, cErr := pgx.Connect(context.Background(), adminDSN)
		if cErr == nil {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, upgDB))
			_ = c.Close(context.Background())
		}
	})

	upgDSN := replaceDBName(adminDSN, upgDB)
	upgStore, err := db.NewStore(ctx, upgDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer upgStore.Close()

	// Apply ONLY migrations 001..007 (simulating an existing v1.0.4 production database)
	migEntries, rDirErr := fs.ReadDir(migrations.FS, ".")
	if rDirErr != nil {
		t.Fatalf("ReadDir migrations: %v", rDirErr)
	}
	var pre110Names []string
	for _, me := range migEntries {
		if !me.IsDir() && strings.HasSuffix(me.Name(), ".sql") && !strings.HasPrefix(me.Name(), "008_") {
			pre110Names = append(pre110Names, me.Name())
		}
	}
	sort.Strings(pre110Names)
	for _, migFile := range pre110Names {
		sqlBytes, rErr := fs.ReadFile(migrations.FS, migFile)
		if rErr != nil {
			t.Fatalf("read %s: %v", migFile, rErr)
		}
		if _, eErr := upgStore.Pool().Exec(ctx, string(sqlBytes)); eErr != nil {
			t.Fatalf("exec %s: %v", migFile, eErr)
		}
	}

	// Insert a legacy v1.0.4 MerkleVersion=2 checkpoint and legacy agent_action_ledger row
	legacyAction := models.AgentLedgerEntry{
		ActionID:          "act-v104-01",
		TaskTokenID:       "tsk-v104-01",
		WarrantID:         "wrt-v104-01",
		WorkerName:        "warrant-extractor",
		TargetAsset:       "payments-ledger-api",
		ActionType:        "EXTRACT_SARIF_2_1_0",
		Slot1PrincipalID:  "usr-alice-so",
		Slot2PrincipalID:  "usr-bob-ao",
		EgressProfile:     "ZERO_EGRESS_ISOLATED",
		RawInputSHA256:    db.GenesisHash,
		ExtractorDigest:   "sha256-v104",
		TypedOutputSHA256: db.GenesisHash,
		TokenTTLSec:       60,
		Status:            "EXECUTED",
		PrevHash:          db.GenesisHash,
	}
	legacyAction.EntryHash = db.ComputeAgentActionEntryHash(db.GenesisHash, legacyAction)
	_, err = upgStore.Pool().Exec(ctx, `
		INSERT INTO agent_action_ledger (
			action_id, task_token_id, warrant_id, remediation_id, worker_name, target_asset, action_type,
			slot1_principal_id, slot2_principal_id, egress_profile,
			raw_input_sha256, extractor_digest, typed_output_sha256,
			token_ttl_sec, status, violation_code, prev_hash, entry_hash
		) VALUES ($1,$2,$3,'',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'',$15,$16)
	`,
		legacyAction.ActionID, legacyAction.TaskTokenID, legacyAction.WarrantID,
		legacyAction.WorkerName, legacyAction.TargetAsset, legacyAction.ActionType,
		legacyAction.Slot1PrincipalID, legacyAction.Slot2PrincipalID, legacyAction.EgressProfile,
		legacyAction.RawInputSHA256, legacyAction.ExtractorDigest, legacyAction.TypedOutputSHA256,
		legacyAction.TokenTTLSec, legacyAction.Status, legacyAction.PrevHash, legacyAction.EntryHash,
	)
	if err != nil {
		t.Fatalf("insert legacy v1.0.4 agent_action_ledger row: %v", err)
	}

	v2Root := db.ComputeCombinedMerkleRootV2(
		db.GenesisHash, 0,
		legacyAction.EntryHash, 1,
		db.GenesisHash, 0,
		db.GenesisHash, 0,
		db.GenesisHash, 0,
		db.GenesisHash, 0,
	)
	_, err = upgStore.Pool().Exec(ctx, `
		INSERT INTO ledger_checkpoints (
			checkpoint_id, merkle_version,
			warrant_head_hash, warrant_row_count,
			agent_head_hash, agent_row_count,
			attestation_head_hash, attestation_row_count,
			principal_head_hash, principal_row_count,
			revocation_head_hash, revocation_row_count,
			kernel_key_head_hash, kernel_key_row_count,
			combined_merkle_root, dsse_envelope, external_anchor_target, external_receipt_hash
		) VALUES ('chk-v104', 2, $1, 0, $2, 1, $1, 0, $1, 0, $1, 0, $1, 0, $3, '{"payloadType":"test","payload":"","signatures":[]}'::jsonb, 'LOCAL', 'abcd')
	`, db.GenesisHash, legacyAction.EntryHash, v2Root)
	if err != nil {
		t.Fatalf("insert legacy v1.0.4 checkpoint: %v", err)
	}

	// Now run full Migrate() applying 008_v1_1_0_agent_identities.sql and boot Orchestrator!
	if err := upgStore.Migrate(ctx); err != nil {
		t.Fatalf("upgrade Migrate() to v1.1.0 failed: %v", err)
	}
	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-upg-ext"))
	defer extSrv.Close()
	upgOrch, err := server.NewOrchestrator(ctx, upgStore, extSrv.URL, "http://127.0.0.1:1", "upg-kernel-seed", crypto.DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("NewOrchestrator on upgraded v1.1.0 DB failed: %v", err)
	}
	v3CP, err := upgOrch.N5Ledger.CreateCheckpoint(ctx)
	if err != nil || v3CP.MerkleVersion != 3 {
		t.Fatalf("expected MerkleVersion=3 checkpoint on upgraded DB, got %+v err=%v", v3CP, err)
	}

	upgRep, err := upgOrch.Store.VerifyAllLedgerChains(ctx)
	if err != nil || !upgRep.AllValid || !upgRep.ExternalAnchorVerified {
		t.Fatalf("expected upgraded v1.0.4 -> v1.1.0 ledger chains + mixed V2/V3 checkpoints to verify cleanly, got %+v err=%v", upgRep, err)
	}

	// Inject an unattested raw SQL INSERT into agent_identities -> VerifyAllLedgerChains MUST detect UNATTESTED_AUTHORITY_LINEAGE_INSERT_DETECTED!
	var prevAIHash string
	_ = upgStore.Pool().QueryRow(ctx, `SELECT entry_hash FROM agent_identities ORDER BY seq_no DESC LIMIT 1`).Scan(&prevAIHash)
	rogueAgent := models.AgentIdentity{
		AgentID:                   "agt-rogue-sql-insert",
		DisplayName:               "Rogue SQL Injected Agent",
		AgentKind:                 models.AgentKindExternalAutonomous,
		CommissioningFunctionID:   models.SystemCommissioningFunctionID,
		KeyID:                     "ed25519-rogue-sql",
		Alg:                       crypto.AlgEd25519,
		PublicKeyB64:              base64.StdEncoding.EncodeToString(make([]byte, 32)),
		KeyFingerprint:            strings.Repeat("e", 64),
		ArtifactDigest:            "sha256:" + strings.Repeat("a", 64),
		BuilderPrincipalID:        "bld-rogue",
		BuilderKeyFingerprint:     strings.Repeat("b", 64),
		BuilderProvenanceSigB64:   "ZmFrZQ==",
		AllowedActions:            []string{"EXTRACT_SARIF_2_1_0"},
		AllowedServices:           []string{"*"},
		AllowedEgressProfile:      models.EgressProfileZeroIsolated,
		MaxTTLSeconds:             60,
		MaxDelegationDepth:        0,
		RecertifyExpiresAt:        time.Now().UTC().Add(24 * time.Hour),
		CommissionerSOPrincipalID: "usr-alice-so",
		CommissionerAOPrincipalID: "usr-bob-ao",
		LineageMode:               models.LineageModePostSeal2Of2,
	}
	rogueHash := db.ComputeAgentIdentityEntryHash(prevAIHash, rogueAgent)
	_, err = upgStore.Pool().Exec(ctx, `
		INSERT INTO agent_identities (
			agent_id, display_name, agent_kind, commissioning_function_id,
			key_id, alg, public_key_b64, key_fingerprint,
			artifact_digest, builder_principal_id, builder_key_fingerprint, builder_provenance_sig_b64,
			allowed_actions, allowed_services, allowed_egress_profile,
			max_ttl_seconds, max_delegation_depth, allow_autonomous_intake, recertify_expires_at,
			commissioner_so_principal_id, commissioner_ao_principal_id,
			lineage_mode, governance_dsse, prev_hash, entry_hash
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'["EXTRACT_SARIF_2_1_0"]'::jsonb,'["*"]'::jsonb,$13,60,0,false,$14,'usr-alice-so','usr-bob-ao',$15,NULL,$16,$17
		)
	`,
		rogueAgent.AgentID, rogueAgent.DisplayName, rogueAgent.AgentKind, rogueAgent.CommissioningFunctionID,
		rogueAgent.KeyID, rogueAgent.Alg, rogueAgent.PublicKeyB64, rogueAgent.KeyFingerprint,
		rogueAgent.ArtifactDigest, rogueAgent.BuilderPrincipalID, rogueAgent.BuilderKeyFingerprint, rogueAgent.BuilderProvenanceSigB64,
		rogueAgent.AllowedEgressProfile, rogueAgent.RecertifyExpiresAt, rogueAgent.LineageMode, prevAIHash, rogueHash,
	)
	if err != nil {
		t.Fatalf("insert rogue SQL agent row: %v", err)
	}
	tamperRep, err := upgOrch.Store.VerifyAllLedgerChains(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tamperRep.AllValid || !strings.Contains(tamperRep.SuperuserTamperDetail, db.CodeUnattestedAuthorityLineageInsert) {
		t.Fatalf("expected VerifyAllLedgerChains to detect raw SQL INSERT into agent_identities (%s), got valid=%v detail=%s",
			db.CodeUnattestedAuthorityLineageInsert, tamperRep.AllValid, tamperRep.SuperuserTamperDetail)
	}
}
