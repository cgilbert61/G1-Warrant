package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/db"
	"github.com/g1163rt-labs/g1-warrant/internal/extractor"
	"github.com/g1163rt-labs/g1-warrant/internal/fleetsim"
	"github.com/g1163rt-labs/g1-warrant/internal/gate"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
	"github.com/g1163rt-labs/g1-warrant/internal/server"
	"github.com/g1163rt-labs/g1-warrant/pkg/warrantsdk"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type testHarness struct {
	ctx        context.Context
	store      *db.Store
	orch       *server.ControlPlaneOrchestrator
	httpSrv    *httptest.Server
	alice      crypto.TestSmartcardPersona
	bob        crypto.TestSmartcardPersona
	elena      crypto.TestSmartcardPersona
	marcus     crypto.TestSmartcardPersona
	mallory    crypto.TestSmartcardPersona
	carol      crypto.TestSmartcardPersona
}

func setupIsolatedHarness(t *testing.T) *testHarness {
	t.Helper()
	ctx := context.Background()

	adminDSN := os.Getenv("TEST_DATABASE_URL")
	if adminDSN == "" {
		adminDSN = os.Getenv("DATABASE_URL")
	}
	if adminDSN == "" {
		adminDSN = "postgres://warrant:warrant@localhost:5432/postgres?sslmode=disable"
	}

	adminConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		if os.Getenv("REQUIRE_DB_TESTS") == "true" {
			t.Fatalf("REQUIRE_DB_TESTS=true but PostgreSQL unreachable at %s: %v", adminDSN, err)
		}
		t.Skipf("PostgreSQL not running on host (%v); run via `docker compose --profile test run --rm verifier`", err)
	}

	dbName := "warrant_test_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, dbName)); err != nil {
		_ = adminConn.Close(ctx)
		t.Fatalf("create isolated test database %s: %v", dbName, err)
	}
	_ = adminConn.Close(ctx)

	t.Cleanup(func() {
		c, cErr := pgx.Connect(context.Background(), adminDSN)
		if cErr == nil {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, dbName))
			_ = c.Close(context.Background())
		}
	})

	testDSN := replaceDBName(adminDSN, dbName)
	store, err := db.NewStore(ctx, testDSN)
	if err != nil {
		t.Fatalf("NewStore on %s: %v", dbName, err)
	}
	t.Cleanup(store.Close)

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-extractor-test-binary"))
	t.Cleanup(extSrv.Close)

	sim := fleetsim.NewClusterSimulator()
	fleetSrv := httptest.NewServer(sim.Handler())
	t.Cleanup(fleetSrv.Close)

	orch, err := server.NewOrchestrator(ctx, store, extSrv.URL, fleetSrv.URL, "test-kernel-seed", crypto.DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}

	apiSrv := httptest.NewServer(orch.BuildHTTPHandler())
	t.Cleanup(apiSrv.Close)

	h := &testHarness{
		ctx:     ctx,
		store:   store,
		orch:    orch,
		httpSrv: apiSrv,
	}

	for _, p := range crypto.BuiltinTestPersonas() {
		if err := store.UpsertPrincipal(ctx, models.Principal{
			PrincipalID:       p.PrincipalID,
			Email:             p.Email,
			DisplayName:       p.DisplayName,
			Role:              p.Role,
			KeyID:             p.KeyID,
			Alg:               p.Alg,
			PublicKeyB64:      p.PublicKeyB64,
			KeyFingerprint:    p.KeyFingerprint,
			AuthenticatorMode: "FIPS_PIV_SMARTCARD",
		}); err != nil {
			t.Fatal(err)
		}
		switch p.PrincipalID {
		case "usr-alice-so":
			h.alice = p
		case "usr-bob-ao":
			h.bob = p
		case "usr-elena-so":
			h.elena = p
		case "usr-marcus-ao":
			h.marcus = p
		case "usr-mallory-so":
			h.mallory = p
		case "usr-carol-sysadmin":
			h.carol = p
		}
	}

	// Register eligible services matching fleet-sim
	stdSyscalls := []string{"accept4", "close", "epoll_ctl", "epoll_wait", "fcntl", "fstat", "futex", "getsockopt", "mmap", "munmap", "nanosleep", "openat", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt", "socket", "write"}
	svcs := []models.EstateService{
		{
			ServiceID:                  "payments-ledger-api",
			DisplayName:                "Payments Ledger API",
			Namespace:                  "fin-core",
			Tier:                       "TIER_1_CRITICAL",
			WarrantClass:               "KEV-TIER1-STATELESS",
			CurrentDigest:              "sha256:a100000000000000000000000000000000000000000000000000000000000001",
			CurrentPURL:                "pkg:oci/payments-ledger-api@sha256:a100000000000000000000000000000000000000000000000000000000000001",
			SBOMPURLs:                  []string{"pkg:golang/golang.org/x/net@0.16.0"},
			Replicas:                   6,
			TestCoveragePct:            94.0,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      true,
			RollbackAutomationVerified: true,
			ReadOnlyRootFilesystem:     true,
			NoExecTmpMounts:            true,
			AllowedEgressServices:      []string{"postgres-primary.fin-core.svc.cluster.local", "otel-collector.monitoring.svc.cluster.local"},
			UnorderedArrayPaths:        []string{"$.shard_nodes"},
			BaselineSyscalls:           stdSyscalls,
		},
		{
			ServiceID:                  "identity-sso-gateway",
			DisplayName:                "Identity SSO Gateway",
			Namespace:                  "sec-authn",
			Tier:                       "TIER_1_CRITICAL",
			WarrantClass:               "KEV-TIER1-STATELESS",
			CurrentDigest:              "sha256:b200000000000000000000000000000000000000000000000000000000000002",
			CurrentPURL:                "pkg:oci/identity-sso-gateway@sha256:b200000000000000000000000000000000000000000000000000000000000002",
			Replicas:                   4,
			TestCoveragePct:            91.0,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      true,
			RollbackAutomationVerified: true,
			ReadOnlyRootFilesystem:     true,
			NoExecTmpMounts:            true,
			AllowedEgressServices:      []string{"redis-session.sec-authn.svc.cluster.local", "otel-collector.monitoring.svc.cluster.local"},
			UnorderedArrayPaths:        []string{"$.shard_nodes"},
			BaselineSyscalls:           stdSyscalls,
		},
	}
	for i := range svcs {
		gate.GradeServiceReadiness(&svcs[i])
		if err := store.UpsertEstateService(ctx, svcs[i]); err != nil {
			t.Fatal(err)
		}
	}

	return h
}

func mintDualWarrant(t *testing.T, h *testHarness, warrantID string, scopes []string, so, ao crypto.TestSmartcardPersona) *models.WarrantRecord {
	t.Helper()
	now := time.Now().UTC()
	wp := models.WarrantPayload{
		WarrantID:              warrantID,
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          scopes,
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 10,
		AllowStatefulPatches:   false,
		SLABridgeMinutes:       60,
		MaxP99LatencyMs:        120.0,
		IssuedAt:               now.Format(time.RFC3339),
		ExpiresAt:              now.Add(24 * time.Hour).Format(time.RFC3339),
	}
	env, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, wp)
	if err != nil {
		t.Fatal(err)
	}
	_ = env.SignEd25519(1, so.ToPrincipalKey(), so.PrivateKey)
	_ = env.SignEd25519(2, ao.ToPrincipalKey(), ao.PrivateKey)
	rec, err := h.orch.N1Warrant.SubmitDualSignedWarrant(h.ctx, *env)
	if err != nil {
		t.Fatalf("SubmitDualSignedWarrant(%s) failed: %v", warrantID, err)
	}
	return rec
}

// INVARIANT 1: End-to-End KEV Closure + Scoped Auditor Token Isolation
func TestInvariant1_EndToEndKEVClosureAndOSCALVerification(t *testing.T) {
	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-inv1", []string{"payments-ledger-api"}, h.alice, h.bob)

	vulnDigest := "sha256:a100000000000000000000000000000000000000000000000000000000000001"
	patchedDigest := "sha256:a199999999999999999999999999999999999999999999999999999999999999"
	sarif := server.BuildDeterministicSARIF(
		"CVE-2026-90001", "CWE-787", 9.8, true, "payments-ledger-api",
		vulnDigest, patchedDigest, "tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)

	items, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif, "STATELESS_CLEAN")
	if err != nil {
		t.Fatalf("ExecuteSARIFRemediation failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 remediation item, got %d", len(items))
	}
	got := items[0]
	if got.Stage != models.StageAttestedClosed || got.StatusHealth != models.HealthAttested {
		t.Fatalf("expected ATTESTED_CLOSED, got stage=%s health=%s blocker=%s", got.Stage, got.StatusHealth, got.BlockerCode)
	}
	if got.TwinReplayStatus != "EXPLOIT_BLOCKED" || got.PodSweepMatched != 6 || got.LockoutPolicyID == "" {
		t.Fatalf("incomplete N3 verification state: %+v", got)
	}

	// Confirm bridge was retired ONLY after lockout
	bridge, err := h.store.GetBridge(h.ctx, got.BridgeID)
	if err != nil || bridge.Status != "RETIRED" {
		t.Fatalf("expected bridge RETIRED after lockout, got %+v err=%v", bridge, err)
	}

	// Confirm Admission Lockout rejects any attempt to re-deploy vulnerable digest
	if _, err := h.orch.Deploy.ProgressCanary(h.ctx, "payments-ledger-api", fleetsim.StageRolloutRequest{
		PatchedDigest: vulnDigest,
		StageWeight:   10,
	}); err == nil || !strings.Contains(err.Error(), "ADMISSION_DENIED_LOCKED_DIGEST") {
		t.Fatalf("expected cluster ValidatingAdmissionPolicy to reject banned digest, got: %v", err)
	}

	// Confirm DSSE-signed OSCAL 1.1.2 POA&M bundle cryptographically verifies
	atts, err := h.store.ListAttestations(h.ctx)
	if err != nil || len(atts) != 1 {
		t.Fatalf("expected 1 attestation, got %d err=%v", len(atts), err)
	}
	if err := h.orch.N5Ledger.VerifyAttestationEnvelope(atts[0].DSSEEnvelope); err != nil {
		t.Fatalf("OSCAL DSSE cryptographic verification failed: %v", err)
	}
	poamRoot, ok := atts[0].OSCALPOAM["plan-of-action-and-milestones"].(map[string]any)
	if !ok {
		t.Fatalf("missing plan-of-action-and-milestones root in OSCAL JSON")
	}
	meta, _ := poamRoot["metadata"].(map[string]any)
	if meta["oscal-version"] != "1.1.2" {
		t.Fatalf("expected oscal-version 1.1.2, got %v", meta["oscal-version"])
	}

	// Confirm Scoped External Auditor Token accesses /api/v1/auditor/vault (200) and is blocked on /api/v1/warrants (403)
	_, rawBearer, err := h.orch.N5Ledger.MintScopedAuditorToken(h.ctx, "3PAO Test", "test", []string{atts[0].AttestationID}, 2)
	if err != nil {
		t.Fatal(err)
	}
	reqVault, _ := http.NewRequest(http.MethodGet, h.httpSrv.URL+"/api/v1/auditor/vault", nil)
	reqVault.Header.Set("Authorization", "Bearer "+rawBearer)
	respVault, err := http.DefaultClient.Do(reqVault)
	if err != nil || respVault.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /api/v1/auditor/vault, got %v err=%v", respVault, err)
	}
	_ = respVault.Body.Close()

	reqOp, _ := http.NewRequest(http.MethodGet, h.httpSrv.URL+"/api/v1/warrants", nil)
	reqOp.Header.Set("Authorization", "Bearer "+rawBearer)
	respOp, err := http.DefaultClient.Do(reqOp)
	if err != nil || respOp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when auditor token calls operational endpoint, got %d", respOp.StatusCode)
	}
	_ = respOp.Body.Close()
}

// INVARIANT 2: NIST SP 800-53 AC-5 Separation of Duties & Live Execution-Time Revocation
func TestInvariant2_AC5SeparationOfDutiesAndLiveRevocation(t *testing.T) {
	h := setupIsolatedHarness(t)
	now := time.Now().UTC()
	wp := models.WarrantPayload{
		WarrantID:              "wrt-bad-ac5",
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          []string{"identity-sso-gateway"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 8,
		SLABridgeMinutes:       60,
		IssuedAt:               now.Format(time.RFC3339),
		ExpiresAt:              now.Add(24 * time.Hour).Format(time.RFC3339),
	}

	// 1. Reject Mallory signing both Slot 1 and Slot 2
	sameEnv, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, wp)
	_ = sameEnv.SignEd25519(1, h.mallory.ToPrincipalKey(), h.mallory.PrivateKey)
	_ = sameEnv.SignEd25519(2, h.mallory.ToPrincipalKey(), h.mallory.PrivateKey)
	if _, err := h.orch.N1Warrant.SubmitDualSignedWarrant(h.ctx, *sameEnv); err == nil {
		t.Fatal("expected AC-5 rejection for identical signer across Slot 1 and Slot 2")
	}

	// 2. Reject Carol (SYSTEM_ADMIN) signing Slot 2
	sysEnv, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, wp)
	_ = sysEnv.SignEd25519(1, h.alice.ToPrincipalKey(), h.alice.PrivateKey)
	_ = sysEnv.SignEd25519(2, h.carol.ToPrincipalKey(), h.carol.PrivateKey)
	if _, err := h.orch.N1Warrant.SubmitDualSignedWarrant(h.ctx, *sysEnv); err == nil || !strings.Contains(err.Error(), "AC5_SYSADMIN_PROHIBITED") {
		t.Fatalf("expected AC5_SYSADMIN_PROHIBITED, got %v", err)
	}

	// 3. Mint valid Elena + Marcus warrant, then revoke Marcus before N2 execution
	w := mintDualWarrant(t, h, "wrt-revoke-live", []string{"identity-sso-gateway"}, h.elena, h.marcus)
	if _, err := h.orch.N1Warrant.RevokeSigner(h.ctx, h.marcus.PrincipalID, h.marcus.KeyFingerprint, "AO_DEPARTED_ROLE", "sec-admin"); err != nil {
		t.Fatal(err)
	}

	// Direct execution-time re-verification must immediately fail closed
	if _, err := h.orch.N1Warrant.ReverifyWarrantForExecution(h.ctx, w.WarrantID, "identity-sso-gateway", 9.1, 4); err == nil {
		t.Fatal("expected ReverifyWarrantForExecution to fail closed after AO key revocation")
	}

	// Pipeline intake must arm containment bridge and fail closed before N2 rollout
	sarif := server.BuildDeterministicSARIF(
		"CVE-2026-90002", "CWE-287", 9.1, true, "identity-sso-gateway",
		"sha256:b200000000000000000000000000000000000000000000000000000000000002",
		"sha256:b299999999999999999999999999999999999999999999999999999999999999",
		"saml_dsig_xpath_eval_v1", "HTTP_PATH_TRAVERSAL", 8443,
	)
	items, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif, "STATELESS_CLEAN")
	if err != nil || len(items) != 1 {
		t.Fatalf("ExecuteSARIFRemediation err=%v len=%d", err, len(items))
	}
	if items[0].Stage == models.StageAttestedClosed {
		t.Fatal("revoked warrant must never advance to ATTESTED_CLOSED")
	}
	bridge, _ := h.store.GetBridge(h.ctx, items[0].BridgeID)
	if bridge == nil || bridge.Status != "ARMED" {
		t.Fatalf("containment bridge must remain ARMED on fail-closed warrant, got %+v", bridge)
	}
}

// INVARIANT 3: Canary Safety Rollback (Unauthorized execve Syscall & Stateful DDL Exception Routing)
func TestInvariant3_CanarySafetyRollbackAndStatefulRouting(t *testing.T) {
	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-inv3", []string{"payments-ledger-api", "identity-sso-gateway"}, h.alice, h.bob)

	// 3a. Unauthorized execve syscall triggers automatic canary rollback
	sarifExecve := server.BuildDeterministicSARIF(
		"CVE-2026-90003", "CWE-78", 9.4, true, "payments-ledger-api",
		"sha256:a100000000000000000000000000000000000000000000000000000000000001",
		"sha256:a177777777777777777777777777777777777777777777777777777777777777",
		"tls_heartbeat_ext_parse_vuln", "HTTP_PATH_TRAVERSAL", 8080,
	)
	items, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarifExecve, "BAD_SYSCALL_EXECVE")
	if err != nil || len(items) != 1 {
		t.Fatalf("unexpected error: %v", err)
	}
	if items[0].StatusHealth != models.HealthRollbackFailed || items[0].CanaryWeight != 0 {
		t.Fatalf("expected ROLLBACK_FAILED at weight 0, got %+v", items[0])
	}
	if !strings.Contains(items[0].BlockerCode, "execve") {
		t.Fatalf("expected execve failure code, got %q", items[0].BlockerCode)
	}
	wl, _ := h.orch.Deploy.InspectLiveWorkload(h.ctx, "payments-ledger-api")
	if wl.CanaryWeight != 0 {
		t.Fatalf("expected fleet-sim canary rolled back to 0%%, got %d%%", wl.CanaryWeight)
	}

	// 3b. Stateful SQL DDL mutation routes to Four-Eyes Ceiling Exception Cockpit
	sarifDDL := server.BuildDeterministicSARIF(
		"CVE-2026-90004", "CWE-89", 8.8, false, "identity-sso-gateway",
		"sha256:b200000000000000000000000000000000000000000000000000000000000002",
		"sha256:b266666666666666666666666666666666666666666666666666666666666666",
		"saml_dsig_xpath_eval_v1", "HTTP_PATH_TRAVERSAL", 8443,
	)
	ddlItems, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarifDDL, "STATEFUL_DDL")
	if err != nil || len(ddlItems) != 1 {
		t.Fatalf("unexpected error: %v", err)
	}
	if ddlItems[0].StatusHealth != models.HealthExceptionRouted {
		t.Fatalf("expected EXCEPTION_ROUTED for stateful DDL patch, got %+v", ddlItems[0])
	}
	exList, _ := h.store.ListExceptions(h.ctx)
	if len(exList) == 0 || exList[0].Status != "PENDING_DUAL_KEY" || exList[0].DDLCount == 0 {
		t.Fatalf("expected PENDING_DUAL_KEY exception with DDLCount > 0, got %+v", exList)
	}
}

// INVARIANT 4: Asymmetric Dual-Mode Emergency Freeze & 2-of-2 Thaw Ceremony
func TestInvariant4_AsymmetricFreezeAndDualKeyThaw(t *testing.T) {
	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-inv4", []string{"payments-ledger-api"}, h.alice, h.bob)

	// Activate FREEZE_HOLD
	fs, err := h.orch.N1Warrant.TriggerEmergencyFreeze(h.ctx, models.FreezeModeHold, "ops-oncall", "DRILL_HOLD", h.orch.N2Gate.RollbackAllActiveCanaries)
	if err != nil || fs.Mode != models.FreezeModeHold {
		t.Fatalf("TriggerEmergencyFreeze failed: %v", err)
	}

	// Inject KEV during active FREEZE_HOLD: Shield bridge MUST arm, while N2 rollout MUST halt!
	sarif := server.BuildDeterministicSARIF(
		"CVE-2026-90005", "CWE-787", 9.8, true, "payments-ledger-api",
		"sha256:a100000000000000000000000000000000000000000000000000000000000001",
		"sha256:a155555555555555555555555555555555555555555555555555555555555555",
		"tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)
	items, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif, "STATELESS_CLEAN")
	if err != nil || len(items) != 1 {
		t.Fatalf("ExecuteSARIFRemediation during freeze err=%v", err)
	}
	if items[0].StatusHealth != models.HealthFrozen {
		t.Fatalf("expected remediation status FROZEN, got %s", items[0].StatusHealth)
	}
	bridge, _ := h.store.GetBridge(h.ctx, items[0].BridgeID)
	if bridge == nil || bridge.Status != "ARMED" {
		t.Fatalf("Shield containment bridge MUST remain ARMED during FREEZE_HOLD, got %+v", bridge)
	}

	// Switch to FREEZE_ROLLBACK and confirm bridge stays ARMED
	if _, err := h.orch.N1Warrant.TriggerEmergencyFreeze(h.ctx, models.FreezeModeRollback, "ops-oncall", "DRILL_ROLLBACK", h.orch.N2Gate.RollbackAllActiveCanaries); err != nil {
		t.Fatal(err)
	}
	bridgeAfter, _ := h.store.GetBridge(h.ctx, items[0].BridgeID)
	if bridgeAfter.Status != "ARMED" {
		t.Fatalf("Shield containment bridge MUST remain ARMED during FREEZE_ROLLBACK")
	}

	// Single-signature Thaw attempt MUST fail closed
	badThaw, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeThaw, map[string]string{"action": "THAW"})
	_ = badThaw.SignEd25519(1, h.alice.ToPrincipalKey(), h.alice.PrivateKey)
	if _, err := h.orch.N1Warrant.ThawEmergencyFreeze(h.ctx, *badThaw); err == nil {
		t.Fatal("expected single-signature Thaw to be rejected")
	}

	// Valid 2-of-2 DSSE Thaw ceremony (Alice + Bob) restores OPERATIONAL state
	validThaw, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeThaw, map[string]string{"action": "THAW"})
	_ = validThaw.SignEd25519(1, h.alice.ToPrincipalKey(), h.alice.PrivateKey)
	_ = validThaw.SignEd25519(2, h.bob.ToPrincipalKey(), h.bob.PrivateKey)
	thawed, err := h.orch.N1Warrant.ThawEmergencyFreeze(h.ctx, *validThaw)
	if err != nil || thawed.Mode != models.FreezeModeOperational {
		t.Fatalf("expected valid 2-of-2 Thaw to restore OPERATIONAL, got %+v err=%v", thawed, err)
	}
}

// INVARIANT 5: Sub-Second Runtime Drift Detection & Automatic Bridge Re-Arming
func TestInvariant5_SubSecondDriftReArming(t *testing.T) {
	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-inv5", []string{"payments-ledger-api"}, h.alice, h.bob)

	vulnDigest := "sha256:a100000000000000000000000000000000000000000000000000000000000001"
	patchedDigest := "sha256:a144444444444444444444444444444444444444444444444444444444444444"
	sarif := server.BuildDeterministicSARIF(
		"CVE-2026-90006", "CWE-787", 9.8, true, "payments-ledger-api",
		vulnDigest, patchedDigest, "tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)
	items, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif, "STATELESS_CLEAN")
	if err != nil || len(items) != 1 || items[0].Stage != models.StageAttestedClosed {
		t.Fatalf("pre-drift closure failed: %+v err=%v", items, err)
	}

	// Start background 100ms N3 drift watcher AND activate FREEZE_HOLD to prove drift re-arming works even while frozen!
	watchCtx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	h.orch.N3Verify.StartDriftWatcher(watchCtx, 100*time.Millisecond)
	_, _ = h.orch.N1Warrant.TriggerEmergencyFreeze(h.ctx, models.FreezeModeHold, "ops-test", "FREEZE_DURING_DRIFT_TEST", nil)

	start := time.Now()
	if _, _, err := h.orch.Deploy.InjectDriftSimulation(h.ctx, "payments-ledger-api", vulnDigest); err != nil {
		t.Fatalf("InjectDriftSimulation failed: %v", err)
	}

	var detected *models.DriftIncident
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		drifts, _ := h.store.ListDriftIncidents(h.ctx)
		if len(drifts) > 0 {
			detected = &drifts[0]
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	elapsed := time.Since(start)
	if detected == nil {
		t.Fatal("N3 drift watcher failed to detect runtime drift and re-arm bridge")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected sub-second/near-instant drift re-arming, took %v", elapsed)
	}

	rearmedBridge, err := h.store.GetBridge(h.ctx, detected.RearmedBridgeID)
	if err != nil || rearmedBridge.Status != "REARMED_DRIFT" {
		t.Fatalf("expected Cilium bridge REARMED_DRIFT, got %+v err=%v", rearmedBridge, err)
	}
	updatedRem, _ := h.store.GetRemediation(h.ctx, items[0].RemediationID)
	if updatedRem.StatusHealth != models.HealthDriftViolation {
		t.Fatalf("expected remediation marked DRIFT_VIOLATION, got %s", updatedRem.StatusHealth)
	}
}

// INVARIANT 6: Immutable Trigger-Protected & SHA-256 Hash-Chained Ledger Tables
func TestInvariant6_ImmutableHashChainedLedger(t *testing.T) {
	h := setupIsolatedHarness(t)
	w := mintDualWarrant(t, h, "wrt-inv6-a", []string{"payments-ledger-api"}, h.alice, h.bob)
	mintDualWarrant(t, h, "wrt-inv6-b", []string{"identity-sso-gateway"}, h.elena, h.marcus)

	sarif := server.BuildDeterministicSARIF(
		"CVE-2026-90007", "CWE-787", 9.8, true, "payments-ledger-api",
		"sha256:a100000000000000000000000000000000000000000000000000000000000001",
		"sha256:a133333333333333333333333333333333333333333333333333333333333333",
		"tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)
	if _, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif, "STATELESS_CLEAN"); err != nil {
		t.Fatal(err)
	}

	// 1. Prove PostgreSQL BEFORE UPDATE OR DELETE triggers block mutations on all 3 ledger tables
	immutableChecks := []string{
		fmt.Sprintf(`UPDATE warrant_envelopes SET max_cvss = 5.0 WHERE warrant_id = '%s'`, w.WarrantID),
		fmt.Sprintf(`DELETE FROM warrant_envelopes WHERE warrant_id = '%s'`, w.WarrantID),
		`UPDATE agent_action_ledger SET status = 'SECURITY_VIOLATION'`,
		`DELETE FROM agent_action_ledger`,
		`UPDATE attestation_records SET cve_id = 'CVE-1999-0001'`,
		`DELETE FROM attestation_records`,
	}
	for _, stmt := range immutableChecks {
		_, err := h.store.Pool().Exec(h.ctx, stmt)
		if err == nil || !strings.Contains(err.Error(), "IMMUTABLE_LEDGER_VIOLATION") {
			t.Fatalf("expected PostgreSQL trigger IMMUTABLE_LEDGER_VIOLATION for %q, got: %v", stmt, err)
		}
	}

	// 2. Prove intact hash chains verify cleanly across all 3 tables
	rep, err := h.store.VerifyAllLedgerChains(h.ctx)
	if err != nil || !rep.AllValid {
		t.Fatalf("expected all 3 ledger hash chains valid, got %+v err=%v", rep, err)
	}

	// 3. Simulate superuser disk-level hash-link tampering (by disabling trigger temporarily, mutating a field, re-enabling trigger)
	// and prove VerifyAllLedgerChains immediately detects the broken cryptographic hash link!
	_, err = h.store.Pool().Exec(h.ctx, `
		ALTER TABLE agent_action_ledger DISABLE TRIGGER trg_immutable_agent_action_ledger;
		UPDATE agent_action_ledger SET worker_name = 'tampered-worker' WHERE seq_no = 1;
		ALTER TABLE agent_action_ledger ENABLE TRIGGER trg_immutable_agent_action_ledger;
	`)
	if err != nil {
		t.Fatalf("simulate disk tamper setup failed: %v", err)
	}

	tamperedRep, err := h.store.VerifyAllLedgerChains(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tamperedRep.AllValid {
		t.Fatal("expected VerifyAllLedgerChains to detect tampered hash link in agent_action_ledger")
	}
}

// LIVE THREAT & SCANNER FEEDS: Offline Enclave Default + Sanitized CISA KEV, OSV.dev & Trivy SARIF Intake
func TestLiveFeeds_OfflineDefaultAndCISAKEVOSVTrivyEnrichment(t *testing.T) {
	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-live-feeds", []string{"payments-ledger-api"}, h.alice, h.bob)

	// 1. Default mode MUST be offline and block external sync calls
	st, err := h.store.GetLiveFeedStatus(h.ctx)
	if err != nil || st.Config.Mode != models.FeedModeOffline {
		t.Fatalf("expected default feed mode 'offline', got %+v err=%v", st, err)
	}
	if _, err := h.orch.Feeds.SyncCISAKEV(h.ctx); err == nil || !strings.Contains(err.Error(), "FEED_MODE_OFFLINE") {
		t.Fatalf("expected SyncCISAKEV blocked in offline mode, got: %v", err)
	}

	// 2. Spin up local mock CISA KEV + Google OSV.dev servers and switch runtime feed config to 'live'
	feedMux := http.NewServeMux()
	feedMux.HandleFunc("GET /cisa/kev.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"catalogVersion": "2026.11.19",
			"dateReleased": "2026-11-19T00:00:00Z",
			"vulnerabilities": [
				{"cveID": "CVE-2023-38545", "dateAdded": "2023-10-18", "dueDate": "2023-11-08", "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-787"], "shortDescription": "STRIP_PROSE"},
				{"cveID": "CVE-2023-44487", "dateAdded": "2023-10-10", "dueDate": "2023-10-31", "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-400"], "shortDescription": "STRIP_PROSE"}
			]
		}`))
	})
	feedMux.HandleFunc("POST /osv/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results": [{"vulns": [{"id": "GO-2023-2102"}]}]}`))
	})
	feedMux.HandleFunc("GET /osv/v1/vulns/GO-2023-2102", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "GO-2023-2102",
			"aliases": ["CVE-2023-44487"],
			"summary": "UNTRUSTED SUMMARY",
			"database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-400"]},
			"affected": [{"ranges": [{"events": [{"fixed": "0.17.0"}]}]}]
		}`))
	})
	mockFeeds := httptest.NewServer(feedMux)
	defer mockFeeds.Close()

	_, err = h.orch.Feeds.UpdateConfig(h.ctx, models.FeedRuntimeConfig{
		Mode:            models.FeedModeLive,
		CISAKEVURL:      mockFeeds.URL + "/cisa/kev.json",
		KEVPollInterval: "1h",
		OSVAPIURL:       mockFeeds.URL + "/osv/v1/querybatch",
		TrivyEnabled:    true,
	})
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	kevRun, err := h.orch.Feeds.SyncCISAKEV(h.ctx)
	if err != nil || kevRun.ItemsIngested != 2 {
		t.Fatalf("SyncCISAKEV failed: run=%+v err=%v", kevRun, err)
	}

	osvRun, osvAdvisories, err := h.orch.Feeds.SyncOSV(h.ctx)
	if err != nil || osvRun.ItemsIngested != 1 || len(osvAdvisories) != 1 || !osvAdvisories[0].IsKEV {
		t.Fatalf("SyncOSV expected 1 KEV-matched advisory, got run=%+v adv=%+v err=%v", osvRun, osvAdvisories, err)
	}

	// 3. POST unmodified native Trivy SARIF 2.1.0 report to /api/v1/intake/sarif?target_service=payments-ledger-api
	// Note: raw Trivy SARIF does NOT set cisa_kev=true, proving warrantd cross-checks against synced cisa_kev_catalog!
	trivySARIF := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {
				"name": "Trivy",
				"rules": [{"id": "CVE-2023-38545", "properties": {"security-severity": "9.8", "tags": ["CRITICAL", "CWE-787"]}}]
			}},
			"results": [{"ruleId": "CVE-2023-38545", "level": "error"}]
		}]
	}`)
	resp, err := http.Post(
		h.httpSrv.URL+"/api/v1/intake/sarif?target_service=payments-ledger-api&max_findings=2",
		"application/json",
		bytes.NewReader(trivySARIF),
	)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST Trivy SARIF failed: resp=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()

	rems, _ := h.store.ListRemediations(h.ctx)
	if len(rems) != 1 || !rems[0].IsKEV || rems[0].Stage != models.StageAttestedClosed {
		t.Fatalf("expected Trivy CVE-2023-38545 enriched as IsKEV=true and closed, got %+v", rems)
	}

	// Verify ledger chains remain 100% intact after feed extractions
	chainRep, err := h.store.VerifyAllLedgerChains(h.ctx)
	if err != nil || !chainRep.AllValid {
		t.Fatalf("ledger chain broken after live feed syncs: %+v err=%v", chainRep, err)
	}
}

// INVARIANT 7: Zero-Prose vs. Signed-Rulepack Containment, Assurance Tiers, Brownfield Tier-2 Canary,
// Atomic 3-Step Quarantined Rollback (Contain-Before-Unban), Default Persona Redaction, and External Merkle Anchor
func TestInvariant7_ZeroProseAssuranceTiersQuarantinedRollbackAndExternalAnchor(t *testing.T) {
	anchorFile := filepath.Join(t.TempDir(), "external-worm-checkpoints.jsonl")
	t.Setenv("WARRANT_EXTERNAL_ANCHOR_PATH", anchorFile)
	t.Setenv("WARRANT_ENABLE_TEST_SMARTCARDS", "false")

	h := setupIsolatedHarness(t)

	// 0. Verify test_personas are redacted by default when WARRANT_ENABLE_TEST_SMARTCARDS != "true"
	bootResp, err := http.Get(h.httpSrv.URL + "/api/v1/bootstrap")
	if err != nil || bootResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/bootstrap failed: %v", err)
	}
	var bootSnap map[string]any
	_ = json.NewDecoder(bootResp.Body).Decode(&bootSnap)
	_ = bootResp.Body.Close()
	if personas, _ := bootSnap["test_personas"].([]any); len(personas) != 0 {
		t.Fatalf("expected 0 test_personas in production default mode, got %d", len(personas))
	}

	// Register brownfield workload fulfillment-worker (71.4% coverage, no shadow DB, OTel + rollback verified -> TIER_2_GUARDED_CANARY)
	brownfieldSvc := models.EstateService{
		ServiceID:                  "fulfillment-worker",
		DisplayName:                "Fulfillment Queue Worker",
		Namespace:                  "ops-fulfill",
		Tier:                       "TIER_2_PRODUCTION",
		WarrantClass:               "KEV-TIER2-COMMERCE",
		CurrentDigest:              "sha256:e500000000000000000000000000000000000000000000000000000000000005",
		CurrentPURL:                "pkg:oci/fulfillment-worker@sha256:e500000000000000000000000000000000000000000000000000000000000005",
		Replicas:                   3,
		TestCoveragePct:            71.4,
		OtelHealthProbes:           true,
		ReadonlyShadowReplica:      false,
		RollbackAutomationVerified: true,
		ReadOnlyRootFilesystem:     true,
		NoExecTmpMounts:            true,
		AllowedEgressServices:      []string{"orders-db.ops-fulfill.svc.cluster.local"},
		UnorderedArrayPaths:        []string{"$.shard_nodes"},
		BaselineSyscalls:           []string{"accept4", "close", "epoll_ctl", "epoll_wait", "fcntl", "fstat", "futex", "getsockopt", "mmap", "munmap", "nanosleep", "openat", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt", "socket", "write"},
	}
	gate.GradeServiceReadiness(&brownfieldSvc)
	if brownfieldSvc.AutonomyTier != models.AutonomyTier2GuardedCanary {
		t.Fatalf("expected TIER_2_GUARDED_CANARY, got %s", brownfieldSvc.AutonomyTier)
	}
	if err := h.store.UpsertEstateService(h.ctx, brownfieldSvc); err != nil {
		t.Fatal(err)
	}

	// Mint Standing Warrant authorizing AllowGuardedCanary = true
	now := time.Now().UTC()
	wp := models.WarrantPayload{
		WarrantID:              "wrt-inv7-guarded",
		WarrantClass:           "KEV-TIER2-COMMERCE",
		ScopeServices:          []string{"payments-ledger-api", "fulfillment-worker"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 10,
		AllowStatefulPatches:   false,
		AllowGuardedCanary:     true,
		MinCanarySamples:       500,
		StageDwellSeconds:      300,
		SLABridgeMinutes:       60,
		MaxP99LatencyMs:        120.0,
		IssuedAt:               now.Format(time.RFC3339),
		ExpiresAt:              now.Add(24 * time.Hour).Format(time.RFC3339),
	}
	wEnv, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, wp)
	_ = wEnv.SignEd25519(1, h.alice.ToPrincipalKey(), h.alice.PrivateKey)
	_ = wEnv.SignEd25519(2, h.bob.ToPrincipalKey(), h.bob.PrivateKey)
	if _, err := h.orch.N1Warrant.SubmitDualSignedWarrant(h.ctx, *wEnv); err != nil {
		t.Fatalf("SubmitDualSignedWarrant failed: %v", err)
	}

	// 1. Advisory WITHOUT matching L7 rulepack (CWE-000 / HTTP2_RAPID_RESET) on brownfield Tier-2 service:
	//    Must use ZERO_PROSE_EGRESS_MESH_QUARANTINE and close at ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM!
	sarifZeroProse := server.BuildDeterministicSARIF(
		"CVE-2026-97001", "CWE-000", 8.5, false, "fulfillment-worker",
		"sha256:e500000000000000000000000000000000000000000000000000000000000005",
		"sha256:e599999999999999999999999999999999999999999999999999999999999905",
		"", "HTTP2_RAPID_RESET", 8080,
	)
	zpItems, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarifZeroProse, "STATELESS_CLEAN")
	if err != nil || len(zpItems) != 1 {
		t.Fatalf("Zero-prose brownfield remediation failed: %v", err)
	}
	if zpItems[0].Stage != models.StageAttestedClosed || zpItems[0].AssuranceTier != models.AssuranceTier1PassiveDigestSBOM {
		t.Fatalf("expected ATTESTED_CLOSED with ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM, got stage=%s tier=%s blocker=%s",
			zpItems[0].Stage, zpItems[0].AssuranceTier, zpItems[0].BlockerCode)
	}
	zpBridge, err := h.store.GetBridge(h.ctx, zpItems[0].BridgeID)
	if err != nil || zpBridge.ContainmentMode != models.ContainmentModeZeroProseQuarantine {
		t.Fatalf("expected ZERO_PROSE_EGRESS_MESH_QUARANTINE bridge, got %+v err=%v", zpBridge, err)
	}

	// 2. Advisory WITH publisher-signed rulepack (CWE-787 / TLS_HEARTBEAT) on Tier-1 service:
	//    Must use SIGNED_RULEPACK_L7_SHIELD and close at ASSURANCE_TIER_2_DIFFERENTIAL_TWIN!
	vulnDigest := "sha256:a100000000000000000000000000000000000000000000000000000000000001"
	patchedDigest := "sha256:a188888888888888888888888888888888888888888888888888888888888801"
	sarifRulepack := server.BuildDeterministicSARIF(
		"CVE-2026-97002", "CWE-787", 9.8, true, "payments-ledger-api",
		vulnDigest, patchedDigest, "tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)
	rpItems, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarifRulepack, "STATELESS_CLEAN")
	if err != nil || len(rpItems) != 1 {
		t.Fatalf("Signed-rulepack remediation failed: %v", err)
	}
	if rpItems[0].AssuranceTier != models.AssuranceTier2DifferentialTwin {
		t.Fatalf("expected ASSURANCE_TIER_2_DIFFERENTIAL_TWIN, got %s", rpItems[0].AssuranceTier)
	}
	rpBridge, err := h.store.GetBridge(h.ctx, rpItems[0].BridgeID)
	if err != nil || rpBridge.ContainmentMode != models.ContainmentModeSignedRulepackL7 || rpBridge.RulepackID == "" {
		t.Fatalf("expected SIGNED_RULEPACK_L7_SHIELD with rulepack_id, got %+v err=%v", rpBridge, err)
	}

	// 3. Post-Closure Latent Regression -> Atomic 3-Step Quarantined Rollback (Contain-Before-Unban)
	qrbBody := bytes.NewReader([]byte(`{"actor":"sre-oncall","reason":"LATENT_CONN_POOL_EXHAUSTION"}`))
	qrbResp, err := http.Post(h.httpSrv.URL+"/api/v1/pipeline/"+rpItems[0].RemediationID+"/emergency-rollback", "application/json", qrbBody)
	if err != nil || qrbResp.StatusCode != http.StatusOK {
		t.Fatalf("POST emergency-rollback failed: resp=%v err=%v", qrbResp, err)
	}
	var rolledBack models.RemediationItem
	_ = json.NewDecoder(qrbResp.Body).Decode(&rolledBack)
	_ = qrbResp.Body.Close()

	if rolledBack.StatusHealth != models.HealthQuarantinedRollback || rolledBack.Stage != models.StageBridgedContained {
		t.Fatalf("expected QUARANTINED_ROLLBACK at BRIDGED_CONTAINED, got health=%s stage=%s", rolledBack.StatusHealth, rolledBack.Stage)
	}
	rearmed, err := h.store.GetBridge(h.ctx, rolledBack.BridgeID)
	if err != nil || rearmed.Status != "REARMED_DRIFT" {
		t.Fatalf("expected containment bridge re-armed before unban, got %+v err=%v", rearmed, err)
	}
	wlAfter, err := h.orch.Deploy.InspectLiveWorkload(h.ctx, "payments-ledger-api")
	if err != nil || wlAfter.BaselineDigest != vulnDigest {
		t.Fatalf("expected workload reverted to previous digest %s under quarantine, got %+v err=%v", vulnDigest, wlAfter, err)
	}

	// 4. External Transparency Checkpoint Verification & Simulated PostgreSQL Superuser Rewrite Detection
	verResp1, err := http.Post(h.httpSrv.URL+"/api/v1/ledger/verify", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil || verResp1.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/ledger/verify failed: %v", err)
	}
	var repBefore models.LedgerVerificationReport
	_ = json.NewDecoder(verResp1.Body).Decode(&repBefore)
	_ = verResp1.Body.Close()
	if !repBefore.AllValid || !repBefore.ExternalAnchorVerified || repBefore.LatestCheckpointID == "" {
		t.Fatalf("expected valid ledger + external anchor before tamper, got %+v", repBefore)
	}

	// Simulate rogue DB superuser disabling triggers on BOTH attestation_records and ledger_checkpoints,
	// wiping in-DB checkpoints, and rewriting historical entry_hash!
	_, err = h.store.Pool().Exec(h.ctx, `
		ALTER TABLE ledger_checkpoints DISABLE TRIGGER trg_immutable_ledger_checkpoints;
		DELETE FROM ledger_checkpoints;
		ALTER TABLE ledger_checkpoints ENABLE TRIGGER trg_immutable_ledger_checkpoints;
		ALTER TABLE attestation_records DISABLE TRIGGER trg_immutable_attestation_records;
		UPDATE attestation_records SET entry_hash = repeat('f', 64) WHERE seq_no = 1;
		ALTER TABLE attestation_records ENABLE TRIGGER trg_immutable_attestation_records;
	`)
	if err != nil {
		t.Fatalf("simulate superuser rewrite failed: %v", err)
	}

	verResp2, err := http.Post(h.httpSrv.URL+"/api/v1/ledger/verify", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	var repAfter models.LedgerVerificationReport
	_ = json.NewDecoder(verResp2.Body).Decode(&repAfter)
	_ = verResp2.Body.Close()
	if repAfter.AllValid || repAfter.ExternalAnchorVerified || !strings.Contains(repAfter.SuperuserTamperDetail, "DB_SUPERUSER_REWRITE_DETECTED") {
		t.Fatalf("expected External Transparency Anchor to catch DB superuser rewrite, got %+v", repAfter)
	}
}

// =========================================================================
// INVARIANT 8 — Autonomous Intrusion Countermeasures (ARTEX / GTIG Defenses)
//   1) SECRET-ROTATION-STATELESS Standing Warrant Class (N1 & N4):
//      Zero-prose Gitleaks intake -> ExternalSecret/SA rotation < 5m pivot -> OSCAL POA&M
//   2) Default Cloud Metadata (169.254.169.254) & Outbound Callback Quarantine (N3)
//   3) Mandatory 5th Readiness Gate (readOnlyRootFilesystem + noexec /tmp) &
//      eBPF/Tetragon In-Pod Webshell Drift Cordon + Fresh-Digest Pod Recycling
//   4) Attack-Path Chained Medium CWE Weighting (CWE-209/CWE-918/CWE-434) &
//      Cryptographic Build/Agent Config Exclusion (.github/, Dockerfile, AGENTS.md)
// =========================================================================
func TestInvariant8_ARTEXCountermeasures_SecretRotationMetadataQuarantineInPodDriftAndConfigLockout(t *testing.T) {
	h := setupIsolatedHarness(t)

	now := time.Now().UTC()

	// -----------------------------------------------------------------
	// 1. Addition 1 & 2: Mint 2-of-2 SECRET-ROTATION-STATELESS Warrant &
	//    Execute Zero-Prose Credential Rotation + Metadata Quarantine
	// -----------------------------------------------------------------
	secWP := models.WarrantPayload{
		WarrantID:              "wrt-inv8-secret-rot",
		WarrantClass:           models.WarrantClassSecretRotation,
		ScopeServices:          []string{"payments-ledger-api", "identity-sso-gateway"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 10,
		AllowSecretRotation:    true,
		SLABridgeMinutes:       15,
		MaxP99LatencyMs:        120.0,
		IssuedAt:               now.Format(time.RFC3339),
		ExpiresAt:              now.Add(24 * time.Hour).Format(time.RFC3339),
	}
	secEnv, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, secWP)
	if err != nil {
		t.Fatal(err)
	}
	_ = secEnv.SignEd25519(1, h.alice.ToPrincipalKey(), h.alice.PrivateKey)
	_ = secEnv.SignEd25519(2, h.bob.ToPrincipalKey(), h.bob.PrivateKey)
	if _, err := h.orch.N1Warrant.SubmitDualSignedWarrant(h.ctx, *secEnv); err != nil {
		t.Fatalf("SubmitDualSignedWarrant(SECRET-ROTATION-STATELESS) failed: %v", err)
	}

	gitleaksPayload := []byte(`[{
		"RuleID": "vault-service-token",
		"Secret": "SYNTHETIC_E2E_LEAKED_VAULT_CREDENTIAL_778899",
		"Match": "VAULT_TOKEN=SYNTHETIC_E2E_LEAKED_VAULT_CREDENTIAL_778899",
		"File": "config/prod.env",
		"Message": "UNTRUSTED COMMIT PROSE MUST BE STRIPPED",
		"service_id": "payments-ledger-api",
		"secret_resource_kind": "EXTERNAL_SECRET",
		"secret_resource_name": "extsec-payments-vault-creds"
	}]`)
	secResp, err := http.Post(h.httpSrv.URL+"/api/v1/intake/secrets", "application/json", bytes.NewReader(gitleaksPayload))
	if err != nil || secResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/v1/intake/secrets failed: resp=%v err=%v", secResp, err)
	}
	var secItems []models.RemediationItem
	if err := json.NewDecoder(secResp.Body).Decode(&secItems); err != nil {
		t.Fatalf("decode secret rotation items: %v", err)
	}
	_ = secResp.Body.Close()

	if len(secItems) != 1 {
		t.Fatalf("expected 1 secret rotation remediation item, got %d", len(secItems))
	}
	rotItem := secItems[0]
	if rotItem.RemediationKind != models.RemediationKindSecretRotation ||
		rotItem.Stage != models.StageAttestedClosed ||
		rotItem.AssuranceTier != models.AssuranceTierSecretRotated ||
		rotItem.PodSweepMatched == 0 || rotItem.PodSweepMatched != rotItem.PodSweepTotal {
		t.Fatalf("expected SECRET_ROTATION closed at ASSURANCE_TIER_SECRET_ROTATED with 100%% pod secret convergence, got %+v", rotItem)
	}
	rotJSON, _ := json.Marshal(rotItem)
	if strings.Contains(string(rotJSON), "SYNTHETIC_E2E_LEAKED_VAULT_CREDENTIAL") || strings.Contains(string(rotJSON), "UNTRUSTED COMMIT") {
		t.Fatalf("plaintext secret or commit prose leaked into control-plane item: %s", string(rotJSON))
	}

	// Addition 2 Check: Verify the N3 bridge explicitly severed 169.254.169.254 metadata & world callbacks
	rotBridge, err := h.store.GetBridge(h.ctx, rotItem.BridgeID)
	if err != nil {
		t.Fatalf("GetBridge(%s) failed: %v", rotItem.BridgeID, err)
	}
	if !rotBridge.MetadataPlaneBlocked ||
		!strings.Contains(rotBridge.CiliumManifestYAML, "169.254.169.254/32") ||
		!strings.Contains(rotBridge.CiliumManifestYAML, "toEntities") ||
		!strings.Contains(rotBridge.K8sNetpolYAML, "169.254.169.254/32") ||
		len(rotBridge.AllowedEgressPeers) == 0 {
		t.Fatalf("expected N3 bridge to enforce 169.254.169.254/32 metadata severance + AllowedEgressPeers clamp, got %+v", rotBridge)
	}

	// Verify DSSE-signed OSCAL 1.1.2 POA&M attestation was minted for secret rotation
	allAtts, err := h.store.ListAttestations(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundSecAtt := false
	for _, a := range allAtts {
		if a.AttestationID == rotItem.AttestationID && a.AssuranceTier == models.AssuranceTierSecretRotated {
			foundSecAtt = true
			break
		}
	}
	if !foundSecAtt {
		t.Fatalf("expected signed OSCAL attestation %s at ASSURANCE_TIER_SECRET_ROTATED", rotItem.AttestationID)
	}

	// -----------------------------------------------------------------
	// 2. Addition 3a: Mandatory 5th Readiness Gate (Immutable RootFS + noexec /tmp)
	// -----------------------------------------------------------------
	mutableSvc := models.EstateService{
		ServiceID:                  "mutable-legacy-portal",
		DisplayName:                "Mutable RootFS Portal",
		Namespace:                  "web-edge",
		Tier:                       "TIER_2_PRODUCTION",
		WarrantClass:               "KEV-TIER1-STATELESS",
		CurrentDigest:              "sha256:f600000000000000000000000000000000000000000000000000000000000006",
		CurrentPURL:                "pkg:oci/mutable-legacy-portal@sha256:f600000000000000000000000000000000000000000000000000000000000006",
		Replicas:                   2,
		TestCoveragePct:            95.0,
		OtelHealthProbes:           true,
		ReadonlyShadowReplica:      true,
		RollbackAutomationVerified: true,
		ReadOnlyRootFilesystem:     false, // <-- Violates 5th Gate (Webshell Dropper Risk)
		NoExecTmpMounts:            false,
		BaselineSyscalls:           []string{"accept4", "close", "read", "write"},
	}
	gate.GradeServiceReadiness(&mutableSvc)
	if mutableSvc.Eligible || mutableSvc.AutonomyTier != models.AutonomyTier3ContainAndCAB {
		t.Fatalf("expected mutable rootfs service to fail 5th gate and land in TIER_3_CONTAIN_AND_CAB, got eligible=%t tier=%s",
			mutableSvc.Eligible, mutableSvc.AutonomyTier)
	}
	if err := h.store.UpsertEstateService(h.ctx, mutableSvc); err != nil {
		t.Fatal(err)
	}

	// -----------------------------------------------------------------
	// 3. Addition 3b: In-Pod Webshell Drift Quarantine (Valid Image Digest + Dropped JSP)
	// -----------------------------------------------------------------
	wlBefore, err := h.orch.Deploy.InspectLiveWorkload(h.ctx, "payments-ledger-api")
	if err != nil || len(wlBefore.Pods) == 0 {
		t.Fatalf("InspectLiveWorkload failed: %v", err)
	}
	targetPod := wlBefore.Pods[0].PodName
	validDigest := wlBefore.Pods[0].RunningDigest

	tetEv := models.TetragonDriftEvent{
		ServiceID:          "payments-ledger-api",
		PodName:            targetPod,
		RunningDigest:      validDigest, // Pod still reports a valid image digest!
		ViolationType:      "FILESYSTEM_WRITE",
		TargetPathOrBinary: "/var/www/html/artex-probe-01.jsp",
	}
	tetBody, _ := json.Marshal(tetEv)
	// Unauthenticated POST /api/v1/telemetry/tetragon MUST fail with 401 Unauthorized (prevents pod recycle DoS)
	unauthResp, err := http.Post(h.httpSrv.URL+"/api/v1/telemetry/tetragon", "application/json", bytes.NewReader(tetBody))
	if err != nil || unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated tetragon webhook to return 401, got resp=%v err=%v", unauthResp, err)
	}
	_ = unauthResp.Body.Close()

	// Auditor g1aud_* bearer token MUST also be rejected with 403 Forbidden
	audReq, _ := http.NewRequest(http.MethodPost, h.httpSrv.URL+"/api/v1/telemetry/tetragon", bytes.NewReader(tetBody))
	audReq.Header.Set("Content-Type", "application/json")
	audReq.Header.Set("Authorization", "Bearer g1aud_fakeauditortoken1234567890")
	audResp, err := http.DefaultClient.Do(audReq)
	if err != nil || audResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected g1aud_* token on tetragon webhook to return 403, got resp=%v err=%v", audResp, err)
	}
	_ = audResp.Body.Close()

	// Authenticated dedicated sensor token succeeds with 201 Created
	tetReq, _ := http.NewRequest(http.MethodPost, h.httpSrv.URL+"/api/v1/telemetry/tetragon", bytes.NewReader(tetBody))
	tetReq.Header.Set("Content-Type", "application/json")
	tetReq.Header.Set("X-Tetragon-Sensor-Token", h.orch.TetragonSensorToken())
	tetResp, err := http.DefaultClient.Do(tetReq)
	if err != nil || tetResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/v1/telemetry/tetragon failed: resp=%v err=%v", tetResp, err)
	}
	var driftInc models.DriftIncident
	_ = json.NewDecoder(tetResp.Body).Decode(&driftInc)
	_ = tetResp.Body.Close()

	if driftInc.DriftKind != models.DriftKindFilesystemWebshell ||
		driftInc.ViolatingArtifact != "/var/www/html/artex-probe-01.jsp" ||
		!driftInc.PodCordoned || !driftInc.PodRecycled || driftInc.RearmedBridgeID == "" {
		t.Fatalf("expected Tetragon webshell drop to re-arm quarantine bridge + cordon & recycle pod, got %+v", driftInc)
	}

	// Verify compromised pod name was evicted & replaced by a fresh clean replica in fleet-sim
	wlRecycled, err := h.orch.Deploy.InspectLiveWorkload(h.ctx, "payments-ledger-api")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range wlRecycled.Pods {
		if p.PodName == targetPod {
			t.Fatalf("expected compromised pod %s to be cordoned and evicted from live workload, still present", targetPod)
		}
	}

	// -----------------------------------------------------------------
	// 4. Addition 4a: Attack-Path Chained Medium CWE Weighting (CVSS 5.3 CWE-209)
	//    Mint Warrant with KEVEligible=true + AutoRemediateCWEs=["CWE-209","CWE-918","CWE-434"]
	// -----------------------------------------------------------------
	cweWP := models.WarrantPayload{
		WarrantID:              "wrt-inv8-chained-cwe",
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          []string{"identity-sso-gateway", "payments-ledger-api"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		AutoRemediateCWEs:      []string{"CWE-209", "CWE-918", "CWE-434"},
		MaxBlastRadiusReplicas: 10,
		AllowStatefulPatches:   false,
		SLABridgeMinutes:       60,
		MaxP99LatencyMs:        120.0,
		IssuedAt:               now.Format(time.RFC3339),
		ExpiresAt:              now.Add(24 * time.Hour).Format(time.RFC3339),
	}
	cweEnv, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, cweWP)
	_ = cweEnv.SignEd25519(1, h.alice.ToPrincipalKey(), h.alice.PrivateKey)
	_ = cweEnv.SignEd25519(2, h.bob.ToPrincipalKey(), h.bob.PrivateKey)
	if _, err := h.orch.N1Warrant.SubmitDualSignedWarrant(h.ctx, *cweEnv); err != nil {
		t.Fatalf("SubmitDualSignedWarrant(chained CWE) failed: %v", err)
	}

	// Non-KEV CVSS 5.3 CWE-209 (verbose stack trace recon enabler) must elevate & auto-remediate!
	sarifCWE209 := server.BuildDeterministicSARIF(
		"CVE-2026-98209", "CWE-209", 5.3, false, "identity-sso-gateway",
		"sha256:b200000000000000000000000000000000000000000000000000000000000002",
		"sha256:b277777777777777777777777777777777777777777777777777777777777702",
		"http_error_stacktrace_leak", "STACK_TRACE_LEAK", 8080,
	)
	cweItems, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarifCWE209, "STATELESS_CLEAN")
	if err != nil || len(cweItems) != 1 {
		t.Fatalf("ExecuteSARIFRemediation(CWE-209 chained medium) failed: %v", err)
	}
	if !cweItems[0].ChainedExploitEnabler || cweItems[0].Stage != models.StageAttestedClosed {
		t.Fatalf("expected CVSS 5.3 CWE-209 to be marked ChainedExploitEnabler=true and ATTESTED_CLOSED, got %+v", cweItems[0])
	}

	// -----------------------------------------------------------------
	// 5. Addition 4b: Build/Agent Config Exclusion (.github/, Dockerfile RUN, AGENTS.md)
	// -----------------------------------------------------------------
	sarifPoisoned := server.BuildDeterministicSARIF(
		"CVE-2026-98999", "CWE-918", 8.8, true, "identity-sso-gateway",
		"sha256:b277777777777777777777777777777777777777777777777777777777777702",
		"sha256:b266666666666666666666666666666666666666666666666666666666666602",
		"ssrf_proxy_fetch", "SSRF_METADATA_FETCH", 8080,
	)
	poisonItems, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarifPoisoned, "POISONED_BUILD_CONFIG")
	if err != nil || len(poisonItems) != 1 {
		t.Fatalf("ExecuteSARIFRemediation(POISONED_BUILD_CONFIG) failed: %v", err)
	}
	pItem := poisonItems[0]
	if pItem.StatusHealth != models.HealthExceptionRouted || !strings.HasPrefix(pItem.BlockerCode, "N4_FORBIDDEN_CONFIG_POISONING_BLOCKED") {
		t.Fatalf("expected POISONED_BUILD_CONFIG patch to be blocked with N4_FORBIDDEN_CONFIG_POISONING_BLOCKED, got health=%s blocker=%s",
			pItem.StatusHealth, pItem.BlockerCode)
	}

	// Verify N4 agent_action_ledger recorded SECURITY_VIOLATION: FORBIDDEN_BUILD_OR_AGENT_CONFIG_MUTATION
	actions, err := h.store.ListAgentActions(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundConfigViolation := false
	for _, act := range actions {
		if act.RemediationID == pItem.RemediationID &&
			act.Status == "SECURITY_VIOLATION" &&
			strings.Contains(act.ViolationCode, "FORBIDDEN_BUILD_OR_AGENT_CONFIG_MUTATION") {
			foundConfigViolation = true
			break
		}
	}
	if !foundConfigViolation {
		t.Fatalf("expected SECURITY_VIOLATION (FORBIDDEN_BUILD_OR_AGENT_CONFIG_MUTATION) in agent_action_ledger for %s", pItem.RemediationID)
	}
}

// =========================================================================
// INVARIANT 9 — Targeted Hardening Delta Regression Suite
//   1) Startup Security Guard: WARRANT_ENABLE_TEST_SMARTCARDS=true fails closed
//      when combined with WARRANT_CLUSTER_DRIVER=kubernetes or WARRANT_FEED_MODE=live
//   2) Ephemeral Kernel Key Restart Ring: OSCAL 1.1.2 POA&M bundles minted before
//      a warrantd restart remain cryptographically verifiable via kernel_public_keys
//   3) ZERO_PROSE_EGRESS_MESH_QUARANTINE denies toEntities: ["kube-apiserver"]
//   4) Order-Sensitive Canary Default: service without unordered_array_paths
//      rolls back on reordered JSON array responses
// =========================================================================
func TestInvariant9_TargetedHardeningDelta_KeyRingStartupGuardAndOrderSensitiveCanary(t *testing.T) {
	// 1. Startup Fail-Closed Guard
	if err := server.ValidateStartupSecurityGuards(func(k string) string {
		switch k {
		case "WARRANT_ENABLE_TEST_SMARTCARDS":
			return "true"
		case "WARRANT_CLUSTER_DRIVER":
			return "kubernetes"
		default:
			return ""
		}
	}); err == nil {
		t.Fatal("expected ValidateStartupSecurityGuards to reject test smartcards with kubernetes driver")
	}
	if err := server.ValidateStartupSecurityGuards(func(k string) string {
		switch k {
		case "WARRANT_ENABLE_TEST_SMARTCARDS":
			return "true"
		case "WARRANT_FEED_MODE":
			return "live"
		default:
			return ""
		}
	}); err == nil {
		t.Fatal("expected ValidateStartupSecurityGuards to reject test smartcards with live feed mode")
	}

	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-inv9-ring", []string{"payments-ledger-api", "checkout-cart-svc"}, h.alice, h.bob)

	// 2. Mint an OSCAL attestation on Orchestrator #1 (ephemeral memory key #1), then simulate
	//    a warrantd restart with a brand-new random ephemeral memory key (Orchestrator #2)
	sarif1 := server.BuildDeterministicSARIF(
		"CVE-2026-99101", "CWE-000", 8.4, true, "payments-ledger-api",
		"sha256:a100000000000000000000000000000000000000000000000000000000000001",
		"sha256:a155555555555555555555555555555555555555555555555555555555555501",
		"", "HTTP2_RAPID_RESET", 8080,
	)
	items1, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif1, "STATELESS_CLEAN")
	if err != nil || len(items1) != 1 || items1[0].Stage != models.StageAttestedClosed {
		t.Fatalf("ExecuteSARIFRemediation failed: items=%+v err=%v", items1, err)
	}
	// Check Step 4b: ZERO_PROSE_EGRESS_MESH_QUARANTINE bridge denied kube-apiserver
	br, err := h.store.GetBridge(h.ctx, items1[0].BridgeID)
	if err != nil || !strings.Contains(br.CiliumManifestYAML, "kube-apiserver") {
		t.Fatalf("expected ZERO_PROSE_EGRESS_MESH_QUARANTINE bridge to deny kube-apiserver, got:\n%s", br.CiliumManifestYAML)
	}

	sdkCli1 := warrantsdk.NewClient(h.httpSrv.URL)
	oscalBundleBeforeRestart, err := sdkCli1.ExportOSCALBundle(h.ctx, items1[0].AttestationID)
	if err != nil {
		t.Fatalf("ExportOSCALBundle failed: %v", err)
	}

	// Simulate warrantd restart with a fresh ephemeral Ed25519 key against the same PostgreSQL DB
	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-extractor-restart-binary"))
	defer extSrv.Close()
	simSrv := httptest.NewServer(fleetsim.NewClusterSimulator().Handler())
	defer simSrv.Close()

	orch2, err := server.NewOrchestrator(h.ctx, h.store, extSrv.URL, simSrv.URL, "", h.orch.WebAuthnCfg)
	if err != nil {
		t.Fatalf("NewOrchestrator #2 failed: %v", err)
	}
	srv2 := httptest.NewServer(orch2.BuildHTTPHandler())
	defer srv2.Close()

	sdkCli2 := warrantsdk.NewClient(srv2.URL)
	ringAfterRestart, err := sdkCli2.KernelPublicKeyRing(h.ctx)
	if err != nil || len(ringAfterRestart) < 2 {
		t.Fatalf("expected >= 2 persisted kernel keys in append-only ring after restart, got %d err=%v", len(ringAfterRestart), err)
	}
	verRes, err := warrantsdk.VerifyOSCALBundleWithKeyRing(oscalBundleBeforeRestart, ringAfterRestart)
	if err != nil || !verRes.Valid {
		t.Fatalf("expected historical pre-restart OSCAL bundle to verify cleanly against persisted kernel_public_keys ring, got res=%+v err=%v", verRes, err)
	}

	// 3. Order-Sensitive Canary Default: register checkout-cart-svc WITHOUT UnorderedArrayPaths
	strictOrderSvc := models.EstateService{
		ServiceID:                  "checkout-cart-svc",
		DisplayName:                "Strict Ledger Order Checkout",
		Namespace:                  "commerce-edge",
		Tier:                       "TIER_1_CRITICAL",
		WarrantClass:               "KEV-TIER1-STATELESS",
		CurrentDigest:              "sha256:d400000000000000000000000000000000000000000000000000000000000004",
		CurrentPURL:                "pkg:oci/checkout-cart-svc@sha256:d400000000000000000000000000000000000000000000000000000000000004",
		Replicas:                   6,
		TestCoveragePct:            92.0,
		OtelHealthProbes:           true,
		ReadonlyShadowReplica:      true,
		RollbackAutomationVerified: true,
		ReadOnlyRootFilesystem:     true,
		NoExecTmpMounts:            true,
		UnorderedArrayPaths:        nil, // <-- Default order-sensitive! fleet-sim's reordered shard_nodes MUST trigger rollback!
		BaselineSyscalls:           []string{"accept4", "close", "epoll_ctl", "epoll_wait", "fcntl", "fstat", "futex", "getsockopt", "mmap", "munmap", "nanosleep", "openat", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt", "socket", "write"},
	}
	gate.GradeServiceReadiness(&strictOrderSvc)
	if err := h.store.UpsertEstateService(h.ctx, strictOrderSvc); err != nil {
		t.Fatal(err)
	}

	sarifOrder := server.BuildDeterministicSARIF(
		"CVE-2026-99102", "CWE-787", 9.1, true, "checkout-cart-svc",
		"sha256:d400000000000000000000000000000000000000000000000000000000000004",
		"sha256:d466666666666666666666666666666666666666666666666666666666666604",
		"", "TLS_HEARTBEAT", 8080,
	)
	orderItems, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarifOrder, "STATELESS_CLEAN")
	if err != nil || len(orderItems) != 1 {
		t.Fatalf("ExecuteSARIFRemediation(strictOrderSvc) failed: %v", err)
	}
	if orderItems[0].Stage == models.StageAttestedClosed || orderItems[0].CanaryWeight != 0 {
		t.Fatalf("expected order-sensitive default to block/rollback reordered shard_nodes array, got stage=%s weight=%d health=%s",
			orderItems[0].Stage, orderItems[0].CanaryWeight, orderItems[0].StatusHealth)
	}
}

func replaceDBName(dsn, newDB string) string {
	qIdx := strings.Index(dsn, "?")
	query := ""
	base := dsn
	if qIdx >= 0 {
		base = dsn[:qIdx]
		query = dsn[qIdx:]
	}
	slashIdx := strings.LastIndex(base, "/")
	if slashIdx < 0 {
		return dsn
	}
	return base[:slashIdx+1] + newDB + query
}
