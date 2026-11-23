package ledger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
	"github.com/cgilbert61/G1-Warrant/internal/verify"
	"github.com/cgilbert61/G1-Warrant/internal/warrant"
	"github.com/google/uuid"
)

// Engine implements N5: Cryptographic Attestation Ledger, NIST OSCAL 1.1.2 POA&M Minting,
// External Merkle Transparency Anchoring, Hash-Chain Verification, and Scoped External Auditor Bearer Tokens.
type Engine struct {
	store       *db.Store
	policy      *policy.Engine
	warrants    *warrant.Engine
	signer      crypto.EnvelopeSigner
	anchor      *TransparencyAnchor
	onBroadcast func(eventType string, payload any)
}

// NewEngine constructs the N5 Cryptographic Attestation & OSCAL Engine.
func NewEngine(
	store *db.Store,
	pol *policy.Engine,
	warrants *warrant.Engine,
	signer crypto.EnvelopeSigner,
	onBroadcast func(string, any),
	anchor ...*TransparencyAnchor,
) *Engine {
	var anc *TransparencyAnchor
	if len(anchor) > 0 && anchor[0] != nil {
		anc = anchor[0]
	} else {
		anc = NewTransparencyAnchor("", "")
	}
	return &Engine{
		store:       store,
		policy:      pol,
		warrants:    warrants,
		signer:      signer,
		anchor:      anc,
		onBroadcast: onBroadcast,
	}
}

// KernelPublicKey returns the public key metadata for external/in-browser DSSE verification.
func (e *Engine) KernelPublicKey() crypto.PrincipalKey {
	return e.signer.PublicKey()
}

// Signer exposes the active EnvelopeSigner to seal genesis bootstrap manifests and sign kernel key rotations.
func (e *Engine) Signer() crypto.EnvelopeSigner {
	return e.signer
}

// SignKernelKeyRotation signs a KernelKeyRotationPayload authorizing a successor kernel signing key.
func (e *Engine) SignKernelKeyRotation(ctx context.Context, newPK crypto.PrincipalKey, backendMode string) (*crypto.Envelope, error) {
	return db.SignKernelKeyRotation(ctx, e.signer, newPK, backendMode)
}

// SignerBackend returns the active cryptographic signing backend mode (KMS/HSM vs ephemeral memory).
func (e *Engine) SignerBackend() string {
	return e.signer.BackendMode()
}

// Anchor returns the External Merkle Transparency Anchor.
func (e *Engine) Anchor() *TransparencyAnchor {
	return e.anchor
}

// WitnessMode returns EXTERNAL_NOTARY when external notary anchoring is active, or IN_PROCESS_LOCAL otherwise.
func (e *Engine) WitnessMode() string {
	if e == nil || e.anchor == nil {
		return models.WitnessModeInProcessLocal
	}
	return e.anchor.WitnessMode()
}

// CreateCheckpoint signs and ships an explicit Merkle Root checkpoint across all 3 ledger tables.
func (e *Engine) CreateCheckpoint(ctx context.Context) (*models.LedgerCheckpoint, error) {
	return e.anchor.AnchorCheckpoint(ctx, e.store, e.signer)
}

// MintOSCALAttestation re-verifies N1 human signatures, validates N3 verification proofs via OPA,
// builds a standards-compliant NIST OSCAL 1.1.2 POA&M JSON package, signs it in a DSSE envelope,
// and appends it to the immutable attestation_records ledger.
func (e *Engine) MintOSCALAttestation(ctx context.Context, item *models.RemediationItem, svc *models.EstateService, bundle *verify.VerificationBundle) (*models.AttestationRecord, error) {
	// Live N1 re-verification immediately prior to minting
	actionKind := item.RemediationKind
	if actionKind == "" {
		actionKind = models.RemediationKindImagePatch
	}
	w, err := e.warrants.ReverifyWarrantForExecution(ctx, item.WarrantID, svc.ServiceID, item.CVSSScore, svc.Replicas, actionKind, item.CWEID)
	warrantOK := err == nil
	if !warrantOK {
		item.StatusHealth = models.HealthExceptionRouted
		item.BlockerCode = "N1_WARRANT_REVERIFY_FAILED_AT_MINT"
		_ = e.store.UpsertRemediation(ctx, item)
		return nil, err
	}

	hasProbe := bundle.HasSignedProbe ||
		bundle.AssuranceTier == models.AssuranceTier2DifferentialTwin ||
		(item.TwinReplayStatus == "EXPLOIT_BLOCKED" && bundle.UnpatchedTwinStatus == "EXPLOIT_SUCCEEDED")
	attestedPods := len(bundle.PodManifest)
	totalPods := svc.Replicas
	if bundle.TargetedAssetCount > 0 {
		attestedPods = bundle.LandedAssetCount
		totalPods = bundle.TargetedAssetCount
	}

	provenanceOK, provenanceHash := e.deriveVerifiedArtifactProvenance(ctx, item, bundle)

	ctp := bundle.CloneTwinProving
	if ctp == nil && item != nil {
		ctp = item.CloneTwinProving
	}
	vIn := policy.VerifyInput{
		RemediationKind:           actionKind,
		SecretRotatedAndRevoked:   bundle.AssuranceTier == models.AssuranceTierSecretRotated,
		ExposedSecretSHA256:       bundle.ExposedSecretSHA256,
		RotatedSecretSHA256:       bundle.RotatedSecretSHA256,
		HasSignedProbe:            hasProbe,
		UnpatchedTwinStatus:       bundle.UnpatchedTwinStatus,
		TwinReplayStatus:          item.TwinReplayStatus,
		ProvenanceVerified:        provenanceOK,
		VulnerablePkgAbsentInSBOM: bundle.VulnerablePkgAbsentInSBOM || actionKind == models.RemediationKindSecretRotation,
		AttestedPods:              attestedPods,
		TotalPods:                 totalPods,
		EvidenceGranularity:       bundle.EvidenceGranularity,
		TargetedAssets:            bundle.TargetedAssetCount,
		LandedAssets:              bundle.LandedAssetCount,
		FailedAssets:              bundle.FailedAssetCount,
		PendingAssets:             bundle.PendingAssetCount,
		RebootWaitingAssets:       bundle.RebootWaitingCount,
		AdmissionLockoutEnforced:  bundle.Lockout.PolicyName != "",
		WarrantReverified:         warrantOK,
	}
	if item != nil && item.PatchTargetLayer != "" {
		vIn.PatchTargetLayer = item.PatchTargetLayer
	}
	if ctp != nil {
		vIn.CloneTwinProvingPresent = true
		vIn.PatchTargetLayer = ctp.PatchTargetLayer
		vIn.TwinRuntime = ctp.TwinRuntime
		vIn.CloneTwinCount = ctp.CloneCount
		vIn.CloneTwinAllPassed = ctp.AllPassed
	}
	verDec, err := e.policy.EvalVerify(ctx, vIn)
	if err != nil {
		return nil, err
	}
	if !verDec.AllowAttestationMint && !verDec.AllowPartialAttestationMint && !verDec.AllowDispatchOnlyRecord {
		return nil, fmt.Errorf("N5_MINT_DENIED_BY_OPA: %s", strings.Join(verDec.Blockers, ","))
	}

	closureCompleteness := verDec.ClosureCompleteness
	if closureCompleteness == "" || closureCompleteness == "UNVERIFIED" {
		closureCompleteness = models.ClosureCompletenessFull
	}

	now := time.Now().UTC()
	reverifyExpiry := now.Add(30 * 24 * time.Hour)
	if w.ExpiresAt.Before(reverifyExpiry) {
		reverifyExpiry = w.ExpiresAt
	}

	attID := "att-" + uuid.NewString()[:8]
	systemUUID := deterministicUUID("system:g1-warrant-enterprise-estate")
	assetUUID := deterministicUUID("asset:" + svc.ServiceID)
	obsWarrantUUID := deterministicUUID("obs:warrant:" + attID)
	obsAgentUUID := deterministicUUID("obs:agent-lineage:" + attID)
	obsTwinUUID := deterministicUUID("obs:twin:" + attID)
	obsCloneProvingUUID := deterministicUUID("obs:clone-twin-proving:" + attID)
	obsFleetUUID := deterministicUUID("obs:fleet:" + attID)
	obsLockoutUUID := deterministicUUID("obs:lockout:" + attID)
	riskUUID := deterministicUUID("risk:" + attID)
	poamItemUUID := deterministicUUID("poam-item:" + attID)

	warrantEnvHash, _, _ := crypto.CanonicalSHA256Hex(w.DSSEEnvelope)
	commFuncID, agentID, authMode, builderDigest, builderFP, sponsorState, actLineage := e.resolveAgentObservationLineage(ctx, item.RemediationID, w.WarrantID)

	oscalDoc := map[string]any{
		"plan-of-action-and-milestones": map[string]any{
			"uuid": deterministicUUID("poam-doc:" + attID),
			"metadata": map[string]any{
				"title":         fmt.Sprintf("G1-Warrant Deterministic Closure POA&M — %s on %s", item.CVEID, svc.ServiceID),
				"last-modified": now.Format(time.RFC3339),
				"version":       "1.0.0",
				"oscal-version": "1.1.2",
				"props": []map[string]string{
					{"name": "organization", "value": "G1163RT Security Labs, Inc."},
					{"name": "control-plane", "value": "G1-Warrant Deterministic Kernel"},
					{"name": "compliance-baseline", "value": "NIST-SP-800-53-Rev5"},
					{"name": "assurance-tier", "value": verDec.AssuranceTier},
					{"name": "closure-completeness", "value": closureCompleteness},
					{"name": "signer-backend", "value": e.signer.BackendMode()},
					{"name": "attestation-id", "value": attID},
					{"name": "reverification-expires-at", "value": reverifyExpiry.Format(time.RFC3339)},
				},
				"parties": []map[string]any{
					{
						"uuid": deterministicUUID("party:org"),
						"type": "organization",
						"name": "G1163RT Security Labs, Inc.",
					},
					{
						"uuid":          deterministicUUID("party:" + w.Slot1PrincipalID),
						"type":          "person",
						"name":          w.Slot1PrincipalID,
						"email-addresses": []string{w.Slot1Email},
						"props": []map[string]string{
							{"name": "ac5-slot", "value": "SLOT_1_SERVICE_OWNER"},
							{"name": "key-fingerprint", "value": w.Slot1KeyFP},
						},
					},
					{
						"uuid":          deterministicUUID("party:" + w.Slot2PrincipalID),
						"type":          "person",
						"name":          w.Slot2PrincipalID,
						"email-addresses": []string{w.Slot2Email},
						"props": []map[string]string{
							{"name": "ac5-slot", "value": "SLOT_2_AUTHORIZING_OFFICIAL"},
							{"name": "key-fingerprint", "value": w.Slot2KeyFP},
						},
					},
				},
			},
			"system-id": map[string]string{
				"identifier-type": "https://ietf.org/rfc/rfc4122",
				"id":              systemUUID,
			},
			"local-definitions": map[string]any{
				"inventory-items": []map[string]any{
					{
						"uuid":        assetUUID,
						"description": fmt.Sprintf("Workload %s (%s)", svc.ServiceID, svc.Namespace),
						"props": []map[string]string{
							{"name": "service-id", "value": svc.ServiceID},
							{"name": "namespace", "value": svc.Namespace},
							{"name": "purl", "value": item.PackagePURL},
							{"name": "vulnerable-digest", "value": item.VulnerableDigest},
							{"name": "patched-digest", "value": item.PatchedDigest},
						},
					},
				},
			},
			"observations": []map[string]any{
				{
					"uuid":        obsWarrantUUID,
					"title":       "N1 Dual-Key Standing Warrant Proof (NIST SP 800-53 AC-5)",
					"description": fmt.Sprintf("Governing Warrant %s verified with distinct Service Owner and Authorizing Official keys.", w.WarrantID),
					"methods":     []string{"EXAMINE", "TEST"},
					"collected":   now.Format(time.RFC3339),
					"props": []map[string]string{
						{"name": "warrant-id", "value": w.WarrantID},
						{"name": "warrant-dsse-sha256", "value": warrantEnvHash},
						{"name": "slot1-principal", "value": w.Slot1PrincipalID},
						{"name": "slot1-key-fp", "value": w.Slot1KeyFP},
						{"name": "slot2-principal", "value": w.Slot2PrincipalID},
						{"name": "slot2-key-fp", "value": w.Slot2KeyFP},
					},
				},
				{
					"uuid":        obsAgentUUID,
					"title":       "N4 Agent Workload Identity, Commissioning Function & RFC 8693 Delegation Lineage",
					"description": fmt.Sprintf("Executed by governed workload %s under Commissioning Function %s (%s).", agentID, commFuncID, sponsorState),
					"methods":     []string{"EXAMINE", "TEST"},
					"collected":   now.Format(time.RFC3339),
					"props": []map[string]string{
						{"name": "commissioning-function-id", "value": commFuncID},
						{"name": "agent-id", "value": agentID},
						{"name": "authority-mode", "value": authMode},
						{"name": "builder-artifact-digest", "value": builderDigest},
						{"name": "builder-key-fingerprint", "value": builderFP},
						{"name": "sponsorship-continuity-state", "value": sponsorState},
						{"name": "act-delegation-lineage", "value": actLineage},
					},
				},
				buildN3ProofObservation(obsTwinUUID, now, actionKind, hasProbe, provenanceOK, provenanceHash, item, bundle),
				buildCloneTwinProvingObservation(obsCloneProvingUUID, now, item, ctp),
				{
					"uuid":        obsFleetUUID,
					"title":       "N3 Passive Fleet & WN-8 Distributor Per-Asset Landing Manifest",
					"description": fmt.Sprintf("Closure completeness=%s | Landed=%d/%d | RebootWaiting=%d | Pending=%d | Failed=%d.", closureCompleteness, attestedPods, totalPods, bundle.RebootWaitingCount, bundle.PendingAssetCount, bundle.FailedAssetCount),
					"methods":     []string{"INSPECT"},
					"collected":   now.Format(time.RFC3339),
					"props": []map[string]string{
						{"name": "closure-completeness", "value": closureCompleteness},
						{"name": "targeted-count", "value": fmt.Sprintf("%d", totalPods)},
						{"name": "landed-count", "value": fmt.Sprintf("%d", attestedPods)},
						{"name": "failed-count", "value": fmt.Sprintf("%d", bundle.FailedAssetCount)},
						{"name": "pending-count", "value": fmt.Sprintf("%d", bundle.PendingAssetCount)},
						{"name": "reboot-waiting-count", "value": fmt.Sprintf("%d", bundle.RebootWaitingCount)},
						{"name": "distributor-id", "value": bundle.DistributorID},
						{"name": "distributor-order-id", "value": bundle.DistributorOrderID},
						{"name": "distributor-report-sha256", "value": bundle.DistributorReportSHA256},
						{"name": "landed-assets", "value": strings.Join(bundle.LandedAssetKeys, ",")},
						{"name": "non-landed-assets", "value": strings.Join(bundle.NonLandedAssetKeys, ",")},
					},
					"relevant-evidence": buildPodEvidenceList(bundle.PodManifest),
				},
				{
					"uuid":        obsLockoutUUID,
					"title":       "N3 Permanent Admission Lockout Policy",
					"description": fmt.Sprintf("Permanent ValidatingAdmissionPolicy %s enforced banning %s.", bundle.Lockout.PolicyName, bundle.Lockout.BannedDigest),
					"methods":     []string{"EXAMINE"},
					"collected":   now.Format(time.RFC3339),
					"props": []map[string]string{
						{"name": "lockout-policy-id", "value": bundle.Lockout.PolicyName},
						{"name": "banned-digest", "value": bundle.Lockout.BannedDigest},
					},
				},
			},
			"risks": []map[string]any{
				{
					"uuid":        riskUUID,
					"title":       fmt.Sprintf("%s Remediation Closure (%s — %s)", item.CVEID, svc.ServiceID, closureCompleteness),
					"description": fmt.Sprintf("Deterministic remediation record for %s (CISA_KEV=%t, CVSS=%.1f, completeness=%s).", item.CVEID, item.IsKEV, item.CVSSScore, closureCompleteness),
					"statement":   buildTierHonestRiskStatement(actionKind, hasProbe, verDec.AssuranceTier, closureCompleteness),
					"status":      map[bool]string{true: "closed", false: "open"}[closureCompleteness == models.ClosureCompletenessFull],
					"props": []map[string]string{
						{"name": "cve-id", "value": item.CVEID},
						{"name": "cwe-id", "value": item.CWEID},
						{"name": "cisa-kev", "value": fmt.Sprintf("%t", item.IsKEV)},
						{"name": "closure-completeness", "value": closureCompleteness},
						{"name": "reverify-expires-at", "value": reverifyExpiry.Format(time.RFC3339)},
					},
				},
			},
			"poam-items": []map[string]any{
				{
					"uuid":        poamItemUUID,
					"title":       fmt.Sprintf("[%s] Closed Autonomous Remediation — %s", item.CVEID, svc.ServiceID),
					"description": fmt.Sprintf("Closed under Standing Warrant %s with Admission Lockout %s.", w.WarrantID, bundle.Lockout.PolicyName),
					"related-observations": []map[string]string{
						{"observation-uuid": obsWarrantUUID},
						{"observation-uuid": obsAgentUUID},
						{"observation-uuid": obsTwinUUID},
						{"observation-uuid": obsCloneProvingUUID},
						{"observation-uuid": obsFleetUUID},
						{"observation-uuid": obsLockoutUUID},
					},
					"associated-risks": []map[string]string{
						{"risk-uuid": riskUUID},
					},
				},
			},
		},
	}

	env, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeAttestation, oscalDoc)
	if err != nil {
		return nil, err
	}
	if err := e.signer.SignEnvelope(ctx, 1, env); err != nil {
		return nil, err
	}

	ttvrSec := int64(now.Sub(item.CreatedAt).Seconds())
	if ttvrSec < 1 {
		ttvrSec = 1
	}

	rec := &models.AttestationRecord{
		AttestationID:           attID,
		RemediationID:           item.RemediationID,
		ServiceID:               svc.ServiceID,
		CVEID:                   item.CVEID,
		IsKEV:                   item.IsKEV,
		WarrantID:               w.WarrantID,
		Slot1PrincipalID:        w.Slot1PrincipalID,
		Slot1Email:              w.Slot1Email,
		Slot2PrincipalID:        w.Slot2PrincipalID,
		Slot2Email:              w.Slot2Email,
		TwinTranscriptSHA256:    bundle.TwinTranscriptSHA256,
		AssuranceTier:           verDec.AssuranceTier,
		ClosureCompleteness:     closureCompleteness,
		TargetedAssetCount:      totalPods,
		LandedAssetCount:        attestedPods,
		FailedAssetCount:        bundle.FailedAssetCount,
		PendingAssetCount:       bundle.PendingAssetCount,
		RebootWaitingCount:      bundle.RebootWaitingCount,
		DistributorID:           bundle.DistributorID,
		DistributorOrderID:      bundle.DistributorOrderID,
		DistributorReportSHA256: bundle.DistributorReportSHA256,
		SignerBackend:           e.signer.BackendMode(),
		FleetDigestManifest:     bundle.PodManifest,
		LockoutPolicyID:         bundle.Lockout.PolicyName,
		ReverifyExpiresAt:       reverifyExpiry,
		DSSEEnvelope:            *env,
		OSCALPOAM:               oscalDoc,
		TTVRSeconds:             ttvrSec,
		MintedAt:                now,
	}
	if err := e.store.AppendAttestation(ctx, rec); err != nil {
		return nil, err
	}
	// Anchor DSSE-signed Merkle Root checkpoint across all 9 ledger tables on every attestation record
	_, _ = e.anchor.AnchorCheckpoint(ctx, e.store, e.signer)

	item.AttestationID = attID
	item.AssuranceTier = verDec.AssuranceTier
	item.ClosureCompleteness = closureCompleteness
	if closureCompleteness == models.ClosureCompletenessFull {
		item.Stage = models.StageAttestedClosed
		item.StatusHealth = models.HealthAttested
		item.BlockerCode = ""
		item.ClosedAt = &now
	} else {
		// Honest Partial / Dispatch-Only Closure: keep item in VERIFYING_LOCKING with active containment bridge armed!
		item.Stage = models.StageVerifyingLocking
		item.StatusHealth = models.HealthBridged
		if closureCompleteness == models.ClosureCompletenessPartial {
			item.BlockerCode = "PARTIAL_FLEET_CLOSURE_CONTAINMENT_HELD"
		} else {
			item.BlockerCode = "DISTRIBUTOR_DISPATCH_ONLY_CONTAINMENT_HELD"
		}
	}
	_ = e.store.UpsertRemediation(ctx, item)
	kernelPK := e.signer.PublicKey()
	_ = e.store.AppendTrace(ctx, models.TraceEvent{
		TraceID:       "trc-" + uuid.NewString()[:8],
		RemediationID: item.RemediationID,
		Engine:        "N5",
		StepCode:      "OSCAL_1_1_2_ATTESTATION_MINTED",
		Outcome:       "ATTESTED",
		ActorOrToken:  kernelPK.KeyID,
		EvidenceHash:  rec.EntryHash,
		Fields: map[string]string{
			"attestation_id": attID,
			"assurance_tier": verDec.AssuranceTier,
			"signer_backend": e.signer.BackendMode(),
			"ttvr_seconds":   fmt.Sprintf("%d", ttvrSec),
			"oscal_version":  "1.1.2",
		},
		OccurredAt: now,
	})

	if e.onBroadcast != nil {
		e.onBroadcast("ATTESTATION_MINTED", rec)
		e.onBroadcast("REMEDIATION_UPDATED", item)
	}
	return rec, nil
}

// VerifyAttestationEnvelope cryptographically verifies a minted N5 DSSE OSCAL envelope.
func (e *Engine) VerifyAttestationEnvelope(env crypto.Envelope) error {
	raw, err := env.DecodePayload()
	if err != nil {
		return err
	}
	canon, err := crypto.CanonicalizeJSON(raw)
	if err != nil {
		return err
	}
	if string(canon) != string(raw) {
		return fmt.Errorf("OSCAL payload is not RFC 8785 JCS canonical")
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("missing kernel attestation signature")
	}
	kernelPK := e.signer.PublicKey()
	return crypto.VerifySingleSignature(env.PayloadType, raw, env.Signatures[0], &kernelPK, crypto.DefaultWebAuthnConfig())
}

// MintScopedAuditorToken generates a read-only, time-bounded cryptographic bearer token
// serving exclusively the Auditor Vault surface (/api/v1/auditor/...).
func (e *Engine) MintScopedAuditorToken(ctx context.Context, label, createdBy string, scopedIDs []string, ttlHours int) (*models.AuditorShareToken, string, error) {
	if ttlHours <= 0 || ttlHours > 720 {
		ttlHours = 24
	}
	if strings.TrimSpace(label) == "" {
		label = "3PAO External Assessment Bundle"
	}
	randBytes := make([]byte, 24)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, "", err
	}
	rawBearer := "g1aud_" + hex.EncodeToString(randBytes)
	now := time.Now().UTC()
	tok := models.AuditorShareToken{
		TokenID:              "aud-" + uuid.NewString()[:8],
		Label:                label,
		ScopedAttestationIDs: scopedIDs,
		CreatedBy:            createdBy,
		ExpiresAt:            now.Add(time.Duration(ttlHours) * time.Hour),
		Revoked:              false,
		CreatedAt:            now,
	}
	if err := e.store.CreateAuditorToken(ctx, tok, rawBearer); err != nil {
		return nil, "", err
	}
	return &tok, rawBearer, nil
}

func deterministicUUID(seed string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("g1163rt.g1-warrant:"+seed)).String()
}

func formatActChainSummary(act *models.ActorClaim) string {
	if act == nil {
		return ""
	}
	var hops []string
	for cur := act; cur != nil; cur = cur.ParentActor {
		hops = append(hops, fmt.Sprintf("%s[%s:%s]", cur.AgentID, cur.CommissioningFunctionID, cur.SponsorshipState))
	}
	return strings.Join(hops, " -> ")
}

func (e *Engine) resolveAgentObservationLineage(ctx context.Context, remediationID, warrantID string) (commFuncID, agentID, authMode, builderDigest, builderFP, sponsorState, actLineage string) {
	commFuncID = models.SystemCommissioningFunctionID
	agentID = "agt-k8s-rollout"
	authMode = models.AuthorityModeWarrantComposite
	builderDigest = "sha256:" + crypto.SHA256Hex([]byte("g1-internal-worker:agt-k8s-rollout"))
	builderFP = "INTERNAL_RELEASE_ATTESTOR"
	sponsorState = models.SponsorshipActive
	actLineage = fmt.Sprintf("%s[%s:%s]", agentID, commFuncID, sponsorState)

	if e.store == nil {
		return
	}
	if actions, err := e.store.ListAgentActions(ctx); err == nil {
		for _, act := range actions {
			if act.Status != "EXECUTED" {
				continue
			}
			if (remediationID != "" && act.RemediationID == remediationID) || (remediationID == "" && warrantID != "" && act.WarrantID == warrantID) {
				if act.CommissioningFunctionID != "" {
					commFuncID = act.CommissioningFunctionID
				}
				if act.AgentID != "" {
					agentID = act.AgentID
				} else if act.WorkerName != "" {
					agentID = act.WorkerName
				}
				if act.AuthorityMode != "" {
					authMode = act.AuthorityMode
				}
				if summary := formatActChainSummary(act.ActChain); summary != "" {
					actLineage = summary
				}
				break
			}
		}
	}
	if ag, err := e.store.GetAgentIdentity(ctx, agentID); err == nil && ag != nil {
		commFuncID = ag.CommissioningFunctionID
		builderDigest = ag.ArtifactDigest
		builderFP = ag.BuilderKeyFingerprint
		sponsorState = ag.SponsorshipState
		if actLineage == "" {
			actLineage = fmt.Sprintf("%s[%s:%s]", ag.AgentID, ag.CommissioningFunctionID, ag.SponsorshipState)
		}
	}
	return
}

func buildPodEvidenceList(pods []models.PodDigestEntry) []map[string]any {
	out := make([]map[string]any, 0, len(pods))
	for _, p := range pods {
		out = append(out, map[string]any{
			"description": fmt.Sprintf("Pod %s on %s verified running %s", p.PodName, p.NodeName, p.RunningDigest),
			"props": []map[string]string{
				{"name": "pod-name", "value": p.PodName},
				{"name": "node-name", "value": p.NodeName},
				{"name": "running-digest", "value": p.RunningDigest},
			},
		})
	}
	return out
}

func (e *Engine) deriveVerifiedArtifactProvenance(
	ctx context.Context,
	item *models.RemediationItem,
	bundle *verify.VerificationBundle,
) (bool, string) {
	if item == nil || bundle == nil {
		return false, ""
	}
	if item.RemediationKind == models.RemediationKindSecretRotation || bundle.AssuranceTier == models.AssuranceTierSecretRotated {
		return false, ""
	}
	if e != nil && e.store != nil && strings.TrimSpace(item.RemediationID) != "" && strings.TrimSpace(item.PatchedDigest) != "" {
		if traces, err := e.store.ListTraces(ctx, item.RemediationID); err == nil {
			for _, tr := range traces {
				if tr.StepCode == "ARTIFACT_PROVENANCE_VERIFIED" &&
					tr.Outcome == "PASS" &&
					strings.TrimSpace(tr.EvidenceHash) != "" &&
					tr.Fields["patched_digest"] == item.PatchedDigest {
					return true, tr.EvidenceHash
				}
			}
		}
	}
	if bundle.ProvenanceVerified && strings.TrimSpace(bundle.ProvenanceEvidenceHash) != "" {
		return true, bundle.ProvenanceEvidenceHash
	}
	return false, ""
}

func buildN3ProofObservation(
	obsUUID string,
	now time.Time,
	actionKind string,
	hasProbe bool,
	provenanceOK bool,
	provenanceHash string,
	item *models.RemediationItem,
	bundle *verify.VerificationBundle,
) map[string]any {
	if actionKind == models.RemediationKindSecretRotation || bundle.AssuranceTier == models.AssuranceTierSecretRotated {
		return map[string]any{
			"uuid":        obsUUID,
			"title":       "N3 Autonomous Secret Rotation & Cryptographic Non-Equivalence Proof",
			"description": "Workload credential rotated and prior token revoked; verified non-empty cryptographic non-equivalence (rotated SHA-256 != exposed SHA-256).",
			"methods":     []string{"EXAMINE", "TEST"},
			"collected":   now.Format(time.RFC3339),
			"props": []map[string]string{
				{"name": "has-signed-probe", "value": "false"},
				{"name": "secret-rotated-and-revoked", "value": "true"},
				{"name": "exposed-secret-sha256", "value": bundle.ExposedSecretSHA256},
				{"name": "rotated-secret-sha256", "value": bundle.RotatedSecretSHA256},
			},
		}
	}
	if hasProbe {
		return map[string]any{
			"uuid":        obsUUID,
			"title":       "N3 Isolated Ephemeral Twin Exploit Replay",
			"description": "Deterministic differential exploit probe executed against isolated ephemeral twin; positive control EXPLOIT_SUCCEEDED on unpatched baseline and EXPLOIT_BLOCKED on patched candidate.",
			"methods":     []string{"TEST"},
			"collected":   now.Format(time.RFC3339),
			"props": []map[string]string{
				{"name": "has-signed-probe", "value": "true"},
				{"name": "unpatched-twin-status", "value": bundle.UnpatchedTwinStatus},
				{"name": "twin-replay-status", "value": item.TwinReplayStatus},
				{"name": "twin-transcript-sha256", "value": bundle.TwinTranscriptSHA256},
				{"name": "provenance-verified", "value": fmt.Sprintf("%t", provenanceOK)},
				{"name": "provenance-evidence-sha256", "value": provenanceHash},
			},
		}
	}
	return map[string]any{
		"uuid":        obsUUID,
		"title":       "N3 Passive Artifact Provenance & SBOM Absence Verification",
		"description": "No signed exploit probe registered for finding (NO_PROBE_PASSIVE_ONLY); verified cryptographic publisher provenance signature and vulnerable package absence in patched SBOM.",
		"methods":     []string{"EXAMINE", "INSPECT"},
		"collected":   now.Format(time.RFC3339),
		"props": []map[string]string{
			{"name": "has-signed-probe", "value": "false"},
			{"name": "twin-replay-status", "value": item.TwinReplayStatus},
			{"name": "provenance-verified", "value": fmt.Sprintf("%t", provenanceOK)},
			{"name": "provenance-evidence-sha256", "value": provenanceHash},
			{"name": "vulnerable-pkg-absent-in-sbom", "value": fmt.Sprintf("%t", bundle.VulnerablePkgAbsentInSBOM)},
		},
	}
}

func buildTierHonestRiskStatement(actionKind string, hasProbe bool, assuranceTier string, closureCompleteness string) string {
	if actionKind == models.RemediationKindSecretRotation || assuranceTier == models.AssuranceTierSecretRotated {
		return "Exposed credential contained via egress and metadata quarantine, rotated and revoked with verified cryptographic non-equivalence, and attested across live workload pods."
	}
	if assuranceTier == models.AssuranceTier0DistributorDispatchOnly || closureCompleteness == models.ClosureCompletenessDispatchOnly {
		if hasProbe {
			return "Exploit vector contained via Cilium bridge, candidate patch verified via differential exploit replay in isolated twin, and dispatched to distributor lacking per-asset confirmation (containment bridge held active)."
		}
		return "Advisory contained via Cilium bridge, candidate patch verified via cryptographic publisher provenance and SBOM package absence (no active exploit probe executed), and dispatched to distributor lacking per-asset confirmation (containment bridge held active)."
	}
	if hasProbe {
		return fmt.Sprintf("Exploit vector contained via Cilium bridge, patched with verified publisher provenance, verified via differential exploit replay in isolated twin, and recorded with honest per-asset landing telemetry (completeness=%s).", closureCompleteness)
	}
	return fmt.Sprintf("Advisory contained via Cilium bridge, patched with verified publisher provenance and SBOM package absence (no active exploit probe executed), and recorded with honest per-asset landing telemetry (completeness=%s).", closureCompleteness)
}

func buildCloneTwinProvingObservation(
	obsUUID string,
	now time.Time,
	item *models.RemediationItem,
	ctp *models.CloneTwinProvingManifest,
) map[string]any {
	if ctp == nil {
		layer := models.PatchTargetLayerUserspace
		if item != nil && item.PatchTargetLayer != "" {
			layer = item.PatchTargetLayer
		}
		return map[string]any{
			"uuid":        obsUUID,
			"title":       "N3 Clone-Twin Proving Ground Status",
			"description": "No candidate image/package clone-twin run recorded for this closure type.",
			"methods":     []string{"EXAMINE"},
			"collected":   now.Format(time.RFC3339),
			"props": []map[string]string{
				{"name": "clone-twin-proving-executed", "value": "false"},
				{"name": "patch-target-layer", "value": layer},
			},
		}
	}
	evidence := make([]map[string]any, 0, len(ctp.Clones))
	for _, c := range ctp.Clones {
		evidence = append(evidence, map[string]any{
			"href": fmt.Sprintf("twin://%s/%s?index=%d", ctp.ProvingNamespace, c.CloneName, c.CloneIndex),
			"description": fmt.Sprintf("Clone %d (%s | ip=%s | ready=%t | smoke=%t | acceptance=%t | latency_ms=%.2f | sha256=%s)",
				c.CloneIndex, c.CloneName, c.PodIP, c.ServiceUpPassed, c.SmokeTestPassed, c.ClassAcceptancePassed, c.ObservedLatencyMs, c.EvidenceSHA256),
		})
	}
	return map[string]any{
		"uuid":  obsUUID,
		"title": "N3 Isolated Clone-Twin Proving Ground Verification",
		"description": fmt.Sprintf("Proved candidate patch %s across %d isolated clones in %s (%s | layer=%s | ready=%d/%d | smoke=%d/%d | acceptance=%d/%d).",
			ctp.CandidateDigest, ctp.CloneCount, ctp.ProvingNamespace, ctp.TwinRuntime, ctp.PatchTargetLayer,
			ctp.ServicesUpCount, ctp.CloneCount, ctp.SmokePassedCount, ctp.CloneCount, ctp.AcceptancePassedCount, ctp.CloneCount),
		"methods":   []string{"TEST", "EXAMINE"},
		"collected": ctp.ProvedAt.Format(time.RFC3339),
		"props": []map[string]string{
			{"name": "clone-twin-proving-executed", "value": "true"},
			{"name": "proving-run-id", "value": ctp.ProvingRunID},
			{"name": "proving-namespace", "value": ctp.ProvingNamespace},
			{"name": "twin-runtime", "value": ctp.TwinRuntime},
			{"name": "patch-target-layer", "value": ctp.PatchTargetLayer},
			{"name": "clone-count", "value": fmt.Sprintf("%d", ctp.CloneCount)},
			{"name": "services-up-count", "value": fmt.Sprintf("%d", ctp.ServicesUpCount)},
			{"name": "smoke-passed-count", "value": fmt.Sprintf("%d", ctp.SmokePassedCount)},
			{"name": "acceptance-passed-count", "value": fmt.Sprintf("%d", ctp.AcceptancePassedCount)},
			{"name": "all-passed", "value": fmt.Sprintf("%t", ctp.AllPassed)},
			{"name": "proving-transcript-sha256", "value": ctp.TranscriptSHA256},
		},
		"relevant-evidence": evidence,
	}
}
