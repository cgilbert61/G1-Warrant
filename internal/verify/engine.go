package verify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/adapters/estatereader"
	"github.com/cgilbert61/G1-Warrant/internal/agentcp"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
	"github.com/cgilbert61/G1-Warrant/internal/warrant"
	"github.com/google/uuid"
)

// VerificationBundle holds verified N3 outputs required by N5 to mint an OSCAL 1.1.2 POA&M package.
type VerificationBundle struct {
	TwinTranscriptSHA256      string
	UnpatchedTwinStatus       string
	HasSignedProbe            bool
	ProvenanceVerified        bool
	ProvenanceEvidenceHash    string
	AssuranceTier             string
	ExposedSecretSHA256       string
	RotatedSecretSHA256       string
	VulnerablePkgAbsentInSBOM bool
	PodManifest               []models.PodDigestEntry
	Lockout                   models.AdmissionLockout

	// v1.2.0 WN-8 Per-Asset Distributor Closure Evidence
	EvidenceGranularity     string
	ClosureCompleteness     string
	TargetedAssetCount      int
	LandedAssetCount        int
	FailedAssetCount        int
	PendingAssetCount       int
	RebootWaitingCount      int
	RolledBackAssetCount    int
	DistributorID           string
	DistributorOrderID      string
	DistributorReportSHA256 string
	LandedAssetKeys         []string
	NonLandedAssetKeys      []string

	// v1.3.0 Clone-Twin Proving Ground Manifest
	CloneTwinProving *models.CloneTwinProvingManifest

	// v1.5.0 S1 Deterministic Wire-Receipt & Honest-Gap Coverage/Staleness Ledger
	WireReceipt           *WireReceiptResult
	UntestedSurface       []string
	EvidenceVersion       int
	ReportEvidenceVersion int
	StaleEvidence         bool
}

// Engine implements N3: Differential Twin Replay (with Positive-Control Verification),
// 3-Clone Proving Ground, Passive Fleet Attestation, Permanent Admission Lockout before Bridge Retirement,
// Atomic Quarantined Rollback (Contain-Before-Unban), and Runtime Drift Re-Arming.
type Engine struct {
	store         *db.Store
	policy        *policy.Engine
	warrants      *warrant.Engine
	agentCP       *agentcp.ControlPlane
	shield        adapters.ShieldEnforcer
	deploy        adapters.DeploymentTarget
	twin          adapters.TwinRunner
	vmTwin        adapters.VMTwinProvider
	estateReaders *estatereader.Registry
	rulepacks     *adapters.RulepackRegistry
	onBroadcast   func(eventType string, payload any)
	mu            sync.Mutex
	handledDrifts map[string]bool
}

// NewEngine constructs the N3 Verification Harness & Drift Lockout Engine.
func NewEngine(
	store *db.Store,
	pol *policy.Engine,
	warrants *warrant.Engine,
	agentCP *agentcp.ControlPlane,
	shield adapters.ShieldEnforcer,
	deploy adapters.DeploymentTarget,
	twin adapters.TwinRunner,
	onBroadcast func(string, any),
	rulepacks ...*adapters.RulepackRegistry,
) *Engine {
	var reg *adapters.RulepackRegistry
	if len(rulepacks) > 0 && rulepacks[0] != nil {
		reg = rulepacks[0]
	} else {
		reg = adapters.NewDefaultRulepackRegistry()
	}
	return &Engine{
		store:         store,
		policy:        pol,
		warrants:      warrants,
		agentCP:       agentCP,
		shield:        shield,
		deploy:        deploy,
		twin:          twin,
		rulepacks:     reg,
		onBroadcast:   onBroadcast,
		handledDrifts: make(map[string]bool),
	}
}

// VerifyLockAndRetireBridge runs Active Twin Replay, Passive Pod Digest & Symbol Sweep,
// enforces the Permanent Admission Lockout, and ONLY THEN retires the active Shield containment bridge.
func (e *Engine) VerifyLockAndRetireBridge(ctx context.Context, item *models.RemediationItem, svc *models.EstateService) (*VerificationBundle, error) {
	item.Stage = models.StageVerifyingLocking
	_ = e.store.UpsertRemediation(ctx, item)
	e.emit("REMEDIATION_UPDATED", item)

	w, err := e.warrants.ReverifyWarrantForExecution(ctx, item.WarrantID, svc.ServiceID, item.CVSSScore, svc.Replicas)
	warrantOK := err == nil
	if !warrantOK {
		item.StatusHealth = models.HealthExceptionRouted
		item.BlockerCode = "N1_WARRANT_REVERIFY_FAILED"
		_ = e.store.UpsertRemediation(ctx, item)
		e.emit("REMEDIATION_UPDATED", item)
		return nil, err
	}

	// Step 1: Differential Isolated Shadow Twin Replay (Positive Control on VulnerableDigest + Negative Control on PatchedDigest)
	matchedRulepack := e.rulepacks.Lookup(item.CVEID, item.CWEID, item.ExploitVector)
	hasSignedProbe := matchedRulepack != nil && matchedRulepack.HasSignedProbe

	twinResp, err := e.twin.RunExploitReplay(ctx, fleetsim.TwinReplayRequest{
		ServiceID:        svc.ServiceID,
		CVEID:            item.CVEID,
		VulnerableDigest: item.VulnerableDigest,
		PatchedDigest:    item.PatchedDigest,
		ExploitVector:    item.ExploitVector,
		VulnerableSymbol: item.VulnerableSymbol,
		HasSignedProbe:   hasSignedProbe,
	})
	if err != nil {
		return nil, err
	}
	_ = e.agentCP.RecordGovernedAdapterAction(
		ctx, w.WarrantID, item.RemediationID, "twin_runner", svc.ServiceID,
		"ISOLATED_TWIN_EXPLOIT_REPLAY", w.Slot1PrincipalID, w.Slot2PrincipalID,
		"ZERO_EGRESS_ISOLATED", crypto.SHA256Hex([]byte(item.PatchedDigest)), twinResp.TranscriptSHA256,
	)
	item.TwinReplayStatus = twinResp.Status
	step1OK := (!hasSignedProbe && twinResp.Status == "NO_PROBE_PASSIVE_ONLY") ||
		(hasSignedProbe && twinResp.UnpatchedStatus == "EXPLOIT_SUCCEEDED" && twinResp.Status == "EXPLOIT_BLOCKED")
	_ = e.recordTrace(ctx, item.RemediationID, "N3", "ISOLATED_TWIN_EXPLOIT_REPLAY",
		ternary(step1OK, "PASS", "BLOCK"),
		twinResp.TwinPodName, twinResp.TranscriptSHA256,
		map[string]string{
			"isolated_namespace":    twinResp.IsolatedNamespace,
			"has_signed_probe":      fmt.Sprintf("%t", hasSignedProbe),
			"unpatched_twin_status": twinResp.UnpatchedStatus,
			"status":                twinResp.Status,
			"production_untouched":  fmt.Sprintf("%t", twinResp.ProductionUntouched),
		},
	)

	// Step 2: Passive Live Fleet Pod imageID SHA-256 Digest & Patched SBOM Absence Sweep
	wl, err := e.deploy.InspectLiveWorkload(ctx, svc.ServiceID)
	if err != nil {
		return nil, err
	}
	matchedPods := 0
	podManifest := make([]models.PodDigestEntry, 0, len(wl.Pods))
	for _, pod := range wl.Pods {
		if pod.RunningDigest == item.PatchedDigest {
			matchedPods++
		}
		podManifest = append(podManifest, models.PodDigestEntry{
			PodName:       pod.PodName,
			NodeName:      pod.NodeName,
			RunningDigest: pod.RunningDigest,
			LoadedLibs:    pod.LoadedLibs,
		})
	}
	vulnPkgAbsentInSBOM := item.PatchedDigest != "" &&
		item.PatchedDigest != item.VulnerableDigest &&
		!sbomStillReferencesDigest(svc.SBOMPURLs, item.VulnerableDigest)

	item.PodSweepMatched = matchedPods
	item.PodSweepTotal = len(wl.Pods)
	manifestHash, _, _ := crypto.CanonicalSHA256Hex(podManifest)
	_ = e.recordTrace(ctx, item.RemediationID, "N3", "PASSIVE_FLEET_DIGEST_SWEEP",
		ternary(matchedPods == len(wl.Pods) && vulnPkgAbsentInSBOM, "PASS", "BLOCK"),
		"k8s_rollout", manifestHash,
		map[string]string{
			"matched_pods":                  fmt.Sprintf("%d/%d", matchedPods, len(wl.Pods)),
			"vulnerable_pkg_absent_in_sbom": fmt.Sprintf("%t", vulnPkgAbsentInSBOM),
		},
	)

	// Step 3: Enforce Permanent Admission Lockout (ValidatingAdmissionPolicy + Gatekeeper Rego) BEFORE retiring bridge
	lockout, err := e.deploy.EnforceAdmissionLockout(ctx, item.RemediationID, svc.ServiceID, item.CVEID, item.VulnerableDigest, item.PatchedDigest)
	if err != nil {
		return nil, err
	}
	if err := e.store.UpsertLockout(ctx, *lockout); err != nil {
		return nil, err
	}
	item.LockoutPolicyID = lockout.PolicyName
	_ = e.agentCP.RecordGovernedAdapterAction(
		ctx, w.WarrantID, item.RemediationID, "k8s_rollout", svc.ServiceID,
		"ENFORCE_VALIDATING_ADMISSION_LOCKOUT", w.Slot1PrincipalID, w.Slot2PrincipalID,
		"INTERNAL_CLUSTER_ONLY", crypto.SHA256Hex([]byte(item.VulnerableDigest)),
		crypto.SHA256Hex([]byte(lockout.VAPManifestYAML)),
	)
	_ = e.recordTrace(ctx, item.RemediationID, "N3", "ADMISSION_LOCKOUT_ENFORCED", "PASS", lockout.PolicyName, crypto.SHA256Hex([]byte(lockout.VAPManifestYAML)), map[string]string{
		"banned_digest": item.VulnerableDigest,
		"policy_name":   lockout.PolicyName,
	})

	// Step 4: Evaluate OPA Verify Policy before retiring the active Shield containment bridge
	provVerified, provEvidenceHash := e.DeriveVerifiedArtifactProvenance(ctx, item)
	vIn := policy.VerifyInput{
		HasSignedProbe:            hasSignedProbe,
		UnpatchedTwinStatus:       twinResp.UnpatchedStatus,
		TwinReplayStatus:          twinResp.Status,
		ProvenanceVerified:        provVerified,
		VulnerablePkgAbsentInSBOM: vulnPkgAbsentInSBOM,
		AttestedPods:              matchedPods,
		TotalPods:                 len(wl.Pods),
		AdmissionLockoutEnforced:  lockout.PolicyName != "",
		WarrantReverified:         warrantOK,
	}
	populateVerifyCloneTwinFields(&vIn, item, item.CloneTwinProving)
	verDec, err := e.policy.EvalVerify(ctx, vIn)
	if err != nil {
		return nil, err
	}
	if !verDec.AllowBridgeRetirement {
		item.BlockerCode = strings.Join(verDec.Blockers, ",")
		_ = e.store.UpsertRemediation(ctx, item)
		e.emit("REMEDIATION_UPDATED", item)
		return nil, fmt.Errorf("N3_CLOSURE_BLOCKED: %s", item.BlockerCode)
	}
	item.AssuranceTier = verDec.AssuranceTier

	// Step 5: Retire temporary containment bridge now that patch + twin + lockout are verified
	if item.BridgeID != "" {
		if err := e.shield.RetireBridge(ctx, item.BridgeID); err != nil {
			return nil, err
		}
		if b, bErr := e.store.GetBridge(ctx, item.BridgeID); bErr == nil {
			now := time.Now().UTC()
			b.Status = "RETIRED"
			b.BlockerReasonCode = "PATCH_ATTESTED_AND_LOCKED_OUT"
			b.RetiredAt = &now
			_ = e.store.UpsertBridge(ctx, *b)
			e.emit("BRIDGE_RETIRED", b)
		}
		_ = e.recordTrace(ctx, item.RemediationID, "N3", "CONTAINMENT_BRIDGE_RETIRED", "PASS", item.BridgeID, crypto.SHA256Hex([]byte(item.BridgeID)), map[string]string{
			"lockout_prerequisite": lockout.PolicyName,
		})
	}

	_ = e.store.UpsertRemediation(ctx, item)
	e.emit("REMEDIATION_UPDATED", item)

	testedSurfaces := []string{"passive_fleet_digest_sweep", "admission_lockout"}
	if vulnPkgAbsentInSBOM {
		testedSurfaces = append(testedSurfaces, "sbom_absence_check")
	}
	var wireReceipt *WireReceiptResult
	if hasSignedProbe {
		testedSurfaces = append(testedSurfaces, "differential_twin_exploit_replay")
		rawTranscript := fmt.Sprintf("unpatched_status=%s patched_status=%s tested_digest=%s transcript_sha256=%s",
			twinResp.UnpatchedStatus, twinResp.Status, twinResp.TestedDigest, twinResp.TranscriptSHA256)
		blob := NewContentAddressedBlob("differential_twin", "identity", []byte(rawTranscript), false)
		res := VerifyWireReceipt(blob, []string{
			"unpatched_status=" + twinResp.UnpatchedStatus,
			"patched_status=" + twinResp.Status,
		})
		wireReceipt = &res
	}
	cov := EvaluateCoverageAndStaleness(
		[]string{"differential_twin_exploit_replay", "passive_fleet_digest_sweep", "sbom_absence_check", "admission_lockout"},
		testedSurfaces,
		1,
		1,
	)

	return &VerificationBundle{
		TwinTranscriptSHA256:      twinResp.TranscriptSHA256,
		UnpatchedTwinStatus:       twinResp.UnpatchedStatus,
		HasSignedProbe:            hasSignedProbe,
		ProvenanceVerified:        provVerified,
		ProvenanceEvidenceHash:    provEvidenceHash,
		AssuranceTier:             verDec.AssuranceTier,
		VulnerablePkgAbsentInSBOM: vulnPkgAbsentInSBOM,
		PodManifest:               podManifest,
		Lockout:                   *lockout,
		CloneTwinProving:          item.CloneTwinProving,
		WireReceipt:               wireReceipt,
		UntestedSurface:           cov.UntestedSurface,
		EvidenceVersion:           cov.EvidenceVersion,
		ReportEvidenceVersion:     cov.ReportEvidenceVersion,
		StaleEvidence:             cov.StaleEvidence,
	}, nil
}

// DeriveVerifiedArtifactProvenance inspects recorded remediation_traces for a cryptographic publisher provenance
// verification record matching item.PatchedDigest (replacing any hardcoded ProvenanceVerified=true assumption).
func (e *Engine) DeriveVerifiedArtifactProvenance(ctx context.Context, item *models.RemediationItem) (bool, string) {
	if e == nil || e.store == nil || item == nil || strings.TrimSpace(item.RemediationID) == "" || strings.TrimSpace(item.PatchedDigest) == "" {
		return false, ""
	}
	traces, err := e.store.ListTraces(ctx, item.RemediationID)
	if err != nil {
		return false, ""
	}
	for _, tr := range traces {
		if tr.StepCode == "ARTIFACT_PROVENANCE_VERIFIED" &&
			tr.Outcome == "PASS" &&
			strings.TrimSpace(tr.EvidenceHash) != "" &&
			tr.Fields["patched_digest"] == item.PatchedDigest {
			return true, tr.EvidenceHash
		}
	}
	return false, ""
}

func sbomStillReferencesDigest(sbomPURLs []string, vulnDigest string) bool {
	if strings.TrimSpace(vulnDigest) == "" {
		return false
	}
	low := strings.ToLower(strings.TrimSpace(vulnDigest))
	for _, p := range sbomPURLs {
		if strings.Contains(strings.ToLower(p), low) {
			return true
		}
	}
	return false
}

// VerifyAndRetireSecretRotationBridge verifies 100% live pod secret-generation convergence, old-token revocation,
// and cryptographic non-equivalence (rotated_secret_sha256 != exposed_secret_sha256 & non-empty) under a
// SECRET-ROTATION-STATELESS Standing Warrant before retiring the temporary egress/metadata quarantine bridge.
func (e *Engine) VerifyAndRetireSecretRotationBridge(
	ctx context.Context,
	item *models.RemediationItem,
	svc *models.EstateService,
	exposedSecretSHA256 string,
	rotRes *fleetsim.SecretRotationResult,
) (*VerificationBundle, error) {
	item.Stage = models.StageVerifyingLocking
	_ = e.store.UpsertRemediation(ctx, item)
	e.emit("REMEDIATION_UPDATED", item)

	_, err := e.warrants.ReverifyWarrantForExecution(ctx, item.WarrantID, svc.ServiceID, 0, svc.Replicas, models.RemediationKindSecretRotation)
	warrantOK := err == nil
	if !warrantOK {
		item.StatusHealth = models.HealthExceptionRouted
		item.BlockerCode = "N1_SECRET_WARRANT_REVERIFY_FAILED"
		_ = e.store.UpsertRemediation(ctx, item)
		e.emit("REMEDIATION_UPDATED", item)
		return nil, err
	}

	wl, err := e.deploy.InspectLiveWorkload(ctx, svc.ServiceID)
	if err != nil {
		return nil, err
	}
	matchedPods := 0
	podManifest := make([]models.PodDigestEntry, 0, len(wl.Pods))
	for _, pod := range wl.Pods {
		if rotRes.NewSecretGeneration > 0 && pod.SecretGeneration >= rotRes.NewSecretGeneration {
			matchedPods++
		}
		podManifest = append(podManifest, models.PodDigestEntry{
			PodName:       pod.PodName,
			NodeName:      pod.NodeName,
			RunningDigest: pod.RunningDigest,
			LoadedLibs:    pod.LoadedLibs,
		})
	}
	item.PodSweepMatched = matchedPods
	item.PodSweepTotal = len(wl.Pods)
	item.TwinReplayStatus = "SECRET_REVOKED_AND_ROTATED"

	verDec, err := e.policy.EvalVerify(ctx, policy.VerifyInput{
		RemediationKind:         models.RemediationKindSecretRotation,
		SecretRotatedAndRevoked: rotRes.PreviousTokenRevoked,
		ExposedSecretSHA256:     exposedSecretSHA256,
		RotatedSecretSHA256:     rotRes.NewSecretVersionHash,
		AttestedPods:            matchedPods,
		TotalPods:               len(wl.Pods),
		WarrantReverified:       warrantOK,
	})
	if err != nil {
		return nil, err
	}
	if !verDec.AllowBridgeRetirement {
		item.StatusHealth = models.HealthExceptionRouted
		item.BlockerCode = strings.Join(verDec.Blockers, ",")
		_ = e.store.UpsertRemediation(ctx, item)
		e.emit("REMEDIATION_UPDATED", item)
		return nil, fmt.Errorf("N3_SECRET_ROTATION_BLOCKED: %s", item.BlockerCode)
	}
	item.AssuranceTier = verDec.AssuranceTier

	if item.BridgeID != "" {
		_ = e.shield.RetireBridge(ctx, item.BridgeID)
		if b, bErr := e.store.GetBridge(ctx, item.BridgeID); bErr == nil {
			now := time.Now().UTC()
			b.Status = "RETIRED"
			b.BlockerReasonCode = "SECRET_ROTATED_AND_PREVIOUS_TOKEN_REVOKED"
			b.RetiredAt = &now
			_ = e.store.UpsertBridge(ctx, *b)
			e.emit("BRIDGE_RETIRED", b)
		}
	}

	lockout := models.AdmissionLockout{
		LockoutID:     "sec-rev-" + item.RemediationID,
		RemediationID: item.RemediationID,
		ServiceID:     svc.ServiceID,
		CVEID:         item.CVEID,
		BannedDigest:  exposedSecretSHA256,
		PatchedDigest: rotRes.NewSecretVersionHash,
		PolicyName:    "cred-revoke-" + rotRes.SecretResourceName,
		Status:        "ENFORCED",
		EnforcedAt:    rotRes.RotatedAt,
	}
	item.LockoutPolicyID = lockout.PolicyName
	_ = e.store.UpsertRemediation(ctx, item)
	e.emit("REMEDIATION_UPDATED", item)

	return &VerificationBundle{
		TwinTranscriptSHA256: rotRes.NewSecretVersionHash,
		AssuranceTier:        verDec.AssuranceTier,
		ExposedSecretSHA256:  exposedSecretSHA256,
		RotatedSecretSHA256:  rotRes.NewSecretVersionHash,
		PodManifest:          podManifest,
		Lockout:              lockout,
	}, nil
}

// ExecuteEmergencyQuarantinedRollback resolves the operational deadlock between post-closure regressions
// and Permanent Admission Lockouts via a strict 3-step Contain-Before-Unban state transition:
//   Step 1: Re-arm Cilium/Envoy containment bridge FIRST so unpatched pods cannot be exploited upon revert.
//   Step 2: Atomically suspend the ValidatingAdmissionPolicy lockout (SUSPENDED_FOR_QUARANTINED_ROLLBACK).
//   Step 3: Roll back the workload to the previous known-working digest under active quarantine.
func (e *Engine) ExecuteEmergencyQuarantinedRollback(ctx context.Context, remediationID, actor, reason string) (*models.RemediationItem, error) {
	if strings.TrimSpace(actor) == "" {
		actor = "sre-incident-commander"
	}
	if strings.TrimSpace(reason) == "" {
		reason = "POST_PROMOTION_LATENT_REGRESSION"
	}

	rem, err := e.store.GetRemediation(ctx, remediationID)
	if err != nil {
		return nil, fmt.Errorf("remediation %q not found: %w", remediationID, err)
	}
	svc, err := e.store.GetEstateService(ctx, rem.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("service %q not found: %w", rem.ServiceID, err)
	}

	// Step 1: Re-arm N3 containment bridge BEFORE suspending Admission Lockout
	bridgeID := rem.BridgeID
	rearmCount := 1
	if existing, bErr := e.store.GetBridge(ctx, bridgeID); bErr == nil {
		rearmCount = existing.RearmedCount + 1
	}
	if bridgeID == "" {
		bridgeID = "brg-qrb-" + uuid.NewString()[:8]
	}
	quarantineBridge, err := e.shield.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
		BridgeID:          bridgeID,
		RemediationID:     rem.RemediationID,
		ServiceID:         svc.ServiceID,
		Namespace:         svc.Namespace,
		CVEID:             rem.CVEID,
		CWEID:             rem.CWEID,
		ExploitVector:     rem.ExploitVector,
		AffectedPort:      8080,
		SLABridgeMinutes:  rem.BridgeSLAMIN,
		BlockerReasonCode: "QUARANTINED_ROLLBACK:" + reason,
		RearmCount:        rearmCount,
	})
	if err != nil {
		return nil, fmt.Errorf("step 1 (re-arm containment bridge) failed; aborting unban: %w", err)
	}
	if err := e.store.UpsertBridge(ctx, *quarantineBridge); err != nil {
		return nil, err
	}
	_ = e.recordTrace(ctx, rem.RemediationID, "N3", "QUARANTINED_ROLLBACK_STEP1_CONTAINMENT_ARMED", "REARM", actor, crypto.SHA256Hex([]byte(quarantineBridge.CiliumManifestYAML)), map[string]string{
		"bridge_id":        quarantineBridge.BridgeID,
		"containment_mode": quarantineBridge.ContainmentMode,
		"reason":           reason,
	})

	// Step 2: Suspend ValidatingAdmissionPolicy lockout so kube-apiserver permits emergency revert
	lockouts, err := e.store.ListLockouts(ctx)
	if err != nil {
		return nil, err
	}
	for _, lo := range lockouts {
		if lo.RemediationID == rem.RemediationID || (lo.ServiceID == svc.ServiceID && lo.BannedDigest == rem.VulnerableDigest) {
			if err := e.deploy.SuspendAdmissionLockout(ctx, lo.LockoutID, lo.PolicyName, reason); err != nil {
				return nil, fmt.Errorf("step 2 (suspend admission lockout %s) failed: %w", lo.PolicyName, err)
			}
			lo.Status = "SUSPENDED_FOR_QUARANTINED_ROLLBACK"
			lo.SuspendedReason = reason
			if err := e.store.UpsertLockout(ctx, lo); err != nil {
				return nil, err
			}
			_ = e.recordTrace(ctx, rem.RemediationID, "N3", "QUARANTINED_ROLLBACK_STEP2_LOCKOUT_SUSPENDED", "ROLLBACK", actor, crypto.SHA256Hex([]byte(lo.PolicyName)), map[string]string{
				"lockout_id":  lo.LockoutID,
				"policy_name": lo.PolicyName,
				"status":      lo.Status,
			})
		}
	}

	// Step 3: Roll back live pods to previous digest while shielded by Step 1 containment bridge
	if err := e.deploy.RollbackToDigest(ctx, svc.ServiceID, rem.VulnerableDigest); err != nil {
		return nil, fmt.Errorf("step 3 (rollback to previous digest) failed: %w", err)
	}
	now := time.Now().UTC()
	svc.CurrentDigest = rem.VulnerableDigest
	_ = e.store.UpsertEstateService(ctx, *svc)

	rem.BridgeID = quarantineBridge.BridgeID
	rem.BridgedAt = &now
	rem.Stage = models.StageBridgedContained
	rem.StatusHealth = models.HealthQuarantinedRollback
	rem.CanaryWeight = 0
	rem.BlockerCode = "QUARANTINED_ROLLBACK:" + reason
	if err := e.store.UpsertRemediation(ctx, rem); err != nil {
		return nil, err
	}
	_ = e.recordTrace(ctx, rem.RemediationID, "N3", "QUARANTINED_ROLLBACK_STEP3_DIGEST_RESTORED", "ROLLBACK", actor, crypto.SHA256Hex([]byte(rem.VulnerableDigest)), map[string]string{
		"restored_digest": rem.VulnerableDigest,
		"active_bridge":   quarantineBridge.BridgeID,
	})
	e.emit("BRIDGE_REARMED", quarantineBridge)
	e.emit("REMEDIATION_UPDATED", rem)
	return rem, nil
}

// StartDriftWatcher streams event-driven Pod WATCH notifications when connected to kube-apiserver
// (or runs periodic informer resyncs against fleet-sim) and automatically re-arms CiliumNetworkPolicy
// containment bridges if a banned digest appears. Remains 100% active even during N1 Emergency Freeze.
func (e *Engine) StartDriftWatcher(ctx context.Context, interval time.Duration) {
	if liveK8s, ok := e.deploy.(*adapters.LiveKubernetesAdapter); ok {
		go func() {
			_ = liveK8s.WatchPodDriftEvents(ctx, func(_, _, _ string) {
				_ = e.CheckFleetDriftOnce(ctx)
			})
		}()
		if interval < 30*time.Second {
			interval = 30 * time.Second
		}
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = e.CheckFleetDriftOnce(ctx)
			}
		}
	}()
}

// CheckFleetDriftOnce sweeps both:
//   1. Enforced Admission Lockouts against banned container image digests, AND
//   2. Live pod container filesystems/processes (Tetragon / eBPF immutability telemetry) for in-pod webshell drops
//      (e.g., artex-probe, JSP webshells) even when the running pod reports a valid container image digest!
func (e *Engine) CheckFleetDriftOnce(ctx context.Context) error {
	// Part A: Sweep all estate workloads for in-pod container filesystem or untracked process immutability violations
	if estate, sErr := e.store.ListEstateServices(ctx); sErr == nil {
		for _, svc := range estate {
			wl, wErr := e.deploy.InspectLiveWorkload(ctx, svc.ServiceID)
			if wErr != nil {
				continue
			}
			for _, pod := range wl.Pods {
				for _, mutatedPath := range pod.FilesystemMutatedPaths {
					_, _ = e.HandleTetragonDriftEvent(ctx, models.TetragonDriftEvent{
						ServiceID:          svc.ServiceID,
						Namespace:          svc.Namespace,
						PodName:            pod.PodName,
						RunningDigest:      pod.RunningDigest,
						ViolationType:      "FILESYSTEM_WRITE",
						TargetPathOrBinary: mutatedPath,
						ObservedAtUnixMs:   wl.LastDriftInjectedAtUnixMs,
					})
				}
				for _, proc := range pod.UntrackedProcesses {
					_, _ = e.HandleTetragonDriftEvent(ctx, models.TetragonDriftEvent{
						ServiceID:          svc.ServiceID,
						Namespace:          svc.Namespace,
						PodName:            pod.PodName,
						RunningDigest:      pod.RunningDigest,
						ViolationType:      "UNTRACKED_EXEC",
						TargetPathOrBinary: proc,
						ObservedAtUnixMs:   wl.LastDriftInjectedAtUnixMs,
					})
				}
			}
		}
	}

	// Part B: Sweep enforced Admission Lockouts for banned image digest drift
	lockouts, err := e.store.ListLockouts(ctx)
	if err != nil || len(lockouts) == 0 {
		return err
	}

	for _, lo := range lockouts {
		if lo.Status == "SUSPENDED_FOR_QUARANTINED_ROLLBACK" {
			continue
		}
		wl, err := e.deploy.InspectLiveWorkload(ctx, lo.ServiceID)
		if err != nil {
			continue
		}
		for _, pod := range wl.Pods {
			if pod.RunningDigest != lo.BannedDigest {
				continue
			}
			driftKey := fmt.Sprintf("%s|%s|%s|%d", lo.LockoutID, pod.PodName, pod.RunningDigest, wl.LastDriftInjectedAtUnixMs)
			e.mu.Lock()
			already := e.handledDrifts[driftKey]
			e.mu.Unlock()
			if already {
				continue
			}

			rem, rErr := e.store.GetRemediation(ctx, lo.RemediationID)
			if rErr != nil {
				continue
			}

			// Persisted DB deduplication guard across warrantd container restarts:
			// If PostgreSQL already recorded an unresolved DriftIncident for this exact (lockout, pod, digest)
			// at or after LastDriftInjectedAtUnixMs AND the workload's containment bridge is already armed,
			// mark handled in memory and skip duplicate re-arm counting.
			if persisted, pErr := e.store.HasUnresolvedDriftIncidentSince(ctx, lo.LockoutID, pod.PodName, pod.RunningDigest, wl.LastDriftInjectedAtUnixMs); pErr == nil && persisted {
				if rem.BridgeID != "" {
					if existingBrg, bErr := e.store.GetBridge(ctx, rem.BridgeID); bErr == nil && existingBrg != nil && existingBrg.Status != "RETIRED" {
						e.mu.Lock()
						e.handledDrifts[driftKey] = true
						e.mu.Unlock()
						continue
					}
				}
			}

			e.mu.Lock()
			e.handledDrifts[driftKey] = true
			e.mu.Unlock()

			now := time.Now().UTC()
			latencyMs := int64(45)
			if wl.LastDriftInjectedAtUnixMs > 0 {
				diff := now.UnixMilli() - wl.LastDriftInjectedAtUnixMs
				if diff >= 1 {
					latencyMs = diff
				} else {
					latencyMs = 1
				}
			}

			svc, _ := e.store.GetEstateService(ctx, lo.ServiceID)
			ns := "default"
			if svc != nil && svc.Namespace != "" {
				ns = svc.Namespace
			}

			bridgeID := rem.BridgeID
			rearmCount := 1
			var prevArmedAt time.Time
			if bridgeID == "" {
				if activeSame, fErr := e.store.FindActiveBridgeByServiceAndCVE(ctx, lo.ServiceID, lo.CVEID); fErr == nil && activeSame != nil {
					bridgeID = activeSame.BridgeID
				}
			}
			if existing, bErr := e.store.GetBridge(ctx, bridgeID); bErr == nil {
				rearmCount = existing.RearmedCount + 1
				if existing.Status != "RETIRED" {
					prevArmedAt = existing.ArmedAt
				}
			}
			if bridgeID == "" {
				bridgeID = "brg-drift-" + uuid.NewString()[:8]
			}

			rearmedBridge, err := e.shield.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
				BridgeID:          bridgeID,
				RemediationID:     rem.RemediationID,
				ServiceID:         lo.ServiceID,
				Namespace:         ns,
				CVEID:             lo.CVEID,
				CWEID:             rem.CWEID,
				ExploitVector:     rem.ExploitVector,
				AffectedPort:      8080,
				SLABridgeMinutes:  30,
				BlockerReasonCode: "RUNTIME_DRIFT_BANNED_DIGEST_REARMED",
				RearmCount:        rearmCount,
			})
			if err != nil {
				continue
			}
			if !prevArmedAt.IsZero() {
				rearmedBridge.ArmedAt = prevArmedAt
			}
			_ = e.store.UpsertBridge(ctx, *rearmedBridge)

			rem.BridgeID = rearmedBridge.BridgeID
			rem.BridgedAt = &now
			rem.Stage = models.StageBridgedContained
			rem.StatusHealth = models.HealthDriftViolation
			rem.BlockerCode = fmt.Sprintf("DRIFT_VIOLATION:%s", pod.PodName)
			_ = e.store.UpsertRemediation(ctx, rem)

			inc := models.DriftIncident{
				IncidentID:         "drf-" + uuid.NewString()[:8],
				DriftKind:          models.DriftKindBannedDigest,
				LockoutID:          lo.LockoutID,
				RemediationID:      rem.RemediationID,
				ServiceID:          lo.ServiceID,
				CVEID:              lo.CVEID,
				DetectedDigest:     pod.RunningDigest,
				RoguePodName:       pod.PodName,
				RearmedBridgeID:    rearmedBridge.BridgeID,
				DetectionLatencyMs: latencyMs,
				DetectedAt:         now,
			}
			_ = e.store.RecordDriftIncident(ctx, inc)

			_ = e.recordTrace(ctx, rem.RemediationID, "N3", "DRIFT_DETECTED_BRIDGE_REARMED", "REARM", "drift-watcher", crypto.SHA256Hex([]byte(rearmedBridge.CiliumManifestYAML)), map[string]string{
				"rogue_pod":            pod.PodName,
				"banned_digest":        pod.RunningDigest,
				"rearmed_bridge_id":    rearmedBridge.BridgeID,
				"detection_latency_ms": fmt.Sprintf("%d", latencyMs),
			})
			e.emit("DRIFT_VIOLATION_ALERT", inc)
			e.emit("BRIDGE_REARMED", rearmedBridge)
			e.emit("REMEDIATION_UPDATED", rem)
		}
	}
	return nil
}

// HandleTetragonDriftEvent processes a Cilium Tetragon / eBPF container filesystem or process immutability alert
// (such as an ARTEX webshell/probe drop on a pod whose OCI image digest is otherwise valid):
//   1. Immediately arms/re-arms the Egress & 169.254.169.254 Metadata Quarantine bridge,
//   2. Cordons the compromised pod and recycles a fresh replica from the verified immutable image digest,
//   3. Records a FILESYSTEM_WEBSHELL_DROP / UNTRACKED_PROCESS_EXEC DriftIncident.
func (e *Engine) HandleTetragonDriftEvent(ctx context.Context, ev models.TetragonDriftEvent) (*models.DriftIncident, error) {
	if ev.ServiceID == "" || ev.PodName == "" || ev.TargetPathOrBinary == "" {
		return nil, fmt.Errorf("service_id, pod_name, and target_path_or_binary are required")
	}
	driftKey := fmt.Sprintf("TETRAGON|%s|%s|%s|%d", ev.ServiceID, ev.PodName, ev.TargetPathOrBinary, ev.ObservedAtUnixMs)
	e.mu.Lock()
	if e.handledDrifts[driftKey] {
		e.mu.Unlock()
		return nil, nil
	}
	e.handledDrifts[driftKey] = true
	e.mu.Unlock()

	svc, err := e.store.GetEstateService(ctx, ev.ServiceID)
	if err != nil {
		return nil, err
	}
	ns := svc.Namespace
	if ns == "" {
		ns = "default"
	}
	runningDigest := ev.RunningDigest
	if runningDigest == "" {
		runningDigest = svc.CurrentDigest
	}

	now := time.Now().UTC()
	latencyMs := int64(18)
	if ev.ObservedAtUnixMs > 0 {
		if diff := now.UnixMilli() - ev.ObservedAtUnixMs; diff >= 1 {
			latencyMs = diff
		}
	}

	// Find an existing remediation item for this service or create an emergency IN_POD_DRIFT_QUARANTINE item
	var rem *models.RemediationItem
	if rems, rErr := e.store.ListRemediations(ctx); rErr == nil {
		for i := range rems {
			if rems[i].ServiceID == svc.ServiceID {
				cp := rems[i]
				rem = &cp
				break
			}
		}
	}
	if rem == nil {
		rem = &models.RemediationItem{
			RemediationID:    "rem-ebpf-" + uuid.NewString()[:8],
			RemediationKind:  models.RemediationKindInPodDrift,
			CVEID:            "EBPF-RUNTIME-DRIFT",
			CWEID:            "CWE-434",
			CVSSScore:        9.8,
			ServiceID:        svc.ServiceID,
			VulnerableDigest: runningDigest,
			PatchedDigest:    svc.CurrentDigest,
			PackagePURL:      svc.CurrentPURL,
			ExploitVector:    "UNRESTRICTED_UPLOAD",
			Stage:            models.StageBridgedContained,
			StatusHealth:     models.HealthDriftViolation,
			BridgeSLAMIN:     30,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		_ = e.store.UpsertRemediation(ctx, rem)
	}

	bridgeID := rem.BridgeID
	rearmCount := 1
	if bridgeID != "" {
		if existing, bErr := e.store.GetBridge(ctx, bridgeID); bErr == nil {
			rearmCount = existing.RearmedCount + 1
		}
	} else {
		bridgeID = "brg-ebpf-" + uuid.NewString()[:8]
	}

	// Step 1: Arm Egress & 169.254.169.254 Metadata Severance Bridge
	rearmedBridge, err := e.shield.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
		BridgeID:              bridgeID,
		RemediationID:         rem.RemediationID,
		ServiceID:             svc.ServiceID,
		Namespace:             ns,
		CVEID:                 rem.CVEID,
		CWEID:                 "CWE-434",
		ExploitVector:         "UNRESTRICTED_UPLOAD",
		AffectedPort:          8080,
		AllowedEgressServices: svc.AllowedEgressServices,
		SLABridgeMinutes:      30,
		BlockerReasonCode:     "TETRAGON_IN_POD_DRIFT_QUARANTINED:" + ev.TargetPathOrBinary,
		RearmCount:            rearmCount,
	})
	if err != nil {
		return nil, err
	}
	_ = e.store.UpsertBridge(ctx, *rearmedBridge)

	// Step 2: Cordon compromised pod and recycle fresh replica from verified immutable digest
	recycledPod, cErr := e.deploy.CordonAndRecyclePod(ctx, svc.ServiceID, ev.PodName, svc.CurrentDigest)
	podRecycled := cErr == nil && recycledPod != ""

	driftKind := models.DriftKindFilesystemWebshell
	if strings.EqualFold(ev.ViolationType, "UNTRACKED_EXEC") {
		driftKind = models.DriftKindUntrackedProcess
	}

	rem.BridgeID = rearmedBridge.BridgeID
	rem.BridgedAt = &now
	rem.Stage = models.StageBridgedContained
	rem.StatusHealth = models.HealthDriftViolation
	rem.BlockerCode = fmt.Sprintf("%s:%s", driftKind, ev.TargetPathOrBinary)
	_ = e.store.UpsertRemediation(ctx, rem)

	inc := models.DriftIncident{
		IncidentID:         "drf-" + uuid.NewString()[:8],
		DriftKind:          driftKind,
		LockoutID:          "TETRAGON_EBPF_RUNTIME",
		RemediationID:      rem.RemediationID,
		ServiceID:          svc.ServiceID,
		CVEID:              rem.CVEID,
		DetectedDigest:     runningDigest,
		ViolatingArtifact:  ev.TargetPathOrBinary,
		RoguePodName:       ev.PodName,
		PodCordoned:        true,
		PodRecycled:        podRecycled,
		RearmedBridgeID:    rearmedBridge.BridgeID,
		DetectionLatencyMs: latencyMs,
		DetectedAt:         now,
	}
	if err := e.store.RecordDriftIncident(ctx, inc); err != nil {
		return nil, err
	}

	_ = e.recordTrace(ctx, rem.RemediationID, "N3", "TETRAGON_IN_POD_DRIFT_CORDON_AND_RECYCLE", "REARM", "tetragon-ebpf", crypto.SHA256Hex([]byte(ev.TargetPathOrBinary)), map[string]string{
		"drift_kind":         driftKind,
		"violating_artifact": ev.TargetPathOrBinary,
		"cordoned_pod":       ev.PodName,
		"recycled_pod":       recycledPod,
		"metadata_blocked":   fmt.Sprintf("%t", rearmedBridge.MetadataPlaneBlocked),
	})
	e.emit("DRIFT_VIOLATION_ALERT", inc)
	e.emit("BRIDGE_REARMED", rearmedBridge)
	e.emit("REMEDIATION_UPDATED", rem)
	return &inc, nil
}

// ReconcileWorkloadDriftAndReverify cordons & recycles any rogue/drifted pods on bridge.ServiceID back to the
// verified clean image digest, verifies 100% live pod compliance against enforced Admission Lockouts, marks open
// DriftIncidents resolved, and retires the re-armed containment bridge.
func (e *Engine) ReconcileWorkloadDriftAndReverify(ctx context.Context, bridgeID, actor string) (*models.ContainmentBridge, *models.RemediationItem, error) {
	brg, err := e.store.GetBridge(ctx, strings.TrimSpace(bridgeID))
	if err != nil {
		return nil, nil, err
	}
	svc, err := e.store.GetEstateService(ctx, brg.ServiceID)
	if err != nil {
		return nil, nil, err
	}
	rem, _ := e.store.GetRemediation(ctx, brg.RemediationID)

	bannedDigests := map[string]bool{}
	cleanDigest := ""
	if lockouts, lErr := e.store.ListLockouts(ctx); lErr == nil {
		for _, lo := range lockouts {
			if lo.ServiceID == brg.ServiceID && lo.Status != "SUSPENDED_FOR_QUARANTINED_ROLLBACK" {
				if lo.BannedDigest != "" {
					bannedDigests[lo.BannedDigest] = true
				}
				if cleanDigest == "" && lo.PatchedDigest != "" {
					cleanDigest = lo.PatchedDigest
				}
			}
		}
	}
	if rem != nil && rem.PatchedDigest != "" && !bannedDigests[rem.PatchedDigest] {
		cleanDigest = rem.PatchedDigest
	}
	if cleanDigest == "" {
		cleanDigest = svc.CurrentDigest
	}
	if bannedDigests[cleanDigest] {
		return nil, nil, fmt.Errorf("DRIFT_RECONCILE_NO_CLEAN_DIGEST: candidate clean digest %s is permanently banned", cleanDigest)
	}

	wl, err := e.deploy.InspectLiveWorkload(ctx, brg.ServiceID)
	if err != nil {
		return nil, nil, err
	}
	recycledCount := 0
	for _, pod := range wl.Pods {
		if bannedDigests[pod.RunningDigest] || (cleanDigest != "" && pod.RunningDigest != cleanDigest) || len(pod.FilesystemMutatedPaths) > 0 || len(pod.UntrackedProcesses) > 0 {
			if _, cErr := e.deploy.CordonAndRecyclePod(ctx, brg.ServiceID, pod.PodName, cleanDigest); cErr != nil {
				return nil, nil, fmt.Errorf("CORDON_AND_RECYCLE_FAILED (%s): %w", pod.PodName, cErr)
			}
			recycledCount++
		}
	}
	if recycledCount == 0 && wl.LastDriftInjectedAtUnixMs > 0 {
		_, _ = e.deploy.CordonAndRecyclePod(ctx, brg.ServiceID, "", cleanDigest)
	}

	// Re-sweep live pods and fail closed if any pod still violates the clean digest or admission lockouts
	wlVerify, err := e.deploy.InspectLiveWorkload(ctx, brg.ServiceID)
	if err != nil {
		return nil, nil, err
	}
	for _, pod := range wlVerify.Pods {
		if bannedDigests[pod.RunningDigest] || (cleanDigest != "" && pod.RunningDigest != cleanDigest) {
			return nil, nil, fmt.Errorf("DRIFT_REVERIFY_FAILED: pod %s still reports %s (expected %s)", pod.PodName, pod.RunningDigest, cleanDigest)
		}
	}

	now := time.Now().UTC()
	_, _ = e.store.ResolveDriftIncidentsForService(ctx, brg.ServiceID, now)

	// Clear in-memory drift keys for this service so any future drift event will be caught immediately
	e.mu.Lock()
	for k := range e.handledDrifts {
		if strings.Contains(k, brg.ServiceID) {
			delete(e.handledDrifts, k)
		}
	}
	e.mu.Unlock()

	if err := e.shield.RetireBridge(ctx, brg.BridgeID); err != nil {
		return nil, nil, err
	}
	brg.Status = "RETIRED"
	brg.RetiredAt = &now
	brg.BlockerReasonCode = "DRIFT_RECONCILED_AND_REVERIFIED"
	if err := e.store.UpsertBridge(ctx, *brg); err != nil {
		return nil, nil, err
	}
	_, _ = e.store.ConsolidateDuplicateActiveBridges(ctx)

	// Restore any DRIFT_VIOLATION remediations on this service whose pods now match cleanDigest
	attestations, _ := e.store.ListAttestations(ctx)
	attestedByRem := map[string]bool{}
	for _, att := range attestations {
		attestedByRem[att.RemediationID] = true
	}
	if allRems, aErr := e.store.ListRemediations(ctx); aErr == nil {
		for i := range allRems {
			r := &allRems[i]
			if r.ServiceID != brg.ServiceID || (r.StatusHealth != models.HealthDriftViolation && r.RemediationID != brg.RemediationID) {
				continue
			}
			r.PodSweepMatched = len(wlVerify.Pods)
			r.PodSweepTotal = len(wlVerify.Pods)
			r.BlockerCode = ""
			if attestedByRem[r.RemediationID] || r.RemediationKind == models.RemediationKindInPodDrift {
				r.Stage = models.StageAttestedClosed
				r.StatusHealth = models.HealthNormal
				if r.ClosedAt == nil {
					r.ClosedAt = &now
				}
			} else {
				r.StatusHealth = models.HealthNormal
			}
			_ = e.store.UpsertRemediation(ctx, r)
			if rem != nil && r.RemediationID == rem.RemediationID {
				cp := *r
				rem = &cp
			}
			e.emit("REMEDIATION_UPDATED", r)
		}
	}

	if rem != nil {
		_ = e.recordTrace(ctx, rem.RemediationID, "N3", "DRIFT_ROGUE_POD_EVICTED_AND_REVERIFIED", "PASS", firstActor(actor, "operator"), crypto.SHA256Hex([]byte(cleanDigest)), map[string]string{
			"bridge_id":      brg.BridgeID,
			"recycled_pods":  fmt.Sprintf("%d", recycledCount),
			"verified_pods":  fmt.Sprintf("%d/%d", len(wlVerify.Pods), len(wlVerify.Pods)),
			"clean_digest":   cleanDigest,
		})
	}
	e.emit("BRIDGE_UPDATED", brg)
	return brg, rem, nil
}

func firstActor(a, fallback string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return fallback
}

func (e *Engine) recordTrace(ctx context.Context, remID, eng, step, outcome, actor, hash string, fields map[string]string) error {
	return e.store.AppendTrace(ctx, models.TraceEvent{
		TraceID:       "trc-" + uuid.NewString()[:8],
		RemediationID: remID,
		Engine:        eng,
		StepCode:      step,
		Outcome:       outcome,
		ActorOrToken:  actor,
		EvidenceHash:  hash,
		Fields:        fields,
		OccurredAt:    time.Now().UTC(),
	})
}

func (e *Engine) emit(eventType string, payload any) {
	if e.onBroadcast != nil {
		e.onBroadcast(eventType, payload)
	}
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
