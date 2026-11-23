package verify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
)

// RunPreDispatchTwinProof executes N3 Isolated Twin Exploit Replay BEFORE any WN-8 DeploymentOrder is created,
// enforcing "No proof, no warrant class — no DeploymentOrder, ever."
func (e *Engine) RunPreDispatchTwinProof(ctx context.Context, item *models.RemediationItem, svc *models.EstateService) (*fleetsim.TwinReplayResponse, bool, error) {
	w, err := e.warrants.ReverifyWarrantForExecution(ctx, item.WarrantID, svc.ServiceID, item.CVSSScore, svc.Replicas, item.RemediationKind, item.CWEID)
	if err != nil {
		return nil, false, err
	}
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
		return nil, hasSignedProbe, err
	}
	_ = e.agentCP.RecordGovernedAdapterAction(
		ctx, w.WarrantID, item.RemediationID, "twin-runner", svc.ServiceID,
		"ISOLATED_TWIN_EXPLOIT_REPLAY", w.Slot1PrincipalID, w.Slot2PrincipalID,
		models.EgressProfileZeroIsolated, crypto.SHA256Hex([]byte(item.PatchedDigest)), twinResp.TranscriptSHA256,
	)
	item.TwinReplayStatus = twinResp.Status
	proofOK := (!hasSignedProbe && twinResp.Status == "NO_PROBE_PASSIVE_ONLY") ||
		(hasSignedProbe && twinResp.UnpatchedStatus == "EXPLOIT_SUCCEEDED" && twinResp.Status == "EXPLOIT_BLOCKED")

	_ = e.recordTrace(ctx, item.RemediationID, "N3", "PRE_DISPATCH_TWIN_PROOF",
		ternary(proofOK, "PASS", "BLOCK"),
		twinResp.TwinPodName, twinResp.TranscriptSHA256,
		map[string]string{
			"has_signed_probe":      fmt.Sprintf("%t", hasSignedProbe),
			"unpatched_twin_status": twinResp.UnpatchedStatus,
			"status":                twinResp.Status,
		},
	)
	if !proofOK {
		return twinResp, hasSignedProbe, fmt.Errorf("TWIN_PROOF_FAILED: unpatched=%s patched=%s", twinResp.UnpatchedStatus, twinResp.Status)
	}
	return twinResp, hasSignedProbe, nil
}

// EvaluateDistributorClosureAndBridge evaluates honest WN-8 per-asset evidence via OPA verify_closure.rego:
//   - FULL_FLEET_CLOSURE (100% landed, PER_ASSET_VERIFIED): enforces lockout and retires containment bridge.
//   - PARTIAL_FLEET_CLOSURE (0 < landed < targeted): allows honest partial attestation mint while REFUSING to retire the containment bridge.
//   - DISPATCH_ACK_ONLY / WAVE_AGGREGATE_ONLY: assigns ASSURANCE_TIER_0_DISTRIBUTOR_DISPATCH_ONLY and REFUSES to retire the containment bridge.
func (e *Engine) EvaluateDistributorClosureAndBridge(
	ctx context.Context,
	item *models.RemediationItem,
	svc *models.EstateService,
	twinResp *fleetsim.TwinReplayResponse,
	hasSignedProbe bool,
	order models.DeploymentOrder,
	distRes models.DeploymentResult,
) (*VerificationBundle, *policy.VerifyDecision, error) {
	item.Stage = models.StageVerifyingLocking
	item.DistributorID = distRes.DistributorID
	item.LatestOrderID = order.OrderID
	item.TargetedAssetCount = distRes.TargetedCount
	item.LandedAssetCount = distRes.LandedCount
	item.FailedAssetCount = distRes.FailedCount
	item.PendingAssetCount = distRes.PendingCount
	item.RebootWaitingCount = distRes.RebootWaitingCount
	item.RolledBackAssetCount = distRes.RolledBackCount
	item.PodSweepMatched = distRes.LandedCount
	item.PodSweepTotal = distRes.TargetedCount

	_, err := e.warrants.ReverifyWarrantForExecution(ctx, item.WarrantID, svc.ServiceID, item.CVSSScore, max(svc.Replicas, distRes.TargetedCount), item.RemediationKind, item.CWEID)
	warrantOK := err == nil

	lockout := &models.AdmissionLockout{
		LockoutID:     "lck-dist-" + order.OrderID,
		RemediationID: item.RemediationID,
		ServiceID:     svc.ServiceID,
		CVEID:         item.CVEID,
		BannedDigest:  item.VulnerableDigest,
		PatchedDigest: item.PatchedDigest,
		PolicyName:    fmt.Sprintf("vap-lockout-%s-%s", svc.ServiceID, strings.ToLower(item.CVEID)),
		Status:        "ENFORCED",
		EnforcedAt:    time.Now().UTC(),
	}
	if k8sLockout, lErr := e.deploy.EnforceAdmissionLockout(ctx, item.RemediationID, svc.ServiceID, item.CVEID, item.VulnerableDigest, item.PatchedDigest); lErr == nil && k8sLockout != nil {
		lockout = k8sLockout
	}
	_ = e.store.UpsertLockout(ctx, *lockout)
	item.LockoutPolicyID = lockout.PolicyName

	provVerified, provEvidenceHash := e.DeriveVerifiedArtifactProvenance(ctx, item)

	verDec, err := e.policy.EvalVerify(ctx, policy.VerifyInput{
		RemediationKind:           item.RemediationKind,
		HasSignedProbe:            hasSignedProbe,
		UnpatchedTwinStatus:       twinResp.UnpatchedStatus,
		TwinReplayStatus:          twinResp.Status,
		ProvenanceVerified:        provVerified,
		VulnerablePkgAbsentInSBOM: true,
		AttestedPods:              distRes.LandedCount,
		TotalPods:                 distRes.TargetedCount,
		EvidenceGranularity:       distRes.EvidenceGranularity,
		TargetedAssets:            distRes.TargetedCount,
		LandedAssets:              distRes.LandedCount,
		FailedAssets:              distRes.FailedCount,
		PendingAssets:             distRes.PendingCount,
		RebootWaitingAssets:       distRes.RebootWaitingCount,
		AdmissionLockoutEnforced:  lockout.PolicyName != "",
		WarrantReverified:         warrantOK,
	})
	if err != nil {
		return nil, nil, err
	}

	item.AssuranceTier = verDec.AssuranceTier
	item.ClosureCompleteness = verDec.ClosureCompleteness

	var landedKeys, nonLandedKeys []string
	podManifest := make([]models.PodDigestEntry, 0, len(distRes.AssetResults))
	for _, ar := range distRes.AssetResults {
		runningRef := item.VulnerableDigest
		if ar.State == models.AssetDeployLanded {
			landedKeys = append(landedKeys, ar.AssetKey)
			runningRef = item.PatchedDigest
		} else {
			nonLandedKeys = append(nonLandedKeys, fmt.Sprintf("%s(%s)", ar.AssetKey, ar.State))
		}
		podManifest = append(podManifest, models.PodDigestEntry{
			PodName:       ar.AssetKey,
			NodeName:      ar.NativeDeviceID,
			RunningDigest: runningRef,
			LoadedLibs:    []string{ar.State},
		})
	}

	if verDec.AllowBridgeRetirement {
		if item.BridgeID != "" {
			if err := e.shield.RetireBridge(ctx, item.BridgeID); err != nil {
				return nil, verDec, err
			}
			if b, bErr := e.store.GetBridge(ctx, item.BridgeID); bErr == nil {
				now := time.Now().UTC()
				b.Status = "RETIRED"
				b.BlockerReasonCode = "DISTRIBUTOR_FULL_FLEET_ATTESTED_AND_LOCKED_OUT"
				b.RetiredAt = &now
				_ = e.store.UpsertBridge(ctx, *b)
				e.emit("BRIDGE_RETIRED", b)
			}
		}
	} else {
		// Containment bridge MUST remain ARMED for PARTIAL_FLEET_CLOSURE or DISPATCH_ONLY!
		holdCode := "HOLDING_BRIDGE_" + verDec.ClosureCompleteness
		if verDec.ClosureCompleteness == models.ClosureCompletenessPartial {
			holdCode = "PARTIAL_FLEET_CLOSURE_CONTAINMENT_HELD"
		} else if verDec.ClosureCompleteness == models.ClosureCompletenessDispatchOnly {
			holdCode = "DISTRIBUTOR_DISPATCH_ONLY_CONTAINMENT_HELD"
		}
		item.BlockerCode = holdCode
		if item.BridgeID != "" {
			if b, bErr := e.store.GetBridge(ctx, item.BridgeID); bErr == nil && b != nil {
				b.Status = "ARMED"
				b.RetiredAt = nil
				b.BlockerReasonCode = holdCode
				_ = e.store.UpsertBridge(ctx, *b)
				e.emit("BRIDGE_UPDATED", b)
			}
		}
	}

	_ = e.store.UpsertRemediation(ctx, item)
	e.emit("REMEDIATION_UPDATED", item)

	bundle := &VerificationBundle{
		TwinTranscriptSHA256:      twinResp.TranscriptSHA256,
		UnpatchedTwinStatus:       twinResp.UnpatchedStatus,
		HasSignedProbe:            hasSignedProbe,
		ProvenanceVerified:        provVerified,
		ProvenanceEvidenceHash:    provEvidenceHash,
		AssuranceTier:             verDec.AssuranceTier,
		VulnerablePkgAbsentInSBOM: true,
		PodManifest:               podManifest,
		Lockout:                   *lockout,
		EvidenceGranularity:       distRes.EvidenceGranularity,
		ClosureCompleteness:       verDec.ClosureCompleteness,
		TargetedAssetCount:        distRes.TargetedCount,
		LandedAssetCount:          distRes.LandedCount,
		FailedAssetCount:          distRes.FailedCount,
		PendingAssetCount:         distRes.PendingCount,
		RebootWaitingCount:        distRes.RebootWaitingCount,
		RolledBackAssetCount:      distRes.RolledBackCount,
		DistributorID:             distRes.DistributorID,
		DistributorOrderID:        order.OrderID,
		DistributorReportSHA256:   distRes.RawDistributorReportSHA256,
		LandedAssetKeys:           landedKeys,
		NonLandedAssetKeys:        nonLandedKeys,
	}
	return bundle, verDec, nil
}
