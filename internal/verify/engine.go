package verify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/adapters"
	"github.com/g1163rt-labs/g1-warrant/internal/agentcp"
	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/db"
	"github.com/g1163rt-labs/g1-warrant/internal/fleetsim"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
	"github.com/g1163rt-labs/g1-warrant/internal/policy"
	"github.com/g1163rt-labs/g1-warrant/internal/warrant"
	"github.com/google/uuid"
)

// VerificationBundle holds verified N3 outputs required by N5 to mint an OSCAL 1.1.2 POA&M package.
type VerificationBundle struct {
	TwinTranscriptSHA256 string
	UnpatchedTwinStatus  string
	AssuranceTier        string
	PodManifest          []models.PodDigestEntry
	Lockout              models.AdmissionLockout
}

// Engine implements N3: Differential Twin Replay (with Positive-Control Verification),
// Passive Fleet Attestation, Permanent Admission Lockout before Bridge Retirement,
// Atomic Quarantined Rollback (Contain-Before-Unban), and Runtime Drift Re-Arming.
type Engine struct {
	store         *db.Store
	policy        *policy.Engine
	warrants      *warrant.Engine
	agentCP       *agentcp.ControlPlane
	shield        adapters.ShieldEnforcer
	deploy        adapters.DeploymentTarget
	twin          adapters.TwinRunner
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

	// Step 2: Passive Live Fleet Pod Digest & Unloaded Shared Symbol Sweep
	wl, err := e.deploy.InspectLiveWorkload(ctx, svc.ServiceID)
	if err != nil {
		return nil, err
	}
	matchedPods := 0
	vulnSymbolsLoaded := 0
	podManifest := make([]models.PodDigestEntry, 0, len(wl.Pods))
	for _, pod := range wl.Pods {
		if pod.RunningDigest == item.PatchedDigest {
			matchedPods++
		}
		for _, sym := range pod.LoadedSymbols {
			if item.VulnerableSymbol != "" && sym == item.VulnerableSymbol {
				vulnSymbolsLoaded++
			}
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
	manifestHash, _, _ := crypto.CanonicalSHA256Hex(podManifest)
	_ = e.recordTrace(ctx, item.RemediationID, "N3", "PASSIVE_FLEET_DIGEST_SWEEP",
		ternary(matchedPods == len(wl.Pods) && vulnSymbolsLoaded == 0, "PASS", "BLOCK"),
		"k8s_rollout", manifestHash,
		map[string]string{
			"matched_pods":              fmt.Sprintf("%d/%d", matchedPods, len(wl.Pods)),
			"vulnerable_symbols_loaded": fmt.Sprintf("%d", vulnSymbolsLoaded),
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
	verDec, err := e.policy.EvalVerify(ctx, policy.VerifyInput{
		HasSignedProbe:           hasSignedProbe,
		UnpatchedTwinStatus:      twinResp.UnpatchedStatus,
		TwinReplayStatus:         twinResp.Status,
		ProvenanceVerified:       true,
		AttestedPods:             matchedPods,
		TotalPods:                len(wl.Pods),
		VulnerableSymbolsLoaded:  vulnSymbolsLoaded,
		AdmissionLockoutEnforced: lockout.PolicyName != "",
		WarrantReverified:        warrantOK,
	})
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

	return &VerificationBundle{
		TwinTranscriptSHA256: twinResp.TranscriptSHA256,
		UnpatchedTwinStatus:  twinResp.UnpatchedStatus,
		AssuranceTier:        verDec.AssuranceTier,
		PodManifest:          podManifest,
		Lockout:              *lockout,
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

// CheckFleetDriftOnce sweeps all enforced Admission Lockouts against live workload pods.
func (e *Engine) CheckFleetDriftOnce(ctx context.Context) error {
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
			if !already {
				e.handledDrifts[driftKey] = true
			}
			e.mu.Unlock()
			if already {
				continue
			}

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

			rem, rErr := e.store.GetRemediation(ctx, lo.RemediationID)
			if rErr != nil {
				continue
			}
			svc, _ := e.store.GetEstateService(ctx, lo.ServiceID)
			ns := "default"
			if svc != nil && svc.Namespace != "" {
				ns = svc.Namespace
			}

			bridgeID := rem.BridgeID
			rearmCount := 1
			if existing, bErr := e.store.GetBridge(ctx, bridgeID); bErr == nil {
				rearmCount = existing.RearmedCount + 1
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
			_ = e.store.UpsertBridge(ctx, *rearmedBridge)

			rem.BridgeID = rearmedBridge.BridgeID
			rem.BridgedAt = &now
			rem.Stage = models.StageBridgedContained
			rem.StatusHealth = models.HealthDriftViolation
			rem.BlockerCode = fmt.Sprintf("DRIFT_VIOLATION:%s", pod.PodName)
			_ = e.store.UpsertRemediation(ctx, rem)

			inc := models.DriftIncident{
				IncidentID:         "drf-" + uuid.NewString()[:8],
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
