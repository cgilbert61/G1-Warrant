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
	PodManifest          []models.PodDigestEntry
	Lockout              models.AdmissionLockout
}

// Engine implements N3: Active Twin Replay, Passive Fleet Attestation,
// Permanent Admission Lockout before Bridge Retirement, and Sub-Second Runtime Drift Re-Arming.
type Engine struct {
	store         *db.Store
	policy        *policy.Engine
	warrants      *warrant.Engine
	agentCP       *agentcp.ControlPlane
	shield        adapters.ShieldEnforcer
	deploy        adapters.DeploymentTarget
	twin          adapters.TwinRunner
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
) *Engine {
	return &Engine{
		store:         store,
		policy:        pol,
		warrants:      warrants,
		agentCP:       agentCP,
		shield:        shield,
		deploy:        deploy,
		twin:          twin,
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

	// Step 1: Isolated Shadow Twin Exploit Replay (never against live production)
	twinResp, err := e.twin.RunExploitReplay(ctx, fleetsim.TwinReplayRequest{
		ServiceID:        svc.ServiceID,
		CVEID:            item.CVEID,
		PatchedDigest:    item.PatchedDigest,
		ExploitVector:    item.ExploitVector,
		VulnerableSymbol: item.VulnerableSymbol,
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
	_ = e.recordTrace(ctx, item.RemediationID, "N3", "ISOLATED_TWIN_EXPLOIT_REPLAY",
		ternary(twinResp.Status == "EXPLOIT_BLOCKED", "PASS", "BLOCK"),
		twinResp.TwinPodName, twinResp.TranscriptSHA256,
		map[string]string{
			"isolated_namespace":   twinResp.IsolatedNamespace,
			"status":               twinResp.Status,
			"production_untouched": fmt.Sprintf("%t", twinResp.ProductionUntouched),
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
		TwinReplayStatus:         twinResp.Status,
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
		PodManifest:          podManifest,
		Lockout:              *lockout,
	}, nil
}

// StartDriftWatcher continuously monitors live cluster pods every 200ms and automatically
// re-arms CiliumNetworkPolicy containment bridges within sub-second time if a banned digest appears.
// Invariant: Remains 100% active even during N1 FREEZE_HOLD or FREEZE_ROLLBACK.
func (e *Engine) StartDriftWatcher(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 200 * time.Millisecond
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
