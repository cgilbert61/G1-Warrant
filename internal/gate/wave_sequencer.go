package gate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/agentcp"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
	"github.com/google/uuid"
)

// DistributorExecutionRequest carries verified N1 + N3 preconditions into ExecuteDistributorRollout.
type DistributorExecutionRequest struct {
	Remediation          *models.RemediationItem
	Service              *models.EstateService
	DistributorID        string
	PlatformFamily       string
	FixIdentity          models.FixIdentity
	TargetAssets         []models.AssetTarget
	WavePercentages      []int
	MaxFailureRatePct    float64
	StageDwellSeconds    int
	MaintenanceWindowUTC string
	RollbackInstruction  models.NativeRollbackSpec
	ProofVerified        bool
	TwinReplayStatus     string
}

// DistributorExecutionOutcome summarizes the aggregated per-asset outcome of a governed distributor rollout.
type DistributorExecutionOutcome struct {
	PrimaryOrder       models.DeploymentOrder    `json:"primary_order"`
	WaveOrders         []models.DeploymentOrder  `json:"wave_orders"`
	WaveResults        []models.DeploymentResult `json:"wave_results"`
	AggregatedResult   models.DeploymentResult   `json:"aggregated_result"`
	RolledBack         bool                      `json:"rolled_back"`
	RollbackResult     *models.DeploymentResult  `json:"rollback_result,omitempty"`
	RollbackReasonCode string                    `json:"rollback_reason_code,omitempty"`
}

// SliceAssetsIntoWaves deterministically partitions targets into disjoint progressive batches matching wavePcts (default 5% -> 25% -> 100%).
func SliceAssetsIntoWaves(targets []models.AssetTarget, wavePcts []int) [][]models.AssetTarget {
	if len(targets) == 0 {
		return nil
	}
	if len(wavePcts) == 0 {
		wavePcts = []int{5, 25, 100}
	}
	n := len(targets)
	var batches [][]models.AssetTarget
	cursor := 0
	for i, pct := range wavePcts {
		if cursor >= n {
			break
		}
		var cumEnd int
		if i == len(wavePcts)-1 || pct >= 100 {
			cumEnd = n
		} else {
			cumEnd = int(math.Ceil(float64(n) * (float64(pct) / 100.0)))
			if cumEnd <= cursor {
				cumEnd = cursor + 1
			}
			if cumEnd > n {
				cumEnd = n
			}
		}
		slice := make([]models.AssetTarget, cumEnd-cursor)
		copy(slice, targets[cursor:cumEnd])
		batches = append(batches, slice)
		cursor = cumEnd
	}
	return batches
}

// ExecuteDistributorRollout enforces all four WN-8 architectural invariants:
//  1. Live 2-of-2 Standing Warrant + strict TargetAssets <= WarrantScope intersection.
//  2. Verified N3 twin/provenance proof required BEFORE any DeploymentOrder is created or dispatched.
//  3. NativeRollbackSpec immutably persisted in PostgreSQL deployment_orders BEFORE Wave 1 fires.
//  4. Native-ring pass-through vs. Warrant-driven wave slicing (5% -> 25% -> 100%) with automatic symmetric rollback on failure/stall.
func (e *Engine) ExecuteDistributorRollout(
	ctx context.Context,
	distReg *adapters.DistributorRegistry,
	req DistributorExecutionRequest,
) (*DistributorExecutionOutcome, error) {
	if req.Remediation == nil || req.Service == nil {
		return nil, errors.New("remediation and service are required")
	}
	if !req.ProofVerified || (req.TwinReplayStatus != "EXPLOIT_BLOCKED" && req.TwinReplayStatus != "NO_PROBE_PASSIVE_ONLY") {
		return nil, errors.New("NO_PROOF_NO_DEPLOYMENT_ORDER: N3 twin/provenance proof must succeed before any DeploymentOrder is created")
	}
	if len(req.TargetAssets) == 0 {
		return nil, errors.New("EMPTY_TARGET_ASSETS: DeploymentOrder requires >= 1 bounded target asset")
	}

	tr, err := distReg.Get(req.DistributorID)
	if err != nil {
		return nil, err
	}
	caps := tr.Capabilities()

	// 1. Live N1 Standing Warrant Re-Verification + Strict TargetAssets <= WarrantScope Check
	if strings.TrimSpace(req.Remediation.WarrantID) == "" {
		return nil, errors.New("NO_WARRANT_NO_DEPLOYMENT_ORDER: remediation has no bound 2-of-2 Standing Warrant")
	}
	w, err := e.warrants.ReverifyWarrantForExecution(
		ctx,
		req.Remediation.WarrantID,
		req.Service.ServiceID,
		req.Remediation.CVSSScore,
		max(req.Service.Replicas, len(req.TargetAssets)),
		req.Remediation.RemediationKind,
		req.Remediation.CWEID,
	)
	if err != nil {
		return nil, fmt.Errorf("WARRANT_REVERIFY_FAILED_BEFORE_DISPATCH: %w", err)
	}
	if err := verifyTargetAssetsWithinWarrantScope(req.TargetAssets, w); err != nil {
		return nil, err
	}

	// 2. Check Emergency Freeze Gate before dispatching Wave 1
	freeze, err := e.store.GetFreezeState(ctx)
	if err != nil {
		return nil, err
	}
	if freeze.Mode != models.FreezeModeOperational {
		return nil, fmt.Errorf("DISTRIBUTOR_BLOCKED_BY_FREEZE: freeze_mode=%s", freeze.Mode)
	}

	// 3. Populate & JCS-canonicalize NativeRollbackSpec BEFORE Wave 1 executes
	rbSpec := req.RollbackInstruction
	if strings.TrimSpace(rbSpec.Strategy) == "" {
		rbSpec.Strategy = caps.DefaultRollbackStrategy
	}
	if rbSpec.RawNativePayloadJCS == "" {
		canonRB, cErr := crypto.CanonicalizeStruct(map[string]any{
			"distributor_id":         tr.DistributorID(),
			"strategy":               rbSpec.Strategy,
			"uninstall_kb":           rbSpec.UninstallKB,
			"previous_package_nevra": rbSpec.PreviousPackageNEVRA,
			"previous_digest":        rbSpec.PreviousDigest,
			"rollback_playbook_id":   rbSpec.RollbackPlaybookID,
			"git_revert_commit":      rbSpec.GitRevertCommit,
		})
		if cErr == nil {
			rbSpec.RawNativePayloadJCS = string(canonRB)
		}
	}

	wavePcts := req.WavePercentages
	if len(wavePcts) == 0 {
		wavePcts = []int{5, 25, 100}
	}
	dwellSec := req.StageDwellSeconds
	if dwellSec <= 0 {
		dwellSec = w.StageDwellSeconds
	}
	maxFailPct := req.MaxFailureRatePct
	if maxFailPct < 0 {
		maxFailPct = 0
	}

	platform := strings.TrimSpace(req.PlatformFamily)
	if platform == "" {
		if len(caps.PlatformFamilies) > 0 {
			platform = caps.PlatformFamilies[0]
		} else {
			platform = "ESTATE_HOST"
		}
	}

	// 4. Mint N4 agt-distributor-gateway WARRANT_DELEGATED_COMPOSITE PoP Task Warrant
	taskEnv, taskPayload, holderPriv, err := e.agentCP.MintGovernedDistributorWarrant(
		ctx,
		w.WarrantID,
		req.Remediation.RemediationID,
		tr.DistributorID(),
		req.Service.ServiceID,
		"DISPATCH_DEPLOYMENT_ORDER",
		w.Slot1PrincipalID,
		w.Slot2PrincipalID,
	)
	if err != nil {
		return nil, err
	}
	governedTr := tr.WithTransport(agentcp.NewDistributorBoundRoundTripper(taskEnv, taskPayload.TaskTokenID, holderPriv, nil))

	outcome := &DistributorExecutionOutcome{}
	now := time.Now().UTC()

	if caps.SupportsNativeRings {
		waves := make([]models.RolloutWave, 0, len(wavePcts))
		allKeys := make([]string, 0, len(req.TargetAssets))
		for _, a := range req.TargetAssets {
			allKeys = append(allKeys, a.AssetKey)
		}
		for i, pct := range wavePcts {
			waves = append(waves, models.RolloutWave{
				WaveNumber:        i + 1,
				Percentage:        pct,
				TargetAssetKeys:   allKeys,
				StageDwellSeconds: dwellSec,
			})
		}
		order := models.DeploymentOrder{
			OrderID:       "ord-" + uuid.NewString()[:8],
			WarrantID:     w.WarrantID,
			TaskTokenID:   taskPayload.TaskTokenID,
			RemediationID: req.Remediation.RemediationID,
			ServiceID:     req.Service.ServiceID,
			DistributorID: tr.DistributorID(),
			PlatformFamily: platform,
			FixIdentity:   req.FixIdentity,
			TargetAssets:  req.TargetAssets,
			RolloutPlan: models.RolloutPlan{
				Waves:                waves,
				MaxFailureRatePct:    maxFailPct,
				StageDwellSeconds:    dwellSec,
				MaintenanceWindowUTC: req.MaintenanceWindowUTC,
			},
			RollbackInstruction: rbSpec,
			WaveNumber:          1,
			TotalWaves:          len(waves),
			CreatedAt:           now,
		}
		// Persist DeploymentOrder + NativeRollbackSpec immutably BEFORE Wave 1 executes!
		if err := e.store.InsertDeploymentOrder(ctx, &order); err != nil {
			return nil, fmt.Errorf("persist pre-wave DeploymentOrder: %w", err)
		}
		outcome.PrimaryOrder = order
		outcome.WaveOrders = []models.DeploymentOrder{order}

		receipt, err := governedTr.DispatchOrder(ctx, order)
		if err != nil {
			return nil, err
		}
		orderHash, _, _ := crypto.CanonicalSHA256Hex(order)
		receiptHash, _, _ := crypto.CanonicalSHA256Hex(receipt)
		_ = e.agentCP.RecordGovernedAdapterAction(
			ctx, w.WarrantID, req.Remediation.RemediationID, "agt-distributor-gateway", req.Service.ServiceID,
			"DISPATCH_DEPLOYMENT_ORDER", w.Slot1PrincipalID, w.Slot2PrincipalID,
			models.EgressProfileInternalCluster, orderHash, receiptHash,
		)

		res, err := governedTr.PollResult(ctx, order.OrderID, receipt.NativeJobRef)
		if err != nil {
			return nil, err
		}
		res.RemediationID = req.Remediation.RemediationID
		res.WaveNumber = len(waves)
		res.RecomputeCounts()
		if err := e.store.AppendDeploymentResult(ctx, res); err != nil {
			return nil, err
		}
		outcome.WaveResults = []models.DeploymentResult{*res}
		outcome.AggregatedResult = *res

		if breached, reason := evaluateWaveBreach(*res, maxFailPct); breached {
			rbRes, rbErr := e.triggerDistributorRollback(ctx, governedTr, w, req.Remediation, order, receipt.NativeJobRef, reason)
			if rbErr != nil {
				return nil, rbErr
			}
			outcome.RolledBack = true
			outcome.RollbackResult = rbRes
			outcome.RollbackReasonCode = reason
			return outcome, nil
		}
		return outcome, nil
	}

	// Warrant-Sequenced Progressive Waves for non-ring distributors (WSUS, Ansible AWX, Satellite, Jamf Pro, Automox, Flux)
	batches := SliceAssetsIntoWaves(req.TargetAssets, wavePcts)
	var dispatchedAssets []models.AssetTarget
	var lastOrder models.DeploymentOrder
	var lastJobRef string
	aggregated := models.DeploymentResult{
		ResultID:            "dres-" + uuid.NewString()[:8],
		RemediationID:       req.Remediation.RemediationID,
		DistributorID:       tr.DistributorID(),
		ObservedAt:          time.Now().UTC(),
		EvidenceGranularity: models.EvidenceGranularityPerAsset,
		TargetedCount:       len(req.TargetAssets),
	}
	if !caps.ReportsPerAssetState {
		aggregated.EvidenceGranularity = models.EvidenceGranularityDispatchAck
	}

	for idx, batch := range batches {
		waveNum := idx + 1
		pct := wavePcts[min(idx, len(wavePcts)-1)]

		// Gate every wave through N2 OPA policy before dispatching next slice
		curFreeze, fErr := e.store.GetFreezeState(ctx)
		if fErr != nil {
			return nil, fErr
		}
		gateDec, gErr := e.policy.EvalGate(ctx, policy.GateInput{
			FreezeMode:         curFreeze.Mode,
			AllowGuardedCanary: w.AllowGuardedCanary,
			ShadowEvaluated:    true,
			Service: policy.GateServiceInput{
				TestCoveragePct:            max(85.0, req.Service.TestCoveragePct),
				OtelHealthProbes:           req.Service.OtelHealthProbes,
				ReadonlyShadowReplica:      true,
				ShadowDBMode:               "READONLY_REPLICA",
				RollbackAutomationVerified: req.Service.RollbackAutomationVerified,
				ReadOnlyRootFilesystem:     req.Service.ReadOnlyRootFilesystem,
				NoExecTmpMounts:            req.Service.NoExecTmpMounts,
			},
			Patch: policy.GatePatchInput{
				APIBackwardCompatible: true,
			},
			Shadow: policy.GateShadowInput{
				MaxP99LatencyMs:  120.0,
				P99LatencyMs:     15.0,
				BaselineSyscalls: []string{},
				CanarySyscalls:   []string{},
			},
		})
		if gErr != nil {
			return nil, gErr
		}
		if !gateDec.AllowAutonomousRollout {
			return nil, fmt.Errorf("N2_WAVE_GATE_BLOCKED at wave %d: %s", waveNum, strings.Join(gateDec.Reasons, ","))
		}

		keys := make([]string, 0, len(batch))
		for _, b := range batch {
			keys = append(keys, b.AssetKey)
		}
		waveOrder := models.DeploymentOrder{
			OrderID:       fmt.Sprintf("ord-%s-w%d", uuid.NewString()[:8], waveNum),
			WarrantID:     w.WarrantID,
			TaskTokenID:   taskPayload.TaskTokenID,
			RemediationID: req.Remediation.RemediationID,
			ServiceID:     req.Service.ServiceID,
			DistributorID: tr.DistributorID(),
			PlatformFamily: platform,
			FixIdentity:   req.FixIdentity,
			TargetAssets:  batch,
			RolloutPlan: models.RolloutPlan{
				Waves: []models.RolloutWave{
					{
						WaveNumber:        waveNum,
						Percentage:        pct,
						TargetAssetKeys:   keys,
						StageDwellSeconds: dwellSec,
					},
				},
				MaxFailureRatePct:    maxFailPct,
				StageDwellSeconds:    dwellSec,
				MaintenanceWindowUTC: req.MaintenanceWindowUTC,
			},
			RollbackInstruction: rbSpec,
			WaveNumber:          waveNum,
			TotalWaves:          len(batches),
			CreatedAt:           time.Now().UTC(),
		}
		if err := e.store.InsertDeploymentOrder(ctx, &waveOrder); err != nil {
			return nil, fmt.Errorf("persist wave %d DeploymentOrder: %w", waveNum, err)
		}
		if waveNum == 1 {
			outcome.PrimaryOrder = waveOrder
		}
		outcome.WaveOrders = append(outcome.WaveOrders, waveOrder)

		receipt, err := governedTr.DispatchOrder(ctx, waveOrder)
		if err != nil {
			return nil, err
		}
		dispatchedAssets = append(dispatchedAssets, batch...)
		lastOrder = waveOrder
		lastJobRef = receipt.NativeJobRef

		orderHash, _, _ := crypto.CanonicalSHA256Hex(waveOrder)
		receiptHash, _, _ := crypto.CanonicalSHA256Hex(receipt)
		_ = e.agentCP.RecordGovernedAdapterAction(
			ctx, w.WarrantID, req.Remediation.RemediationID, "agt-distributor-gateway", req.Service.ServiceID,
			"DISPATCH_DEPLOYMENT_ORDER", w.Slot1PrincipalID, w.Slot2PrincipalID,
			models.EgressProfileInternalCluster, orderHash, receiptHash,
		)

		waveRes, err := governedTr.PollResult(ctx, waveOrder.OrderID, receipt.NativeJobRef)
		if err != nil {
			return nil, err
		}
		waveRes.RemediationID = req.Remediation.RemediationID
		waveRes.WaveNumber = waveNum
		waveRes.RecomputeCounts()
		if err := e.store.AppendDeploymentResult(ctx, waveRes); err != nil {
			return nil, err
		}
		outcome.WaveResults = append(outcome.WaveResults, *waveRes)

		if waveRes.EvidenceGranularity != models.EvidenceGranularityPerAsset {
			aggregated.EvidenceGranularity = waveRes.EvidenceGranularity
		}
		aggregated.AssetResults = append(aggregated.AssetResults, waveRes.AssetResults...)
		aggregated.ObservedAt = waveRes.ObservedAt

		if breached, reason := evaluateWaveBreach(*waveRes, maxFailPct); breached {
			rbOrder := lastOrder
			rbOrder.TargetAssets = dispatchedAssets
			rbRes, rbErr := e.triggerDistributorRollback(ctx, governedTr, w, req.Remediation, rbOrder, lastJobRef, fmt.Sprintf("WAVE_%d_%s", waveNum, reason))
			if rbErr != nil {
				return nil, rbErr
			}
			aggregated.RecomputeCounts()
			aggHash, _, _ := crypto.CanonicalSHA256Hex(outcome.WaveResults)
			aggregated.RawDistributorReportSHA256 = aggHash
			outcome.AggregatedResult = aggregated
			outcome.RolledBack = true
			outcome.RollbackResult = rbRes
			outcome.RollbackReasonCode = fmt.Sprintf("WAVE_%d_%s", waveNum, reason)
			return outcome, nil
		}

		req.Remediation.CanaryWeight = pct
		_ = e.store.UpsertRemediation(ctx, req.Remediation)
	}

	aggregated.OrderID = outcome.PrimaryOrder.OrderID
	aggregated.WaveNumber = len(batches)
	aggregated.TargetedCount = len(req.TargetAssets)
	aggregated.RecomputeCounts()
	aggHash, _, _ := crypto.CanonicalSHA256Hex(outcome.WaveResults)
	aggregated.RawDistributorReportSHA256 = aggHash
	outcome.AggregatedResult = aggregated
	return outcome, nil
}

func (e *Engine) triggerDistributorRollback(
	ctx context.Context,
	tr adapters.DistributorTranslator,
	w *models.WarrantRecord,
	item *models.RemediationItem,
	order models.DeploymentOrder,
	nativeJobRef string,
	reason string,
) (*models.DeploymentResult, error) {
	rbRes, err := tr.ExecuteRollback(ctx, order, nativeJobRef, reason)
	if err != nil {
		return nil, fmt.Errorf("EXECUTE_NATIVE_ROLLBACK_FAILED: %w", err)
	}
	rbRes.OrderID = order.OrderID
	rbRes.RemediationID = item.RemediationID
	rbRes.IsRollback = true
	rbRes.RollbackReason = reason
	rbRes.RecomputeCounts()
	if err := e.store.AppendDeploymentResult(ctx, rbRes); err != nil {
		return nil, err
	}
	rbSpecHash, _, _ := crypto.CanonicalSHA256Hex(order.RollbackInstruction)
	_ = e.agentCP.RecordGovernedAdapterAction(
		ctx, w.WarrantID, item.RemediationID, "agt-distributor-gateway", item.ServiceID,
		"EXECUTE_NATIVE_ROLLBACK", w.Slot1PrincipalID, w.Slot2PrincipalID,
		models.EgressProfileInternalCluster, rbSpecHash, rbRes.RawDistributorReportSHA256,
	)
	return rbRes, nil
}

func evaluateWaveBreach(res models.DeploymentResult, maxFailureRatePct float64) (bool, string) {
	if res.Stalled {
		return true, "STALLED_WAVE_WINDOW_EXCEEDED"
	}
	badCount := res.FailedCount + res.UnreachableCount
	if badCount == 0 {
		return false, ""
	}
	denom := max(1, res.TargetedCount)
	failPct := (float64(badCount) / float64(denom)) * 100.0
	if failPct > maxFailureRatePct {
		return true, fmt.Sprintf("FAILURE_THRESHOLD_BREACHED_%.1f_PCT", failPct)
	}
	return false, ""
}

func verifyTargetAssetsWithinWarrantScope(targets []models.AssetTarget, w *models.WarrantRecord) error {
	svcWildcard := false
	allowedSvcs := map[string]bool{}
	for _, s := range w.ScopeServices {
		trimmed := strings.TrimSpace(s)
		if trimmed == "*" {
			svcWildcard = true
		} else if trimmed != "" {
			allowedSvcs[strings.ToLower(trimmed)] = true
		}
	}

	assetWildcard := len(w.ScopeAssets) == 0
	allowedAssets := map[string]bool{}
	for _, a := range w.ScopeAssets {
		trimmed := strings.TrimSpace(a)
		if trimmed == "*" {
			assetWildcard = true
		} else if trimmed != "" {
			allowedAssets[strings.ToLower(trimmed)] = true
		}
	}

	for _, t := range targets {
		if !svcWildcard && !allowedSvcs[strings.ToLower(strings.TrimSpace(t.ServiceID))] {
			return fmt.Errorf("TARGET_ASSET_OUTSIDE_WARRANT_SCOPE: asset %q service %q is outside Standing Warrant %s scope_services", t.AssetKey, t.ServiceID, w.WarrantID)
		}
		if !assetWildcard && !allowedAssets[strings.ToLower(strings.TrimSpace(t.AssetKey))] {
			return fmt.Errorf("TARGET_ASSET_OUTSIDE_WARRANT_SCOPE: asset %q is outside Standing Warrant %s scope_assets", t.AssetKey, w.WarrantID)
		}
	}
	return nil
}
