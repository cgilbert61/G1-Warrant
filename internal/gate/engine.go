package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
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

var (
	reUUID    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	reRFC3339 = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
	reHexTok  = regexp.MustCompile(`^[0-9a-fA-F]{24,128}$`)
)

// Engine implements N2: Deployment Gate, Estate Readiness Grader, Patch Statelessness Analyzer,
// Normalized HTTP Schema Diff, and Syscall Capability-Set Differential Shadow Execution.
type Engine struct {
	store       *db.Store
	policy      *policy.Engine
	warrants    *warrant.Engine
	agentCP     *agentcp.ControlPlane
	deploy      adapters.DeploymentTarget
	onBroadcast func(eventType string, payload any)
}

// NewEngine constructs the N2 Deployment Gate & Differential Shadow Engine.
func NewEngine(
	store *db.Store,
	pol *policy.Engine,
	warrants *warrant.Engine,
	agentCP *agentcp.ControlPlane,
	deploy adapters.DeploymentTarget,
	onBroadcast func(string, any),
) *Engine {
	return &Engine{
		store:       store,
		policy:      pol,
		warrants:    warrants,
		agentCP:     agentCP,
		deploy:      deploy,
		onBroadcast: onBroadcast,
	}
}

// GradeServiceReadiness deterministically grades an EstateService against N2 eligibility bars.
func GradeServiceReadiness(svc *models.EstateService) {
	covOK := svc.TestCoveragePct >= 80.0
	checks := []models.EligibilityCheckItem{
		{
			CriterionCode:     "TEST_COVERAGE_BAR",
			Passed:            covOK,
			ObservedValue:     fmt.Sprintf("%.1f%%", svc.TestCoveragePct),
			RequiredThreshold: ">= 80.0%",
			ActionCode:        ternary(covOK, "NONE", "INCREASE_INTEGRATION_TEST_COVERAGE_TO_80_PCT"),
		},
		{
			CriterionCode:     "OTEL_HEALTH_PROBES",
			Passed:            svc.OtelHealthProbes,
			ObservedValue:     fmt.Sprintf("%t", svc.OtelHealthProbes),
			RequiredThreshold: "true",
			ActionCode:        ternary(svc.OtelHealthProbes, "NONE", "WIRE_OTEL_GRPC_HTTP_SLI_PROBES"),
		},
		{
			CriterionCode:     "SHADOW_READONLY_REPLICA",
			Passed:            svc.ReadonlyShadowReplica,
			ObservedValue:     fmt.Sprintf("%t", svc.ReadonlyShadowReplica),
			RequiredThreshold: "true",
			ActionCode:        ternary(svc.ReadonlyShadowReplica, "NONE", "PROVISION_READONLY_SHADOW_DB_REPLICA_AND_SINK"),
		},
		{
			CriterionCode:     "AUTOMATED_ROLLBACK_DRILL",
			Passed:            svc.RollbackAutomationVerified,
			ObservedValue:     fmt.Sprintf("%t", svc.RollbackAutomationVerified),
			RequiredThreshold: "true",
			ActionCode:        ternary(svc.RollbackAutomationVerified, "NONE", "VERIFY_DETERMINISTIC_SUB_10S_ROLLBACK_HOOK"),
		},
	}
	svc.EligibilityChecklist = checks
	svc.Eligible = covOK && svc.OtelHealthProbes && svc.ReadonlyShadowReplica && svc.RollbackAutomationVerified
}

// NormalizeAndDiffHTTPJSON strips volatile fields (RFC3339 timestamps, UUIDv4/v7, cryptographic hex nonces),
// canonicalizes both payloads via RFC 8785 JCS, and computes structural field/type diffs.
func NormalizeAndDiffHTTPJSON(baselineRaw, canaryRaw string) (normBase string, normCanary string, maskedPaths []string, diffs []models.SchemaFieldDiff, breakingCount int, err error) {
	var baseVal, canaryVal any
	if err := json.Unmarshal([]byte(baselineRaw), &baseVal); err != nil {
		return "", "", nil, nil, 0, fmt.Errorf("parse baseline json: %w", err)
	}
	if err := json.Unmarshal([]byte(canaryRaw), &canaryVal); err != nil {
		return "", "", nil, nil, 0, fmt.Errorf("parse canary json: %w", err)
	}

	maskedSet := map[string]bool{}
	maskedBase := maskVolatileValue("$", baseVal, maskedSet)
	maskedCanary := maskVolatileValue("$", canaryVal, maskedSet)

	canonBase, err := crypto.CanonicalizeStruct(maskedBase)
	if err != nil {
		return "", "", nil, nil, 0, err
	}
	canonCanary, err := crypto.CanonicalizeStruct(maskedCanary)
	if err != nil {
		return "", "", nil, nil, 0, err
	}

	diffs = compareSchemaStructure("$", maskedBase, maskedCanary)
	for _, d := range diffs {
		if d.Breaking {
			breakingCount++
		}
	}

	maskedList := make([]string, 0, len(maskedSet))
	for p := range maskedSet {
		maskedList = append(maskedList, p)
	}
	sort.Strings(maskedList)
	return string(canonBase), string(canonCanary), maskedList, diffs, breakingCount, nil
}

func maskVolatileValue(path string, v any, masked map[string]bool) any {
	switch val := v.(type) {
	case string:
		switch {
		case reUUID.MatchString(val):
			masked[path+" (UUID)"] = true
			return "[MASKED:UUID]"
		case reRFC3339.MatchString(val):
			masked[path+" (RFC3339)"] = true
			return "[MASKED:RFC3339]"
		case reHexTok.MatchString(val):
			masked[path+" (NONCE)"] = true
			return "[MASKED:NONCE]"
		default:
			return val
		}
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, child := range val {
			out[k] = maskVolatileValue(path+"."+k, child, masked)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, elem := range val {
			out[i] = maskVolatileValue(fmt.Sprintf("%s[%d]", path, i), elem, masked)
		}
		return out
	default:
		return val
	}
}

func compareSchemaStructure(path string, base, canary any) []models.SchemaFieldDiff {
	var out []models.SchemaFieldDiff
	bType := jsonKind(base)
	cType := jsonKind(canary)
	if bType != cType {
		return []models.SchemaFieldDiff{{
			JSONPath:     path,
			BaselineType: bType,
			CanaryType:   cType,
			ChangeKind:   "TYPE_CHANGED",
			Breaking:     true,
		}}
	}
	bMap, okB := base.(map[string]any)
	cMap, okC := canary.(map[string]any)
	if okB && okC {
		keys := map[string]bool{}
		for k := range bMap {
			keys[k] = true
		}
		for k := range cMap {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			bChild, hasB := bMap[k]
			cChild, hasC := cMap[k]
			childPath := path + "." + k
			switch {
			case hasB && !hasC:
				out = append(out, models.SchemaFieldDiff{
					JSONPath:     childPath,
					BaselineType: jsonKind(bChild),
					CanaryType:   "MISSING",
					ChangeKind:   "MISSING_KEY",
					Breaking:     true,
				})
			case !hasB && hasC:
				out = append(out, models.SchemaFieldDiff{
					JSONPath:     childPath,
					BaselineType: "ABSENT",
					CanaryType:   jsonKind(cChild),
					ChangeKind:   "ADDED_NULLABLE",
					Breaking:     false,
				})
			default:
				out = append(out, compareSchemaStructure(childPath, bChild, cChild)...)
			}
		}
	}
	return out
}

func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64, json.Number:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// EvaluateAndRollout executes N2 gating, Patch Statelessness checks, Exception routing,
// and Differential Shadow Canary stages (0% -> 10% -> 50% -> 100%).
func (e *Engine) EvaluateAndRollout(ctx context.Context, item *models.RemediationItem, svc *models.EstateService, patchMeta *models.ExtractedPatchMetadata, exceptionApproved bool) error {
	// 1. Check Asymmetric Emergency Freeze before touching N2 rollout
	freeze := e.warrants.CurrentFreezeState()
	if freeze.Mode != models.FreezeModeOperational {
		item.StatusHealth = models.HealthFrozen
		item.BlockerCode = freeze.Mode
		_ = e.store.UpsertRemediation(ctx, item)
		_ = e.recordTrace(ctx, item.RemediationID, "N2", "FREEZE_GATE_CHECK", "BLOCK", freeze.Actor, crypto.SHA256Hex([]byte(freeze.Mode)), map[string]string{
			"freeze_mode": freeze.Mode,
			"bridge_kept": item.BridgeID,
		})
		if freeze.Mode == models.FreezeModeRollback && item.CanaryWeight > 0 {
			_ = e.deploy.RollbackCanary(ctx, item.ServiceID)
			item.CanaryWeight = 0
			_ = e.store.UpsertRemediation(ctx, item)
		}
		e.emit("REMEDIATION_UPDATED", item)
		return fmt.Errorf("N2_HALTED_BY_EMERGENCY_FREEZE (%s)", freeze.Mode)
	}

	// 2. Re-verify N1 Standing Warrant signatures & live revocation registry
	w, err := e.warrants.ReverifyWarrantForExecution(ctx, item.WarrantID, svc.ServiceID, item.CVSSScore, svc.Replicas)
	if err != nil {
		item.StatusHealth = models.HealthExceptionRouted
		item.BlockerCode = "N1_WARRANT_REVERIFY_FAILED"
		_ = e.store.UpsertRemediation(ctx, item)
		_ = e.recordTrace(ctx, item.RemediationID, "N1", "EXECUTION_TIME_WARRANT_REVERIFY", "BLOCK", item.WarrantID, crypto.SHA256Hex([]byte(err.Error())), map[string]string{
			"error": err.Error(),
		})
		e.emit("REMEDIATION_UPDATED", item)
		return err
	}
	_ = e.recordTrace(ctx, item.RemediationID, "N1", "EXECUTION_TIME_WARRANT_REVERIFY", "PASS", w.WarrantID, w.EntryHash, map[string]string{
		"slot1": w.Slot1PrincipalID,
		"slot2": w.Slot2PrincipalID,
	})

	// 3. Pre-rollout OPA Gate Check (Service Readiness + Patch Statelessness + Blast Radius)
	blastExceeded := svc.Replicas > w.MaxBlastRadiusReplicas
	preGate, err := e.policy.EvalGate(ctx, policy.GateInput{
		FreezeMode:          freeze.Mode,
		BlastRadiusExceeded: blastExceeded,
		ShadowEvaluated:     false,
		Service: policy.GateServiceInput{
			TestCoveragePct:            svc.TestCoveragePct,
			OtelHealthProbes:           svc.OtelHealthProbes,
			ReadonlyShadowReplica:      svc.ReadonlyShadowReplica,
			RollbackAutomationVerified: svc.RollbackAutomationVerified,
		},
		Patch: policy.GatePatchInput{
			DDLMigrations:         patchMeta.DDLMigrations,
			ORMModelMutations:     patchMeta.ORMModelMutations,
			SerializationBreaks:   patchMeta.SerializationBreaks,
			APIBackwardCompatible: patchMeta.APIBackwardCompatible,
		},
		Shadow: policy.GateShadowInput{
			MaxP99LatencyMs:  w.MaxP99LatencyMs,
			BaselineSyscalls: svc.BaselineSyscalls,
			CanarySyscalls:   svc.BaselineSyscalls,
		},
	})
	if err != nil {
		return err
	}

	statelessBool := preGate.PatchStateless
	item.StatelessPassed = &statelessBool
	item.PatchMetadata = patchMeta

	if preGate.RouteToExceptionCockpit && !exceptionApproved {
		triggerCode := strings.Join(preGate.Reasons, ",")
		if triggerCode == "" {
			triggerCode = "CEILING_OR_STATEFUL_EXCEPTION"
		}
		ex := models.CeilingException{
			ExceptionID:           "exc-" + uuid.NewString()[:8],
			RemediationID:         item.RemediationID,
			ServiceID:             svc.ServiceID,
			CVEID:                 item.CVEID,
			WarrantClass:          w.WarrantClass,
			TriggerCode:           triggerCode,
			DDLCount:              patchMeta.DDLMigrations,
			ORMMutations:          patchMeta.ORMModelMutations,
			SerializationBreaks:   patchMeta.SerializationBreaks,
			APIBackwardCompatible: patchMeta.APIBackwardCompatible,
			ShadowReplayStatus:    "DEFERRED_PENDING_FOUR_EYES",
			SyscallDiffSummary:    strings.Join(patchMeta.DeclaredSyscallDelta, ","),
			ActiveBridgeID:        item.BridgeID,
			Status:                "PENDING_DUAL_KEY",
			CreatedAt:             time.Now().UTC(),
		}
		_ = e.store.UpsertException(ctx, ex)
		item.StatusHealth = models.HealthExceptionRouted
		item.BlockerCode = triggerCode
		_ = e.store.UpsertRemediation(ctx, item)
		_ = e.recordTrace(ctx, item.RemediationID, "N2", "STATELESS_AND_ELIGIBILITY_GATE", "BLOCK", w.WarrantID, patchMeta.TypedOutputSHA256, map[string]string{
			"exception_id": ex.ExceptionID,
			"reasons":      triggerCode,
		})
		e.emit("EXCEPTION_ROUTED", ex)
		e.emit("REMEDIATION_UPDATED", item)
		return fmt.Errorf("ROUTED_TO_FOUR_EYES_EXCEPTION_COCKPIT: %s", triggerCode)
	}

	_ = e.recordTrace(ctx, item.RemediationID, "N2", "STATELESS_AND_ELIGIBILITY_GATE", "PASS", w.WarrantID, patchMeta.TypedOutputSHA256, map[string]string{
		"ddl_migrations": "0",
		"orm_mutations":  "0",
	})

	// 4. Differential Shadow & Progressive Canary Execution: 0% (Shadow) -> 10% -> 50% -> 100%
	item.Stage = models.StageShadowCanary
	item.StatusHealth = models.HealthNormal
	_ = e.store.UpsertRemediation(ctx, item)

	stages := []int{0, 10, 50, 100}
	for _, weight := range stages {
		// Re-check freeze & warrant before EVERY canary step
		curFreeze := e.warrants.CurrentFreezeState()
		if curFreeze.Mode != models.FreezeModeOperational {
			if curFreeze.Mode == models.FreezeModeRollback {
				_ = e.deploy.RollbackCanary(ctx, svc.ServiceID)
				item.CanaryWeight = 0
			}
			item.StatusHealth = models.HealthFrozen
			item.BlockerCode = curFreeze.Mode
			_ = e.store.UpsertRemediation(ctx, item)
			e.emit("REMEDIATION_UPDATED", item)
			return fmt.Errorf("N2_CANARY_HALTED_BY_FREEZE (%s)", curFreeze.Mode)
		}
		if _, err := e.warrants.ReverifyWarrantForExecution(ctx, item.WarrantID, svc.ServiceID, item.CVSSScore, svc.Replicas); err != nil {
			_ = e.deploy.RollbackCanary(ctx, svc.ServiceID)
			item.CanaryWeight = 0
			item.StatusHealth = models.HealthRollbackFailed
			item.BlockerCode = "SIGNER_REVOKED_MID_ROLLOUT"
			_ = e.store.UpsertRemediation(ctx, item)
			e.emit("REMEDIATION_UPDATED", item)
			return err
		}

		stageResp, err := e.deploy.ProgressCanary(ctx, svc.ServiceID, fleetsim.StageRolloutRequest{
			PatchedDigest:  item.PatchedDigest,
			StageWeight:    weight,
			ClearSymbol:    item.VulnerableSymbol,
			InjectSyscalls: patchMeta.DeclaredSyscallDelta,
		})
		if err != nil {
			return err
		}
		_ = e.agentCP.RecordGovernedAdapterAction(
			ctx, w.WarrantID, item.RemediationID, "k8s_rollout", svc.ServiceID,
			fmt.Sprintf("CANARY_STAGE_%d_PCT", weight),
			w.Slot1PrincipalID, w.Slot2PrincipalID, "INTERNAL_CLUSTER_ONLY",
			crypto.SHA256Hex([]byte(item.PatchedDigest)),
			crypto.SHA256Hex([]byte(stageResp.CanaryHTTPBody)),
		)

		normBase, normCanary, maskedFields, schemaDiffs, breakingCount, err := NormalizeAndDiffHTTPJSON(stageResp.BaselineHTTPBody, stageResp.CanaryHTTPBody)
		if err != nil {
			return err
		}

		shadowGate, err := e.policy.EvalGate(ctx, policy.GateInput{
			FreezeMode:          curFreeze.Mode,
			BlastRadiusExceeded: false,
			ShadowEvaluated:     true,
			Service: policy.GateServiceInput{
				TestCoveragePct:            svc.TestCoveragePct,
				OtelHealthProbes:           true,
				ReadonlyShadowReplica:      stageResp.ReadonlyDBBound,
				RollbackAutomationVerified: true,
			},
			Patch: policy.GatePatchInput{
				DDLMigrations:         0,
				ORMModelMutations:     0,
				SerializationBreaks:   0,
				APIBackwardCompatible: true,
			},
			Shadow: policy.GateShadowInput{
				SchemaBreakingDiffs: breakingCount,
				StatusCodeDriftPct:  stageResp.StatusCodeDriftPct,
				P99LatencyMs:        stageResp.CanaryP99Ms,
				MaxP99LatencyMs:     w.MaxP99LatencyMs,
				BaselineSyscalls:    stageResp.BaselineSyscalls,
				CanarySyscalls:      stageResp.CanarySyscalls,
			},
		})
		if err != nil {
			return err
		}

		schemaOK := breakingCount == 0
		syscallOK := len(shadowGate.UnauthorizedSyscalls) == 0
		isolationOK := stageResp.ReadonlyDBBound && stageResp.OutboundMutationSinkActive
		passed := shadowGate.ShadowSafe && isolationOK

		failureCode := ""
		if !passed {
			if !syscallOK {
				failureCode = "SHADOW_UNAUTHORIZED_SYSCALL:" + strings.Join(shadowGate.UnauthorizedSyscalls, ",")
			} else if !schemaOK {
				failureCode = "SHADOW_BREAKING_HTTP_SCHEMA_DIFF"
			} else if !isolationOK {
				failureCode = "SHADOW_ISOLATION_CONTRACT_VIOLATION"
			} else {
				failureCode = strings.Join(shadowGate.Reasons, ",")
			}
		}

		report := models.ShadowComparisonReport{
			RunID:                      fmt.Sprintf("shd-%s-%d", item.RemediationID, weight),
			RemediationID:              item.RemediationID,
			ServiceID:                  svc.ServiceID,
			StageWeight:                weight,
			ShadowIsolationVerified:    isolationOK,
			ReadonlyDBBound:            stageResp.ReadonlyDBBound,
			OutboundMutationSinkActive: stageResp.OutboundMutationSinkActive,
			NormalizedBaselineSample:   normBase,
			NormalizedCanarySample:     normCanary,
			VolatileFieldsMasked:       maskedFields,
			SchemaBreakingDiffs:        breakingCount,
			SchemaFieldDiffs:           schemaDiffs,
			StatusCodeDriftPct:         stageResp.StatusCodeDriftPct,
			BaselineLatency: models.LatencySummary{
				P50Ms: stageResp.BaselineP50Ms,
				P95Ms: stageResp.BaselineP95Ms,
				P99Ms: stageResp.BaselineP99Ms,
			},
			CanaryLatency: models.LatencySummary{
				P50Ms: stageResp.CanaryP50Ms,
				P95Ms: stageResp.CanaryP95Ms,
				P99Ms: stageResp.CanaryP99Ms,
			},
			MaxP99LatencyMs:      w.MaxP99LatencyMs,
			BaselineSyscalls:     stageResp.BaselineSyscalls,
			CanarySyscalls:       stageResp.CanarySyscalls,
			UnauthorizedSyscalls: shadowGate.UnauthorizedSyscalls,
			Passed:               passed,
			FailureCode:          failureCode,
			EvaluatedAt:          time.Now().UTC(),
		}
		_ = e.store.SaveShadowRun(ctx, report)

		item.CanaryWeight = weight
		item.SchemaDiffPassed = &schemaOK
		item.SyscallPassed = &syscallOK
		item.ShadowReport = &report

		if !passed || shadowGate.TriggerCanaryRollback {
			_ = e.deploy.RollbackCanary(ctx, svc.ServiceID)
			item.CanaryWeight = 0
			item.StatusHealth = models.HealthRollbackFailed
			item.BlockerCode = failureCode
			_ = e.store.UpsertRemediation(ctx, item)
			repHash, _, _ := crypto.CanonicalSHA256Hex(report)
			_ = e.recordTrace(ctx, item.RemediationID, "N2", fmt.Sprintf("CANARY_ROLLBACK_%d_PCT", weight), "ROLLBACK", "k8s_rollout", repHash, map[string]string{
				"failure_code":          failureCode,
				"unauthorized_syscalls": strings.Join(shadowGate.UnauthorizedSyscalls, ","),
				"active_bridge_kept":    item.BridgeID,
			})
			e.emit("CANARY_ROLLED_BACK", report)
			e.emit("REMEDIATION_UPDATED", item)
			return fmt.Errorf("N2_CANARY_SAFETY_ROLLBACK (%s)", failureCode)
		}

		_ = e.store.UpsertRemediation(ctx, item)
		repHash, _, _ := crypto.CanonicalSHA256Hex(report)
		_ = e.recordTrace(ctx, item.RemediationID, "N2", fmt.Sprintf("SHADOW_CANARY_%d_PCT", weight), "PASS", "k8s_rollout", repHash, map[string]string{
			"canary_p99_ms": fmt.Sprintf("%.1f", stageResp.CanaryP99Ms),
			"masked_fields": fmt.Sprintf("%d", len(maskedFields)),
		})
		e.emit("REMEDIATION_UPDATED", item)
	}

	// Update service registry current digest upon 100% promotion
	svc.CurrentDigest = item.PatchedDigest
	_ = e.store.UpsertEstateService(ctx, *svc)
	return nil
}

// RollbackAllActiveCanaries is invoked by N1 FREEZE_ROLLBACK to immediately roll back all in-flight canaries
// while preserving active Shield containment bridges.
func (e *Engine) RollbackAllActiveCanaries(ctx context.Context) error {
	items, err := e.store.ListRemediations(ctx)
	if err != nil {
		return err
	}
	for i := range items {
		it := &items[i]
		if it.Stage == models.StageShadowCanary || (it.CanaryWeight > 0 && it.CanaryWeight < 100) {
			_ = e.deploy.RollbackCanary(ctx, it.ServiceID)
			it.CanaryWeight = 0
			it.StatusHealth = models.HealthFrozen
			it.BlockerCode = models.FreezeModeRollback
			_ = e.store.UpsertRemediation(ctx, it)
			_ = e.recordTrace(ctx, it.RemediationID, "N1", "EMERGENCY_FREEZE_ROLLBACK", "ROLLBACK", "freeze-controller", crypto.SHA256Hex([]byte(it.RemediationID)), map[string]string{
				"bridge_preserved": it.BridgeID,
			})
			e.emit("REMEDIATION_UPDATED", it)
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
