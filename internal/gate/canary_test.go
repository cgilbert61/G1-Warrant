package gate

import (
	"context"
	"strings"
	"testing"

	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
)

func buildCanaryTestFixture(t *testing.T) (*Engine, *models.WarrantRecord, *models.EstateService, *models.ExtractedPatchMetadata, *fleetsim.StageRolloutResponse) {
	t.Helper()
	pol, err := policy.NewEngine(context.Background())
	if err != nil {
		t.Fatalf("compile embedded OPA policy engine: %v", err)
	}
	eng := NewEngine(nil, pol, nil, nil, nil, nil)

	w := &models.WarrantRecord{
		WarrantID:              "war-canary-floor-01",
		WarrantClass:           "KEV-TIER1-STATELESS",
		MaxBlastRadiusReplicas: 8,
		AllowStatefulPatches:   false,
		AllowGuardedCanary:     false,
		MinCanarySamples:       500,
		StageDwellSeconds:      300,
		MaxP99LatencyMs:        100.0,
	}
	svc := &models.EstateService{
		ServiceID:                  "payments-ledger-api",
		Replicas:                   6,
		TestCoveragePct:            94.0,
		OtelHealthProbes:           true,
		ReadonlyShadowReplica:      true,
		RollbackAutomationVerified: true,
		ReadOnlyRootFilesystem:     true,
		NoExecTmpMounts:            true,
		BaselineSyscalls:           []string{"accept4", "read", "write", "futex"},
	}
	pm := &models.ExtractedPatchMetadata{
		DDLMigrations:         0,
		ORMModelMutations:     0,
		SerializationBreaks:   0,
		APIBackwardCompatible: true,
		StatelessEligible:     true,
	}
	resp := &fleetsim.StageRolloutResponse{
		ServiceID:                  "payments-ledger-api",
		StageWeight:                10,
		ObservedSamples:            750,
		ObservedDwellSeconds:       360,
		ReadonlyDBBound:            true,
		OutboundMutationSinkActive: true,
		BaselineHTTPBody:           `{"status":"SETTLED","schema_ver":2}`,
		CanaryHTTPBody:             `{"status":"SETTLED","schema_ver":2}`,
		StatusCodeDriftPct:         0.01,
		BaselineP99Ms:              32.0,
		CanaryP99Ms:                34.5,
		BaselineSyscalls:           []string{"accept4", "read", "write", "futex"},
		CanarySyscalls:             []string{"accept4", "read", "write", "futex"},
	}
	return eng, w, svc, pm, resp
}

func TestEvalStagePromotion_PassesWhenFloorsAndMeasuredMetricsSatisfied(t *testing.T) {
	eng, w, svc, pm, resp := buildCanaryTestFixture(t)

	report, _, err := eng.EvalStagePromotion(
		context.Background(), "rem-01", 10, models.FreezeModeOperational, models.AutonomyTier1FullAutonomous, w, svc, pm, resp,
	)
	if err != nil {
		t.Fatalf("unexpected EvalStagePromotion error: %v", err)
	}
	if !report.Passed {
		t.Fatalf("expected stage promotion to pass, got failure_code=%q", report.FailureCode)
	}
	if report.SampleCount != 750 || report.ObservedDwellSeconds != 360 {
		t.Fatalf("expected measured sample=750 dwell=360 persisted in report, got sample=%d dwell=%d", report.SampleCount, report.ObservedDwellSeconds)
	}
}

func TestEvalStagePromotion_BlocksWhenSampleCountBelowMinCanarySamples(t *testing.T) {
	eng, w, svc, pm, resp := buildCanaryTestFixture(t)
	resp.ObservedSamples = 180 // below w.MinCanarySamples (500)

	report, _, err := eng.EvalStagePromotion(
		context.Background(), "rem-02", 10, models.FreezeModeOperational, models.AutonomyTier1FullAutonomous, w, svc, pm, resp,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Passed {
		t.Fatal("expected stage promotion to fail closed when ObservedSamples < MinCanarySamples")
	}
	if !strings.Contains(report.FailureCode, "CANARY_MIN_SAMPLES_NOT_MET") {
		t.Fatalf("expected explicit CANARY_MIN_SAMPLES_NOT_MET reason, got %q", report.FailureCode)
	}
}

func TestEvalStagePromotion_BlocksWhenDwellTimeBelowStageDwellSeconds(t *testing.T) {
	eng, w, svc, pm, resp := buildCanaryTestFixture(t)
	resp.ObservedDwellSeconds = 45 // below w.StageDwellSeconds (300)

	report, _, err := eng.EvalStagePromotion(
		context.Background(), "rem-03", 10, models.FreezeModeOperational, models.AutonomyTier1FullAutonomous, w, svc, pm, resp,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Passed {
		t.Fatal("expected stage promotion to fail closed when ObservedDwellSeconds < StageDwellSeconds")
	}
	if !strings.Contains(report.FailureCode, "CANARY_STAGE_DWELL_NOT_MET") {
		t.Fatalf("expected explicit CANARY_STAGE_DWELL_NOT_MET reason, got %q", report.FailureCode)
	}
}

func TestEvalStagePromotion_ConsumesMeasuredDDLAndSyscallAndHealthTelemetry(t *testing.T) {
	t.Run("measured_ddl_mutation_blocks_promotion", func(t *testing.T) {
		eng, w, svc, pm, resp := buildCanaryTestFixture(t)
		pm.DDLMigrations = 1 // must NOT be masked by hardcoded 0!

		report, _, err := eng.EvalStagePromotion(
			context.Background(), "rem-ddl", 10, models.FreezeModeOperational, models.AutonomyTier1FullAutonomous, w, svc, pm, resp,
		)
		if err != nil {
			t.Fatal(err)
		}
		if report.Passed || !strings.Contains(report.FailureCode, "STATEFUL_PATCH_DDL_DETECTED") {
			t.Fatalf("expected measured DDLMigrations=1 to block stage promotion, got passed=%v code=%q", report.Passed, report.FailureCode)
		}
	})

	t.Run("measured_otel_probe_drop_blocks_promotion", func(t *testing.T) {
		eng, w, svc, pm, resp := buildCanaryTestFixture(t)
		probeFalse := false
		resp.OtelHealthProbes = &probeFalse // must NOT be masked by hardcoded true!

		report, _, err := eng.EvalStagePromotion(
			context.Background(), "rem-otel", 10, models.FreezeModeOperational, models.AutonomyTier1FullAutonomous, w, svc, pm, resp,
		)
		if err != nil {
			t.Fatal(err)
		}
		if report.Passed || !strings.Contains(report.FailureCode, "SERVICE_MISSING_OTEL_PROBES") {
			t.Fatalf("expected lost OTel health probes to block stage promotion, got passed=%v code=%q", report.Passed, report.FailureCode)
		}
	})

	t.Run("unauthorized_syscall_against_service_baseline_blocks_promotion", func(t *testing.T) {
		eng, w, svc, pm, resp := buildCanaryTestFixture(t)
		resp.CanarySyscalls = append(resp.CanarySyscalls, "execve")

		report, dec, err := eng.EvalStagePromotion(
			context.Background(), "rem-sc", 10, models.FreezeModeOperational, models.AutonomyTier1FullAutonomous, w, svc, pm, resp,
		)
		if err != nil {
			t.Fatal(err)
		}
		if report.Passed || !dec.TriggerCanaryRollback || !strings.Contains(report.FailureCode, "SHADOW_UNAUTHORIZED_SYSCALL:execve") {
			t.Fatalf("expected unauthorized execve syscall to trigger rollback, got passed=%v rollback=%v code=%q",
				report.Passed, dec.TriggerCanaryRollback, report.FailureCode)
		}
	})
}
