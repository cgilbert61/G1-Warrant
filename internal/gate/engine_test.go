package gate

import (
	"testing"

	"github.com/g1163rt-labs/g1-warrant/internal/models"
)

func TestNormalizeAndDiffHTTPJSON_MasksVolatilesAndDetectsBreaking(t *testing.T) {
	base := `{"status":"SETTLED","request_id":"550e8400-e29b-41d4-a716-446655440000","responded_at":"2026-11-19T12:00:00Z","nonce":"abcdef0123456789abcdef0123456789","schema_ver":2}`
	canaryClean := `{"nonce":"99999999999999998888888888888888","request_id":"123e4567-e89b-12d3-a456-426614174000","responded_at":"2026-11-19T12:00:05.123456Z","schema_ver":2,"status":"SETTLED"}`

	normB, normC, masked, diffs, breaking, err := NormalizeAndDiffHTTPJSON(base, canaryClean)
	if err != nil {
		t.Fatal(err)
	}
	if normB != normC || breaking != 0 || len(diffs) != 0 || len(masked) != 3 {
		t.Fatalf("expected identical normalized schema, got normB=%s normC=%s breaking=%d masked=%v", normB, normC, breaking, masked)
	}

	canaryBreaking := `{"status":"SETTLED","request_id":"123e4567-e89b-12d3-a456-426614174000","responded_at":"2026-11-19T12:00:05Z","nonce":"99999999999999998888888888888888","schema_ver":"v2"}`
	_, _, _, diffs2, breaking2, err := NormalizeAndDiffHTTPJSON(base, canaryBreaking)
	if err != nil {
		t.Fatal(err)
	}
	if breaking2 != 1 || len(diffs2) != 1 || diffs2[0].ChangeKind != "TYPE_CHANGED" {
		t.Fatalf("expected 1 breaking type change, got breaking=%d diffs=%+v", breaking2, diffs2)
	}
}

func TestNormalizeAndDiffHTTPJSON_UnorderedArraysFloatToleranceAndCustomMasks(t *testing.T) {
	base := `{
		"status": "SETTLED",
		"amount": 12.0000001,
		"shard_nodes": ["fin-core-a", "fin-core-b", "fin-core-c"],
		"custom_trace_token": "req-abc-001"
	}`
	canary := `{
		"status": "SETTLED",
		"amount": 12.0,
		"shard_nodes": ["fin-core-c", "fin-core-a", "fin-core-b"],
		"custom_trace_token": "req-xyz-999"
	}`

	normB, normC, masked, diffs, breaking, err := NormalizeAndDiffHTTPJSON(base, canary, "$.custom_trace_token")
	if err != nil {
		t.Fatal(err)
	}
	if normB != normC || breaking != 0 || len(diffs) != 0 || len(masked) != 1 {
		t.Fatalf("expected unordered arrays + 1e-6 float drift + custom mask to match cleanly, got normB=%s normC=%s breaking=%d diffs=%+v masked=%v", normB, normC, breaking, diffs, masked)
	}
}

func TestGradeServiceReadiness(t *testing.T) {
	svcTier2 := models.EstateService{
		ServiceID:                  "fulfillment-worker",
		TestCoveragePct:            71.4,
		OtelHealthProbes:           true,
		ReadonlyShadowReplica:      false,
		RollbackAutomationVerified: true,
		ReadOnlyRootFilesystem:     true,
		NoExecTmpMounts:            true,
	}
	GradeServiceReadiness(&svcTier2)
	if svcTier2.Eligible {
		t.Fatal("expected service with 71.4% coverage and missing shadow replica to be false for Tier 1 full shadow Eligible")
	}
	if svcTier2.AutonomyTier != models.AutonomyTier2GuardedCanary {
		t.Fatalf("expected brownfield service with OTel + rollback + immutable rootfs to receive TIER_2_GUARDED_CANARY, got %s", svcTier2.AutonomyTier)
	}
	if len(svcTier2.EligibilityChecklist) != 5 {
		t.Fatalf("expected 5 mandatory scorecard criteria including IMMUTABLE_ROOTFS_NOEXEC_TMP, got %d", len(svcTier2.EligibilityChecklist))
	}

	// Mutable rootfs even with 95% coverage MUST be downgraded to TIER_3_CONTAIN_AND_CAB
	svcMutableFS := models.EstateService{
		ServiceID:                  "mutable-webshell-target",
		TestCoveragePct:            95.0,
		OtelHealthProbes:           true,
		ReadonlyShadowReplica:      true,
		RollbackAutomationVerified: true,
		ReadOnlyRootFilesystem:     false,
		NoExecTmpMounts:            false,
	}
	GradeServiceReadiness(&svcMutableFS)
	if svcMutableFS.Eligible || svcMutableFS.AutonomyTier != models.AutonomyTier3ContainAndCAB {
		t.Fatalf("expected mutable rootfs workload to fail 5th gate into TIER_3_CONTAIN_AND_CAB, got %+v", svcMutableFS)
	}

	svcTier3 := models.EstateService{
		ServiceID:                  "legacy-billing-monolith",
		TestCoveragePct:            54.0,
		OtelHealthProbes:           false,
		ReadonlyShadowReplica:      false,
		RollbackAutomationVerified: false,
	}
	GradeServiceReadiness(&svcTier3)
	if svcTier3.AutonomyTier != models.AutonomyTier3ContainAndCAB {
		t.Fatalf("expected legacy monolith to receive TIER_3_CONTAIN_AND_CAB, got %s", svcTier3.AutonomyTier)
	}
}
