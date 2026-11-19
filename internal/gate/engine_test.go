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

func TestGradeServiceReadiness(t *testing.T) {
	svc := models.EstateService{
		ServiceID:                  "fulfillment-worker",
		TestCoveragePct:            71.4,
		OtelHealthProbes:           true,
		ReadonlyShadowReplica:      false,
		RollbackAutomationVerified: true,
	}
	GradeServiceReadiness(&svc)
	if svc.Eligible {
		t.Fatal("expected service with 71.4% coverage and missing shadow replica to be ineligible")
	}
}
