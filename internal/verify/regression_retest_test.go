package verify

import (
	"context"
	"errors"
	"testing"
)

func TestRunDeterministicRegressionRetestVerdicts(t *testing.T) {
	req := RegressionRetestRequest{
		RemediationID: "rem-100",
		AttestationID: "att-100",
		ServiceID:     "payments-api",
		CVEID:         "CVE-2026-1000",
	}

	// 1. Healthy normal control + blocked negative control -> RETEST_STILL_FIXED
	fixed := RunDeterministicRegressionRetest(
		context.Background(),
		req,
		func(context.Context, RegressionRetestRequest) (bool, string, error) { return true, "HTTP 200 /healthz", nil },
		func(context.Context, RegressionRetestRequest) (bool, string, error) { return true, "HTTP 403 EXPLOIT_BLOCKED", nil },
	)
	if fixed.Verdict != RetestVerdictStillFixed || fixed.ShouldRearmContainment || fixed.ShouldReopenItem {
		t.Fatalf("expected RETEST_STILL_FIXED, got %+v", fixed)
	}

	// 2. Broken normal control + blocked negative control -> RETEST_INCONCLUSIVE (never falsely fixed!)
	inconc := RunDeterministicRegressionRetest(
		context.Background(),
		req,
		func(context.Context, RegressionRetestRequest) (bool, string, error) { return false, "HTTP 503", nil },
		func(context.Context, RegressionRetestRequest) (bool, string, error) { return true, "connection refused", nil },
	)
	if inconc.Verdict != RetestVerdictInconclusive || inconc.ShouldRearmContainment {
		t.Fatalf("expected RETEST_INCONCLUSIVE when normal control fails, got %+v", inconc)
	}

	// 3. Negative control NOT blocked (exploit succeeded again!) -> RETEST_REGRESSED + re-arm containment
	regressed := RunDeterministicRegressionRetest(
		context.Background(),
		req,
		func(context.Context, RegressionRetestRequest) (bool, string, error) { return true, "HTTP 200", nil },
		func(context.Context, RegressionRetestRequest) (bool, string, error) { return false, "EXPLOIT_SUCCEEDED", nil },
	)
	if regressed.Verdict != RetestVerdictRegressed || !regressed.ShouldRearmContainment || !regressed.ShouldReopenItem {
		t.Fatalf("expected RETEST_REGRESSED with rearm & reopen, got %+v", regressed)
	}

	// 4. Negative control probe error -> RETEST_INCONCLUSIVE
	errRes := RunDeterministicRegressionRetest(
		context.Background(),
		req,
		func(context.Context, RegressionRetestRequest) (bool, string, error) { return true, "ok", nil },
		func(context.Context, RegressionRetestRequest) (bool, string, error) { return false, "", errors.New("timeout") },
	)
	if errRes.Verdict != RetestVerdictInconclusive {
		t.Fatalf("expected RETEST_INCONCLUSIVE on probe error, got %+v", errRes)
	}
}
