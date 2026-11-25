package verify

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	RetestVerdictStillFixed   = "RETEST_STILL_FIXED"
	RetestVerdictRegressed    = "RETEST_REGRESSED"
	RetestVerdictInconclusive = "RETEST_INCONCLUSIVE"
)

// RegressionRetestRequest defines a deterministic post-closure regression retest for an attested remediation.
type RegressionRetestRequest struct {
	RemediationID string
	AttestationID string
	ServiceID     string
	CVEID         string
	PatchedDigest string
}

// RegressionRetestResult captures the deterministic verdict of a post-closure regression check.
// Following ARTEX's retester principle: a service MUST pass a working normal control before
// a blocked exploit probe is accepted as RETEST_STILL_FIXED (preventing false "fixed" verdicts
// when a service is simply down or returning 500s).
type RegressionRetestResult struct {
	RemediationID          string    `json:"remediation_id"`
	AttestationID          string    `json:"attestation_id"`
	ServiceID              string    `json:"service_id"`
	CVEID                  string    `json:"cve_id"`
	CheckedAt              time.Time `json:"checked_at"`
	NormalControlPassed    bool      `json:"normal_control_passed"`
	NormalControlDetail    string    `json:"normal_control_detail,omitempty"`
	NegativeControlBlocked bool      `json:"negative_control_blocked"`
	NegativeControlDetail  string    `json:"negative_control_detail,omitempty"`
	Verdict                string    `json:"verdict"`
	ShouldRearmContainment bool      `json:"should_rearm_containment"`
	ShouldReopenItem       bool      `json:"should_reopen_item"`
}

// RegressionProbeFunc executes a deterministic probe and returns (passed, detail, err).
type RegressionProbeFunc func(ctx context.Context, req RegressionRetestRequest) (bool, string, error)

// RunDeterministicRegressionRetest runs a normal control followed by a negative exploit control.
// - If negative control detects exploitability (blocked == false): RETEST_REGRESSED -> re-arm containment & re-open.
// - If normal control fails or errors: RETEST_INCONCLUSIVE (never falsely declare fixed).
// - Only when normal control passes AND negative control is blocked: RETEST_STILL_FIXED.
func RunDeterministicRegressionRetest(
	ctx context.Context,
	req RegressionRetestRequest,
	normalControl RegressionProbeFunc,
	negativeControl RegressionProbeFunc,
) RegressionRetestResult {
	res := RegressionRetestResult{
		RemediationID: strings.TrimSpace(req.RemediationID),
		AttestationID: strings.TrimSpace(req.AttestationID),
		ServiceID:     strings.TrimSpace(req.ServiceID),
		CVEID:         strings.TrimSpace(req.CVEID),
		CheckedAt:     time.Now().UTC(),
		Verdict:       RetestVerdictInconclusive,
	}

	if normalControl == nil || negativeControl == nil {
		res.NormalControlDetail = "missing required normal or negative control probe"
		return res
	}

	normOK, normDetail, normErr := normalControl(ctx, req)
	res.NormalControlPassed = normOK && normErr == nil
	if normErr != nil {
		res.NormalControlDetail = fmt.Sprintf("normal control error: %v", normErr)
	} else {
		res.NormalControlDetail = normDetail
	}

	negBlocked, negDetail, negErr := negativeControl(ctx, req)
	res.NegativeControlBlocked = negBlocked && negErr == nil
	if negErr != nil {
		res.NegativeControlDetail = fmt.Sprintf("negative control error: %v", negErr)
		res.Verdict = RetestVerdictInconclusive
		return res
	}
	res.NegativeControlDetail = negDetail

	// Regression takes highest priority even if normal control is degraded.
	if !negBlocked {
		res.Verdict = RetestVerdictRegressed
		res.ShouldRearmContainment = true
		res.ShouldReopenItem = true
		return res
	}

	// Refuse to conclude STILL_FIXED if normal control failed (service down/broken != fixed).
	if !res.NormalControlPassed {
		res.Verdict = RetestVerdictInconclusive
		return res
	}

	res.Verdict = RetestVerdictStillFixed
	return res
}
