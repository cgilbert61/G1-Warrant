package gate

import (
	"strings"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

const (
	RiskLevelLow      = "LOW"
	RiskLevelMedium   = "MEDIUM"
	RiskLevelHigh     = "HIGH"
	RiskLevelCritical = "CRITICAL"
)

// QueueRiskAssessment provides a deterministic 0-100 triage risk score with human-readable
// reasons for TIER_3_CONTAIN_AND_CAB and UNBOUND containment approval queues.
type QueueRiskAssessment struct {
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
}

var chainedCWEBonus = map[string]bool{
	"CWE-22":  true,
	"CWE-98":  true,
	"CWE-209": true,
	"CWE-287": true,
	"CWE-347": true,
	"CWE-434": true,
	"CWE-611": true,
	"CWE-639": true,
	"CWE-863": true,
	"CWE-918": true,
}

// ScoreQueueItemRisk deterministically scores a pending CAB or UNBOUND remediation item (0-100)
// using CVSS, CISA KEV status, chained-exploit CWEs, blast-radius reachability, and containment posture.
func ScoreQueueItemRisk(item models.RemediationItem, reach *ReachabilitySubgraph) QueueRiskAssessment {
	score := 0
	reasons := make([]string, 0, 6)

	switch {
	case item.CVSSScore >= 9.0:
		score += 35
		reasons = append(reasons, "CVSS_CRITICAL_GE_9_0")
	case item.CVSSScore >= 7.0:
		score += 25
		reasons = append(reasons, "CVSS_HIGH_GE_7_0")
	case item.CVSSScore >= 4.0:
		score += 12
		reasons = append(reasons, "CVSS_MEDIUM_GE_4_0")
	}

	if item.IsKEV {
		score += 25
		reasons = append(reasons, "CISA_KEV_ACTIVE_EXPLOITATION")
	}

	cwe := strings.ToUpper(strings.TrimSpace(item.CWEID))
	if chainedCWEBonus[cwe] {
		score += 15
		reasons = append(reasons, "CHAINED_EXPLOIT_CWE_"+cwe)
	}

	if item.BridgeID == "" {
		score += 15
		reasons = append(reasons, "NO_ACTIVE_CONTAINMENT_BRIDGE")
	}

	if reach != nil {
		if reach.CrownJewelReachable {
			score += 15
			reasons = append(reasons, "CROWN_JEWEL_REACHABLE")
		} else if reach.ChokepointScore >= 40 {
			score += 8
			reasons = append(reasons, "HIGH_BLAST_RADIUS_CHOKEPOINT")
		}
	}

	if score > 100 {
		score = 100
	}

	level := RiskLevelLow
	switch {
	case score >= 80:
		level = RiskLevelCritical
	case score >= 55:
		level = RiskLevelHigh
	case score >= 30:
		level = RiskLevelMedium
	}

	return QueueRiskAssessment{
		Score:   score,
		Level:   level,
		Reasons: reasons,
	}
}
