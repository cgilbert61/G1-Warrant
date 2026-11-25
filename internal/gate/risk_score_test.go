package gate

import (
	"testing"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

func TestScoreQueueItemRiskDeterministicTiers(t *testing.T) {
	crit := ScoreQueueItemRisk(models.RemediationItem{
		CVSSScore: 9.8,
		IsKEV:     true,
		CWEID:     "CWE-918",
		BridgeID:  "",
	}, &ReachabilitySubgraph{CrownJewelReachable: true, ChokepointScore: 80})
	if crit.Level != RiskLevelCritical || crit.Score < 80 {
		t.Fatalf("expected CRITICAL >= 80, got %+v", crit)
	}

	low := ScoreQueueItemRisk(models.RemediationItem{
		CVSSScore: 3.1,
		IsKEV:     false,
		CWEID:     "CWE-1104",
		BridgeID:  "brg-1",
	}, &ReachabilitySubgraph{CrownJewelReachable: false, ChokepointScore: 10})
	if low.Level != RiskLevelLow || low.Score >= 30 {
		t.Fatalf("expected LOW < 30, got %+v", low)
	}
}
