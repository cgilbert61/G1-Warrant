package gate

import (
	"testing"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

func TestComputeEphemeralReachabilitySubgraphMultiHopAndCrownJewel(t *testing.T) {
	estate := []models.EstateService{
		{ServiceID: "edge-gateway", Namespace: "prod", AllowedEgressServices: []string{"checkout-api.prod.svc.cluster.local"}},
		{ServiceID: "checkout-api", Namespace: "prod", AllowedEgressServices: []string{"ledger-service", "metrics-sink"}},
		{ServiceID: "ledger-service", Namespace: "prod", AllowedEgressServices: []string{"postgres-primary"}},
		{ServiceID: "isolated-worker", Namespace: "batch", AllowedEgressServices: []string{"kube-dns.kube-system.svc.cluster.local"}},
	}

	edgeSub := ComputeEphemeralReachabilitySubgraph("edge-gateway", estate, 4)
	if !edgeSub.CrownJewelReachable {
		t.Fatalf("expected edge-gateway to reach crown-jewel ledger/postgres, got %+v", edgeSub)
	}
	if edgeSub.MaxHopDepth != 3 {
		t.Fatalf("expected MaxHopDepth=3, got %d", edgeSub.MaxHopDepth)
	}
	if len(edgeSub.ReachableServices) != 4 {
		t.Fatalf("expected 4 reachable services, got %v", edgeSub.ReachableServices)
	}

	isoSub := ComputeEphemeralReachabilitySubgraph("isolated-worker", estate, 4)
	if isoSub.CrownJewelReachable {
		t.Fatalf("expected isolated-worker NOT to reach crown jewel")
	}
	if edgeSub.ChokepointScore <= isoSub.ChokepointScore {
		t.Fatalf("expected edge-gateway chokepoint score (%d) > isolated-worker (%d)", edgeSub.ChokepointScore, isoSub.ChokepointScore)
	}
}
