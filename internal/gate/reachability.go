package gate

import (
	"sort"
	"strings"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// ReachabilitySubgraph summarizes an ephemeral, per-incident multi-hop reachability analysis
// computed from EstateService egress declarations without replicating a persistent CMDB graph in PostgreSQL.
type ReachabilitySubgraph struct {
	RootServiceID       string   `json:"root_service_id"`
	DirectNeighbors     []string `json:"direct_neighbors,omitempty"`
	ReachableServices   []string `json:"reachable_services,omitempty"`
	MaxHopDepth         int      `json:"max_hop_depth"`
	CrownJewelReachable bool     `json:"crown_jewel_reachable"`
	ChokepointScore     int      `json:"chokepoint_score"` // 0-100 deterministic blast-radius score
}

// ComputeEphemeralReachabilitySubgraph performs a deterministic BFS over EstateService.AllowedEgressServices
// starting from rootServiceID (bounded to maxHops, default 4) to quantify multi-hop lateral-movement blast radius.
func ComputeEphemeralReachabilitySubgraph(rootServiceID string, services []models.EstateService, maxHops int) ReachabilitySubgraph {
	if maxHops <= 0 {
		maxHops = 4
	}
	byID := make(map[string]models.EstateService, len(services))
	adj := make(map[string][]string, len(services))
	for _, s := range services {
		id := strings.TrimSpace(s.ServiceID)
		if id == "" {
			continue
		}
		byID[id] = s
		for _, peer := range s.AllowedEgressServices {
			p := normalizePeerServiceID(peer)
			if p != "" && p != id {
				adj[id] = append(adj[id], p)
			}
		}
	}

	root := strings.TrimSpace(rootServiceID)
	res := ReachabilitySubgraph{RootServiceID: root}
	if root == "" {
		return res
	}

	type qItem struct {
		id    string
		depth int
	}
	visited := map[string]bool{root: true}
	queue := []qItem{{id: root, depth: 0}}
	directSet := map[string]bool{}
	reachSet := map[string]bool{}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth > res.MaxHopDepth {
			res.MaxHopDepth = cur.depth
		}
		if cur.depth >= maxHops {
			continue
		}
		for _, next := range adj[cur.id] {
			if cur.depth == 0 {
				directSet[next] = true
			}
			if visited[next] {
				continue
			}
			visited[next] = true
			reachSet[next] = true
			if isCrownJewelService(next, byID[next]) {
				res.CrownJewelReachable = true
			}
			queue = append(queue, qItem{id: next, depth: cur.depth + 1})
		}
	}

	for k := range directSet {
		res.DirectNeighbors = append(res.DirectNeighbors, k)
	}
	sort.Strings(res.DirectNeighbors)

	for k := range reachSet {
		res.ReachableServices = append(res.ReachableServices, k)
	}
	sort.Strings(res.ReachableServices)

	score := len(res.DirectNeighbors)*12 + len(res.ReachableServices)*8 + res.MaxHopDepth*6
	if res.CrownJewelReachable {
		score += 30
	}
	if score > 100 {
		score = 100
	}
	res.ChokepointScore = score
	return res
}

func normalizePeerServiceID(peer string) string {
	p := strings.TrimSpace(peer)
	if p == "" {
		return ""
	}
	if idx := strings.IndexByte(p, '.'); idx > 0 {
		return p[:idx]
	}
	return p
}

func isCrownJewelService(id string, svc models.EstateService) bool {
	low := strings.ToLower(id + " " + svc.Namespace)
	for _, kw := range []string{"db", "postgres", "vault", "kms", "auth", "iam", "ledger", "payment", "secret", "kube-apiserver"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}
