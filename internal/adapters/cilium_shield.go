package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"gopkg.in/yaml.v3"
)

// CiliumShieldAdapter compiles declarative containment policies in two distinct safety modes:
//   1. ZERO_PROSE_EGRESS_MESH_QUARANTINE (Default when warrant-extractor strips prose and no signed L7 rulepack exists):
//      Enforces L3/L4 internet egress cut (stopping reverse shells, JNDI callbacks, and C2) + strict mTLS peer ingress
//      WITHOUT guessing application HTTP routes or causing blind L7 outages.
//   2. SIGNED_RULEPACK_L7_SHIELD (When a publisher-signed CWE/CVE rulepack matches in RulepackRegistry):
//      Enforces targeted Envoy/Cilium L7 HTTP path/header deny rules alongside internet egress denial.
type CiliumShieldAdapter struct {
	fleetBaseURL string
	httpClient   *http.Client
	rulepacks    *RulepackRegistry
}

// NewCiliumShieldAdapter constructs a CiliumShieldAdapter with a verified RulepackRegistry.
func NewCiliumShieldAdapter(fleetBaseURL string, rulepacks ...*RulepackRegistry) *CiliumShieldAdapter {
	var reg *RulepackRegistry
	if len(rulepacks) > 0 && rulepacks[0] != nil {
		reg = rulepacks[0]
	} else {
		reg = NewDefaultRulepackRegistry()
	}
	return &CiliumShieldAdapter{
		fleetBaseURL: fleetBaseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		rulepacks: reg,
	}
}

// Rulepacks exposes the verified publisher-signed rulepack registry.
func (c *CiliumShieldAdapter) Rulepacks() *RulepackRegistry {
	return c.rulepacks
}

func (c *CiliumShieldAdapter) CompileAndApplyBridge(ctx context.Context, req BridgeApplyRequest) (*models.ContainmentBridge, error) {
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	if req.AffectedPort <= 0 {
		req.AffectedPort = 8080
	}
	allowedPeers := req.AllowedEgressServices
	if len(allowedPeers) == 0 {
		allowedPeers = []string{"kube-dns.kube-system.svc.cluster.local"}
	}
	metadataCIDRs := []string{"169.254.169.254/32", "169.254.170.2/32", "fd00:ec2::254/128"}
	allowKubeAPI := req.AllowKubeAPIServerEgress
	for _, peer := range allowedPeers {
		pLow := strings.ToLower(strings.TrimSpace(peer))
		if pLow == "kube-apiserver" || pLow == "kubernetes.default.svc" || pLow == "kubernetes.default.svc.cluster.local" {
			allowKubeAPI = true
			break
		}
	}
	deniedEntities := []string{"world"}
	if !allowKubeAPI {
		deniedEntities = append(deniedEntities, "kube-apiserver")
	}

	matchedRP := c.rulepacks.Lookup(req.CVEID, req.CWEID, req.ExploitVector)
	containmentMode := models.ContainmentModeZeroProseQuarantine
	rulepackID := ""
	bridgeType := "K8S_NETPOL"
	var blockedPaths []string

	if matchedRP != nil {
		containmentMode = models.ContainmentModeSignedRulepackL7
		rulepackID = matchedRP.RulepackID
		blockedPaths = matchedRP.BlockedPaths
		bridgeType = "CILIUM_L7_NETPOL"
		if matchedRP.ExploitVector == "TLS_HEARTBEAT" {
			bridgeType = "ENVOY_MTLS_WAF"
		}
	}

	// 1. Declarative CiliumNetworkPolicy (cilium.io/v2)
	// In ZERO_PROSE_EGRESS_MESH_QUARANTINE mode, we NEVER invent HTTP path allowlists that break business traffic;
	// instead we restrict ingress to authenticated cluster mesh entities and cut external world egress.
	ingressPortSpec := map[string]any{
		"ports": []map[string]string{
			{"port": strconv.Itoa(req.AffectedPort), "protocol": "TCP"},
		},
	}
	if containmentMode == models.ContainmentModeSignedRulepackL7 && len(blockedPaths) > 0 {
		// Apply L7 inspection only when backed by a verified publisher-signed rulepack
		ingressPortSpec["rules"] = map[string]any{
			"http": []map[string]any{
				{"headers": []string{"X-G1-Signed-Rulepack: " + rulepackID}},
			},
		}
	}

	ciliumDoc := map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"name":      fmt.Sprintf("g1-shield-%s", req.BridgeID),
			"namespace": req.Namespace,
			"labels": map[string]string{
				"g1.warrant/bridge-id":        req.BridgeID,
				"g1.warrant/remediation-id":   req.RemediationID,
				"g1.warrant/cve":              req.CVEID,
				"g1.warrant/containment-mode": containmentMode,
				"g1.warrant/rulepack-id":      rulepackID,
				"g1.warrant/managed-by":       "warrantd",
			},
		},
		"spec": map[string]any{
			"endpointSelector": map[string]any{
				"matchLabels": map[string]string{
					"app.kubernetes.io/name": req.ServiceID,
				},
			},
			"ingress": []map[string]any{
				{
					"fromEntities": []string{"cluster"},
					"toPorts":      []map[string]any{ingressPortSpec},
				},
			},
			"egress": []map[string]any{
				{
					"toEndpoints": []map[string]any{
						{
							"matchLabels": map[string]string{
								"io.kubernetes.pod.namespace": req.Namespace,
							},
						},
						{
							"matchLabels": map[string]string{
								"io.kubernetes.pod.namespace": "kube-system",
								"k8s-app":                     "kube-dns",
							},
						},
					},
				},
			},
			"egressDeny": []map[string]any{
				{
					"toEntities": deniedEntities,
				},
				{
					"toCIDR": metadataCIDRs,
				},
			},
		},
	}
	ciliumYAMLBytes, err := yaml.Marshal(ciliumDoc)
	if err != nil {
		return nil, fmt.Errorf("marshal CiliumNetworkPolicy YAML: %w", err)
	}

	// 2. Standard Kubernetes NetworkPolicy (networking.k8s.io/v1)
	k8sDoc := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name":      fmt.Sprintf("g1-netpol-%s", req.BridgeID),
			"namespace": req.Namespace,
			"annotations": map[string]string{
				"g1.warrant/blocked-metadata-cidrs": "169.254.169.254/32,169.254.170.2/32,fd00:ec2::254/128",
			},
		},
		"spec": map[string]any{
			"podSelector": map[string]any{
				"matchLabels": map[string]string{
					"app.kubernetes.io/name": req.ServiceID,
				},
			},
			"policyTypes": []string{"Ingress", "Egress"},
			"ingress": []map[string]any{
				{
					"from": []map[string]any{
						{
							"namespaceSelector": map[string]any{
								"matchLabels": map[string]string{"g1.warrant/trusted-mesh": "true"},
							},
						},
					},
				},
			},
			"egress": []map[string]any{
				{
					"to": []map[string]any{
						{
							"namespaceSelector": map[string]any{
								"matchLabels": map[string]string{"kubernetes.io/metadata.name": req.Namespace},
							},
						},
					},
				},
			},
		},
	}
	k8sYAMLBytes, err := yaml.Marshal(k8sDoc)
	if err != nil {
		return nil, fmt.Errorf("marshal NetworkPolicy YAML: %w", err)
	}

	// 3. Edge Envoy filter config (SPIFFE mTLS peer enforcement + metadata/callback severance + optional signed L7 rulepack)
	envoyRules := map[string]any{
		"mode":                    containmentMode,
		"mtls_spiffe_required":    fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/*", req.Namespace),
		"blocked_metadata_cidrs":  metadataCIDRs,
		"allowed_internal_egress": allowedPeers,
	}
	if containmentMode == models.ContainmentModeSignedRulepackL7 {
		envoyRules["signed_rulepack_id"] = rulepackID
		envoyRules["deny_paths"] = blockedPaths
	}
	envoyDoc := map[string]any{
		"filter_name":  "envoy.filters.http.rbac",
		"typed_config": envoyRules,
	}
	envoyCanon, err := crypto.CanonicalizeStruct(envoyDoc)
	if err != nil {
		return nil, err
	}

	status := "ARMED"
	if req.RearmCount > 0 {
		status = "REARMED_DRIFT"
	}

	now := time.Now().UTC()
	payload := fleetsim.BridgePolicyState{
		BridgeID:           req.BridgeID,
		ServiceID:          req.ServiceID,
		CVEID:              req.CVEID,
		CiliumManifestYAML: string(ciliumYAMLBytes),
		K8sNetpolYAML:      string(k8sYAMLBytes),
		EnvoyFilterJSON:    string(envoyCanon),
		AppliedAt:          now,
	}
	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.fleetBaseURL+"/v1/cilium/bridges", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("apply cilium bridge on cluster: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cluster rejected cilium bridge with HTTP %d", resp.StatusCode)
	}

	return &models.ContainmentBridge{
		BridgeID:             req.BridgeID,
		RemediationID:        req.RemediationID,
		ServiceID:            req.ServiceID,
		CVEID:                req.CVEID,
		BridgeType:           bridgeType,
		ContainmentMode:      containmentMode,
		RulepackID:           rulepackID,
		MetadataPlaneBlocked: true,
		AllowedEgressPeers:   allowedPeers,
		Status:               status,
		SLABridgeMinutes:   req.SLABridgeMinutes,
		BlockerReasonCode:  req.BlockerReasonCode,
		CiliumManifestYAML: string(ciliumYAMLBytes),
		K8sNetpolYAML:      string(k8sYAMLBytes),
		EnvoyFilterJSON:    string(envoyCanon),
		ArmedAt:            now,
		RearmedCount:       req.RearmCount,
	}, nil
}

func (c *CiliumShieldAdapter) RetireBridge(ctx context.Context, bridgeID string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.fleetBaseURL+"/v1/cilium/bridges/"+bridgeID, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("retire cilium bridge %s: %w", bridgeID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("cluster failed retiring bridge %s: HTTP %d", bridgeID, resp.StatusCode)
	}
	return nil
}
