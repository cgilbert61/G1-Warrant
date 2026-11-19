package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/fleetsim"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
	"gopkg.in/yaml.v3"
)

// CiliumShieldAdapter compiles declarative CiliumNetworkPolicy, NetworkPolicy, and Envoy mTLS
// manifests and applies/retires them over HTTP against the target cluster.
type CiliumShieldAdapter struct {
	fleetBaseURL string
	httpClient   *http.Client
}

// NewCiliumShieldAdapter constructs a CiliumShieldAdapter targeting fleetBaseURL.
func NewCiliumShieldAdapter(fleetBaseURL string) *CiliumShieldAdapter {
	return &CiliumShieldAdapter{
		fleetBaseURL: fleetBaseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *CiliumShieldAdapter) CompileAndApplyBridge(ctx context.Context, req BridgeApplyRequest) (*models.ContainmentBridge, error) {
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	if req.AffectedPort <= 0 {
		req.AffectedPort = 8080
	}
	if len(req.BlockedPaths) == 0 {
		req.BlockedPaths = []string{"/api/v1/debug", "/.."}
	}

	// 1. Declarative CiliumNetworkPolicy (cilium.io/v2)
	ciliumDoc := map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"name":      fmt.Sprintf("g1-shield-%s", req.BridgeID),
			"namespace": req.Namespace,
			"labels": map[string]string{
				"g1.warrant/bridge-id":      req.BridgeID,
				"g1.warrant/remediation-id": req.RemediationID,
				"g1.warrant/cve":            req.CVEID,
				"g1.warrant/managed-by":     "warrantd",
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
					"toPorts": []map[string]any{
						{
							"ports": []map[string]string{
								{"port": strconv.Itoa(req.AffectedPort), "protocol": "TCP"},
							},
							"rules": map[string]any{
								"http": []map[string]string{
									{"method": "GET", "path": "^/healthz$"},
									{"method": "POST", "path": "^/api/v2/safe/.*$"},
								},
							},
						},
					},
				},
			},
			"egressDeny": []map[string]any{
				{
					"toEntities": []string{"world"},
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

	// 3. Edge Envoy HTTP RBAC + SPIFFE mTLS filter config
	envoyDoc := map[string]any{
		"filter_name": "envoy.filters.http.rbac",
		"typed_config": map[string]any{
			"@type": "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC",
			"shadow_rules_stat_prefix": "g1_shield_",
			"rules": map[string]any{
				"action": "DENY",
				"policies": map[string]any{
					fmt.Sprintf("block-%s-%s", req.CVEID, req.ExploitVector): map[string]any{
						"permissions": []map[string]any{
							{"blocked_paths": req.BlockedPaths},
						},
						"principals": []map[string]any{
							{"any": true},
						},
					},
				},
			},
			"mtls_spiffe_required": fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/*", req.Namespace),
		},
	}
	envoyCanon, err := crypto.CanonicalizeStruct(envoyDoc)
	if err != nil {
		return nil, err
	}

	status := "ARMED"
	if req.RearmCount > 0 {
		status = "REARMED_DRIFT"
	}
	bridgeType := "CILIUM_L7_NETPOL"
	if req.ExploitVector == "TLS_HEARTBEAT" {
		bridgeType = "ENVOY_MTLS_WAF"
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
		BridgeID:           req.BridgeID,
		RemediationID:      req.RemediationID,
		ServiceID:          req.ServiceID,
		CVEID:              req.CVEID,
		BridgeType:         bridgeType,
		Status:             status,
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
