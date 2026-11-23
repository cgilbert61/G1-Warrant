package distributors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// MultiPlatformHTTPTranslator implements the identical DeploymentOrder -> DeploymentResult + ExecuteRollback
// contract for cross-platform enterprise endpoint patchers (Tanium Patch, Ivanti Neurons, Automox).
type MultiPlatformHTTPTranslator struct {
	baseHTTPDistributor
	dispatchPath string
	pollPathFmt  string
	rollbackPath string
}

func NewTaniumPatchTranslator(baseURL, token string, rt http.RoundTripper) *MultiPlatformHTTPTranslator {
	return &MultiPlatformHTTPTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorTaniumPatch,
			"Tanium Patch Ring Deployment",
			"MULTIPLATFORM_PATCH",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     true,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"WINDOWS", "LINUX_RPM", "LINUX_DEB", "MACOS"},
				DefaultRollbackStrategy: "TANIUM_PATCH_UNINSTALL_ACTION",
			},
			rt,
		),
		dispatchPath: "/plugin/products/patch/v2/deployments",
		pollPathFmt:  "/plugin/products/patch/v2/deployments/%s/endpoints?order_id=%s",
		rollbackPath: "/plugin/products/patch/v2/deployments/rollback",
	}
}

func NewIvantiNeuronsTranslator(baseURL, token string, rt http.RoundTripper) *MultiPlatformHTTPTranslator {
	return &MultiPlatformHTTPTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorIvantiNeurons,
			"Ivanti Neurons for Patch Management",
			"MULTIPLATFORM_PATCH",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     true,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"WINDOWS", "LINUX_RPM", "LINUX_DEB", "MACOS"},
				DefaultRollbackStrategy: "IVANTI_ROLLBACK_PACKAGE_BUNDLE",
			},
			rt,
		),
		dispatchPath: "/api/patch/v1/deployments",
		pollPathFmt:  "/api/patch/v1/deployments/%s/devices?order_id=%s",
		rollbackPath: "/api/patch/v1/deployments/rollback",
	}
}

func NewAutomoxTranslator(baseURL, token string, rt http.RoundTripper) *MultiPlatformHTTPTranslator {
	return &MultiPlatformHTTPTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorAutomox,
			"Automox Patch & Worklet Automation",
			"MULTIPLATFORM_PATCH",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     false,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"WINDOWS", "LINUX_RPM", "LINUX_DEB", "MACOS"},
				DefaultRollbackStrategy: "AUTOMOX_REMEDIATION_WORKLET_REVERT",
			},
			rt,
		),
		dispatchPath: "/api/policies/execute",
		pollPathFmt:  "/api/events?job_ref=%s&order_id=%s",
		rollbackPath: "/api/worklets/rollback",
	}
}

func (m *MultiPlatformHTTPTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &MultiPlatformHTTPTranslator{
		baseHTTPDistributor: m.cloneWithTransport(rt),
		dispatchPath:        m.dispatchPath,
		pollPathFmt:         m.pollPathFmt,
		rollbackPath:        m.rollbackPath,
	}
}

func (m *MultiPlatformHTTPTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("%s-w%d-%s", m.id, max(1, order.WaveNumber), order.OrderID)
	m.recordLocalOrder(jobRef, order)
	if m.EndpointConfigured() {
		raw, err := m.doJSON(ctx, http.MethodPost, m.dispatchPath, order)
		if err != nil {
			return nil, err
		}
		var resp struct {
			JobID string `json:"job_id"`
			ID    string `json:"id"`
		}
		if json.Unmarshal(raw, &resp) == nil {
			if id := firstNonEmpty(resp.JobID, resp.ID); id != "" {
				jobRef = id
				m.recordLocalOrder(jobRef, order)
			}
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        m.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  m.caps.SupportsNativeRings,
		ReportsPerAssetState: m.caps.ReportsPerAssetState,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (m *MultiPlatformHTTPTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !m.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&m.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := m.doJSON(ctx, http.MethodGet, fmt.Sprintf(m.pollPathFmt, nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(m.DistributorID(), orderID, nativeJobRef, m.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return buildSimulatedPerAssetResult(&m.baseHTTPDistributor, orderID, nativeJobRef, false, "").AssetResults, models.EvidenceGranularityPerAsset, false, nil
	})
}

func (m *MultiPlatformHTTPTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if !m.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&m.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
	}
	raw, err := m.doJSON(ctx, http.MethodPost, m.rollbackPath, map[string]any{
		"order_id":             order.OrderID,
		"native_job_ref":       nativeJobRef,
		"rollback_instruction": order.RollbackInstruction,
		"reason":               reason,
	})
	if err != nil {
		return nil, err
	}
	res, err := parseVendorPollResponse(m.DistributorID(), order.OrderID, nativeJobRef, m.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return buildSimulatedPerAssetResult(&m.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason).AssetResults, models.EvidenceGranularityPerAsset, false, nil
	})
	if err != nil {
		return nil, err
	}
	res.IsRollback = true
	res.RollbackReason = reason
	res.RecomputeCounts()
	return res, nil
}
