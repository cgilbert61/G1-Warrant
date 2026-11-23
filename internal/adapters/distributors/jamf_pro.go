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

// JamfProTranslator translates DeploymentOrders into Jamf Pro Patch Policies / Software Update Plans
// scoped to static target computer groups (SupportsNativeRings: false -> wave-sequenced by N2).
type JamfProTranslator struct {
	baseHTTPDistributor
}

func NewJamfProTranslator(baseURL, token string, rt http.RoundTripper) *JamfProTranslator {
	return &JamfProTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorJamfPro,
			"Jamf Pro macOS Patch Policy & DDM Software Update",
			"APPLE_ESTATE",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     false,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"MACOS"},
				DefaultRollbackStrategy: "JAMF_POLICY_DISABLE_AND_PKG_REVERT",
			},
			rt,
		),
	}
}

func (j *JamfProTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &JamfProTranslator{baseHTTPDistributor: j.cloneWithTransport(rt)}
}

func (j *JamfProTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("jamf-policy-w%d-%s", max(1, order.WaveNumber), order.OrderID)
	j.recordLocalOrder(jobRef, order)
	if j.EndpointConfigured() {
		serials := make([]string, 0, len(order.TargetAssets))
		for _, t := range order.TargetAssets {
			serials = append(serials, firstNonEmpty(t.NativeDeviceID, t.AssetKey))
		}
		raw, err := j.doJSON(ctx, http.MethodPost, "/api/v2/patch-policies", map[string]any{
			"orderId":        order.OrderID,
			"warrantId":      order.WarrantID,
			"waveNumber":     order.WaveNumber,
			"cveId":          order.FixIdentity.CVEID,
			"targetVersion":  firstNonEmpty(order.FixIdentity.PackageNEVRA, order.FixIdentity.AdvisoryID),
			"scopedDevices":  serials,
			"enabled":        true,
		})
		if err != nil {
			return nil, err
		}
		var resp struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.ID != "" {
			jobRef = resp.ID
			j.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        j.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  false,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (j *JamfProTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !j.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&j.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := j.doJSON(ctx, http.MethodGet, fmt.Sprintf("/api/v2/patch-policies/%s/logs?order_id=%s", nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(j.DistributorID(), orderID, nativeJobRef, j.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return buildSimulatedPerAssetResult(&j.baseHTTPDistributor, orderID, nativeJobRef, false, "").AssetResults, models.EvidenceGranularityPerAsset, false, nil
	})
}

func (j *JamfProTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if !j.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&j.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
	}
	raw, err := j.doJSON(ctx, http.MethodPost, fmt.Sprintf("/api/v2/patch-policies/%s/revert", nativeJobRef), map[string]any{
		"orderId":             order.OrderID,
		"rollbackPolicyId":    order.RollbackInstruction.RollbackPlaybookID,
		"previousPackage":     order.RollbackInstruction.PreviousPackageNEVRA,
		"reason":              reason,
	})
	if err != nil {
		return nil, err
	}
	res, err := parseVendorPollResponse(j.DistributorID(), order.OrderID, nativeJobRef, j.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return buildSimulatedPerAssetResult(&j.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason).AssetResults, models.EvidenceGranularityPerAsset, false, nil
	})
	if err != nil {
		return nil, err
	}
	res.IsRollback = true
	res.RollbackReason = reason
	res.RecomputeCounts()
	return res, nil
}
