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

// AWSSSMTranslator translates DeploymentOrders into AWS Systems Manager Patch Manager (AWS-RunPatchBaseline)
// rate-controlled commands + ListCommandInvocations per-instance status.
type AWSSSMTranslator struct {
	baseHTTPDistributor
}

func NewAWSSSMTranslator(baseURL, token string, rt http.RoundTripper) *AWSSSMTranslator {
	return &AWSSSMTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorAWSSSM,
			"AWS Systems Manager Patch Manager (SSM)",
			"CLOUD_PATCHERS",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     true,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"LINUX_RPM", "LINUX_DEB", "WINDOWS"},
				DefaultRollbackStrategy: "SSM_ROLLBACK_DOCUMENT_EXECUTION",
			},
			rt,
		),
	}
}

func (s *AWSSSMTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &AWSSSMTranslator{baseHTTPDistributor: s.cloneWithTransport(rt)}
}

func (s *AWSSSMTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("ssm-cmd-%s", order.OrderID)
	s.recordLocalOrder(jobRef, order)
	if s.EndpointConfigured() {
		instanceIDs := make([]string, 0, len(order.TargetAssets))
		for _, t := range order.TargetAssets {
			instanceIDs = append(instanceIDs, firstNonEmpty(t.NativeDeviceID, t.AssetKey))
		}
		maxErrPct := fmt.Sprintf("%.0f%%", max(1.0, order.RolloutPlan.MaxFailureRatePct))
		raw, err := s.doJSON(ctx, http.MethodPost, "/ssm/SendCommand", map[string]any{
			"DocumentName":   "AWS-RunPatchBaseline",
			"InstanceIds":    instanceIDs,
			"MaxConcurrency": "25%",
			"MaxErrors":      maxErrPct,
			"Parameters": map[string][]string{
				"Operation":  {"Install"},
				"RebootOption": {"RebootIfNeeded"},
				"CVEID":      {order.FixIdentity.CVEID},
				"OrderID":    {order.OrderID},
			},
		})
		if err != nil {
			return nil, err
		}
		var resp struct {
			Command struct {
				CommandID string `json:"CommandId"`
			} `json:"Command"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.Command.CommandID != "" {
			jobRef = resp.Command.CommandID
			s.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        s.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  true,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (s *AWSSSMTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !s.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&s.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := s.doJSON(ctx, http.MethodGet, fmt.Sprintf("/ssm/ListCommandInvocations?CommandId=%s&order_id=%s", nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(s.DistributorID(), orderID, nativeJobRef, s.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		var ssmResp struct {
			Stalled            bool `json:"stalled"`
			CommandInvocations []struct {
				InstanceID    string `json:"InstanceId"`
				InstanceName  string `json:"InstanceName"`
				Status        string `json:"Status"`
				StatusDetails string `json:"StatusDetails"`
				ResponseCode  int    `json:"ResponseCode"`
				RequestedDateTime string `json:"RequestedDateTime"`
			} `json:"CommandInvocations"`
		}
		if err := json.Unmarshal(b, &ssmResp); err != nil {
			return nil, "", false, err
		}
		now := time.Now().UTC()
		var out []models.AssetDeploymentStatus
		for _, inv := range ssmResp.CommandInvocations {
			st := normalizeDeviceState(firstNonEmpty(inv.StatusDetails, inv.Status))
			if inv.ResponseCode == 194 {
				st = models.AssetDeployRebootWaiting
			}
			out = append(out, models.AssetDeploymentStatus{
				AssetKey:       firstNonEmpty(inv.InstanceName, inv.InstanceID),
				NativeDeviceID: inv.InstanceID,
				State:          st,
				NativeExitCode: inv.ResponseCode,
				ReportedAt:     now,
			})
		}
		return out, models.EvidenceGranularityPerAsset, ssmResp.Stalled, nil
	})
}

func (s *AWSSSMTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if !s.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&s.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
	}
	raw, err := s.doJSON(ctx, http.MethodPost, "/ssm/SendCommand", map[string]any{
		"DocumentName":         firstNonEmpty(order.RollbackInstruction.RollbackPlaybookID, "G1-RollbackPatchBaseline"),
		"OrderID":              order.OrderID,
		"PreviousPackageNEVRA": order.RollbackInstruction.PreviousPackageNEVRA,
		"UninstallKB":          order.RollbackInstruction.UninstallKB,
		"Reason":               reason,
	})
	if err != nil {
		return nil, err
	}
	res, err := parseVendorPollResponse(s.DistributorID(), order.OrderID, nativeJobRef, s.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return buildSimulatedPerAssetResult(&s.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason).AssetResults, models.EvidenceGranularityPerAsset, false, nil
	})
	if err != nil {
		return nil, err
	}
	res.IsRollback = true
	res.RollbackReason = reason
	res.RecomputeCounts()
	return res, nil
}

// AzureUpdateManagerTranslator translates DeploymentOrders into Azure Update Manager installPatches executions.
type AzureUpdateManagerTranslator struct {
	baseHTTPDistributor
}

func NewAzureUpdateManagerTranslator(baseURL, token string, rt http.RoundTripper) *AzureUpdateManagerTranslator {
	return &AzureUpdateManagerTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorAzureUpdateManager,
			"Azure Update Manager Maintenance & installPatches",
			"CLOUD_PATCHERS",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     true,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"WINDOWS", "LINUX_RPM", "LINUX_DEB"},
				DefaultRollbackStrategy: "AZURE_VM_RUN_COMMAND_ROLLBACK",
			},
			rt,
		),
	}
}

func (az *AzureUpdateManagerTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &AzureUpdateManagerTranslator{baseHTTPDistributor: az.cloneWithTransport(rt)}
}

func (az *AzureUpdateManagerTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("az-um-%s", order.OrderID)
	az.recordLocalOrder(jobRef, order)
	if az.EndpointConfigured() {
		raw, err := az.doJSON(ctx, http.MethodPost, "/azure/update-manager/installPatches", order)
		if err != nil {
			return nil, err
		}
		var resp struct {
			OperationID string `json:"operation_id"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.OperationID != "" {
			jobRef = resp.OperationID
			az.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        az.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  true,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (az *AzureUpdateManagerTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !az.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&az.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := az.doJSON(ctx, http.MethodGet, fmt.Sprintf("/azure/update-manager/operations/%s?order_id=%s", nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(az.DistributorID(), orderID, nativeJobRef, az.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return buildSimulatedPerAssetResult(&az.baseHTTPDistributor, orderID, nativeJobRef, false, "").AssetResults, models.EvidenceGranularityPerAsset, false, nil
	})
}

func (az *AzureUpdateManagerTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if az.EndpointConfigured() {
		_, err := az.doJSON(ctx, http.MethodPost, "/azure/update-manager/rollback", map[string]any{
			"order_id":             order.OrderID,
			"rollback_instruction": order.RollbackInstruction,
			"reason":               reason,
		})
		if err != nil {
			return nil, err
		}
	}
	return buildSimulatedPerAssetResult(&az.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
}

// GCPOSConfigTranslator translates DeploymentOrders into Google Cloud OS Config patchJobs.execute calls.
type GCPOSConfigTranslator struct {
	baseHTTPDistributor
}

func NewGCPOSConfigTranslator(baseURL, token string, rt http.RoundTripper) *GCPOSConfigTranslator {
	return &GCPOSConfigTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorGCPOSConfig,
			"Google Cloud OS Config Patch Deployments",
			"CLOUD_PATCHERS",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     true,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"LINUX_DEB", "LINUX_RPM", "WINDOWS"},
				DefaultRollbackStrategy: "GCP_OS_CONFIG_EXEC_STEP_ROLLBACK",
			},
			rt,
		),
	}
}

func (g *GCPOSConfigTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &GCPOSConfigTranslator{baseHTTPDistributor: g.cloneWithTransport(rt)}
}

func (g *GCPOSConfigTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("gcp-patchjob-%s", order.OrderID)
	g.recordLocalOrder(jobRef, order)
	if g.EndpointConfigured() {
		raw, err := g.doJSON(ctx, http.MethodPost, "/v1/projects/default/patchJobs:execute", order)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.Name != "" {
			jobRef = resp.Name
			g.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        g.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  true,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (g *GCPOSConfigTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !g.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&g.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := g.doJSON(ctx, http.MethodGet, fmt.Sprintf("/v1/projects/default/patchJobs/%s/instanceDetails?order_id=%s", nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(g.DistributorID(), orderID, nativeJobRef, g.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return buildSimulatedPerAssetResult(&g.baseHTTPDistributor, orderID, nativeJobRef, false, "").AssetResults, models.EvidenceGranularityPerAsset, false, nil
	})
}

func (g *GCPOSConfigTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if g.EndpointConfigured() {
		_, err := g.doJSON(ctx, http.MethodPost, "/v1/projects/default/patchJobs:rollback", map[string]any{
			"order_id":             order.OrderID,
			"rollback_instruction": order.RollbackInstruction,
			"reason":               reason,
		})
		if err != nil {
			return nil, err
		}
	}
	return buildSimulatedPerAssetResult(&g.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
}
