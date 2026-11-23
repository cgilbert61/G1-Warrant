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

// MSIntuneTranslator translates DeploymentOrders into Microsoft Intune Graph Windows Update Rings / Expedited Quality Update calls.
type MSIntuneTranslator struct {
	baseHTTPDistributor
}

func NewMSIntuneTranslator(baseURL, token string, rt http.RoundTripper) *MSIntuneTranslator {
	return &MSIntuneTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorMSIntune,
			"Microsoft Intune Windows Update Rings & Expedited KB",
			"MICROSOFT_ESTATE",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     true,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"WINDOWS"},
				DefaultRollbackStrategy: "INTUNE_UNINSTALL_KB_OR_SUPERSEDENCE",
			},
			rt,
		),
	}
}

func (m *MSIntuneTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &MSIntuneTranslator{baseHTTPDistributor: m.cloneWithTransport(rt)}
}

func (m *MSIntuneTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("intune-qprofile-%s", order.OrderID)
	m.recordLocalOrder(jobRef, order)
	if m.EndpointConfigured() {
		deviceIDs := make([]string, 0, len(order.TargetAssets))
		for _, a := range order.TargetAssets {
			deviceIDs = append(deviceIDs, firstNonEmpty(a.NativeDeviceID, a.AssetKey))
		}
		payload := map[string]any{
			"displayName":          fmt.Sprintf("G1-Warrant-%s-%s", order.FixIdentity.CVEID, order.OrderID),
			"expeditedUpdateKB":    order.FixIdentity.KBArticleID,
			"cveId":                order.FixIdentity.CVEID,
			"warrantId":            order.WarrantID,
			"assignedDeviceIds":    deviceIDs,
			"deploymentRings":      order.RolloutPlan.Waves,
			"daysUntilForcedReboot": 1,
		}
		raw, err := m.doJSON(ctx, http.MethodPost, "/beta/deviceManagement/windowsQualityUpdateProfiles", payload)
		if err != nil {
			return nil, err
		}
		var resp struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.ID != "" {
			jobRef = resp.ID
			m.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        m.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  true,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (m *MSIntuneTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !m.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&m.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := m.doJSON(ctx, http.MethodGet, fmt.Sprintf("/beta/deviceManagement/windowsQualityUpdateProfiles/%s/deviceUpdateStates?order_id=%s", nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(m.DistributorID(), orderID, nativeJobRef, m.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		var graphResp struct {
			Stalled bool `json:"stalled"`
			Value   []struct {
				DeviceID            string `json:"deviceId"`
				DeviceDisplayName   string `json:"deviceDisplayName"`
				Status              string `json:"status"` // succeeded | pendingReboot | failed | inProgress
				ErrorCode           string `json:"errorCode"`
				LastReportedDateTime string `json:"lastReportedDateTime"`
			} `json:"value"`
		}
		if err := json.Unmarshal(b, &graphResp); err != nil {
			return nil, "", false, err
		}
		now := time.Now().UTC()
		out := make([]models.AssetDeploymentStatus, 0, len(graphResp.Value))
		for _, d := range graphResp.Value {
			ts := now
			if parsed, pErr := time.Parse(time.RFC3339, d.LastReportedDateTime); pErr == nil {
				ts = parsed.UTC()
			}
			out = append(out, models.AssetDeploymentStatus{
				AssetKey:        firstNonEmpty(d.DeviceDisplayName, d.DeviceID),
				NativeDeviceID:  d.DeviceID,
				State:           normalizeDeviceState(d.Status),
				NativeErrorCode: d.ErrorCode,
				ReportedAt:      ts,
			})
		}
		return out, models.EvidenceGranularityPerAsset, graphResp.Stalled, nil
	})
}

func (m *MSIntuneTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if !m.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&m.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
	}
	uninstallCmd := fmt.Sprintf("wusa.exe /uninstall /kb:%s /quiet /norestart", trimKBPrefix(order.RollbackInstruction.UninstallKB))
	raw, err := m.doJSON(ctx, http.MethodPost, fmt.Sprintf("/beta/deviceManagement/windowsQualityUpdateProfiles/%s/uninstall", nativeJobRef), map[string]any{
		"order_id":             order.OrderID,
		"uninstall_kb":         order.RollbackInstruction.UninstallKB,
		"native_command":       uninstallCmd,
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

// MSMECMTranslator translates DeploymentOrders into Microsoft Endpoint Configuration Manager (SCCM/MECM) Phased Deployments.
type MSMECMTranslator struct {
	baseHTTPDistributor
}

func NewMSMECMTranslator(baseURL, token string, rt http.RoundTripper) *MSMECMTranslator {
	return &MSMECMTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorMSMECM,
			"Microsoft Configuration Manager (MECM) Phased Deployment",
			"MICROSOFT_ESTATE",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     true,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"WINDOWS"},
				DefaultRollbackStrategy: "MECM_WUSA_UNINSTALL_DEPLOYMENT",
			},
			rt,
		),
	}
}

func (m *MSMECMTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &MSMECMTranslator{baseHTTPDistributor: m.cloneWithTransport(rt)}
}

func (m *MSMECMTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("mecm-assign-%s", order.OrderID)
	m.recordLocalOrder(jobRef, order)
	if m.EndpointConfigured() {
		raw, err := m.doJSON(ctx, http.MethodPost, "/AdminService/v1.0/SMS_UpdateGroupAssignment", order)
		if err != nil {
			return nil, err
		}
		var resp struct {
			AssignmentUniqueID string `json:"AssignmentUniqueID"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.AssignmentUniqueID != "" {
			jobRef = resp.AssignmentUniqueID
			m.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        m.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  true,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (m *MSMECMTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !m.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&m.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := m.doJSON(ctx, http.MethodGet, fmt.Sprintf("/AdminService/v1.0/SMS_UpdateGroupAssignment/%s/Compliance?order_id=%s", nativeJobRef, orderID), nil)
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

func (m *MSMECMTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if m.EndpointConfigured() {
		_, err := m.doJSON(ctx, http.MethodPost, fmt.Sprintf("/AdminService/v1.0/SMS_UpdateGroupAssignment/%s/Rollback", nativeJobRef), map[string]any{
			"order_id":             order.OrderID,
			"uninstall_kb":         order.RollbackInstruction.UninstallKB,
			"native_command":       fmt.Sprintf("wusa.exe /uninstall /kb:%s /quiet /norestart", trimKBPrefix(order.RollbackInstruction.UninstallKB)),
			"rollback_instruction": order.RollbackInstruction,
			"reason":               reason,
		})
		if err != nil {
			return nil, err
		}
	}
	return buildSimulatedPerAssetResult(&m.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
}

// MSWSUSTranslator translates DeploymentOrders into WSUS Target Computer Group update approvals.
// SupportsNativeRings == false -> wave_sequencer.go slices target hosts into deterministic 5% -> 25% -> 100% batches!
type MSWSUSTranslator struct {
	baseHTTPDistributor
}

func NewMSWSUSTranslator(baseURL, token string, rt http.RoundTripper) *MSWSUSTranslator {
	return &MSWSUSTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorMSWSUS,
			"Microsoft WSUS Computer Group Update Approval",
			"MICROSOFT_ESTATE",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     false,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"WINDOWS"},
				DefaultRollbackStrategy: "WSUS_DECLINE_AND_WUSA_UNINSTALL",
			},
			rt,
		),
	}
}

func (w *MSWSUSTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &MSWSUSTranslator{baseHTTPDistributor: w.cloneWithTransport(rt)}
}

func (w *MSWSUSTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("wsus-wave%d-%s", max(1, order.WaveNumber), order.OrderID)
	w.recordLocalOrder(jobRef, order)
	if w.EndpointConfigured() {
		hosts := make([]string, 0, len(order.TargetAssets))
		for _, a := range order.TargetAssets {
			hosts = append(hosts, a.AssetKey)
		}
		raw, err := w.doJSON(ctx, http.MethodPost, "/wsus/v1/approvals", map[string]any{
			"order_id":        order.OrderID,
			"wave_number":     order.WaveNumber,
			"kb_article_id":   order.FixIdentity.KBArticleID,
			"target_computers": hosts,
			"action":          "Install",
		})
		if err != nil {
			return nil, err
		}
		var resp struct {
			ApprovalID string `json:"approval_id"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.ApprovalID != "" {
			jobRef = resp.ApprovalID
			w.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        w.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  false,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (w *MSWSUSTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !w.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&w.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := w.doJSON(ctx, http.MethodGet, fmt.Sprintf("/wsus/v1/approvals/%s/summaries?order_id=%s", nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(w.DistributorID(), orderID, nativeJobRef, w.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		var wsusResp struct {
			Stalled   bool `json:"stalled"`
			Summaries []struct {
				ComputerTargetID string `json:"computerTargetId"`
				FullDomainName   string `json:"fullDomainName"`
				InstallationState string `json:"installationState"` // Installed | InstalledPendingReboot | Failed | Downloaded
				LastUpdated      string `json:"lastUpdated"`
			} `json:"summaries"`
		}
		if err := json.Unmarshal(b, &wsusResp); err != nil {
			return nil, "", false, err
		}
		now := time.Now().UTC()
		var out []models.AssetDeploymentStatus
		for _, s := range wsusResp.Summaries {
			st := normalizeDeviceState(s.InstallationState)
			if s.InstallationState == "InstalledPendingReboot" {
				st = models.AssetDeployRebootWaiting
			}
			ts := now
			if parsed, pErr := time.Parse(time.RFC3339, s.LastUpdated); pErr == nil {
				ts = parsed.UTC()
			}
			out = append(out, models.AssetDeploymentStatus{
				AssetKey:       firstNonEmpty(s.FullDomainName, s.ComputerTargetID),
				NativeDeviceID: s.ComputerTargetID,
				State:          st,
				ReportedAt:     ts,
			})
		}
		return out, models.EvidenceGranularityPerAsset, wsusResp.Stalled, nil
	})
}

func (w *MSWSUSTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if !w.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&w.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
	}
	hosts := make([]string, 0, len(order.TargetAssets))
	for _, a := range order.TargetAssets {
		hosts = append(hosts, a.AssetKey)
	}
	raw, err := w.doJSON(ctx, http.MethodPost, "/wsus/v1/approvals/uninstall", map[string]any{
		"order_id":         order.OrderID,
		"approval_id":      nativeJobRef,
		"uninstall_kb":     order.RollbackInstruction.UninstallKB,
		"wusa_command":     fmt.Sprintf("wusa /uninstall /kb:%s /quiet /norestart", trimKBPrefix(order.RollbackInstruction.UninstallKB)),
		"target_computers": hosts,
		"reason":           reason,
	})
	if err != nil {
		return nil, err
	}
	res, err := parseVendorPollResponse(w.DistributorID(), order.OrderID, nativeJobRef, w.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return buildSimulatedPerAssetResult(&w.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason).AssetResults, models.EvidenceGranularityPerAsset, false, nil
	})
	if err != nil {
		return nil, err
	}
	res.IsRollback = true
	res.RollbackReason = reason
	res.RecomputeCounts()
	return res, nil
}

func trimKBPrefix(kb string) string {
	up := kb
	if len(up) >= 2 && (up[:2] == "KB" || up[:2] == "kb") {
		return up[2:]
	}
	return up
}
