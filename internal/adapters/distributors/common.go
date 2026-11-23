package distributors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
)

// baseHTTPDistributor provides governed HTTP transport, deterministic sandbox simulation when no external
// vendor URL is configured in local simulator mode, and RFC 8785 JCS hashing of native status reports.
type baseHTTPDistributor struct {
	id          string
	displayName string
	family      string
	caps        models.DistributorCapabilities
	baseURL     string
	bearerToken string
	httpClient  *http.Client

	mu          sync.Mutex
	localOrders map[string]models.DeploymentOrder
}

func newBaseHTTPDistributor(
	id, displayName, family, baseURL, bearerToken string,
	caps models.DistributorCapabilities,
	transport http.RoundTripper,
) baseHTTPDistributor {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return baseHTTPDistributor{
		id:          id,
		displayName: displayName,
		family:      family,
		caps:        caps,
		baseURL:     strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		bearerToken: strings.TrimSpace(bearerToken),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		localOrders: make(map[string]models.DeploymentOrder),
	}
}

func (b *baseHTTPDistributor) DistributorID() string                     { return b.id }
func (b *baseHTTPDistributor) DisplayName() string                       { return b.displayName }
func (b *baseHTTPDistributor) Family() string                            { return b.family }
func (b *baseHTTPDistributor) Capabilities() models.DistributorCapabilities { return b.caps }
func (b *baseHTTPDistributor) EndpointConfigured() bool                  { return b.baseURL != "" }

func (b *baseHTTPDistributor) cloneWithTransport(rt http.RoundTripper) baseHTTPDistributor {
	if rt == nil {
		rt = http.DefaultTransport
	}
	b.mu.Lock()
	copiedOrders := make(map[string]models.DeploymentOrder, len(b.localOrders))
	for k, v := range b.localOrders {
		copiedOrders[k] = v
	}
	b.mu.Unlock()
	return baseHTTPDistributor{
		id:          b.id,
		displayName: b.displayName,
		family:      b.family,
		caps:        b.caps,
		baseURL:     b.baseURL,
		bearerToken: b.bearerToken,
		httpClient: &http.Client{
			Transport: rt,
			Timeout:   15 * time.Second,
		},
		localOrders: copiedOrders,
	}
}

func (b *baseHTTPDistributor) recordLocalOrder(jobRef string, order models.DeploymentOrder) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.localOrders[jobRef] = order
	b.localOrders[order.OrderID] = order
}

func (b *baseHTTPDistributor) lookupLocalOrder(orderID, jobRef string) (models.DeploymentOrder, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if o, ok := b.localOrders[jobRef]; ok {
		return o, true
	}
	o, ok := b.localOrders[orderID]
	return o, ok
}

func (b *baseHTTPDistributor) doJSON(ctx context.Context, method, path string, reqPayload any) ([]byte, error) {
	var bodyBytes []byte
	if reqPayload != nil {
		raw, err := json.Marshal(reqPayload)
		if err != nil {
			return nil, err
		}
		bodyBytes = raw
	}
	var reader io.Reader
	if bodyBytes != nil {
		reader = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+b.bearerToken)
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respRaw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s %s failed (HTTP %d): %s", b.id, method, path, resp.StatusCode, strings.TrimSpace(string(respRaw)))
	}
	return respRaw, nil
}

// parseStandardOrVendorResult decodes any vendor HTTP response into a normalized DeploymentResult,
// supporting both native vendor device/host arrays and canonical wire status structures.
func parseVendorPollResponse(
	distributorID, orderID, nativeJobRef string,
	caps models.DistributorCapabilities,
	raw []byte,
	vendorMapper func(raw []byte) ([]models.AssetDeploymentStatus, string, bool, error),
) (*models.DeploymentResult, error) {
	now := time.Now().UTC()
	reportHash := computeCanonicalOrRawSHA256(raw)

	// Allow vendor endpoints to return per-asset mappings via vendorMapper first
	assets, granularity, stalled, err := vendorMapper(raw)
	if err != nil {
		return nil, err
	}
	if granularity == "" {
		if !caps.ReportsPerAssetState && len(assets) == 0 {
			granularity = models.EvidenceGranularityDispatchAck
		} else if len(assets) > 0 {
			granularity = models.EvidenceGranularityPerAsset
		} else {
			granularity = models.EvidenceGranularityDispatchAck
		}
	}

	res := &models.DeploymentResult{
		ResultID:                   "dres-" + uuid.NewString()[:8],
		OrderID:                    orderID,
		DistributorID:              distributorID,
		NativeJobRef:               nativeJobRef,
		ObservedAt:                 now,
		EvidenceGranularity:        granularity,
		AssetResults:               assets,
		TargetedCount:              len(assets),
		Stalled:                    stalled,
		RawDistributorReportSHA256: reportHash,
	}
	res.RecomputeCounts()
	return res, nil
}

func buildSimulatedPerAssetResult(b *baseHTTPDistributor, orderID, nativeJobRef string, isRollback bool, rollbackReason string) *models.DeploymentResult {
	order, _ := b.lookupLocalOrder(orderID, nativeJobRef)
	now := time.Now().UTC()
	if !b.caps.ReportsPerAssetState && !isRollback {
		ackDoc := map[string]any{
			"distributor_id": b.id,
			"order_id":       orderID,
			"native_job_ref": nativeJobRef,
			"ack_only":       true,
			"observed_at":    now.Format(time.RFC3339),
		}
		ackHash, _, _ := crypto.CanonicalSHA256Hex(ackDoc)
		return &models.DeploymentResult{
			ResultID:                   "dres-" + uuid.NewString()[:8],
			OrderID:                    orderID,
			RemediationID:              order.RemediationID,
			DistributorID:              b.id,
			NativeJobRef:               nativeJobRef,
			WaveNumber:                 max(1, order.WaveNumber),
			ObservedAt:                 now,
			EvidenceGranularity:        models.EvidenceGranularityDispatchAck,
			AssetResults:               []models.AssetDeploymentStatus{},
			TargetedCount:              len(order.TargetAssets),
			RawDistributorReportSHA256: ackHash,
		}
	}

	stateVal := models.AssetDeployLanded
	if isRollback {
		stateVal = models.AssetDeployRolledBack
	}
	assets := make([]models.AssetDeploymentStatus, 0, len(order.TargetAssets))
	for _, t := range order.TargetAssets {
		devID := t.NativeDeviceID
		if devID == "" {
			devID = t.AssetKey
		}
		assets = append(assets, models.AssetDeploymentStatus{
			AssetKey:       t.AssetKey,
			NativeDeviceID: devID,
			State:          stateVal,
			NativeExitCode: 0,
			ReportedAt:     now,
		})
	}
	reportHash, _, _ := crypto.CanonicalSHA256Hex(assets)
	res := &models.DeploymentResult{
		ResultID:                   "dres-" + uuid.NewString()[:8],
		OrderID:                    orderID,
		RemediationID:              order.RemediationID,
		DistributorID:              b.id,
		NativeJobRef:               nativeJobRef,
		WaveNumber:                 max(1, order.WaveNumber),
		ObservedAt:                 now,
		EvidenceGranularity:        models.EvidenceGranularityPerAsset,
		AssetResults:               assets,
		TargetedCount:              len(assets),
		IsRollback:                 isRollback,
		RollbackReason:             rollbackReason,
		RawDistributorReportSHA256: reportHash,
	}
	res.RecomputeCounts()
	return res
}

func computeCanonicalOrRawSHA256(raw []byte) string {
	canon, err := crypto.CanonicalizeJSON(raw)
	if err == nil {
		return crypto.SHA256Hex(canon)
	}
	return crypto.SHA256Hex(raw)
}

func parseCommonAssetItems(raw []byte) ([]models.AssetDeploymentStatus, string, bool, bool) {
	var doc struct {
		EvidenceGranularity string `json:"evidence_granularity"`
		Stalled             bool   `json:"stalled"`
		Devices             []struct {
			AssetKey   string `json:"asset_key"`
			DeviceID   string `json:"device_id"`
			Host       string `json:"host"`
			InstanceID string `json:"instance_id"`
			State      string `json:"state"`
			Status     string `json:"status"`
			ExitCode   int    `json:"exit_code"`
			ErrorCode  string `json:"error_code"`
			ReportedAt string `json:"reported_at"`
		} `json:"devices"`
	}
	if json.Unmarshal(raw, &doc) != nil || (len(doc.Devices) == 0 && doc.EvidenceGranularity == "") {
		return nil, "", false, false
	}
	now := time.Now().UTC()
	out := make([]models.AssetDeploymentStatus, 0, len(doc.Devices))
	for _, d := range doc.Devices {
		key := firstNonEmpty(d.AssetKey, d.Host, d.InstanceID, d.DeviceID)
		devID := firstNonEmpty(d.DeviceID, d.InstanceID, d.Host, d.AssetKey)
		ts := now
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(d.ReportedAt)); err == nil {
			ts = parsed.UTC()
		}
		out = append(out, models.AssetDeploymentStatus{
			AssetKey:        key,
			NativeDeviceID:  devID,
			State:           normalizeDeviceState(firstNonEmpty(d.State, d.Status)),
			NativeExitCode:  d.ExitCode,
			NativeErrorCode: d.ErrorCode,
			ReportedAt:      ts,
		})
	}
	return out, doc.EvidenceGranularity, doc.Stalled, true
}

func normalizeDeviceState(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "LANDED", "SUCCEEDED", "SUCCESS", "INSTALLED", "COMPLIANT", "OK", "CHANGED", "SYNCED", "HEALTHY":
		return models.AssetDeployLanded
	case "REBOOT_WAITING", "PENDING_REBOOT", "PENDINGREBOOT", "REBOOT_REQUIRED", "SOFT_REBOOT_REQUIRED":
		return models.AssetDeployRebootWaiting
	case "PENDING", "IN_PROGRESS", "INPROGRESS", "QUEUED", "DOWNLOADING", "INSTALLING":
		return models.AssetDeployPending
	case "UNREACHABLE", "OFFLINE", "TIMED_OUT", "NO_HEARTBEAT":
		return models.AssetDeployUnreachable
	case "ROLLED_BACK", "UNINSTALLED", "REVERTED", "SUPERSEDED_REVERT":
		return models.AssetDeployRolledBack
	default:
		return models.AssetDeployFailed
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

var _ = adapters.NewDistributorRegistry
