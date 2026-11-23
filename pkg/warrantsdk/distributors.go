package warrantsdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// FinderIntakeOptions configures query parameters for POST /api/v1/intake/{qualys|tenable|rapid7}.
type FinderIntakeOptions struct {
	PatchProfile  string
	TargetService string
	DistributorID string
	MaxFindings   int
}

// DistributorDispatchRequest invokes governed WN-8 patch deployment via POST /api/v1/distributors/dispatch.
type DistributorDispatchRequest struct {
	RemediationID        string             `json:"remediation_id"`
	DistributorID        string             `json:"distributor_id"`
	PlatformFamily       string             `json:"platform_family,omitempty"`
	FixIdentity          *FixIdentity       `json:"fix_identity,omitempty"`
	TargetAssets         []AssetTarget      `json:"target_assets,omitempty"`
	WavePercentages      []int              `json:"wave_percentages,omitempty"`
	MaxFailureRatePct    float64            `json:"max_failure_rate_pct,omitempty"`
	StageDwellSeconds    int                `json:"stage_dwell_seconds,omitempty"`
	MaintenanceWindowUTC string             `json:"maintenance_window_utc,omitempty"`
	RollbackInstruction  NativeRollbackSpec `json:"rollback_instruction"`
}

// DistributorRolloutSummary mirrors gate.DistributorRolloutOutcome returned from POST /api/v1/distributors/dispatch.
type DistributorRolloutSummary struct {
	PrimaryOrder       DeploymentOrder           `json:"primary_order"`
	WaveOrders         []DeploymentOrder         `json:"wave_orders,omitempty"`
	Receipts           []DeploymentDispatchReceipt `json:"receipts,omitempty"`
	WaveResults        []DeploymentResult        `json:"wave_results,omitempty"`
	AggregatedResult   DeploymentResult          `json:"aggregated_result"`
	Capabilities       DistributorCapabilities   `json:"capabilities"`
	RolledBack         bool                      `json:"rolled_back"`
	RollbackReasonCode string                    `json:"rollback_reason_code,omitempty"`
	RollbackResult     *DeploymentResult         `json:"rollback_result,omitempty"`
}

// DistributorDispatchResponse represents the response from POST /api/v1/distributors/dispatch.
type DistributorDispatchResponse struct {
	Remediation RemediationItem           `json:"remediation"`
	Rollout     DistributorRolloutSummary `json:"rollout"`
	Attestation *AttestationRecord        `json:"attestation,omitempty"`
}

// SubmitFinderIntake submits raw Qualys VMDR (XML/JSON), Tenable.io/sc (JSON), or Rapid7 InsightVM (JSON)
// scan output to POST /api/v1/intake/{qualys|tenable|rapid7}.
func (c *Client) SubmitFinderIntake(ctx context.Context, vendor string, rawPayload []byte, opts FinderIntakeOptions) ([]RemediationItem, error) {
	slug := strings.ToLower(strings.TrimSpace(vendor))
	switch slug {
	case "qualys", "qualys_vmdr":
		slug = "qualys"
	case "tenable", "tenable_io_sc", "tenable.io", "tenable.sc":
		slug = "tenable"
	case "rapid7", "rapid7_insightvm":
		slug = "rapid7"
	default:
		return nil, fmt.Errorf("warrantsdk: unsupported finder vendor %q (expected qualys, tenable, or rapid7)", vendor)
	}
	q := url.Values{}
	if opts.PatchProfile != "" {
		q.Set("patch_profile", opts.PatchProfile)
	}
	if opts.TargetService != "" {
		q.Set("target_service", opts.TargetService)
	}
	if opts.DistributorID != "" {
		q.Set("distributor_id", opts.DistributorID)
	}
	if opts.MaxFindings > 0 {
		q.Set("max_findings", strconv.Itoa(opts.MaxFindings))
	}
	path := "/api/v1/intake/" + slug
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	contentType := "application/json"
	trimmed := strings.TrimSpace(string(rawPayload))
	if strings.HasPrefix(trimmed, "<") {
		contentType = "application/xml"
	}
	respBytes, err := c.doRaw(ctx, http.MethodPost, path, contentType, rawPayload)
	if err != nil {
		return nil, err
	}
	var items []RemediationItem
	if err := json.Unmarshal(respBytes, &items); err != nil {
		return nil, fmt.Errorf("warrantsdk: decode finder intake response: %w", err)
	}
	return items, nil
}

// ListAssetAliases returns all registered WN-7 scanner asset-to-service aliases (GET /api/v1/finders/aliases).
func (c *Client) ListAssetAliases(ctx context.Context) ([]AssetIdentityAlias, error) {
	var out []AssetIdentityAlias
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/finders/aliases", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertAssetAlias registers or updates a deterministic WN-7 scanner asset alias (POST /api/v1/finders/aliases).
func (c *Client) UpsertAssetAlias(ctx context.Context, alias AssetIdentityAlias) (*AssetIdentityAlias, error) {
	var out AssetIdentityAlias
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/finders/aliases", GovActionFeedMutation, PrincipalGovernancePayload{}, alias, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListDistributors returns all registered WN-8 patch distributor translators and their capability flags (GET /api/v1/distributors).
func (c *Client) ListDistributors(ctx context.Context) ([]DistributorDescriptor, error) {
	var out []DistributorDescriptor
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/distributors", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListDeploymentOrders lists immutable WORM deployment orders, optionally filtered by remediationID (GET /api/v1/distributors/orders).
func (c *Client) ListDeploymentOrders(ctx context.Context, remediationID string) ([]DeploymentOrder, error) {
	path := "/api/v1/distributors/orders"
	if strings.TrimSpace(remediationID) != "" {
		path += "?remediation_id=" + url.QueryEscape(strings.TrimSpace(remediationID))
	}
	var out []DeploymentOrder
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListDeploymentResults lists immutable WORM per-asset deployment results, optionally filtered by orderID (GET /api/v1/distributors/results).
func (c *Client) ListDeploymentResults(ctx context.Context, orderID string) ([]DeploymentResult, error) {
	path := "/api/v1/distributors/results"
	if strings.TrimSpace(orderID) != "" {
		path += "?order_id=" + url.QueryEscape(strings.TrimSpace(orderID))
	}
	var out []DeploymentResult
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DispatchDistributorOrder executes a governed WN-8 patch rollout under an active 2-of-2 Standing Warrant and N3 proof (POST /api/v1/distributors/dispatch).
func (c *Client) DispatchDistributorOrder(ctx context.Context, req DistributorDispatchRequest) (*DistributorDispatchResponse, error) {
	var out DistributorDispatchResponse
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/distributors/dispatch", GovActionFeedMutation, PrincipalGovernancePayload{}, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RollbackDistributorOrder invokes symmetric native rollback using the immutable pre-recorded RollbackInstruction on orderID
// and re-arms containment (POST /api/v1/distributors/orders/{order_id}/rollback).
func (c *Client) RollbackDistributorOrder(ctx context.Context, orderID, reason string) (*DeploymentResult, error) {
	if strings.TrimSpace(reason) == "" {
		reason = "OPERATOR_DISTRIBUTOR_ROLLBACK"
	}
	path := "/api/v1/distributors/orders/" + url.PathEscape(strings.TrimSpace(orderID)) + "/rollback"
	body := map[string]string{"reason_code": reason}
	var out DeploymentResult
	if err := c.doActionJSON(ctx, http.MethodPost, path, GovActionEmergencyRollback, PrincipalGovernancePayload{
		ReasonCode: reason,
	}, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
