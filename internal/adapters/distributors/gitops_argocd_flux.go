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

// ArgoCDTranslator translates DeploymentOrders into Argo CD Application sync & history rollback REST calls.
type ArgoCDTranslator struct {
	baseHTTPDistributor
}

func NewArgoCDTranslator(baseURL, token string, rt http.RoundTripper) *ArgoCDTranslator {
	return &ArgoCDTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorArgoCD,
			"Argo CD GitOps Application Sync",
			"CONTAINERS_GITOPS",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     true,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  false,
				PlatformFamilies:        []string{"CONTAINER_LINUX", "KUBERNETES_GITOPS"},
				DefaultRollbackStrategy: "ARGOCD_APPLICATION_HISTORY_ROLLBACK",
			},
			rt,
		),
	}
}

func (a *ArgoCDTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &ArgoCDTranslator{baseHTTPDistributor: a.cloneWithTransport(rt)}
}

func (a *ArgoCDTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("argocd-sync-%s-%s", order.ServiceID, order.OrderID)
	a.recordLocalOrder(jobRef, order)
	if a.EndpointConfigured() {
		payload := map[string]any{
			"name":     order.ServiceID,
			"revision": order.FixIdentity.TargetDigest,
			"syncStrategy": map[string]any{
				"apply": map[string]any{"force": false},
			},
			"info": []map[string]string{
				{"name": "warrant_id", "value": order.WarrantID},
				{"name": "order_id", "value": order.OrderID},
				{"name": "cve_id", "value": order.FixIdentity.CVEID},
			},
		}
		raw, err := a.doJSON(ctx, http.MethodPost, "/api/v1/applications/"+order.ServiceID+"/sync", payload)
		if err != nil {
			return nil, err
		}
		var resp struct {
			OperationID string `json:"operation_id"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.OperationID != "" {
			jobRef = resp.OperationID
			a.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        a.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  true,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (a *ArgoCDTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !a.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&a.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	order, _ := a.lookupLocalOrder(orderID, nativeJobRef)
	raw, err := a.doJSON(ctx, http.MethodGet, fmt.Sprintf("/api/v1/applications/%s?operation=%s&order_id=%s", order.ServiceID, nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(a.DistributorID(), orderID, nativeJobRef, a.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		var app struct {
			Status struct {
				Resources []struct {
					Kind   string `json:"kind"`
					Name   string `json:"name"`
					Status string `json:"status"`
					Health struct {
						Status string `json:"status"`
					} `json:"health"`
				} `json:"resources"`
			} `json:"status"`
		}
		if err := json.Unmarshal(b, &app); err != nil {
			return nil, "", false, err
		}
		now := time.Now().UTC()
		var out []models.AssetDeploymentStatus
		for _, r := range app.Status.Resources {
			st := normalizeDeviceState(r.Health.Status)
			if r.Status != "" && r.Health.Status == "" {
				st = normalizeDeviceState(r.Status)
			}
			out = append(out, models.AssetDeploymentStatus{
				AssetKey:       r.Name,
				NativeDeviceID: r.Kind + "/" + r.Name,
				State:          st,
				ReportedAt:     now,
			})
		}
		return out, models.EvidenceGranularityPerAsset, false, nil
	})
}

func (a *ArgoCDTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if !a.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&a.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
	}
	payload := map[string]any{
		"order_id":          order.OrderID,
		"git_revert_commit": order.RollbackInstruction.GitRevertCommit,
		"previous_digest":   order.RollbackInstruction.PreviousDigest,
		"reason":            reason,
	}
	raw, err := a.doJSON(ctx, http.MethodPost, "/api/v1/applications/"+order.ServiceID+"/rollback", payload)
	if err != nil {
		return nil, err
	}
	res, err := parseVendorPollResponse(a.DistributorID(), order.OrderID, nativeJobRef, a.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return buildSimulatedPerAssetResult(&a.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason).AssetResults, models.EvidenceGranularityPerAsset, false, nil
	})
	if err != nil {
		return nil, err
	}
	res.IsRollback = true
	res.RollbackReason = reason
	res.RecomputeCounts()
	return res, nil
}

// FluxGitOpsTranslator translates DeploymentOrders into Flux GitOps commit / HelmRelease updates.
// By default Flux GitOps commit-dispatch reports DISPATCH_ACK_ONLY unless per-pod telemetry is returned,
// exercising honest ASSURANCE_TIER_0_DISTRIBUTOR_DISPATCH_ONLY closure classification.
type FluxGitOpsTranslator struct {
	baseHTTPDistributor
}

func NewFluxGitOpsTranslator(baseURL, token string, rt http.RoundTripper) *FluxGitOpsTranslator {
	return &FluxGitOpsTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorFlux,
			"Flux CD GitOps Commit & HelmRelease",
			"CONTAINERS_GITOPS",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     false,
				ReportsPerAssetState:    false,
				SupportsRebootTracking:  false,
				PlatformFamilies:        []string{"CONTAINER_LINUX", "KUBERNETES_GITOPS"},
				DefaultRollbackStrategy: "GIT_REVERT_COMMIT",
			},
			rt,
		),
	}
}

func (f *FluxGitOpsTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &FluxGitOpsTranslator{baseHTTPDistributor: f.cloneWithTransport(rt)}
}

func (f *FluxGitOpsTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("flux-commit-%s", order.OrderID)
	f.recordLocalOrder(jobRef, order)
	if f.EndpointConfigured() {
		raw, err := f.doJSON(ctx, http.MethodPost, "/v1/flux/reconcile", order)
		if err != nil {
			return nil, err
		}
		var resp struct {
			CommitSHA string `json:"commit_sha"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.CommitSHA != "" {
			jobRef = resp.CommitSHA
			f.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        f.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  false,
		ReportsPerAssetState: false,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (f *FluxGitOpsTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !f.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&f.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := f.doJSON(ctx, http.MethodGet, fmt.Sprintf("/v1/flux/status?commit=%s&order_id=%s", nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(f.DistributorID(), orderID, nativeJobRef, f.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return nil, models.EvidenceGranularityDispatchAck, false, nil
	})
}

func (f *FluxGitOpsTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if f.EndpointConfigured() {
		_, err := f.doJSON(ctx, http.MethodPost, "/v1/flux/revert", map[string]any{
			"order_id":          order.OrderID,
			"git_revert_commit": order.RollbackInstruction.GitRevertCommit,
			"previous_digest":   order.RollbackInstruction.PreviousDigest,
			"reason":            reason,
		})
		if err != nil {
			return nil, err
		}
	}
	return buildSimulatedPerAssetResult(&f.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
}
