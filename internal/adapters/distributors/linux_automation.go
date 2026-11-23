package distributors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// AnsibleAWXTranslator translates DeploymentOrders into Ansible Automation Platform / AWX Job Template launches
// and harvests per-host /job_events/ results (SupportsNativeRings: false -> wave-sequenced by N2).
type AnsibleAWXTranslator struct {
	baseHTTPDistributor
}

func NewAnsibleAWXTranslator(baseURL, token string, rt http.RoundTripper) *AnsibleAWXTranslator {
	return &AnsibleAWXTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorAnsibleAWX,
			"Ansible Automation Platform / AWX Job Templates",
			"LINUX_AUTOMATION",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     false,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"LINUX_RPM", "LINUX_DEB", "LINUX_GENERIC"},
				DefaultRollbackStrategy: "ANSIBLE_PLAYBOOK_DOWNGRADE_NEVRA",
			},
			rt,
		),
	}
}

func (a *AnsibleAWXTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &AnsibleAWXTranslator{baseHTTPDistributor: a.cloneWithTransport(rt)}
}

func (a *AnsibleAWXTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("awx-job-w%d-%s", max(1, order.WaveNumber), order.OrderID)
	a.recordLocalOrder(jobRef, order)
	if a.EndpointConfigured() {
		hosts := make([]string, 0, len(order.TargetAssets))
		for _, t := range order.TargetAssets {
			hosts = append(hosts, firstNonEmpty(t.Hostname, t.AssetKey))
		}
		payload := map[string]any{
			"limit": strings.Join(hosts, ","),
			"extra_vars": map[string]any{
				"order_id":      order.OrderID,
				"warrant_id":    order.WarrantID,
				"wave_number":   order.WaveNumber,
				"cve_id":        order.FixIdentity.CVEID,
				"package_nevra": order.FixIdentity.PackageNEVRA,
				"target_hosts":  hosts,
			},
		}
		raw, err := a.doJSON(ctx, http.MethodPost, "/api/v2/job_templates/patch/launch/", payload)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Job any `json:"job"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.Job != nil {
			jobRef = fmt.Sprintf("%v", resp.Job)
			a.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        a.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  false,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (a *AnsibleAWXTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !a.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&a.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := a.doJSON(ctx, http.MethodGet, fmt.Sprintf("/api/v2/jobs/%s/job_events/?order_id=%s", nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(a.DistributorID(), orderID, nativeJobRef, a.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		var awx struct {
			Stalled bool `json:"stalled"`
			Results []struct {
				Host     string `json:"host"`
				Event    string `json:"event"` // runner_on_ok | runner_on_failed | runner_on_unreachable
				Changed  bool   `json:"changed"`
				Modified string `json:"modified"`
				EventData struct {
					Res struct {
						RC             int  `json:"rc"`
						RebootRequired bool `json:"reboot_required"`
					} `json:"res"`
				} `json:"event_data"`
			} `json:"results"`
		}
		if err := json.Unmarshal(b, &awx); err != nil {
			return nil, "", false, err
		}
		now := time.Now().UTC()
		var out []models.AssetDeploymentStatus
		for _, ev := range awx.Results {
			if strings.TrimSpace(ev.Host) == "" {
				continue
			}
			state := models.AssetDeployLanded
			switch ev.Event {
			case "runner_on_failed":
				state = models.AssetDeployFailed
			case "runner_on_unreachable":
				state = models.AssetDeployUnreachable
			case "runner_on_ok":
				if ev.EventData.Res.RebootRequired {
					state = models.AssetDeployRebootWaiting
				} else {
					state = models.AssetDeployLanded
				}
			}
			ts := now
			if parsed, pErr := time.Parse(time.RFC3339, ev.Modified); pErr == nil {
				ts = parsed.UTC()
			}
			out = append(out, models.AssetDeploymentStatus{
				AssetKey:       ev.Host,
				NativeDeviceID: ev.Host,
				State:          state,
				NativeExitCode: ev.EventData.Res.RC,
				ReportedAt:     ts,
			})
		}
		return out, models.EvidenceGranularityPerAsset, awx.Stalled, nil
	})
}

func (a *AnsibleAWXTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if !a.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&a.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
	}
	hosts := make([]string, 0, len(order.TargetAssets))
	for _, t := range order.TargetAssets {
		hosts = append(hosts, firstNonEmpty(t.Hostname, t.AssetKey))
	}
	playbook := firstNonEmpty(order.RollbackInstruction.RollbackPlaybookID, "rollback_package_downgrade")
	raw, err := a.doJSON(ctx, http.MethodPost, fmt.Sprintf("/api/v2/job_templates/%s/launch/", playbook), map[string]any{
		"limit": strings.Join(hosts, ","),
		"extra_vars": map[string]any{
			"order_id":               order.OrderID,
			"previous_package_nevra": order.RollbackInstruction.PreviousPackageNEVRA,
			"target_hosts":           hosts,
			"rollback_reason":        reason,
		},
	})
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

// RedHatSatelliteTranslator translates DeploymentOrders into Red Hat Satellite / Katello remote errata execution.
type RedHatSatelliteTranslator struct {
	baseHTTPDistributor
}

func NewRedHatSatelliteTranslator(baseURL, token string, rt http.RoundTripper) *RedHatSatelliteTranslator {
	return &RedHatSatelliteTranslator{
		baseHTTPDistributor: newBaseHTTPDistributor(
			models.DistributorRedHatSatellite,
			"Red Hat Satellite / Katello Errata Execution",
			"LINUX_AUTOMATION",
			baseURL,
			token,
			models.DistributorCapabilities{
				SupportsNativeRings:     false,
				ReportsPerAssetState:    true,
				SupportsRebootTracking:  true,
				PlatformFamilies:        []string{"LINUX_RPM"},
				DefaultRollbackStrategy: "DNF_HISTORY_UNDO_OR_CONTENT_VIEW_REVERT",
			},
			rt,
		),
	}
}

func (s *RedHatSatelliteTranslator) WithTransport(rt http.RoundTripper) adapters.DistributorTranslator {
	return &RedHatSatelliteTranslator{baseHTTPDistributor: s.cloneWithTransport(rt)}
}

func (s *RedHatSatelliteTranslator) DispatchOrder(ctx context.Context, order models.DeploymentOrder) (*models.DeploymentDispatchReceipt, error) {
	jobRef := fmt.Sprintf("sat-inv-w%d-%s", max(1, order.WaveNumber), order.OrderID)
	s.recordLocalOrder(jobRef, order)
	if s.EndpointConfigured() {
		raw, err := s.doJSON(ctx, http.MethodPost, "/api/job_invocations", order)
		if err != nil {
			return nil, err
		}
		var resp struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &resp) == nil && resp.ID != "" {
			jobRef = resp.ID
			s.recordLocalOrder(jobRef, order)
		}
	}
	return &models.DeploymentDispatchReceipt{
		OrderID:              order.OrderID,
		DistributorID:        s.DistributorID(),
		NativeJobRef:         jobRef,
		SupportsNativeRings:  false,
		ReportsPerAssetState: true,
		DispatchedAt:         time.Now().UTC(),
	}, nil
}

func (s *RedHatSatelliteTranslator) PollResult(ctx context.Context, orderID string, nativeJobRef string) (*models.DeploymentResult, error) {
	if !s.EndpointConfigured() {
		return buildSimulatedPerAssetResult(&s.baseHTTPDistributor, orderID, nativeJobRef, false, ""), nil
	}
	raw, err := s.doJSON(ctx, http.MethodGet, fmt.Sprintf("/api/job_invocations/%s?order_id=%s", nativeJobRef, orderID), nil)
	if err != nil {
		return nil, err
	}
	return parseVendorPollResponse(s.DistributorID(), orderID, nativeJobRef, s.Capabilities(), raw, func(b []byte) ([]models.AssetDeploymentStatus, string, bool, error) {
		if items, gran, stalled, ok := parseCommonAssetItems(b); ok {
			return items, gran, stalled, nil
		}
		return buildSimulatedPerAssetResult(&s.baseHTTPDistributor, orderID, nativeJobRef, false, "").AssetResults, models.EvidenceGranularityPerAsset, false, nil
	})
}

func (s *RedHatSatelliteTranslator) ExecuteRollback(ctx context.Context, order models.DeploymentOrder, nativeJobRef string, reason string) (*models.DeploymentResult, error) {
	if s.EndpointConfigured() {
		_, err := s.doJSON(ctx, http.MethodPost, "/api/job_invocations/rollback", map[string]any{
			"order_id":               order.OrderID,
			"previous_package_nevra": order.RollbackInstruction.PreviousPackageNEVRA,
			"dnf_command":            "dnf history undo last -y",
			"reason":                 reason,
		})
		if err != nil {
			return nil, err
		}
	}
	return buildSimulatedPerAssetResult(&s.baseHTTPDistributor, order.OrderID, nativeJobRef, true, reason), nil
}
