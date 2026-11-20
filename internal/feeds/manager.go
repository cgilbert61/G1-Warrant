package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/agentcp"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/extractor"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
)

const (
	DefaultCISAKEVURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultKEVPollInterval = "1h"
	DefaultOSVAPIURL       = "https://api.osv.dev/v1/querybatch"
)

// Manager orchestrates optional live threat & scanner feeds (CISA KEV, Google OSV.dev, Trivy SARIF tracking).
// Defaults strictly to offline mode for air-gapped federal enclaves and deterministic CI tests.
type Manager struct {
	store       *db.Store
	agentCP     *agentcp.ControlPlane
	httpClient  *http.Client
	onBroadcast func(eventType string, payload any)
	wakeCh      chan struct{}
	mu          sync.Mutex
}

// ConfigFromEnv constructs a FeedRuntimeConfig from WARRANT_* environment variables.
func ConfigFromEnv() (cfg models.FeedRuntimeConfig, explicitEnv bool) {
	rawMode := strings.ToLower(strings.TrimSpace(os.Getenv("WARRANT_FEED_MODE")))
	mode := models.FeedModeOffline
	if rawMode == models.FeedModeLive {
		mode = models.FeedModeLive
	}
	kevURL := strings.TrimSpace(os.Getenv("WARRANT_CISA_KEV_URL"))
	if kevURL == "" {
		kevURL = DefaultCISAKEVURL
	}
	pollInt := strings.TrimSpace(os.Getenv("WARRANT_KEV_POLL_INTERVAL"))
	if pollInt == "" {
		pollInt = DefaultKEVPollInterval
	}
	osvURL := strings.TrimSpace(os.Getenv("WARRANT_OSV_API_URL"))
	if osvURL == "" {
		osvURL = DefaultOSVAPIURL
	}
	trivyRaw := strings.ToLower(strings.TrimSpace(os.Getenv("WARRANT_TRIVY_ENABLED")))
	trivyEnabled := trivyRaw == "true" || trivyRaw == "1" || trivyRaw == "yes"

	explicit := rawMode != "" || os.Getenv("WARRANT_CISA_KEV_URL") != "" || os.Getenv("WARRANT_OSV_API_URL") != "" || trivyRaw != ""
	return models.FeedRuntimeConfig{
		Mode:            mode,
		CISAKEVURL:      kevURL,
		KEVPollInterval: pollInt,
		OSVAPIURL:       osvURL,
		TrivyEnabled:    trivyEnabled,
		UpdatedAt:       time.Now().UTC(),
	}, explicit
}

// NewManager initializes the Live Feed Manager and persists initial runtime configuration.
func NewManager(ctx context.Context, store *db.Store, agentCP *agentcp.ControlPlane, onBroadcast func(string, any)) (*Manager, error) {
	envCfg, explicit := ConfigFromEnv()
	if explicit {
		if err := store.SaveFeedConfig(ctx, envCfg); err != nil {
			return nil, err
		}
	} else {
		if _, err := store.EnsureFeedConfig(ctx, envCfg); err != nil {
			return nil, err
		}
	}
	return &Manager{
		store:   store,
		agentCP: agentCP,
		httpClient: &http.Client{
			Timeout: 35 * time.Second,
		},
		onBroadcast: onBroadcast,
		wakeCh:      make(chan struct{}, 1),
	}, nil
}

// UpdateConfig updates runtime feed toggles (e.g., switching between offline enclave mode and live feeds).
func (m *Manager) UpdateConfig(ctx context.Context, next models.FeedRuntimeConfig) (*models.FeedRuntimeConfig, error) {
	next.Mode = strings.ToLower(strings.TrimSpace(next.Mode))
	if next.Mode != models.FeedModeOffline && next.Mode != models.FeedModeLive {
		return nil, errors.New("mode must be 'offline' or 'live'")
	}
	if strings.TrimSpace(next.CISAKEVURL) == "" {
		next.CISAKEVURL = DefaultCISAKEVURL
	}
	if strings.TrimSpace(next.KEVPollInterval) == "" {
		next.KEVPollInterval = DefaultKEVPollInterval
	}
	if _, err := time.ParseDuration(next.KEVPollInterval); err != nil {
		return nil, fmt.Errorf("invalid kev_poll_interval duration %q: %w", next.KEVPollInterval, err)
	}
	if strings.TrimSpace(next.OSVAPIURL) == "" {
		next.OSVAPIURL = DefaultOSVAPIURL
	}
	if err := m.store.SaveFeedConfig(ctx, next); err != nil {
		return nil, err
	}
	if next.Mode == models.FeedModeLive {
		select {
		case m.wakeCh <- struct{}{}:
		default:
		}
	}
	m.emitStatus(ctx)
	return &next, nil
}

// StartBackgroundPoller runs the periodic CISA KEV & OSV poller when WARRANT_FEED_MODE=live.
func (m *Manager) StartBackgroundPoller(ctx context.Context) {
	go func() {
		// Check immediately on startup if live mode is enabled
		if cfg, err := m.store.GetFeedConfig(ctx); err == nil && cfg.Mode == models.FeedModeLive {
			_, _ = m.SyncCISAKEV(ctx)
			_, _, _ = m.SyncOSV(ctx)
		}

		for {
			interval := time.Hour
			if cfg, err := m.store.GetFeedConfig(ctx); err == nil {
				if d, pErr := time.ParseDuration(cfg.KEVPollInterval); pErr == nil && d >= 30*time.Second {
					interval = d
				}
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-m.wakeCh:
				timer.Stop()
			case <-timer.C:
			}

			cfg, err := m.store.GetFeedConfig(ctx)
			if err != nil || cfg.Mode != models.FeedModeLive {
				continue
			}
			if _, err := m.SyncCISAKEV(ctx); err != nil {
				log.Printf("live CISA KEV background sync error: %v", err)
			}
			if _, _, err := m.SyncOSV(ctx); err != nil {
				log.Printf("live OSV background sync error: %v", err)
			}
		}
	}()
}

// SyncCISAKEV fetches the live CISA KEV JSON feed, sanitizes it through the isolated warrant-extractor,
// stores the catalog, and upgrades active Race Pipeline items matching live KEV CVEs.
func (m *Manager) SyncCISAKEV(ctx context.Context) (*models.FeedSyncRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, err := m.store.GetFeedConfig(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.Mode != models.FeedModeLive {
		return nil, errors.New("FEED_MODE_OFFLINE: set WARRANT_FEED_MODE=live (or toggle Live Mode in Console) before polling external feeds")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.CISAKEVURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "G1-Warrant-ControlPlane/1.0")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		run := m.recordErrorRun(ctx, "CISA_KEV", err)
		return &run, err
	}
	defer resp.Body.Close()
	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		run := m.recordErrorRun(ctx, "CISA_KEV", err)
		return &run, err
	}
	if resp.StatusCode >= 300 {
		httpErr := fmt.Errorf("CISA KEV endpoint returned HTTP %d", resp.StatusCode)
		run := m.recordErrorRun(ctx, "CISA_KEV", httpErr)
		return &run, httpErr
	}

	// Sanitize untrusted CISA KEV feed via zero-egress warrant-extractor (N4 governed)
	catalog, err := m.agentCP.ExtractCISAKEVGoverned(ctx, rawBytes)
	if err != nil {
		run := m.recordErrorRun(ctx, "CISA_KEV", err)
		return &run, err
	}

	if err := m.store.UpsertCISAKEVCatalog(ctx, catalog.Entries); err != nil {
		return nil, err
	}

	kevMap := make(map[string]models.ExtractedKEVEntry, len(catalog.Entries))
	for _, e := range catalog.Entries {
		kevMap[strings.ToUpper(e.CVEID)] = e
	}

	// Cross-check active Race Pipeline items and upgrade exploitation flags deterministically
	rems, _ := m.store.ListRemediations(ctx)
	upgraded := 0
	for i := range rems {
		r := &rems[i]
		if kevEntry, ok := kevMap[strings.ToUpper(r.CVEID)]; ok {
			if !r.IsKEV {
				r.IsKEV = true
				_ = m.store.UpsertRemediation(ctx, r)
				_ = m.store.AppendTrace(ctx, models.TraceEvent{
					TraceID:       "trc-" + uuid.NewString()[:8],
					RemediationID: r.RemediationID,
					Engine:        "N4",
					StepCode:      "CISA_KEV_LIVE_CATALOG_FLAGGED",
					Outcome:       "PASS",
					ActorOrToken:  "cisa-kev-poller",
					EvidenceHash:  catalog.TypedOutputSHA256,
					Fields: map[string]string{
						"catalog_version": catalog.CatalogVersion,
						"date_added":      kevEntry.DateAdded,
						"ransomware":      kevEntry.RansomwareCampaign,
					},
					OccurredAt: time.Now().UTC(),
				})
				if m.onBroadcast != nil {
					m.onBroadcast("REMEDIATION_UPDATED", r)
				}
			}
			upgraded++
		}
	}

	run := models.FeedSyncRun{
		SyncID:            "syn-" + uuid.NewString()[:8],
		FeedSource:        "CISA_KEV",
		Status:            "SUCCESS",
		CatalogVersion:    catalog.CatalogVersion,
		ItemsIngested:     len(catalog.Entries),
		KEVMatches:        upgraded,
		RawInputSHA256:    catalog.RawInputSHA256,
		TypedOutputSHA256: catalog.TypedOutputSHA256,
		ExtractorDigest:   catalog.ExtractorDigest,
		SyncedAt:          time.Now().UTC(),
	}
	_ = m.store.RecordFeedSyncRun(ctx, run)
	m.emitStatus(ctx)
	return &run, nil
}

// SyncOSV queries Google OSV.dev (/v1/querybatch + /v1/vulns/{id}) against registered estate SBOM PURLs,
// pipes the untrusted responses through warrant-extractor, and cross-checks CISA KEV status.
func (m *Manager) SyncOSV(ctx context.Context) (*models.FeedSyncRun, []models.ExtractedOSVEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, err := m.store.GetFeedConfig(ctx)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Mode != models.FeedModeLive {
		return nil, nil, errors.New("FEED_MODE_OFFLINE: set WARRANT_FEED_MODE=live before querying Google OSV.dev")
	}

	svcs, err := m.store.ListEstateServices(ctx)
	if err != nil {
		return nil, nil, err
	}

	type purlTarget struct {
		serviceID string
		purl      string
	}
	var targets []purlTarget
	for _, svc := range svcs {
		for _, p := range svc.SBOMPURLs {
			if strings.HasPrefix(p, "pkg:") {
				targets = append(targets, purlTarget{serviceID: svc.ServiceID, purl: p})
			}
		}
	}
	if len(targets) == 0 {
		return nil, nil, errors.New("no SBOM PURLs registered on estate workloads")
	}

	type osvQuery struct {
		Package map[string]string `json:"package"`
	}
	queries := make([]osvQuery, 0, len(targets))
	for _, t := range targets {
		queries = append(queries, osvQuery{Package: map[string]string{"purl": t.purl}})
	}
	reqBody, _ := json.Marshal(map[string]any{"queries": queries})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.OSVAPIURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		run := m.recordErrorRun(ctx, "GOOGLE_OSV", err)
		return &run, nil, err
	}
	defer resp.Body.Close()
	batchBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		run := m.recordErrorRun(ctx, "GOOGLE_OSV", err)
		return &run, nil, err
	}
	if resp.StatusCode >= 300 {
		httpErr := fmt.Errorf("OSV API returned HTTP %d", resp.StatusCode)
		run := m.recordErrorRun(ctx, "GOOGLE_OSV", httpErr)
		return &run, nil, httpErr
	}

	var batchResp struct {
		Results []struct {
			Vulns []json.RawMessage `json:"vulns"`
		} `json:"results"`
	}
	if err := json.Unmarshal(batchBytes, &batchResp); err != nil {
		run := m.recordErrorRun(ctx, "GOOGLE_OSV", err)
		return &run, nil, err
	}

	// Derive base OSV URL for hydrating /vulns/{id} details if querybatch returned minimal stubs
	osvBase := strings.TrimSuffix(strings.TrimRight(cfg.OSVAPIURL, "/"), "/querybatch")
	hydratedCache := map[string]json.RawMessage{}
	var bundleItems []extractor.UntrustedOSVInputItem

	for idx, res := range batchResp.Results {
		if idx >= len(targets) {
			break
		}
		tgt := targets[idx]
		for vIdx, rawV := range res.Vulns {
			if vIdx >= 3 {
				break // top 3 advisories per package PURL
			}
			var stub struct {
				ID      string   `json:"id"`
				Aliases []string `json:"aliases"`
			}
			if json.Unmarshal(rawV, &stub) != nil || stub.ID == "" {
				continue
			}
			fullVuln := rawV
			if len(stub.Aliases) == 0 && len(hydratedCache) < 18 {
				if cached, ok := hydratedCache[stub.ID]; ok {
					fullVuln = cached
				} else if detail, hErr := m.fetchOSVVulnDetail(ctx, osvBase+"/vulns/"+stub.ID); hErr == nil {
					hydratedCache[stub.ID] = detail
					fullVuln = detail
				}
			}
			bundleItems = append(bundleItems, extractor.UntrustedOSVInputItem{
				ServiceID:   tgt.serviceID,
				PackagePURL: tgt.purl,
				Vuln:        fullVuln,
			})
		}
	}

	rawBundle, _ := json.Marshal(map[string]any{"items": bundleItems})
	osvReport, err := m.agentCP.ExtractOSVBundleGoverned(ctx, rawBundle)
	if err != nil {
		run := m.recordErrorRun(ctx, "GOOGLE_OSV", err)
		return &run, nil, err
	}

	kevSet, _ := m.store.LookupCISAKEVSet(ctx)
	kevMatches := 0
	for i := range osvReport.Advisories {
		if _, ok := kevSet[strings.ToUpper(osvReport.Advisories[i].CVEID)]; ok {
			osvReport.Advisories[i].IsKEV = true
			kevMatches++
		}
	}

	if err := m.store.UpsertOSVAdvisories(ctx, osvReport.Advisories); err != nil {
		return nil, nil, err
	}

	run := models.FeedSyncRun{
		SyncID:            "syn-" + uuid.NewString()[:8],
		FeedSource:        "GOOGLE_OSV",
		Status:            "SUCCESS",
		ItemsIngested:     len(osvReport.Advisories),
		KEVMatches:        kevMatches,
		RawInputSHA256:    osvReport.RawInputSHA256,
		TypedOutputSHA256: osvReport.TypedOutputSHA256,
		ExtractorDigest:   osvReport.ExtractorDigest,
		SyncedAt:          time.Now().UTC(),
	}
	_ = m.store.RecordFeedSyncRun(ctx, run)
	m.emitStatus(ctx)
	return &run, osvReport.Advisories, nil
}

// RecordTrivyIntake logs a completed Trivy sidecar SARIF intake in feed_sync_runs.
func (m *Manager) RecordTrivyIntake(ctx context.Context, set *models.ExtractedFindingSet, kevMatches int) {
	run := models.FeedSyncRun{
		SyncID:            "syn-" + uuid.NewString()[:8],
		FeedSource:        "TRIVY_SARIF",
		Status:            "SUCCESS",
		CatalogVersion:    set.ScannerToolID,
		ItemsIngested:     len(set.Findings),
		KEVMatches:        kevMatches,
		RawInputSHA256:    set.RawInputSHA256,
		TypedOutputSHA256: set.TypedOutputSHA256,
		ExtractorDigest:   set.ExtractorDigest,
		SyncedAt:          time.Now().UTC(),
	}
	_ = m.store.RecordFeedSyncRun(ctx, run)
	m.emitStatus(ctx)
}

func (m *Manager) fetchOSVVulnDetail(ctx context.Context, url string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

func (m *Manager) recordErrorRun(ctx context.Context, source string, err error) models.FeedSyncRun {
	run := models.FeedSyncRun{
		SyncID:       "syn-" + uuid.NewString()[:8],
		FeedSource:   source,
		Status:       "ERROR",
		ErrorMessage: err.Error(),
		SyncedAt:     time.Now().UTC(),
	}
	_ = m.store.RecordFeedSyncRun(ctx, run)
	m.emitStatus(ctx)
	return run
}

func (m *Manager) emitStatus(ctx context.Context) {
	if m.onBroadcast != nil {
		if st, err := m.store.GetLiveFeedStatus(ctx); err == nil {
			m.onBroadcast("FEED_STATUS_UPDATED", st)
		}
	}
}
