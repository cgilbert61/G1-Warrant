package db

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/models"
	"github.com/jackc/pgx/v5"
)

// EnsureFeedConfig initializes feed_runtime_config from defaults if not yet present, or returns existing config.
func (s *Store) EnsureFeedConfig(ctx context.Context, def models.FeedRuntimeConfig) (models.FeedRuntimeConfig, error) {
	if def.UpdatedAt.IsZero() {
		def.UpdatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_runtime_config (singleton_id, mode, cisa_kev_url, kev_poll_interval, osv_api_url, trivy_enabled, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6)
		ON CONFLICT (singleton_id) DO NOTHING
	`, def.Mode, def.CISAKEVURL, def.KEVPollInterval, def.OSVAPIURL, def.TrivyEnabled, def.UpdatedAt)
	if err != nil {
		return def, err
	}
	return s.GetFeedConfig(ctx)
}

// GetFeedConfig fetches the singleton runtime feed configuration.
func (s *Store) GetFeedConfig(ctx context.Context) (models.FeedRuntimeConfig, error) {
	var cfg models.FeedRuntimeConfig
	err := s.pool.QueryRow(ctx, `
		SELECT mode, cisa_kev_url, kev_poll_interval, osv_api_url, trivy_enabled, updated_at
		FROM feed_runtime_config WHERE singleton_id = 1
	`).Scan(&cfg.Mode, &cfg.CISAKEVURL, &cfg.KEVPollInterval, &cfg.OSVAPIURL, &cfg.TrivyEnabled, &cfg.UpdatedAt)
	return cfg, err
}

// SaveFeedConfig updates the singleton runtime feed configuration.
func (s *Store) SaveFeedConfig(ctx context.Context, cfg models.FeedRuntimeConfig) error {
	cfg.UpdatedAt = time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_runtime_config (singleton_id, mode, cisa_kev_url, kev_poll_interval, osv_api_url, trivy_enabled, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6)
		ON CONFLICT (singleton_id) DO UPDATE SET
			mode = EXCLUDED.mode,
			cisa_kev_url = EXCLUDED.cisa_kev_url,
			kev_poll_interval = EXCLUDED.kev_poll_interval,
			osv_api_url = EXCLUDED.osv_api_url,
			trivy_enabled = EXCLUDED.trivy_enabled,
			updated_at = EXCLUDED.updated_at
	`, cfg.Mode, cfg.CISAKEVURL, cfg.KEVPollInterval, cfg.OSVAPIURL, cfg.TrivyEnabled, cfg.UpdatedAt)
	return err
}

// UpsertCISAKEVCatalog batch-upserts sanitized CISA KEV entries into cisa_kev_catalog.
func (s *Store) UpsertCISAKEVCatalog(ctx context.Context, entries []models.ExtractedKEVEntry) error {
	if len(entries) == 0 {
		return nil
	}
	now := time.Now().UTC()
	batch := &pgx.Batch{}
	for _, e := range entries {
		batch.Queue(`
			INSERT INTO cisa_kev_catalog (cve_id, cwe_id, date_added, due_date, ransomware_campaign, synced_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (cve_id) DO UPDATE SET
				cwe_id = EXCLUDED.cwe_id,
				date_added = EXCLUDED.date_added,
				due_date = EXCLUDED.due_date,
				ransomware_campaign = EXCLUDED.ransomware_campaign,
				synced_at = EXCLUDED.synced_at
		`, strings.ToUpper(e.CVEID), e.CWEID, e.DateAdded, e.DueDate, e.RansomwareCampaign, now)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range entries {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// LookupCISAKEVSet returns a fast lookup map of all synced CISA KEV CVE IDs.
func (s *Store) LookupCISAKEVSet(ctx context.Context) (map[string]models.ExtractedKEVEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT cve_id, cwe_id, date_added, due_date, ransomware_campaign
		FROM cisa_kev_catalog
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]models.ExtractedKEVEntry)
	for rows.Next() {
		var e models.ExtractedKEVEntry
		if err := rows.Scan(&e.CVEID, &e.CWEID, &e.DateAdded, &e.DueDate, &e.RansomwareCampaign); err != nil {
			return nil, err
		}
		out[strings.ToUpper(e.CVEID)] = e
	}
	return out, rows.Err()
}

// UpsertOSVAdvisories stores sanitized OSV advisories in osv_advisories.
func (s *Store) UpsertOSVAdvisories(ctx context.Context, list []models.ExtractedOSVEntry) error {
	if len(list) == 0 {
		return nil
	}
	now := time.Now().UTC()
	batch := &pgx.Batch{}
	for _, a := range list {
		batch.Queue(`
			INSERT INTO osv_advisories (osv_id, cve_id, cwe_id, service_id, package_purl, cvss_score, fixed_version, is_kev, synced_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (osv_id, service_id, package_purl) DO UPDATE SET
				cve_id = EXCLUDED.cve_id,
				cvss_score = EXCLUDED.cvss_score,
				fixed_version = EXCLUDED.fixed_version,
				is_kev = EXCLUDED.is_kev,
				synced_at = EXCLUDED.synced_at
		`, a.OSVID, a.CVEID, a.CWEID, a.ServiceID, a.PackagePURL, a.CVSSScore, a.FixedVersion, a.IsKEV, now)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range list {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// ListOSVAdvisories lists stored OSV advisories ordered by KEV status and CVSS score.
func (s *Store) ListOSVAdvisories(ctx context.Context) ([]models.ExtractedOSVEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT osv_id, cve_id, cwe_id, service_id, package_purl, cvss_score, fixed_version, is_kev
		FROM osv_advisories
		ORDER BY is_kev DESC, cvss_score DESC, osv_id ASC LIMIT 100
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.ExtractedOSVEntry{}
	for rows.Next() {
		var a models.ExtractedOSVEntry
		if err := rows.Scan(&a.OSVID, &a.CVEID, &a.CWEID, &a.ServiceID, &a.PackagePURL, &a.CVSSScore, &a.FixedVersion, &a.IsKEV); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RecordFeedSyncRun inserts a feed_sync_runs audit row.
func (s *Store) RecordFeedSyncRun(ctx context.Context, run models.FeedSyncRun) error {
	if run.SyncedAt.IsZero() {
		run.SyncedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_sync_runs (
			sync_id, feed_source, status, catalog_version, items_ingested, kev_matches,
			raw_input_sha256, typed_output_sha256, extractor_digest, error_message, synced_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`,
		run.SyncID, run.FeedSource, run.Status, run.CatalogVersion, run.ItemsIngested, run.KEVMatches,
		run.RawInputSHA256, run.TypedOutputSHA256, run.ExtractorDigest, run.ErrorMessage, run.SyncedAt,
	)
	return err
}

// GetLiveFeedStatus aggregates current feed config, CISA KEV catalog count, OSV advisories, and sync history.
func (s *Store) GetLiveFeedStatus(ctx context.Context) (*models.LiveFeedStatus, error) {
	cfg, err := s.GetFeedConfig(ctx)
	if err != nil {
		return nil, err
	}
	var kevCount int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM cisa_kev_catalog`).Scan(&kevCount)

	var latestVer string
	var lastSync time.Time
	var lastSyncPtr *time.Time
	err = s.pool.QueryRow(ctx, `
		SELECT catalog_version, synced_at FROM feed_sync_runs
		WHERE feed_source = 'CISA_KEV' AND status = 'SUCCESS'
		ORDER BY synced_at DESC LIMIT 1
	`).Scan(&latestVer, &lastSync)
	if err == nil {
		lastSyncPtr = &lastSync
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	osvList, _ := s.ListOSVAdvisories(ctx)

	rows, err := s.pool.Query(ctx, `
		SELECT sync_id, feed_source, status, catalog_version, items_ingested, kev_matches,
		       raw_input_sha256, typed_output_sha256, extractor_digest, error_message, synced_at
		FROM feed_sync_runs ORDER BY synced_at DESC LIMIT 25
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := []models.FeedSyncRun{}
	for rows.Next() {
		var r models.FeedSyncRun
		if err := rows.Scan(
			&r.SyncID, &r.FeedSource, &r.Status, &r.CatalogVersion, &r.ItemsIngested, &r.KEVMatches,
			&r.RawInputSHA256, &r.TypedOutputSHA256, &r.ExtractorDigest, &r.ErrorMessage, &r.SyncedAt,
		); err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}

	return &models.LiveFeedStatus{
		Config:               cfg,
		CISAKEVCatalogCount:  kevCount,
		LatestCatalogVersion: latestVer,
		LastKEVSyncAt:        lastSyncPtr,
		OSVAdvisories:        osvList,
		RecentSyncRuns:       runs,
	}, nil
}
