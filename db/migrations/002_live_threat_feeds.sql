-- G1-Warrant Optional Live Threat & Scanner Feed Schema (CISA KEV, Google OSV.dev, Trivy Sidecar)

ALTER TABLE estate_services
ADD COLUMN IF NOT EXISTS sbom_purls JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE TABLE IF NOT EXISTS feed_runtime_config (
    singleton_id        INTEGER PRIMARY KEY DEFAULT 1 CHECK (singleton_id = 1),
    mode                TEXT NOT NULL CHECK (mode IN ('offline', 'live')),
    cisa_kev_url        TEXT NOT NULL,
    kev_poll_interval   TEXT NOT NULL,
    osv_api_url         TEXT NOT NULL,
    trivy_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cisa_kev_catalog (
    cve_id              TEXT PRIMARY KEY,
    cwe_id              TEXT NOT NULL,
    date_added          TEXT NOT NULL,
    due_date            TEXT NOT NULL,
    ransomware_campaign TEXT NOT NULL,
    synced_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS osv_advisories (
    osv_id          TEXT NOT NULL,
    cve_id          TEXT NOT NULL,
    cwe_id          TEXT NOT NULL,
    service_id      TEXT NOT NULL,
    package_purl    TEXT NOT NULL,
    cvss_score      DOUBLE PRECISION NOT NULL,
    fixed_version   TEXT NOT NULL,
    is_kev          BOOLEAN NOT NULL DEFAULT FALSE,
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (osv_id, service_id, package_purl)
);

CREATE TABLE IF NOT EXISTS feed_sync_runs (
    sync_id             TEXT PRIMARY KEY,
    feed_source         TEXT NOT NULL CHECK (feed_source IN ('CISA_KEV', 'GOOGLE_OSV', 'TRIVY_SARIF')),
    status              TEXT NOT NULL CHECK (status IN ('SUCCESS', 'ERROR', 'SKIPPED_OFFLINE')),
    catalog_version     TEXT NOT NULL DEFAULT '',
    items_ingested      INTEGER NOT NULL DEFAULT 0,
    kev_matches         INTEGER NOT NULL DEFAULT 0,
    raw_input_sha256    TEXT NOT NULL DEFAULT '',
    typed_output_sha256 TEXT NOT NULL DEFAULT '',
    extractor_digest    TEXT NOT NULL DEFAULT '',
    error_message       TEXT NOT NULL DEFAULT '',
    synced_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_feed_sync_runs_ts ON feed_sync_runs(synced_at DESC);
