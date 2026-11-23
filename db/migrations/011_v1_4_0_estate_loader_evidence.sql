-- =============================================================================
-- G1-Warrant v1.4.0 Migration 011:
--   Estate Loader: Bounded Decision-Time Estate Reading Evidence (WORM, Hash-Chained)
--   & Standing Warrant Clone-Source Declaration (Zero Asset Replication Doctrine)
-- =============================================================================

ALTER TABLE warrant_envelopes
    ADD COLUMN IF NOT EXISTS clone_sources_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS estate_snapshot_sha256 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS estate_drift_policy TEXT NOT NULL DEFAULT 'RECORD_ONLY',
    ADD COLUMN IF NOT EXISTS estate_drift_tolerance_pct DOUBLE PRECISION NOT NULL DEFAULT 10.0,
    ADD COLUMN IF NOT EXISTS max_estate_staleness_seconds BIGINT NOT NULL DEFAULT 0;

-- Append-Only Hash-Chained Estate Read Evidence (stores ONLY bounded summary digests & snapshot hashes;
-- ZERO per-host or shadow asset-inventory mirror tables are ever created).
CREATE TABLE IF NOT EXISTS estate_read_evidence (
    seq_no                    BIGSERIAL PRIMARY KEY,
    evidence_id               TEXT UNIQUE NOT NULL,
    source_system             TEXT NOT NULL,
    source_tier               TEXT NOT NULL,
    handler_family            TEXT NOT NULL,
    phase                     TEXT NOT NULL,
    warrant_id                TEXT NOT NULL DEFAULT '',
    remediation_id            TEXT NOT NULL DEFAULT '',
    query_identity            TEXT NOT NULL,
    class_membership_count    INTEGER NOT NULL DEFAULT 0,
    os_dist_summary_json      JSONB NOT NULL DEFAULT '[]'::jsonb,
    sw_dist_summary_json      JSONB NOT NULL DEFAULT '[]'::jsonb,
    candidate_sources_json    JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_freshness_at       TIMESTAMPTZ NOT NULL,
    source_freshness_age_sec  BIGINT NOT NULL DEFAULT 0,
    observed_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    snapshot_sha256           TEXT NOT NULL,
    prev_hash                 TEXT NOT NULL,
    entry_hash                TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_estate_read_evidence_snapshot ON estate_read_evidence (snapshot_sha256, seq_no DESC);
CREATE INDEX IF NOT EXISTS idx_estate_read_evidence_warrant ON estate_read_evidence (warrant_id, seq_no DESC);
CREATE INDEX IF NOT EXISTS idx_estate_read_evidence_source ON estate_read_evidence (source_system, seq_no DESC);

DROP TRIGGER IF EXISTS trg_worm_estate_read_evidence ON estate_read_evidence;
CREATE TRIGGER trg_worm_estate_read_evidence
BEFORE UPDATE OR DELETE ON estate_read_evidence
FOR EACH ROW EXECUTE FUNCTION enforce_append_only_ledger();
