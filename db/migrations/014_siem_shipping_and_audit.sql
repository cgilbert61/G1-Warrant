-- =============================================================================
-- G1-Warrant Migration 014:
--   SIEM Multi-Destination Outbox Cursors, UI-Driven Destination Registry
--   (Credential-Reference-Only, Zero Raw Secrets) & WORM Hash-Chained Config Audit
-- =============================================================================

CREATE TABLE IF NOT EXISTS siem_destinations (
    destination_id        TEXT PRIMARY KEY,
    display_name          TEXT NOT NULL,
    siem_vendor           TEXT NOT NULL CHECK (
        siem_vendor IN (
            'splunk_es',
            'microsoft_sentinel',
            'ibm_qradar',
            'google_secops',
            'crowdstrike_logscale',
            'elastic_security',
            'cortex_xsiam',
            'exabeam',
            'logrhythm',
            'sumo_logic',
            'fortisiem',
            'arcsight',
            'generic_fallback'
        )
    ),
    endpoint              TEXT NOT NULL,
    credential_ref        TEXT NOT NULL DEFAULT 'none://' CHECK (
        credential_ref = 'none://'
        OR credential_ref LIKE 'env://%'
        OR credential_ref LIKE 'file://%'
        OR credential_ref LIKE 'k8s-secret://%'
        OR credential_ref LIKE 'aws-sm://%'
        OR credential_ref LIKE 'azure-kv://%'
        OR credential_ref LIKE 'gcp-sm://%'
    ),
    format                TEXT NOT NULL,
    vendor_options_json   JSONB NOT NULL DEFAULT '{}'::jsonb,
    record_types          JSONB NOT NULL DEFAULT '[]'::jsonb,
    batch_size            INTEGER NOT NULL DEFAULT 50 CHECK (batch_size >= 1 AND batch_size <= 500),
    schedule_seconds      INTEGER NOT NULL DEFAULT 10 CHECK (schedule_seconds >= 1 AND schedule_seconds <= 3600),
    enabled               BOOLEAN NOT NULL DEFAULT TRUE,
    console_views         JSONB NOT NULL DEFAULT '["VIEW1_RACE","VIEW4_CONTAINMENT","VIEW5_AUDITOR"]'::jsonb,
    sent_count            BIGINT NOT NULL DEFAULT 0,
    queued_count          BIGINT NOT NULL DEFAULT 0,
    failed_count          BIGINT NOT NULL DEFAULT 0,
    retry_count           BIGINT NOT NULL DEFAULT 0,
    last_sent_at          TIMESTAMPTZ,
    last_error            TEXT NOT NULL DEFAULT '',
    last_error_at         TIMESTAMPTZ,
    last_transport_status TEXT NOT NULL DEFAULT '',
    next_attempt_at       TIMESTAMPTZ,
    created_by            TEXT NOT NULL DEFAULT '',
    updated_by            TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS siem_stream_cursors (
    destination_id  TEXT NOT NULL REFERENCES siem_destinations (destination_id) ON DELETE CASCADE,
    stream_name     TEXT NOT NULL,
    last_acked_seq  BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (destination_id, stream_name)
);

-- Append-Only WORM Hash-Chained Audit Ledger for SIEM Destination Configuration Changes
CREATE TABLE IF NOT EXISTS siem_config_audit (
    seq_no               BIGSERIAL PRIMARY KEY,
    audit_id             TEXT NOT NULL UNIQUE,
    destination_id       TEXT NOT NULL,
    siem_vendor          TEXT NOT NULL,
    action               TEXT NOT NULL CHECK (
        action IN ('CREATE_DESTINATION', 'UPDATE_DESTINATION', 'TOGGLE_DESTINATION', 'DELETE_DESTINATION')
    ),
    actor                TEXT NOT NULL,
    config_snapshot_json JSONB NOT NULL,
    config_sha256        TEXT NOT NULL,
    prev_hash            TEXT NOT NULL,
    entry_hash           TEXT NOT NULL UNIQUE,
    occurred_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_siem_config_audit_dest ON siem_config_audit (destination_id, seq_no DESC);

DROP TRIGGER IF EXISTS trg_worm_siem_config_audit ON siem_config_audit;
CREATE TRIGGER trg_worm_siem_config_audit
BEFORE UPDATE OR DELETE ON siem_config_audit
FOR EACH ROW EXECUTE FUNCTION enforce_append_only_ledger();
