-- Migration 012: ARTEX-Inspired P0 Hardening
-- 1. Persisted vendor connector / distributor configurations with per-column AAD AES-256-GCM encryption on value_text.

CREATE TABLE IF NOT EXISTS vendor_connector_configs (
    env_key TEXT PRIMARY KEY,
    source_system TEXT NOT NULL DEFAULT '',
    is_secret BOOLEAN NOT NULL DEFAULT FALSE,
    value_text TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vendor_connector_configs_source
    ON vendor_connector_configs (source_system);
