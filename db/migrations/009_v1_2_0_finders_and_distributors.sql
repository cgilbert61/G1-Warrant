-- =============================================================================
-- G1-Warrant v1.2.0 Migration 009:
--   WN-7 Finder Translation Layer (Asset Identity Aliases & Fail-Visible Unmapped Advisories)
--   WN-8 Distributor Translation Layer (Immutable Pre-Wave DeploymentOrders & Per-Asset Results)
-- =============================================================================

CREATE OR REPLACE FUNCTION enforce_append_only_ledger()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABLE_LEDGER_VIOLATION: UPDATE or DELETE prohibited on WORM table %', TG_TABLE_NAME;
END;
$$;

CREATE TABLE IF NOT EXISTS asset_identity_aliases (
    alias_key         TEXT PRIMARY KEY,
    alias_type        TEXT NOT NULL,
    service_id        TEXT NOT NULL,
    asset_key         TEXT NOT NULL,
    hostname          TEXT NOT NULL DEFAULT '',
    ipv4              TEXT NOT NULL DEFAULT '',
    ipv6              TEXT NOT NULL DEFAULT '',
    scanner_asset_id  TEXT NOT NULL DEFAULT '',
    cloud_instance_id TEXT NOT NULL DEFAULT '',
    platform_family   TEXT NOT NULL DEFAULT 'CONTAINER_LINUX',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_aliases_service_id ON asset_identity_aliases (service_id);
CREATE INDEX IF NOT EXISTS idx_asset_aliases_asset_key ON asset_identity_aliases (asset_key);

ALTER TABLE warrant_envelopes
    ADD COLUMN IF NOT EXISTS scope_assets JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS authorized_vendor_detections JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE remediation_items
    ADD COLUMN IF NOT EXISTS finder_vendor TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS vendor_detection_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cve_mapping_status TEXT NOT NULL DEFAULT 'MAPPED',
    ADD COLUMN IF NOT EXISTS normalized_detection_state TEXT NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN IF NOT EXISTS asset_identity_json JSONB,
    ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS distributor_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS latest_order_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS closure_completeness TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS targeted_asset_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS landed_asset_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS failed_asset_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pending_asset_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS reboot_waiting_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rolled_back_asset_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE attestation_records
    ADD COLUMN IF NOT EXISTS closure_completeness TEXT NOT NULL DEFAULT 'FULL',
    ADD COLUMN IF NOT EXISTS targeted_asset_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS landed_asset_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS failed_asset_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS pending_asset_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS reboot_waiting_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS distributor_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS distributor_order_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS distributor_report_sha256 TEXT NOT NULL DEFAULT '';

-- Immutable Pre-Wave-1 DeploymentOrders (RollbackInstruction persisted BEFORE Wave 1 executes; WORM-protected)
CREATE TABLE IF NOT EXISTS deployment_orders (
    seq_no                    BIGSERIAL PRIMARY KEY,
    order_id                  TEXT UNIQUE NOT NULL,
    warrant_id                TEXT NOT NULL,
    task_token_id             TEXT NOT NULL,
    remediation_id            TEXT NOT NULL,
    service_id                TEXT NOT NULL,
    distributor_id            TEXT NOT NULL,
    platform_family           TEXT NOT NULL,
    fix_identity_json         JSONB NOT NULL,
    target_assets_json        JSONB NOT NULL,
    rollout_plan_json         JSONB NOT NULL,
    rollback_instruction_json JSONB NOT NULL,
    native_job_ref            TEXT NOT NULL DEFAULT '',
    wave_number               INTEGER NOT NULL DEFAULT 1,
    total_waves               INTEGER NOT NULL DEFAULT 1,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deployment_orders_remediation ON deployment_orders (remediation_id, seq_no DESC);

DROP TRIGGER IF EXISTS trg_worm_deployment_orders ON deployment_orders;
CREATE TRIGGER trg_worm_deployment_orders
BEFORE UPDATE OR DELETE ON deployment_orders
FOR EACH ROW EXECUTE FUNCTION enforce_append_only_ledger();

-- Append-Only Per-Asset DeploymentResults & Native Rollback Telemetry
CREATE TABLE IF NOT EXISTS deployment_results (
    seq_no                        BIGSERIAL PRIMARY KEY,
    result_id                     TEXT UNIQUE NOT NULL,
    order_id                      TEXT NOT NULL REFERENCES deployment_orders (order_id),
    remediation_id                TEXT NOT NULL DEFAULT '',
    distributor_id                TEXT NOT NULL,
    native_job_ref                TEXT NOT NULL DEFAULT '',
    wave_number                   INTEGER NOT NULL DEFAULT 1,
    evidence_granularity          TEXT NOT NULL,
    asset_results_json            JSONB NOT NULL DEFAULT '[]'::jsonb,
    targeted_count                INTEGER NOT NULL DEFAULT 0,
    landed_count                  INTEGER NOT NULL DEFAULT 0,
    failed_count                  INTEGER NOT NULL DEFAULT 0,
    pending_count                 INTEGER NOT NULL DEFAULT 0,
    reboot_waiting_count          INTEGER NOT NULL DEFAULT 0,
    unreachable_count             INTEGER NOT NULL DEFAULT 0,
    rolled_back_count             INTEGER NOT NULL DEFAULT 0,
    stalled                       BOOLEAN NOT NULL DEFAULT FALSE,
    is_rollback                   BOOLEAN NOT NULL DEFAULT FALSE,
    rollback_reason               TEXT NOT NULL DEFAULT '',
    raw_distributor_report_sha256 TEXT NOT NULL,
    observed_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deployment_results_order ON deployment_results (order_id, seq_no DESC);
CREATE INDEX IF NOT EXISTS idx_deployment_results_remediation ON deployment_results (remediation_id, seq_no DESC);

DROP TRIGGER IF EXISTS trg_worm_deployment_results ON deployment_results;
CREATE TRIGGER trg_worm_deployment_results
BEFORE UPDATE OR DELETE ON deployment_results
FOR EACH ROW EXECUTE FUNCTION enforce_append_only_ledger();
