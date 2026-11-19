-- 003_architectural_hardening.sql
-- Adds External Merkle Transparency Checkpoints, Assurance Tiers, Graduated Autonomy Tiers,
-- Containment Modes, and Quarantined Emergency Rollback state tracking.

ALTER TABLE estate_services
    ADD COLUMN IF NOT EXISTS autonomy_tier TEXT NOT NULL DEFAULT 'TIER_3_CONTAIN_AND_CAB',
    ADD COLUMN IF NOT EXISTS shadow_db_mode TEXT NOT NULL DEFAULT 'NONE',
    ADD COLUMN IF NOT EXISTS volatile_json_paths JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE warrant_envelopes
    ADD COLUMN IF NOT EXISTS allow_guarded_canary BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS min_canary_samples INTEGER NOT NULL DEFAULT 500,
    ADD COLUMN IF NOT EXISTS stage_dwell_seconds INTEGER NOT NULL DEFAULT 300;

ALTER TABLE containment_bridges
    ADD COLUMN IF NOT EXISTS containment_mode TEXT NOT NULL DEFAULT 'ZERO_PROSE_EGRESS_MESH_QUARANTINE',
    ADD COLUMN IF NOT EXISTS rulepack_id TEXT NOT NULL DEFAULT '';

ALTER TABLE admission_lockouts
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ENFORCED',
    ADD COLUMN IF NOT EXISTS suspended_reason TEXT NOT NULL DEFAULT '';

ALTER TABLE remediation_items
    ADD COLUMN IF NOT EXISTS assurance_tier TEXT NOT NULL DEFAULT 'PENDING';

ALTER TABLE remediation_items
    DROP CONSTRAINT IF EXISTS remediation_items_status_health_check;

ALTER TABLE remediation_items
    ADD CONSTRAINT remediation_items_status_health_check
    CHECK (status_health IN ('NORMAL', 'BRIDGED', 'EXCEPTION_ROUTED', 'ROLLBACK_FAILED', 'QUARANTINED_ROLLBACK', 'DRIFT_VIOLATION', 'FROZEN', 'ATTESTED'));

ALTER TABLE attestation_records
    ADD COLUMN IF NOT EXISTS assurance_tier TEXT NOT NULL DEFAULT 'ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM',
    ADD COLUMN IF NOT EXISTS signer_backend TEXT NOT NULL DEFAULT 'EPHEMERAL_OR_KMS';

-- External Transparency Checkpoint Log (anchors local PostgreSQL hash-chain heads to external WORM / Rekor / S3 Object Lock)
CREATE TABLE IF NOT EXISTS ledger_checkpoints (
    checkpoint_id           TEXT PRIMARY KEY,
    warrant_head_hash       TEXT NOT NULL,
    warrant_row_count       INTEGER NOT NULL,
    agent_head_hash         TEXT NOT NULL,
    agent_row_count         INTEGER NOT NULL,
    attestation_head_hash   TEXT NOT NULL,
    attestation_row_count   INTEGER NOT NULL,
    combined_merkle_root    TEXT NOT NULL UNIQUE,
    dsse_envelope           JSONB NOT NULL,
    external_anchor_target  TEXT NOT NULL,
    external_receipt_hash   TEXT NOT NULL,
    anchored_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS trg_immutable_ledger_checkpoints ON ledger_checkpoints;
CREATE TRIGGER trg_immutable_ledger_checkpoints
BEFORE UPDATE OR DELETE ON ledger_checkpoints
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();
