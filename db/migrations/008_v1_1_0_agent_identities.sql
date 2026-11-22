-- 008_v1_1_0_agent_identities.sql
-- G1-Warrant v1.1.0 Agent Workload Identity, Commissioning Function Governance,
-- Event-Driven IGA Orphan Quarantine & 9-Chain Merkle Transparency Anchoring:
--   1. Append-only WORM hash-chained commissioning_functions table (versioned per function_id)
--   2. Append-only WORM hash-chained agent_identities table (unique Ed25519 keys, 3-Way Builder != Commissioner SoD)
--   3. Append-only WORM hash-chained agent_lifecycle_events table (IGA transfers, grace escalations, recertifications, revocations)
--   4. Composite delegation & commissioning lineage columns on agent_action_ledger
--   5. 9-Chain Combined Merkle Root V3 columns on ledger_checkpoints (preserving V1 & V2 upgrade verification)

CREATE SEQUENCE IF NOT EXISTS authority_event_seq;

-- 1. Commissioning Functions (Append-Only WORM Ledger; latest row per function_id is active revision)
CREATE TABLE IF NOT EXISTS commissioning_functions (
    seq_no                    BIGSERIAL PRIMARY KEY,
    authority_seq             BIGINT NOT NULL DEFAULT nextval('authority_event_seq'),
    function_id               TEXT NOT NULL,
    display_name              TEXT NOT NULL,
    owning_org_unit           TEXT NOT NULL,
    cost_center               TEXT NOT NULL DEFAULT '',
    primary_so_principal_id   TEXT NOT NULL,
    secondary_so_principal_id TEXT NOT NULL DEFAULT '',
    primary_ao_principal_id   TEXT NOT NULL,
    secondary_ao_principal_id TEXT NOT NULL DEFAULT '',
    escalation_contact        TEXT NOT NULL,
    orphan_grace_hours        INTEGER NOT NULL DEFAULT 168 CHECK (orphan_grace_hours >= 0 AND orphan_grace_hours <= 336),
    lineage_mode              TEXT NOT NULL,
    governance_dsse           JSONB,
    prev_hash                 TEXT NOT NULL,
    entry_hash                TEXT NOT NULL UNIQUE,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_commissioning_functions_latest
    ON commissioning_functions (function_id, seq_no DESC);

DROP TRIGGER IF EXISTS trg_immutable_commissioning_functions ON commissioning_functions;
CREATE TRIGGER trg_immutable_commissioning_functions
BEFORE UPDATE OR DELETE ON commissioning_functions
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

-- 2. Agent Workload Identities (Append-Only WORM Ledger; strict key uniqueness + Builder Provenance + Commissioning binding)
CREATE TABLE IF NOT EXISTS agent_identities (
    seq_no                       BIGSERIAL UNIQUE NOT NULL,
    authority_seq                BIGINT NOT NULL DEFAULT nextval('authority_event_seq'),
    agent_id                     TEXT PRIMARY KEY,
    display_name                 TEXT NOT NULL,
    agent_kind                   TEXT NOT NULL CHECK (agent_kind IN ('INTERNAL_WORKER', 'EXTERNAL_AUTONOMOUS_AGENT')),
    commissioning_function_id    TEXT NOT NULL,
    key_id                       TEXT NOT NULL UNIQUE,
    alg                          TEXT NOT NULL DEFAULT 'Ed25519',
    public_key_b64               TEXT NOT NULL UNIQUE,
    key_fingerprint              TEXT NOT NULL UNIQUE,
    spiffe_id                    TEXT NOT NULL DEFAULT '',
    artifact_digest              TEXT NOT NULL,
    builder_principal_id         TEXT NOT NULL,
    builder_public_key_b64       TEXT NOT NULL DEFAULT '',
    builder_key_fingerprint      TEXT NOT NULL,
    builder_provenance_sig_b64   TEXT NOT NULL,
    allowed_actions              JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_services             JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_egress_profile       TEXT NOT NULL CHECK (allowed_egress_profile IN ('ZERO_EGRESS_ISOLATED', 'INTERNAL_CLUSTER_ONLY')),
    max_ttl_seconds              INTEGER NOT NULL CHECK (max_ttl_seconds >= 1 AND max_ttl_seconds <= 300),
    max_delegation_depth         INTEGER NOT NULL DEFAULT 0 CHECK (max_delegation_depth >= 0 AND max_delegation_depth <= 3),
    allow_autonomous_intake      BOOLEAN NOT NULL DEFAULT FALSE,
    recertify_expires_at         TIMESTAMPTZ NOT NULL,
    commissioner_so_principal_id TEXT NOT NULL,
    commissioner_so_key_fp       TEXT NOT NULL DEFAULT '',
    commissioner_ao_principal_id TEXT NOT NULL,
    commissioner_ao_key_fp       TEXT NOT NULL DEFAULT '',
    lineage_mode                 TEXT NOT NULL,
    governance_dsse              JSONB,
    prev_hash                    TEXT NOT NULL,
    entry_hash                   TEXT NOT NULL UNIQUE,
    enrolled_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_identities_function
    ON agent_identities (commissioning_function_id, seq_no ASC);

DROP TRIGGER IF EXISTS trg_immutable_agent_identities ON agent_identities;
CREATE TRIGGER trg_immutable_agent_identities
BEFORE UPDATE OR DELETE ON agent_identities
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

-- 3. Agent Lifecycle & IGA Events (Append-Only WORM Ledger; records HR sponsor events, grace windows, recertifications & revocations)
CREATE TABLE IF NOT EXISTS agent_lifecycle_events (
    seq_no                BIGSERIAL UNIQUE NOT NULL,
    authority_seq         BIGINT NOT NULL DEFAULT nextval('authority_event_seq'),
    event_id              TEXT PRIMARY KEY,
    event_type            TEXT NOT NULL,
    target_agent_id       TEXT NOT NULL DEFAULT '',
    target_function_id    TEXT NOT NULL DEFAULT '',
    affected_principal_id TEXT NOT NULL DEFAULT '',
    new_sponsorship_state TEXT NOT NULL,
    grace_expires_at      TIMESTAMPTZ,
    recertify_expires_at  TIMESTAMPTZ,
    reason_code           TEXT NOT NULL DEFAULT '',
    triggered_by          TEXT NOT NULL DEFAULT '',
    lineage_mode          TEXT NOT NULL,
    governance_dsse       JSONB,
    prev_hash             TEXT NOT NULL,
    entry_hash            TEXT NOT NULL UNIQUE,
    occurred_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_lifecycle_agent
    ON agent_lifecycle_events (target_agent_id, seq_no DESC);
CREATE INDEX IF NOT EXISTS idx_agent_lifecycle_function
    ON agent_lifecycle_events (target_function_id, seq_no DESC);
CREATE INDEX IF NOT EXISTS idx_agent_lifecycle_principal
    ON agent_lifecycle_events (affected_principal_id, seq_no DESC);

DROP TRIGGER IF EXISTS trg_immutable_agent_lifecycle_events ON agent_lifecycle_events;
CREATE TRIGGER trg_immutable_agent_lifecycle_events
BEFORE UPDATE OR DELETE ON agent_lifecycle_events
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

-- 4. Extend agent_action_ledger with Commissioning Function, Authority Mode, Agent ID & RFC 8693 act chain
ALTER TABLE agent_action_ledger
    ADD COLUMN IF NOT EXISTS authority_mode TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS commissioning_function_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS agent_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS delegation_depth INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS act_chain_json JSONB;

-- 5. Extend ledger_checkpoints for 9-Chain Merkle Root V3 (backwards-compatible with MerkleVersion 1 & 2)
ALTER TABLE ledger_checkpoints
    ADD COLUMN IF NOT EXISTS commissioning_head_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    ADD COLUMN IF NOT EXISTS commissioning_row_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS agent_identity_head_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    ADD COLUMN IF NOT EXISTS agent_identity_row_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS agent_lifecycle_head_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    ADD COLUMN IF NOT EXISTS agent_lifecycle_row_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE ledger_checkpoints ALTER COLUMN merkle_version SET DEFAULT 3;
