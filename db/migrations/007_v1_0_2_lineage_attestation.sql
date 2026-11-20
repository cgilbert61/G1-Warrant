-- 007_v1_0_2_lineage_attestation.sql
-- G1-Warrant v1.0.2 Lineage Attestation, Quorum Survivor Floor & Epoch Replay Hardening:
--   1. Kernel-signed Genesis Seal Manifest columns on bootstrap_state
--   2. Monotonic freeze_epoch counter on system_freeze_state (prevents cross-epoch THAW replay)
--   3. Authorizing DSSE Governance Envelope lineage columns on principals and principal_revocations
--      (backfilling pre-existing/genesis rows as 'GENESIS_SEALED')
--   4. Preceding-key rotation attestation column (rotation_dsse) on kernel_public_keys

-- 1. Extend bootstrap_state with Genesis Seal Manifest lineage metadata
ALTER TABLE bootstrap_state
    ADD COLUMN IF NOT EXISTS genesis_principal_max_seq BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS genesis_revocation_max_seq BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS genesis_manifest_sha256 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS genesis_seal_dsse JSONB;

CREATE OR REPLACE FUNCTION prevent_bootstrap_unseal()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'IMMUTABLE_LEDGER_VIOLATION: bootstrap_state cannot be deleted'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.sealed = TRUE AND NEW.sealed = FALSE THEN
        RAISE EXCEPTION 'IMMUTABLE_LEDGER_VIOLATION: bootstrap_state is permanently sealed and cannot be unsealed'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.sealed = TRUE AND OLD.genesis_seal_dsse IS NOT NULL THEN
        IF NEW.genesis_principal_max_seq <> OLD.genesis_principal_max_seq
           OR NEW.genesis_revocation_max_seq <> OLD.genesis_revocation_max_seq
           OR NEW.genesis_manifest_sha256 <> OLD.genesis_manifest_sha256
           OR NEW.genesis_seal_dsse::text <> OLD.genesis_seal_dsse::text THEN
            RAISE EXCEPTION 'IMMUTABLE_LEDGER_VIOLATION: sealed genesis manifest in bootstrap_state cannot be mutated'
                USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_bootstrap_unseal ON bootstrap_state;
CREATE TRIGGER trg_prevent_bootstrap_unseal
BEFORE UPDATE OR DELETE ON bootstrap_state
FOR EACH ROW EXECUTE FUNCTION prevent_bootstrap_unseal();

-- 2. Add monotonic freeze_epoch to system_freeze_state for cross-epoch THAW replay prevention
ALTER TABLE system_freeze_state
    ADD COLUMN IF NOT EXISTS freeze_epoch BIGINT NOT NULL DEFAULT 1;

CREATE OR REPLACE FUNCTION notify_freeze_state_change()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify(
        'warrant_freeze_channel',
        json_build_object(
            'mode', NEW.mode,
            'actor', NEW.actor,
            'reason_code', NEW.reason_code,
            'freeze_epoch', NEW.freeze_epoch,
            'updated_at', to_char(NEW.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        )::text
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Allow key rotation for an existing human email once the prior principal row is revoked
-- (active email uniqueness and AC-5 distinct-email rules remain strictly enforced).
ALTER TABLE principals DROP CONSTRAINT IF EXISTS principals_email_key;

-- 3. Add total-order authority_seq, lineage_mode, and governance_dsse to principals & principal_revocations, and rotation_dsse to kernel_public_keys
CREATE SEQUENCE IF NOT EXISTS authority_event_seq;

ALTER TABLE principals
    ADD COLUMN IF NOT EXISTS authority_seq BIGINT,
    ADD COLUMN IF NOT EXISTS lineage_mode TEXT,
    ADD COLUMN IF NOT EXISTS governance_dsse JSONB;
ALTER TABLE principals ALTER COLUMN authority_seq SET DEFAULT nextval('authority_event_seq');

ALTER TABLE principal_revocations
    ADD COLUMN IF NOT EXISTS authority_seq BIGINT,
    ADD COLUMN IF NOT EXISTS lineage_mode TEXT,
    ADD COLUMN IF NOT EXISTS governance_dsse JSONB;
ALTER TABLE principal_revocations ALTER COLUMN authority_seq SET DEFAULT nextval('authority_event_seq');

ALTER TABLE kernel_public_keys
    ADD COLUMN IF NOT EXISTS rotation_dsse JSONB;

-- 4. Backfill pre-existing v1.0.0 / v1.0.1 rows cleanly as GENESIS_SEALED
DO $$
DECLARE
    v_max_p BIGINT;
    v_max_r BIGINT;
    r RECORD;
BEGIN
    IF EXISTS (SELECT 1 FROM principals WHERE lineage_mode IS NULL OR authority_seq IS NULL) THEN
        EXECUTE 'DROP TRIGGER IF EXISTS trg_immutable_principals ON principals';
        FOR r IN SELECT principal_id FROM principals ORDER BY seq_no ASC LOOP
            UPDATE principals
            SET lineage_mode = COALESCE(lineage_mode, 'GENESIS_SEALED'),
                authority_seq = COALESCE(authority_seq, nextval('authority_event_seq'))
            WHERE principal_id = r.principal_id;
        END LOOP;
    END IF;

    IF EXISTS (SELECT 1 FROM principal_revocations WHERE lineage_mode IS NULL OR authority_seq IS NULL) THEN
        EXECUTE 'DROP TRIGGER IF EXISTS trg_immutable_principal_revocations ON principal_revocations';
        FOR r IN SELECT revocation_id FROM principal_revocations ORDER BY seq_no ASC LOOP
            UPDATE principal_revocations
            SET lineage_mode = COALESCE(lineage_mode, 'GENESIS_SEALED'),
                authority_seq = COALESCE(authority_seq, nextval('authority_event_seq'))
            WHERE revocation_id = r.revocation_id;
        END LOOP;
    END IF;

    SELECT COALESCE(MAX(seq_no), 0) INTO v_max_p FROM principals WHERE lineage_mode = 'GENESIS_SEALED';
    SELECT COALESCE(MAX(seq_no), 0) INTO v_max_r FROM principal_revocations WHERE lineage_mode = 'GENESIS_SEALED';

    UPDATE bootstrap_state
    SET genesis_principal_max_seq = GREATEST(genesis_principal_max_seq, v_max_p),
        genesis_revocation_max_seq = GREATEST(genesis_revocation_max_seq, v_max_r)
    WHERE singleton_id = 1 AND sealed = TRUE AND genesis_seal_dsse IS NULL;
END $$;

ALTER TABLE principals
    ALTER COLUMN authority_seq SET NOT NULL,
    ALTER COLUMN lineage_mode SET DEFAULT 'GENESIS_SEALED',
    ALTER COLUMN lineage_mode SET NOT NULL;

DROP TRIGGER IF EXISTS trg_immutable_principals ON principals;
CREATE TRIGGER trg_immutable_principals
BEFORE UPDATE OR DELETE ON principals
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

ALTER TABLE principal_revocations
    ALTER COLUMN authority_seq SET NOT NULL,
    ALTER COLUMN lineage_mode SET DEFAULT 'GENESIS_SEALED',
    ALTER COLUMN lineage_mode SET NOT NULL;

DROP TRIGGER IF EXISTS trg_immutable_principal_revocations ON principal_revocations;
CREATE TRIGGER trg_immutable_principal_revocations
BEFORE UPDATE OR DELETE ON principal_revocations
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();
