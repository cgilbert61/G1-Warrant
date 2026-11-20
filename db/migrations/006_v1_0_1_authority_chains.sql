-- 006_v1_0_1_authority_chains.sql
-- G1-Warrant v1.0.1 Security & Cryptographic Root-of-Trust Hardening:
--   1. Genesis-only Bootstrap Sealing state (bootstrap_state) & single-use Governance Nonces (governance_envelope_nonces)
--   2. Unique public-key / SHA-256 fingerprint constraints on principals (preventing duplicate-key AC-5 spoofing)
--   3. Backfill + NOT NULL + UNIQUE + BEFORE UPDATE OR DELETE immutability triggers + SHA-256 hash-chaining across:
--      - principals
--      - principal_revocations
--      - kernel_public_keys
--   4. 6-Chain Combined Merkle Root columns on ledger_checkpoints (preserving merkle_version=1 for v1.0.0 upgrades)

-- 1. Bootstrap Seal State (One-Shot Genesis Seal)
CREATE TABLE IF NOT EXISTS bootstrap_state (
    singleton_id    INTEGER PRIMARY KEY DEFAULT 1 CHECK (singleton_id = 1),
    sealed          BOOLEAN NOT NULL DEFAULT FALSE,
    sealed_by       TEXT NOT NULL DEFAULT '',
    sealed_reason   TEXT NOT NULL DEFAULT '',
    sealed_at       TIMESTAMPTZ
);

INSERT INTO bootstrap_state (singleton_id, sealed, sealed_by, sealed_reason)
VALUES (1, FALSE, '', '')
ON CONFLICT (singleton_id) DO NOTHING;

-- Prevent unsealing once sealed=TRUE
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
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_bootstrap_unseal ON bootstrap_state;
CREATE TRIGGER trg_prevent_bootstrap_unseal
BEFORE UPDATE OR DELETE ON bootstrap_state
FOR EACH ROW EXECUTE FUNCTION prevent_bootstrap_unseal();

-- 2. Single-Use Replay Protection Nonces for Principal Governance & Emergency DSSE Envelopes
CREATE TABLE IF NOT EXISTS governance_envelope_nonces (
    envelope_id     TEXT PRIMARY KEY,
    action_type     TEXT NOT NULL,
    payload_sha256  TEXT NOT NULL,
    signer_summary  TEXT NOT NULL DEFAULT '',
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS trg_immutable_governance_nonces ON governance_envelope_nonces;
CREATE TRIGGER trg_immutable_governance_nonces
BEFORE UPDATE OR DELETE ON governance_envelope_nonces
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

-- 3. Add hash-chain columns to principals, principal_revocations, and kernel_public_keys (nullable first for v1.0.0 upgrade backfill)
CREATE SEQUENCE IF NOT EXISTS principals_seq_no_seq;
ALTER TABLE principals
    ADD COLUMN IF NOT EXISTS seq_no BIGINT,
    ADD COLUMN IF NOT EXISTS prev_hash TEXT,
    ADD COLUMN IF NOT EXISTS entry_hash TEXT;
ALTER TABLE principals ALTER COLUMN seq_no SET DEFAULT nextval('principals_seq_no_seq');

CREATE SEQUENCE IF NOT EXISTS principal_revocations_seq_no_seq;
ALTER TABLE principal_revocations
    ADD COLUMN IF NOT EXISTS seq_no BIGINT,
    ADD COLUMN IF NOT EXISTS prev_hash TEXT,
    ADD COLUMN IF NOT EXISTS entry_hash TEXT;
ALTER TABLE principal_revocations ALTER COLUMN seq_no SET DEFAULT nextval('principal_revocations_seq_no_seq');

CREATE SEQUENCE IF NOT EXISTS kernel_public_keys_seq_no_seq;
ALTER TABLE kernel_public_keys
    ADD COLUMN IF NOT EXISTS seq_no BIGINT,
    ADD COLUMN IF NOT EXISTS prev_hash TEXT,
    ADD COLUMN IF NOT EXISTS entry_hash TEXT;
ALTER TABLE kernel_public_keys ALTER COLUMN seq_no SET DEFAULT nextval('kernel_public_keys_seq_no_seq');

-- 4. Deterministic Upgrade Backfill for Pre-Existing v1.0.0 Rows
DO $$
DECLARE
    v_genesis CONSTANT TEXT := '0000000000000000000000000000000000000000000000000000000000000000';
    v_prev TEXT;
    v_hash TEXT;
    v_seq  BIGINT;
    r      RECORD;
BEGIN
    -- Backfill principals if any unchained rows exist
    IF EXISTS (SELECT 1 FROM principals WHERE seq_no IS NULL OR prev_hash IS NULL OR entry_hash IS NULL) THEN
        EXECUTE 'DROP TRIGGER IF EXISTS trg_immutable_principals ON principals';
        v_prev := v_genesis;
        v_seq := 0;
        FOR r IN
            SELECT principal_id, email, role, key_id, alg, public_key_b64, key_fingerprint
            FROM principals
            ORDER BY COALESCE(seq_no, 9223372036854775807) ASC, created_at ASC, principal_id ASC
        LOOP
            v_seq := v_seq + 1;
            v_hash := encode(
                sha256(
                    convert_to(
                        'principals|' || v_prev || '|' || r.principal_id || '|' || lower(r.email) || '|' ||
                        r.role || '|' || r.key_id || '|' || r.alg || '|' || r.public_key_b64 || '|' || lower(r.key_fingerprint),
                        'UTF8'
                    )
                ),
                'hex'
            );
            UPDATE principals
            SET seq_no = v_seq, prev_hash = v_prev, entry_hash = v_hash
            WHERE principal_id = r.principal_id;
            v_prev := v_hash;
        END LOOP;
        IF v_seq > 0 THEN
            PERFORM setval('principals_seq_no_seq', v_seq, true);
        END IF;
    END IF;

    -- Backfill principal_revocations if any unchained rows exist
    IF EXISTS (SELECT 1 FROM principal_revocations WHERE seq_no IS NULL OR prev_hash IS NULL OR entry_hash IS NULL) THEN
        EXECUTE 'DROP TRIGGER IF EXISTS trg_immutable_principal_revocations ON principal_revocations';
        v_prev := v_genesis;
        v_seq := 0;
        FOR r IN
            SELECT revocation_id, principal_id, key_fingerprint, reason_code, revoked_by
            FROM principal_revocations
            ORDER BY COALESCE(seq_no, 9223372036854775807) ASC, revoked_at ASC, revocation_id ASC
        LOOP
            v_seq := v_seq + 1;
            v_hash := encode(
                sha256(
                    convert_to(
                        'principal_revocations|' || v_prev || '|' || r.revocation_id || '|' || r.principal_id || '|' ||
                        lower(r.key_fingerprint) || '|' || r.reason_code || '|' || r.revoked_by,
                        'UTF8'
                    )
                ),
                'hex'
            );
            UPDATE principal_revocations
            SET seq_no = v_seq, prev_hash = v_prev, entry_hash = v_hash
            WHERE revocation_id = r.revocation_id;
            v_prev := v_hash;
        END LOOP;
        IF v_seq > 0 THEN
            PERFORM setval('principal_revocations_seq_no_seq', v_seq, true);
        END IF;
    END IF;

    -- Backfill kernel_public_keys if any unchained rows exist
    IF EXISTS (SELECT 1 FROM kernel_public_keys WHERE seq_no IS NULL OR prev_hash IS NULL OR entry_hash IS NULL) THEN
        EXECUTE 'DROP TRIGGER IF EXISTS trg_immutable_kernel_public_keys ON kernel_public_keys';
        v_prev := v_genesis;
        v_seq := 0;
        FOR r IN
            SELECT key_id, alg, public_key_b64, key_fingerprint, backend_mode
            FROM kernel_public_keys
            ORDER BY COALESCE(seq_no, 9223372036854775807) ASC, registered_at ASC, key_id ASC
        LOOP
            v_seq := v_seq + 1;
            v_hash := encode(
                sha256(
                    convert_to(
                        'kernel_public_keys|' || v_prev || '|' || r.key_id || '|' || r.alg || '|' ||
                        r.public_key_b64 || '|' || lower(r.key_fingerprint) || '|' || r.backend_mode,
                        'UTF8'
                    )
                ),
                'hex'
            );
            UPDATE kernel_public_keys
            SET seq_no = v_seq, prev_hash = v_prev, entry_hash = v_hash
            WHERE key_id = r.key_id;
            v_prev := v_hash;
        END LOOP;
        IF v_seq > 0 THEN
            PERFORM setval('kernel_public_keys_seq_no_seq', v_seq, true);
        END IF;
    END IF;

    -- Auto-seal bootstrap if pre-existing Standing Warrants exist on an upgraded v1.0.0 database
    IF EXISTS (SELECT 1 FROM warrant_envelopes LIMIT 1) THEN
        UPDATE bootstrap_state
        SET sealed = TRUE,
            sealed_by = 'migration-006',
            sealed_reason = 'UPGRADE_EXISTING_STANDING_WARRANTS',
            sealed_at = COALESCE(sealed_at, NOW())
        WHERE singleton_id = 1 AND sealed = FALSE;
    END IF;
END $$;

-- 5. Enforce NOT NULL, UNIQUE (seq_no), UNIQUE (entry_hash), UNIQUE key constraints, and BEFORE UPDATE OR DELETE triggers
ALTER TABLE principals
    ALTER COLUMN seq_no SET NOT NULL,
    ALTER COLUMN prev_hash SET NOT NULL,
    ALTER COLUMN entry_hash SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_principals_seq_no ON principals(seq_no);
CREATE UNIQUE INDEX IF NOT EXISTS uq_principals_entry_hash ON principals(entry_hash);
CREATE UNIQUE INDEX IF NOT EXISTS uq_principals_public_key_b64 ON principals(public_key_b64);
CREATE UNIQUE INDEX IF NOT EXISTS uq_principals_fingerprint_sha256 ON principals(lower(key_fingerprint));

DROP TRIGGER IF EXISTS trg_immutable_principals ON principals;
CREATE TRIGGER trg_immutable_principals
BEFORE UPDATE OR DELETE ON principals
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

ALTER TABLE principal_revocations
    ALTER COLUMN seq_no SET NOT NULL,
    ALTER COLUMN prev_hash SET NOT NULL,
    ALTER COLUMN entry_hash SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_principal_revocations_seq_no ON principal_revocations(seq_no);
CREATE UNIQUE INDEX IF NOT EXISTS uq_principal_revocations_entry_hash ON principal_revocations(entry_hash);

DROP TRIGGER IF EXISTS trg_immutable_principal_revocations ON principal_revocations;
CREATE TRIGGER trg_immutable_principal_revocations
BEFORE UPDATE OR DELETE ON principal_revocations
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

ALTER TABLE kernel_public_keys
    ALTER COLUMN seq_no SET NOT NULL,
    ALTER COLUMN prev_hash SET NOT NULL,
    ALTER COLUMN entry_hash SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_kernel_public_keys_seq_no ON kernel_public_keys(seq_no);
CREATE UNIQUE INDEX IF NOT EXISTS uq_kernel_public_keys_entry_hash ON kernel_public_keys(entry_hash);

DROP TRIGGER IF EXISTS trg_immutable_kernel_public_keys ON kernel_public_keys;
CREATE TRIGGER trg_immutable_kernel_public_keys
BEFORE UPDATE OR DELETE ON kernel_public_keys
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

-- 6. Extend ledger_checkpoints for 6-Chain Combined Merkle Root (V2) while preserving V1 compatibility on upgraded rows
ALTER TABLE ledger_checkpoints
    ADD COLUMN IF NOT EXISTS merkle_version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS principal_head_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    ADD COLUMN IF NOT EXISTS principal_row_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS revocation_head_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    ADD COLUMN IF NOT EXISTS revocation_row_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS kernel_key_head_hash TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    ADD COLUMN IF NOT EXISTS kernel_key_row_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE ledger_checkpoints ALTER COLUMN merkle_version SET DEFAULT 2;
