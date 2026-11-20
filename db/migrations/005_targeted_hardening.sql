-- 005_targeted_hardening.sql
-- Targeted SRE & Security Hardening Delta:
--   1. Per-service unordered_array_paths opt-in (restoring order-sensitive JSON array diff default)
--   2. Per-service allow_kube_apiserver_egress opt-in (denying toEntities: kube-apiserver by default)
--   3. Append-only kernel_public_keys verification ring so warrantd restarts with ephemeral memory keys
--      never invalidate previously minted OSCAL 1.1.2 POA&M bundles.

ALTER TABLE estate_services
    ADD COLUMN IF NOT EXISTS unordered_array_paths JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS allow_kube_apiserver_egress BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS kernel_public_keys (
    key_id          TEXT PRIMARY KEY,
    alg             TEXT NOT NULL,
    public_key_b64  TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL UNIQUE,
    backend_mode    TEXT NOT NULL,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS trg_immutable_kernel_public_keys ON kernel_public_keys;
CREATE TRIGGER trg_immutable_kernel_public_keys
BEFORE UPDATE OR DELETE ON kernel_public_keys
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();
