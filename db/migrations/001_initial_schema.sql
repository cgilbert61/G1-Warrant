-- G1-Warrant Production Database Schema & Immutable Cryptographic Ledger Triggers
-- Organization: G1163RT Security Labs, Inc.

CREATE OR REPLACE FUNCTION prevent_immutable_ledger_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABLE_LEDGER_VIOLATION: table % is append-only; % operations are prohibited by G1-Warrant safety kernel', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

-- 1. Principals & WebAuthn / PIV Key Registry
CREATE TABLE IF NOT EXISTS principals (
    principal_id        TEXT PRIMARY KEY,
    email               TEXT NOT NULL UNIQUE,
    display_name        TEXT NOT NULL,
    role                TEXT NOT NULL CHECK (role IN ('SERVICE_OWNER', 'AUTHORIZING_OFFICIAL', 'SYSTEM_ADMIN', 'OPERATOR', 'AUDITOR', 'ATTESTATION_KERNEL', 'ARTIFACT_PUBLISHER')),
    key_id              TEXT NOT NULL UNIQUE,
    alg                 TEXT NOT NULL,
    public_key_b64      TEXT NOT NULL,
    key_fingerprint     TEXT NOT NULL,
    authenticator_mode  TEXT NOT NULL DEFAULT 'FIPS_PIV_SMARTCARD',
    credential_id       TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Live Principal & Hardware Key Revocations (N1)
CREATE TABLE IF NOT EXISTS principal_revocations (
    revocation_id       TEXT PRIMARY KEY,
    principal_id        TEXT NOT NULL REFERENCES principals(principal_id),
    key_fingerprint     TEXT NOT NULL,
    reason_code         TEXT NOT NULL,
    revoked_by          TEXT NOT NULL,
    revoked_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_revocations_principal ON principal_revocations(principal_id);
CREATE INDEX IF NOT EXISTS idx_revocations_fp ON principal_revocations(key_fingerprint);

-- 3. Immutable Standing Warrant Envelopes (N1 - Append-Only + AC-5 Enforced)
CREATE TABLE IF NOT EXISTS warrant_envelopes (
    seq_no                      BIGSERIAL PRIMARY KEY,
    warrant_id                  TEXT NOT NULL UNIQUE,
    warrant_class               TEXT NOT NULL,
    scope_services              JSONB NOT NULL,
    max_cvss                    DOUBLE PRECISION NOT NULL CHECK (max_cvss > 0 AND max_cvss <= 10.0),
    kev_eligible                BOOLEAN NOT NULL DEFAULT TRUE,
    max_blast_radius_replicas   INTEGER NOT NULL CHECK (max_blast_radius_replicas > 0),
    allow_stateful_patches      BOOLEAN NOT NULL DEFAULT FALSE,
    sla_bridge_minutes          INTEGER NOT NULL CHECK (sla_bridge_minutes > 0),
    max_p99_latency_ms          DOUBLE PRECISION NOT NULL DEFAULT 120.0,
    issued_at                   TIMESTAMPTZ NOT NULL,
    expires_at                  TIMESTAMPTZ NOT NULL,
    dsse_envelope               JSONB NOT NULL,
    slot1_principal_id          TEXT NOT NULL,
    slot1_email                 TEXT NOT NULL,
    slot1_key_fp                TEXT NOT NULL,
    slot1_role                  TEXT NOT NULL,
    slot2_principal_id          TEXT NOT NULL,
    slot2_email                 TEXT NOT NULL,
    slot2_key_fp                TEXT NOT NULL,
    slot2_role                  TEXT NOT NULL,
    prev_hash                   TEXT NOT NULL,
    entry_hash                  TEXT NOT NULL UNIQUE,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_ac5_distinct_principals CHECK (slot1_principal_id <> slot2_principal_id),
    CONSTRAINT chk_ac5_distinct_emails CHECK (lower(slot1_email) <> lower(slot2_email)),
    CONSTRAINT chk_ac5_distinct_keys CHECK (lower(slot1_key_fp) <> lower(slot2_key_fp)),
    CONSTRAINT chk_ac5_slot1_role CHECK (slot1_role = 'SERVICE_OWNER'),
    CONSTRAINT chk_ac5_slot2_role CHECK (slot2_role = 'AUTHORIZING_OFFICIAL')
);

DROP TRIGGER IF EXISTS trg_immutable_warrant_envelopes ON warrant_envelopes;
CREATE TRIGGER trg_immutable_warrant_envelopes
BEFORE UPDATE OR DELETE ON warrant_envelopes
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

-- 4. Asymmetric Dual-Mode Emergency Freeze Posture + LISTEN/NOTIFY (N1)
CREATE TABLE IF NOT EXISTS system_freeze_state (
    singleton_id    INTEGER PRIMARY KEY DEFAULT 1 CHECK (singleton_id = 1),
    mode            TEXT NOT NULL CHECK (mode IN ('OPERATIONAL', 'FREEZE_HOLD', 'FREEZE_ROLLBACK')),
    actor           TEXT NOT NULL,
    reason_code     TEXT NOT NULL,
    thaw_dsse       JSONB,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO system_freeze_state (singleton_id, mode, actor, reason_code, updated_at)
VALUES (1, 'OPERATIONAL', 'sys-warrantd-kernel', 'BOOT_INITIALIZED', NOW())
ON CONFLICT (singleton_id) DO NOTHING;

CREATE OR REPLACE FUNCTION notify_freeze_state_change()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify(
        'warrant_freeze_channel',
        json_build_object(
            'mode', NEW.mode,
            'actor', NEW.actor,
            'reason_code', NEW.reason_code,
            'updated_at', to_char(NEW.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        )::text
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_notify_freeze_state ON system_freeze_state;
CREATE TRIGGER trg_notify_freeze_state
AFTER INSERT OR UPDATE ON system_freeze_state
FOR EACH ROW EXECUTE FUNCTION notify_freeze_state_change();

-- 5. Estate Services & N2 Readiness Grader Registry
CREATE TABLE IF NOT EXISTS estate_services (
    service_id                      TEXT PRIMARY KEY,
    display_name                    TEXT NOT NULL,
    namespace                       TEXT NOT NULL,
    tier                            TEXT NOT NULL,
    warrant_class                   TEXT NOT NULL,
    current_digest                  TEXT NOT NULL,
    current_purl                    TEXT NOT NULL,
    replicas                        INTEGER NOT NULL,
    test_coverage_pct               DOUBLE PRECISION NOT NULL,
    otel_health_probes              BOOLEAN NOT NULL,
    readonly_shadow_replica         BOOLEAN NOT NULL,
    rollback_automation_verified    BOOLEAN NOT NULL,
    baseline_syscalls               JSONB NOT NULL,
    eligible                        BOOLEAN NOT NULL,
    eligibility_checklist           JSONB NOT NULL,
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. Remediation Race Pipeline Items
CREATE TABLE IF NOT EXISTS remediation_items (
    remediation_id      TEXT PRIMARY KEY,
    cve_id              TEXT NOT NULL,
    cwe_id              TEXT NOT NULL,
    is_kev              BOOLEAN NOT NULL,
    cvss_score          DOUBLE PRECISION NOT NULL,
    service_id          TEXT NOT NULL REFERENCES estate_services(service_id),
    warrant_id          TEXT NOT NULL DEFAULT '',
    vulnerable_digest   TEXT NOT NULL,
    patched_digest      TEXT NOT NULL,
    package_purl        TEXT NOT NULL,
    vulnerable_symbol   TEXT NOT NULL DEFAULT '',
    exploit_vector      TEXT NOT NULL DEFAULT 'HTTP_PATH_TRAVERSAL',
    stage               TEXT NOT NULL CHECK (stage IN ('INTAKE_REPRO', 'BRIDGED_CONTAINED', 'SHADOW_CANARY', 'VERIFYING_LOCKING', 'ATTESTED_CLOSED')),
    status_health       TEXT NOT NULL CHECK (status_health IN ('NORMAL', 'BRIDGED', 'EXCEPTION_ROUTED', 'ROLLBACK_FAILED', 'DRIFT_VIOLATION', 'FROZEN', 'ATTESTED')),
    blocker_code        TEXT NOT NULL DEFAULT '',
    canary_weight       INTEGER NOT NULL DEFAULT 0,
    stateless_passed    BOOLEAN,
    schema_diff_passed  BOOLEAN,
    syscall_diff_passed BOOLEAN,
    twin_replay_status  TEXT NOT NULL DEFAULT 'PENDING',
    pod_sweep_matched   INTEGER NOT NULL DEFAULT 0,
    pod_sweep_total     INTEGER NOT NULL DEFAULT 0,
    lockout_policy_id   TEXT NOT NULL DEFAULT '',
    bridge_id           TEXT NOT NULL DEFAULT '',
    bridge_sla_minutes  INTEGER NOT NULL DEFAULT 60,
    attestation_id      TEXT NOT NULL DEFAULT '',
    patch_metadata      JSONB,
    shadow_report       JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    bridged_at          TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Millisecond-Timestamped Deterministic Execution Traces
CREATE TABLE IF NOT EXISTS remediation_traces (
    seq_no          BIGSERIAL PRIMARY KEY,
    trace_id        TEXT NOT NULL UNIQUE,
    remediation_id  TEXT NOT NULL REFERENCES remediation_items(remediation_id),
    engine          TEXT NOT NULL,
    step_code       TEXT NOT NULL,
    outcome         TEXT NOT NULL,
    actor_or_token  TEXT NOT NULL,
    evidence_hash   TEXT NOT NULL,
    fields          JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_traces_remediation ON remediation_traces(remediation_id, seq_no);

-- 8. Four-Eyes Ceiling Exception Cockpit Queue (N1/N2)
CREATE TABLE IF NOT EXISTS ceiling_exceptions (
    exception_id            TEXT PRIMARY KEY,
    remediation_id          TEXT NOT NULL REFERENCES remediation_items(remediation_id),
    service_id              TEXT NOT NULL,
    cve_id                  TEXT NOT NULL,
    warrant_class           TEXT NOT NULL,
    trigger_code            TEXT NOT NULL,
    ddl_count               INTEGER NOT NULL DEFAULT 0,
    orm_mutations           INTEGER NOT NULL DEFAULT 0,
    serialization_breaks    INTEGER NOT NULL DEFAULT 0,
    api_backward_compatible BOOLEAN NOT NULL DEFAULT TRUE,
    shadow_replay_status    TEXT NOT NULL DEFAULT 'NOT_RUN',
    syscall_diff_summary    TEXT NOT NULL DEFAULT 'NONE',
    active_bridge_id        TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL CHECK (status IN ('PENDING_DUAL_KEY', 'APPROVED', 'REJECTED')),
    resolution_dsse         JSONB,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at             TIMESTAMPTZ
);

-- 9. Containment Bridges (Cilium L7 / K8s NetPol / Envoy mTLS)
CREATE TABLE IF NOT EXISTS containment_bridges (
    bridge_id               TEXT PRIMARY KEY,
    remediation_id          TEXT NOT NULL REFERENCES remediation_items(remediation_id),
    service_id              TEXT NOT NULL,
    cve_id                  TEXT NOT NULL,
    bridge_type             TEXT NOT NULL CHECK (bridge_type IN ('CILIUM_L7_NETPOL', 'ENVOY_MTLS_WAF', 'K8S_NETPOL')),
    status                  TEXT NOT NULL CHECK (status IN ('ARMED', 'RETIRED', 'REARMED_DRIFT')),
    sla_minutes             INTEGER NOT NULL,
    blocker_reason_code     TEXT NOT NULL,
    cilium_manifest_yaml    TEXT NOT NULL,
    k8s_netpol_yaml         TEXT NOT NULL,
    envoy_filter_json       TEXT NOT NULL,
    armed_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at              TIMESTAMPTZ,
    rearmed_count           INTEGER NOT NULL DEFAULT 0
);

-- 10. Permanent Admission Lockout Register & Drift Incidents (N3)
CREATE TABLE IF NOT EXISTS admission_lockouts (
    lockout_id          TEXT PRIMARY KEY,
    remediation_id      TEXT NOT NULL REFERENCES remediation_items(remediation_id),
    service_id          TEXT NOT NULL,
    cve_id              TEXT NOT NULL,
    banned_digest       TEXT NOT NULL,
    patched_digest      TEXT NOT NULL,
    policy_name         TEXT NOT NULL UNIQUE,
    vap_manifest_yaml   TEXT NOT NULL,
    gatekeeper_rego     TEXT NOT NULL,
    enforced_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    drift_count         INTEGER NOT NULL DEFAULT 0,
    last_drift_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_lockouts_service_digest ON admission_lockouts(service_id, banned_digest);

CREATE TABLE IF NOT EXISTS drift_incidents (
    incident_id             TEXT PRIMARY KEY,
    lockout_id              TEXT NOT NULL REFERENCES admission_lockouts(lockout_id),
    remediation_id          TEXT NOT NULL REFERENCES remediation_items(remediation_id),
    service_id              TEXT NOT NULL,
    cve_id                  TEXT NOT NULL,
    detected_digest         TEXT NOT NULL,
    rogue_pod_name          TEXT NOT NULL,
    rearmed_bridge_id       TEXT NOT NULL,
    detection_latency_ms    BIGINT NOT NULL,
    detected_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at             TIMESTAMPTZ
);

-- 11. Differential Shadow Comparison Runs History (N2)
CREATE TABLE IF NOT EXISTS shadow_comparison_runs (
    run_id          TEXT PRIMARY KEY,
    remediation_id  TEXT NOT NULL REFERENCES remediation_items(remediation_id),
    service_id      TEXT NOT NULL,
    stage_weight    INTEGER NOT NULL,
    passed          BOOLEAN NOT NULL,
    failure_code    TEXT NOT NULL DEFAULT '',
    report_json     JSONB NOT NULL,
    evaluated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 12. Immutable Governed Agent Action Ledger (N4 - Append-Only)
CREATE TABLE IF NOT EXISTS agent_action_ledger (
    seq_no              BIGSERIAL PRIMARY KEY,
    action_id           TEXT NOT NULL UNIQUE,
    task_token_id       TEXT NOT NULL,
    warrant_id          TEXT NOT NULL,
    remediation_id      TEXT NOT NULL DEFAULT '',
    worker_name         TEXT NOT NULL,
    target_asset        TEXT NOT NULL,
    action_type         TEXT NOT NULL,
    slot1_principal_id  TEXT NOT NULL,
    slot2_principal_id  TEXT NOT NULL,
    egress_profile      TEXT NOT NULL,
    raw_input_sha256    TEXT NOT NULL,
    extractor_digest    TEXT NOT NULL,
    typed_output_sha256 TEXT NOT NULL,
    token_ttl_sec       INTEGER NOT NULL CHECK (token_ttl_sec >= 0 AND token_ttl_sec <= 300),
    status              TEXT NOT NULL CHECK (status IN ('EXECUTED', 'SECURITY_VIOLATION')),
    violation_code      TEXT NOT NULL DEFAULT '',
    prev_hash           TEXT NOT NULL,
    entry_hash          TEXT NOT NULL UNIQUE,
    executed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS trg_immutable_agent_action_ledger ON agent_action_ledger;
CREATE TRIGGER trg_immutable_agent_action_ledger
BEFORE UPDATE OR DELETE ON agent_action_ledger
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

-- 13. Immutable Cryptographic Attestation & OSCAL POA&M Records (N5 - Append-Only)
CREATE TABLE IF NOT EXISTS attestation_records (
    seq_no                  BIGSERIAL PRIMARY KEY,
    attestation_id          TEXT NOT NULL UNIQUE,
    remediation_id          TEXT NOT NULL UNIQUE REFERENCES remediation_items(remediation_id),
    service_id              TEXT NOT NULL,
    cve_id                  TEXT NOT NULL,
    is_kev                  BOOLEAN NOT NULL,
    warrant_id              TEXT NOT NULL,
    slot1_principal_id      TEXT NOT NULL,
    slot1_email             TEXT NOT NULL,
    slot2_principal_id      TEXT NOT NULL,
    slot2_email             TEXT NOT NULL,
    twin_transcript_sha256  TEXT NOT NULL,
    fleet_digest_manifest   JSONB NOT NULL,
    lockout_policy_id       TEXT NOT NULL,
    reverify_expires_at     TIMESTAMPTZ NOT NULL,
    dsse_envelope           JSONB NOT NULL,
    oscal_poam_json         JSONB NOT NULL,
    ttvr_seconds            BIGINT NOT NULL,
    prev_hash               TEXT NOT NULL,
    entry_hash              TEXT NOT NULL UNIQUE,
    minted_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DROP TRIGGER IF EXISTS trg_immutable_attestation_records ON attestation_records;
CREATE TRIGGER trg_immutable_attestation_records
BEFORE UPDATE OR DELETE ON attestation_records
FOR EACH ROW EXECUTE FUNCTION prevent_immutable_ledger_mutation();

-- 14. Scoped External Auditor Bearer Tokens (N5)
CREATE TABLE IF NOT EXISTS auditor_tokens (
    token_id                TEXT PRIMARY KEY,
    token_hash              TEXT NOT NULL UNIQUE,
    label                   TEXT NOT NULL,
    scoped_attestation_ids  JSONB NOT NULL,
    created_by              TEXT NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    revoked                 BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
