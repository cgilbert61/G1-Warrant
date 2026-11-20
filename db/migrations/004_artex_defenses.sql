-- 004_artex_defenses.sql
-- Implements G1-Warrant Autonomous Intrusion Countermeasures (ARTEX / GTIG / Phoenix Findings):
--   1. SECRET-ROTATION-STATELESS Standing Warrant Class & Workload Secret Rotation Tracking (N1 & N4)
--   2. Default Outbound Egress & Cloud Metadata (169.254.169.254) Severance on Containment Bridges (N3)
--   3. Mandatory Immutable Root Filesystem + noexec /tmp Gate (N2) & In-Pod eBPF/Tetragon Drift Quarantine (N3)
--   4. Attack-Path Chained-Medium CWE Weighting (CWE-209, CWE-918, CWE-434) & Build/Agent Config Lockout (N1 & N4)

ALTER TABLE estate_services
    ADD COLUMN IF NOT EXISTS readonly_root_filesystem BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS noexec_tmp_mounts BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS allowed_egress_services JSONB NOT NULL DEFAULT '["kube-dns.kube-system.svc.cluster.local"]'::jsonb;

ALTER TABLE warrant_envelopes
    ADD COLUMN IF NOT EXISTS allow_secret_rotation BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS auto_remediate_cwes JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE containment_bridges
    ADD COLUMN IF NOT EXISTS metadata_plane_blocked BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS allowed_egress_peers JSONB NOT NULL DEFAULT '["kube-dns.kube-system.svc.cluster.local"]'::jsonb;

ALTER TABLE drift_incidents
    DROP CONSTRAINT IF EXISTS drift_incidents_lockout_id_fkey;

ALTER TABLE drift_incidents
    ADD COLUMN IF NOT EXISTS drift_kind TEXT NOT NULL DEFAULT 'BANNED_IMAGE_DIGEST',
    ADD COLUMN IF NOT EXISTS violating_artifact TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS pod_cordoned BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS pod_recycled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE remediation_items
    ADD COLUMN IF NOT EXISTS remediation_kind TEXT NOT NULL DEFAULT 'IMAGE_PATCH',
    ADD COLUMN IF NOT EXISTS secret_resource_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS chained_exploit_enabler BOOLEAN NOT NULL DEFAULT FALSE;
