-- =============================================================================
-- G1-Warrant v1.3.0 Migration 010:
--   Item 1: Zero-Signature Intake Doctrine (ClassBindingStatus decoupled from arrival)
--   Item 2: 3-Clone Proving Ground & Runtime-Follows-Patch (PatchTargetLayer + CloneTwinProvingManifest)
-- =============================================================================

ALTER TABLE remediation_items
    ADD COLUMN IF NOT EXISTS class_binding_status TEXT NOT NULL DEFAULT 'UNBOUND',
    ADD COLUMN IF NOT EXISTS patch_target_layer TEXT NOT NULL DEFAULT 'USERSPACE_SOFTWARE',
    ADD COLUMN IF NOT EXISTS clone_twin_proving_json JSONB;

ALTER TABLE warrant_envelopes
    ADD COLUMN IF NOT EXISTS clone_twin_count INTEGER NOT NULL DEFAULT 3;
