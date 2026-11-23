package warrant.ac5

import rego.v1

default allow := false
default chained_cwe_elevated := false

allow if {
	count(violations) == 0
}

# Attack-Path CWE Weighting: Internet-facing "mediums" (CWE-209 error stack traces,
# CWE-918 SSRF, CWE-434 unrestricted upload) enable autonomous LLM exploit chaining
# and qualify for autonomous remediation even when non-KEV / below high-CVSS floors.
chained_cwe_elevated if {
	finding_cwe := upper(object.get(input, "finding_cwe", ""))
	finding_cwe != ""
	some allowed_cwe in object.get(input, "auto_remediate_cwes", [])
	upper(allowed_cwe) == finding_cwe
}

violations contains "AC5_SYSADMIN_PROHIBITED" if {
	input.slot1.role == "SYSTEM_ADMIN"
}

violations contains "AC5_SYSADMIN_PROHIBITED" if {
	input.slot2.role == "SYSTEM_ADMIN"
}

violations contains "AC5_SLOT1_MUST_BE_SERVICE_OWNER" if {
	input.slot1.role != "SERVICE_OWNER"
}

violations contains "AC5_SLOT2_MUST_BE_AUTHORIZING_OFFICIAL" if {
	input.slot2.role != "AUTHORIZING_OFFICIAL"
}

violations contains "AC5_IDENTICAL_PRINCIPAL" if {
	input.slot1.principal_id == input.slot2.principal_id
}

violations contains "AC5_IDENTICAL_EMAIL" if {
	lower(input.slot1.email) == lower(input.slot2.email)
}

violations contains "AC5_IDENTICAL_KEY_FINGERPRINT" if {
	lower(input.slot1.key_fingerprint) == lower(input.slot2.key_fingerprint)
}

violations contains "REVOKED_SLOT1_SIGNER" if {
	input.slot1.revoked == true
}

violations contains "REVOKED_SLOT2_SIGNER" if {
	input.slot2.revoked == true
}

violations contains "WARRANT_EXPIRED" if {
	input.expires_unix > 0
	input.now_unix >= input.expires_unix
}

service_in_scope if {
	some svc in input.scope_services
	svc == "*"
}

service_in_scope if {
	some svc in input.scope_services
	svc == input.target_service
}

violations contains "SCOPE_SERVICE_NOT_COVERED" if {
	input.target_service != ""
	not service_in_scope
}

violations contains "CVSS_EXCEEDS_WARRANT_CEILING" if {
	input.max_cvss > 0
	input.finding_cvss > input.max_cvss
}

# When a warrant enforces a minimum CVSS or KEV-only floor, allow override ONLY if
# the finding is a CISA KEV or matches pre-authorized attack-path CWEs (e.g. CWE-209/918/434).
violations contains "FINDING_BELOW_PRIORITY_FLOOR_UNLESS_CHAINED_CWE" if {
	min_cvss := object.get(input, "min_cvss", 0)
	min_cvss > 0
	input.finding_cvss > 0
	input.finding_cvss < min_cvss
	object.get(input, "finding_is_kev", false) != true
	not chained_cwe_elevated
}

secret_rotation_authorized if {
	object.get(input, "warrant_class", "") == "SECRET-ROTATION-STATELESS"
}

secret_rotation_authorized if {
	object.get(input, "allow_secret_rotation", false) == true
}

violations contains "SECRET_ROTATION_NOT_AUTHORIZED_BY_WARRANT" if {
	object.get(input, "action_kind", "IMAGE_PATCH") == "SECRET_ROTATION"
	not secret_rotation_authorized
}

violations contains "BLAST_RADIUS_EXCEEDS_CEILING" if {
	input.max_blast_radius_replicas > 0
	input.target_replicas > input.max_blast_radius_replicas
}

# v1.4.0 Estate Loader Clone-Source Declaration Rules:
# 1. Tier C vulnerability scanners provide corroborating census ONLY and can never be declared as clone sources.
tier_c_scanner_systems := {"qualys", "qualys_vmdr", "qualys-vmdr", "tenable", "tenable_io", "tenable_sc", "tenable_io_sc", "rapid7", "insightvm", "rapid7_insightvm"}

violations contains "TIER_C_SCANNER_CANNOT_DECLARE_CLONE_SOURCE" if {
	some cs in object.get(input, "clone_sources", [])
	lower(trim_space(object.get(cs, "source_system", ""))) in tier_c_scanner_systems
}

# 2. ESTATE_LOADER clone sources MUST bind a non-empty snapshot_sha256; MANUAL overrides MUST NOT carry a fabricated snapshot_sha256.
violations contains "ESTATE_LOADER_CLONE_SOURCE_MISSING_SNAPSHOT_HASH" if {
	some cs in object.get(input, "clone_sources", [])
	upper(trim_space(object.get(cs, "source_mode", "ESTATE_LOADER"))) == "ESTATE_LOADER"
	trim_space(object.get(cs, "snapshot_sha256", "")) == ""
}

violations contains "MANUAL_CLONE_SOURCE_FORBIDS_FABRICATED_SNAPSHOT_HASH" if {
	some cs in object.get(input, "clone_sources", [])
	upper(trim_space(object.get(cs, "source_mode", ""))) == "MANUAL"
	trim_space(object.get(cs, "snapshot_sha256", "")) != ""
}

violations contains "INVALID_ESTATE_DRIFT_POLICY" if {
	pol := upper(trim_space(object.get(input, "estate_drift_policy", "")))
	pol != ""
	not pol in {"RECORD_ONLY", "FAIL_CLOSED"}
}
