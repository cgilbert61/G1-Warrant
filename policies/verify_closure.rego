package warrant.verify

import rego.v1

default allow_bridge_retirement := false
default allow_attestation_mint := false
default allow_partial_attestation_mint := false
default allow_dispatch_only_record := false
default assurance_tier := "UNVERIFIED"
default closure_completeness := "UNVERIFIED"

is_secret_rotation if {
	object.get(input, "remediation_kind", "IMAGE_PATCH") == "SECRET_ROTATION"
}

exposed_secret_sha := trim_space(object.get(input, "exposed_secret_sha256", ""))
rotated_secret_sha := trim_space(object.get(input, "rotated_secret_sha256", ""))

secret_hashes_distinct_and_nonempty if {
	exposed_secret_sha != ""
	rotated_secret_sha != ""
	lower(rotated_secret_sha) != lower(exposed_secret_sha)
}

# Normalize WN-8 per-asset telemetry alongside legacy pod-sweep fields (100% backwards-compatible)
raw_granularity := trim_space(object.get(input, "evidence_granularity", ""))

effective_granularity := "PER_ASSET_VERIFIED" if {
	raw_granularity == ""
} else := raw_granularity

has_distributor_counts if {
	object.get(input, "targeted_assets", 0) > 0
}

eff_targeted := object.get(input, "targeted_assets", 0) if {
	has_distributor_counts
} else := object.get(input, "total_pods", 0)

eff_landed := object.get(input, "landed_assets", 0) if {
	has_distributor_counts
} else := object.get(input, "attested_pods", 0)

is_dispatch_or_wave_only if {
	effective_granularity in {"DISPATCH_ACK_ONLY", "WAVE_AGGREGATE_ONLY"}
}

# Case A: Signed Regression Probe Present -> Differential Twin Proof Required
has_probe if {
	not is_secret_rotation
	object.get(input, "has_signed_probe", true) == true
}

differential_twin_valid if {
	has_probe
	object.get(input, "unpatched_twin_status", "EXPLOIT_SUCCEEDED") == "EXPLOIT_SUCCEEDED"
	input.twin_replay_status == "EXPLOIT_BLOCKED"
}

# Case B: Advisory-Only Finding -> Strictly Verifiable Passive Digest, SBOM Absence & Lockout Proof
passive_sbom_valid if {
	not is_secret_rotation
	not has_probe
	object.get(input, "provenance_verified", false) == true
	object.get(input, "vulnerable_pkg_absent_in_sbom", false) == true
	input.twin_replay_status == "NO_PROBE_PASSIVE_ONLY"
}

# Case C: Autonomous Credential / Secret Rotation Proof (Requires Cryptographic Non-Equivalence)
secret_rotation_valid if {
	is_secret_rotation
	object.get(input, "secret_rotated_and_revoked", false) == true
	secret_hashes_distinct_and_nonempty
}

# v1.3.0 Runtime-Follows-Patch & 3-Clone Proving Ground Enforcement
patch_layer := trim_space(object.get(input, "patch_target_layer", "USERSPACE_SOFTWARE"))
twin_runtime := trim_space(object.get(input, "twin_runtime", "CONTAINER_TWIN"))

kernel_or_boot_patch if {
	patch_layer in {"KERNEL", "BOOT_LAYER"}
}

runtime_matches_patch_layer if {
	not kernel_or_boot_patch
}

runtime_matches_patch_layer if {
	kernel_or_boot_patch
	twin_runtime == "VM_TWIN"
}

estate_drift_blocks_closure if {
	upper(trim_space(object.get(input, "estate_drift_policy", ""))) == "FAIL_CLOSED"
	object.get(input, "estate_drift_exceeded", false) == true
}

clone_twin_valid if {
	object.get(input, "clone_twin_proving_present", false) != true
	runtime_matches_patch_layer
	not estate_drift_blocks_closure
}

clone_twin_valid if {
	object.get(input, "clone_twin_proving_present", false) == true
	runtime_matches_patch_layer
	object.get(input, "clone_twin_count", 0) >= 1
	object.get(input, "clone_twin_all_passed", false) == true
	not estate_drift_blocks_closure
}

closure_evidence_valid if {
	differential_twin_valid
	clone_twin_valid
}

closure_evidence_valid if {
	passive_sbom_valid
	clone_twin_valid
}

# Honest Assurance Tiering: distributors lacking per-asset reporting are capped at ASSURANCE_TIER_0_DISTRIBUTOR_DISPATCH_ONLY
assurance_tier := "ASSURANCE_TIER_0_DISTRIBUTOR_DISPATCH_ONLY" if {
	is_dispatch_or_wave_only
	closure_evidence_valid
} else := "ASSURANCE_TIER_SECRET_ROTATED" if {
	secret_rotation_valid
} else := "ASSURANCE_TIER_2_DIFFERENTIAL_TWIN" if {
	differential_twin_valid
} else := "ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM" if {
	passive_sbom_valid
}

closure_completeness := "DISPATCH_ONLY" if {
	is_dispatch_or_wave_only
	closure_evidence_valid
} else := "FULL" if {
	effective_granularity == "PER_ASSET_VERIFIED"
	eff_targeted > 0
	eff_landed == eff_targeted
	closure_evidence_valid
} else := "FULL" if {
	effective_granularity == "PER_ASSET_VERIFIED"
	eff_targeted > 0
	eff_landed == eff_targeted
	secret_rotation_valid
} else := "PARTIAL" if {
	effective_granularity == "PER_ASSET_VERIFIED"
	eff_targeted > 0
	eff_landed > 0
	eff_landed < eff_targeted
	closure_evidence_valid
}

blockers contains "SECRET_ROTATION_INCOMPLETE" if {
	is_secret_rotation
	object.get(input, "secret_rotated_and_revoked", false) != true
}

blockers contains "SECRET_VALUE_UNCHANGED_OR_EMPTY" if {
	is_secret_rotation
	not secret_hashes_distinct_and_nonempty
}

blockers contains "BROKEN_PROBE_POSITIVE_CONTROL_FAILED" if {
	has_probe
	object.get(input, "unpatched_twin_status", "EXPLOIT_SUCCEEDED") != "EXPLOIT_SUCCEEDED"
}

blockers contains "TWIN_REPLAY_NOT_BLOCKED" if {
	has_probe
	input.twin_replay_status != "EXPLOIT_BLOCKED"
}

blockers contains "PASSIVE_CLOSURE_MISSING_PROVENANCE" if {
	not is_secret_rotation
	not has_probe
	object.get(input, "provenance_verified", false) != true
}

blockers contains "SBOM_STILL_CONTAINS_VULNERABLE_PACKAGE" if {
	not is_secret_rotation
	not has_probe
	object.get(input, "vulnerable_pkg_absent_in_sbom", false) != true
}

blockers contains "DISTRIBUTOR_LACKS_PER_ASSET_EVIDENCE" if {
	is_dispatch_or_wave_only
}

blockers contains "PARTIAL_FLEET_LANDING_BRIDGE_HELD" if {
	effective_granularity == "PER_ASSET_VERIFIED"
	has_distributor_counts
	eff_landed > 0
	eff_landed < eff_targeted
}

blockers contains "FLEET_DIGEST_SWEEP_INCOMPLETE" if {
	not is_dispatch_or_wave_only
	eff_targeted <= 0
}

blockers contains "FLEET_DIGEST_SWEEP_INCOMPLETE" if {
	not is_dispatch_or_wave_only
	not has_distributor_counts
	eff_landed != eff_targeted
}

blockers contains "FLEET_DIGEST_SWEEP_INCOMPLETE" if {
	not is_dispatch_or_wave_only
	has_distributor_counts
	eff_landed <= 0
}

blockers contains "ADMISSION_LOCKOUT_NOT_ENFORCED" if {
	not is_secret_rotation
	input.admission_lockout_enforced != true
}

blockers contains "N1_WARRANT_REVERIFY_FAILED" if {
	input.warrant_reverified != true
}

blockers contains "KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME" if {
	not is_secret_rotation
	not runtime_matches_patch_layer
}

blockers contains "ESTATE_DRIFT_TOLERANCE_EXCEEDED" if {
	not is_secret_rotation
	estate_drift_blocks_closure
}

blockers contains "CLONE_TWIN_PROVING_FAILED" if {
	not is_secret_rotation
	object.get(input, "clone_twin_proving_present", false) == true
	not clone_twin_valid
}

allow_bridge_retirement if {
	effective_granularity == "PER_ASSET_VERIFIED"
	closure_evidence_valid
	eff_targeted > 0
	eff_landed == eff_targeted
	object.get(input, "vulnerable_pkg_absent_in_sbom", false) == true
	input.admission_lockout_enforced == true
}

allow_bridge_retirement if {
	effective_granularity == "PER_ASSET_VERIFIED"
	secret_rotation_valid
	eff_targeted > 0
	eff_landed == eff_targeted
}

allow_attestation_mint if {
	allow_bridge_retirement
	input.warrant_reverified == true
}

allow_partial_attestation_mint if {
	effective_granularity == "PER_ASSET_VERIFIED"
	closure_evidence_valid
	eff_targeted > 0
	eff_landed > 0
	eff_landed < eff_targeted
	input.warrant_reverified == true
}

allow_dispatch_only_record if {
	is_dispatch_or_wave_only
	closure_evidence_valid
	input.warrant_reverified == true
}
