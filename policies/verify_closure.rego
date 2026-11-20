package warrant.verify

import rego.v1

default allow_bridge_retirement := false
default allow_attestation_mint := false
default assurance_tier := "UNVERIFIED"

is_secret_rotation if {
	object.get(input, "remediation_kind", "IMAGE_PATCH") == "SECRET_ROTATION"
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

# Case B: Advisory-Only Finding (No Weaponized PoC Available) -> Passive Digest & Provenance Proof
passive_sbom_valid if {
	not is_secret_rotation
	not has_probe
	object.get(input, "provenance_verified", false) == true
	input.twin_replay_status == "NO_PROBE_PASSIVE_ONLY"
}

# Case C: Autonomous Credential / Secret Rotation Proof
secret_rotation_valid if {
	is_secret_rotation
	object.get(input, "secret_rotated_and_revoked", false) == true
}

assurance_tier := "ASSURANCE_TIER_SECRET_ROTATED" if {
	secret_rotation_valid
} else := "ASSURANCE_TIER_2_DIFFERENTIAL_TWIN" if {
	differential_twin_valid
} else := "ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM" if {
	passive_sbom_valid
}

blockers contains "SECRET_ROTATION_INCOMPLETE" if {
	is_secret_rotation
	object.get(input, "secret_rotated_and_revoked", false) != true
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

blockers contains "FLEET_DIGEST_SWEEP_INCOMPLETE" if {
	input.total_pods <= 0
}

blockers contains "FLEET_DIGEST_SWEEP_INCOMPLETE" if {
	input.attested_pods != input.total_pods
}

blockers contains "VULNERABLE_SYMBOLS_STILL_LOADED" if {
	input.vulnerable_symbols_loaded > 0
}

blockers contains "ADMISSION_LOCKOUT_NOT_ENFORCED" if {
	not is_secret_rotation
	input.admission_lockout_enforced != true
}

blockers contains "N1_WARRANT_REVERIFY_FAILED" if {
	input.warrant_reverified != true
}

closure_evidence_valid if {
	differential_twin_valid
}

closure_evidence_valid if {
	passive_sbom_valid
}

allow_bridge_retirement if {
	closure_evidence_valid
	input.total_pods > 0
	input.attested_pods == input.total_pods
	input.vulnerable_symbols_loaded == 0
	input.admission_lockout_enforced == true
}

allow_bridge_retirement if {
	secret_rotation_valid
	input.total_pods > 0
	input.attested_pods == input.total_pods
}

allow_attestation_mint if {
	allow_bridge_retirement
	input.warrant_reverified == true
}
