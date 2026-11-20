package warrant.verify_test

import data.warrant.verify
import rego.v1

verified_input := {
	"remediation_kind": "IMAGE_PATCH",
	"has_signed_probe": true,
	"unpatched_twin_status": "EXPLOIT_SUCCEEDED",
	"twin_replay_status": "EXPLOIT_BLOCKED",
	"provenance_verified": true,
	"vulnerable_pkg_absent_in_sbom": true,
	"attested_pods": 6,
	"total_pods": 6,
	"admission_lockout_enforced": true,
	"warrant_reverified": true,
}

test_full_verification_allows_retirement_and_mint if {
	verify.allow_bridge_retirement with input as verified_input
	verify.allow_attestation_mint with input as verified_input
	verify.assurance_tier == "ASSURANCE_TIER_2_DIFFERENTIAL_TWIN" with input as verified_input
	count(verify.blockers) == 0 with input as verified_input
}

test_secret_rotation_closure_allows_retirement_and_mint if {
	sec_rot := {
		"remediation_kind": "SECRET_ROTATION",
		"secret_rotated_and_revoked": true,
		"exposed_secret_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
		"rotated_secret_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
		"attested_pods": 4,
		"total_pods": 4,
		"warrant_reverified": true,
	}
	verify.allow_bridge_retirement with input as sec_rot
	verify.allow_attestation_mint with input as sec_rot
	verify.assurance_tier == "ASSURANCE_TIER_SECRET_ROTATED" with input as sec_rot
}

test_secret_rotation_blocks_when_rotated_hash_matches_exposed_or_empty if {
	unchanged := {
		"remediation_kind": "SECRET_ROTATION",
		"secret_rotated_and_revoked": true,
		"exposed_secret_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"rotated_secret_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"attested_pods": 4,
		"total_pods": 4,
		"warrant_reverified": true,
	}
	not verify.allow_bridge_retirement with input as unchanged
	not verify.allow_attestation_mint with input as unchanged
	"SECRET_VALUE_UNCHANGED_OR_EMPTY" in verify.blockers with input as unchanged

	empty_rot := object.union(unchanged, {"rotated_secret_sha256": ""})
	not verify.allow_bridge_retirement with input as empty_rot
	"SECRET_VALUE_UNCHANGED_OR_EMPTY" in verify.blockers with input as empty_rot
}

test_reject_broken_poc_positive_control_false_negative if {
	broken_poc := object.union(verified_input, {
		"unpatched_twin_status": "EXPLOIT_BLOCKED",
	})
	not verify.allow_bridge_retirement with input as broken_poc
	not verify.allow_attestation_mint with input as broken_poc
	"BROKEN_PROBE_POSITIVE_CONTROL_FAILED" in verify.blockers with input as broken_poc
}

test_passive_advisory_closure_without_poc_assigns_tier1 if {
	passive := object.union(verified_input, {
		"has_signed_probe": false,
		"unpatched_twin_status": "NOT_APPLICABLE",
		"twin_replay_status": "NO_PROBE_PASSIVE_ONLY",
		"provenance_verified": true,
		"vulnerable_pkg_absent_in_sbom": true,
	})
	verify.allow_bridge_retirement with input as passive
	verify.allow_attestation_mint with input as passive
	verify.assurance_tier == "ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM" with input as passive

	still_in_sbom := object.union(passive, {"vulnerable_pkg_absent_in_sbom": false})
	not verify.allow_bridge_retirement with input as still_in_sbom
	"SBOM_STILL_CONTAINS_VULNERABLE_PACKAGE" in verify.blockers with input as still_in_sbom
}

test_block_bridge_retirement_without_admission_lockout if {
	missing_lockout := object.union(verified_input, {"admission_lockout_enforced": false})
	not verify.allow_bridge_retirement with input as missing_lockout
	not verify.allow_attestation_mint with input as missing_lockout
	"ADMISSION_LOCKOUT_NOT_ENFORCED" in verify.blockers with input as missing_lockout
}

test_block_mint_if_warrant_revoked_at_mint_time if {
	revoked := object.union(verified_input, {"warrant_reverified": false})
	verify.allow_bridge_retirement with input as revoked
	not verify.allow_attestation_mint with input as revoked
	"N1_WARRANT_REVERIFY_FAILED" in verify.blockers with input as revoked
}
