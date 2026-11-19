package warrant.verify_test

import data.warrant.verify
import rego.v1

verified_input := {
	"has_signed_probe": true,
	"unpatched_twin_status": "EXPLOIT_SUCCEEDED",
	"twin_replay_status": "EXPLOIT_BLOCKED",
	"provenance_verified": true,
	"attested_pods": 6,
	"total_pods": 6,
	"vulnerable_symbols_loaded": 0,
	"admission_lockout_enforced": true,
	"warrant_reverified": true,
}

test_full_verification_allows_retirement_and_mint if {
	verify.allow_bridge_retirement with input as verified_input
	verify.allow_attestation_mint with input as verified_input
	verify.assurance_tier == "ASSURANCE_TIER_2_DIFFERENTIAL_TWIN" with input as verified_input
	count(verify.blockers) == 0 with input as verified_input
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
	})
	verify.allow_bridge_retirement with input as passive
	verify.allow_attestation_mint with input as passive
	verify.assurance_tier == "ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM" with input as passive
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
