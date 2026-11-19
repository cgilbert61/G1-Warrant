package warrant.verify_test

import data.warrant.verify
import rego.v1

verified_input := {
	"twin_replay_status": "EXPLOIT_BLOCKED",
	"attested_pods": 6,
	"total_pods": 6,
	"vulnerable_symbols_loaded": 0,
	"admission_lockout_enforced": true,
	"warrant_reverified": true,
}

test_full_verification_allows_retirement_and_mint if {
	verify.allow_bridge_retirement with input as verified_input
	verify.allow_attestation_mint with input as verified_input
	count(verify.blockers) == 0 with input as verified_input
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
