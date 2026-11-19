package warrant.verify

import rego.v1

default allow_bridge_retirement := false
default allow_attestation_mint := false

blockers contains "TWIN_REPLAY_NOT_BLOCKED" if {
	input.twin_replay_status != "EXPLOIT_BLOCKED"
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
	input.admission_lockout_enforced != true
}

blockers contains "N1_WARRANT_REVERIFY_FAILED" if {
	input.warrant_reverified != true
}

allow_bridge_retirement if {
	input.twin_replay_status == "EXPLOIT_BLOCKED"
	input.total_pods > 0
	input.attested_pods == input.total_pods
	input.vulnerable_symbols_loaded == 0
	input.admission_lockout_enforced == true
}

allow_attestation_mint if {
	allow_bridge_retirement
	input.warrant_reverified == true
}
