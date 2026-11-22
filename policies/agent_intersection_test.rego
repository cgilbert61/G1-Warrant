package warrant.agent_test

import data.warrant.agent
import rego.v1

base_input := {
	"now_unix": 1795000000,
	"authority_mode": "WARRANT_DELEGATED_COMPOSITE",
	"requested_action": "EXTRACT_PATCH_DIFF",
	"target_asset": "svc-payments-api",
	"requested_egress_profile": "ZERO_EGRESS_ISOLATED",
	"requested_ttl_seconds": 120,
	"delegation_depth": 0,
	"agent": {
		"agent_id": "agt-patch-analyzer",
		"commissioning_function_id": "fn-fin-core-remediation",
		"revoked": false,
		"sponsorship_state": "ACTIVE",
		"sponsor_compromised": false,
		"grace_active": false,
		"grace_expires_unix": 0,
		"recertify_expires_unix": 1797592000,
		"allowed_actions": ["EXTRACT_SARIF_2_1_0", "EXTRACT_PATCH_DIFF"],
		"allowed_services": ["svc-payments-api", "svc-ledger-core"],
		"allowed_egress_profile": "ZERO_EGRESS_ISOLATED",
		"max_ttl_seconds": 180,
		"max_delegation_depth": 2,
		"allow_autonomous_intake": false,
		"builder_principal_id": "bld-ci-publisher",
		"builder_key_fingerprint": "aaaa1111",
		"commissioner_so_principal_id": "usr-so-primary",
		"commissioner_so_key_fingerprint": "bbbb2222",
		"commissioner_ao_principal_id": "usr-ao-primary",
		"commissioner_ao_key_fingerprint": "cccc3333",
	},
	"standing_warrant": {
		"present": true,
		"active": true,
		"scope_services": ["svc-payments-api"],
		"allowed_actions": ["EXTRACT_PATCH_DIFF", "ROLLOUT_CANARY_STAGE"],
		"expires_unix": 1796000000,
	},
}

test_composite_intersection_allows_valid_sponsored_agent if {
	agent.allow with input as base_input
	agent.effective_ttl_seconds == 120 with input as base_input
	count(agent.violations) == 0 with input as base_input
}

test_sod_builder_cannot_self_commission_blocks_principal_and_fingerprint if {
	same_principal := json.patch(base_input, [
		{"op": "replace", "path": "/agent/builder_principal_id", "value": "usr-so-primary"},
	])
	not agent.allow with input as same_principal
	"SOD_BUILDER_CANNOT_SELF_COMMISSION" in agent.violations with input as same_principal

	same_key := json.patch(base_input, [
		{"op": "replace", "path": "/agent/builder_key_fingerprint", "value": "CCCC3333"},
	])
	not agent.allow with input as same_key
	"SOD_BUILDER_CANNOT_SELF_COMMISSION" in agent.violations with input as same_key
}

test_secondary_sponsor_continuity_preserves_uptime_on_hr_transfer if {
	continuity := json.patch(base_input, [
		{"op": "replace", "path": "/agent/sponsorship_state", "value": "ACTIVE_SECONDARY_CONTINUITY"},
	])
	agent.allow with input as continuity
	agent.effective_ttl_seconds == 120 with input as continuity
}

test_grace_window_clamps_ttl_to_remaining_grace_seconds if {
	grace := json.patch(base_input, [
		{"op": "replace", "path": "/agent/sponsorship_state", "value": "SPONSOR_GRACE_ESCALATED"},
		{"op": "replace", "path": "/agent/grace_active", "value": true},
		{"op": "replace", "path": "/agent/grace_expires_unix", "value": 1795000045},
		{"op": "replace", "path": "/requested_ttl_seconds", "value": 180},
	])
	agent.allow with input as grace
	agent.effective_ttl_seconds == 45 with input as grace
}

test_post_grace_orphan_quarantine_denies_token_issuance if {
	expired_grace := json.patch(base_input, [
		{"op": "replace", "path": "/agent/sponsorship_state", "value": "SPONSOR_GRACE_ESCALATED"},
		{"op": "replace", "path": "/agent/grace_active", "value": true},
		{"op": "replace", "path": "/agent/grace_expires_unix", "value": 1795000000},
	])
	not agent.allow with input as expired_grace
	"GHOST_AGENT_ORPHAN_QUARANTINED" in agent.violations with input as expired_grace
}

test_key_compromise_enforces_zero_second_immediate_kill if {
	compromised := json.patch(base_input, [
		{"op": "replace", "path": "/agent/sponsor_compromised", "value": true},
		{"op": "replace", "path": "/agent/grace_active", "value": true},
		{"op": "replace", "path": "/agent/grace_expires_unix", "value": 1795604800},
	])
	not agent.allow with input as compromised
	"SPONSOR_KEY_COMPROMISED_IMMEDIATE_KILL" in agent.violations with input as compromised
}

test_recertification_lease_expiry_quarantines_ghost_agent if {
	expired_lease := json.patch(base_input, [
		{"op": "replace", "path": "/agent/recertify_expires_unix", "value": 1794999999},
	])
	not agent.allow with input as expired_lease
	"GHOST_AGENT_LEASE_EXPIRED" in agent.violations with input as expired_lease
}

test_permission_intersection_blocks_out_of_ceiling_action_service_and_egress if {
	bad_action := json.patch(base_input, [
		{"op": "replace", "path": "/requested_action", "value": "ROLLOUT_CANARY_STAGE"},
	])
	not agent.allow with input as bad_action
	"ACTION_OUTSIDE_AGENT_CAPABILITY_CEILING" in agent.violations with input as bad_action

	bad_warrant_svc := json.patch(base_input, [
		{"op": "replace", "path": "/target_asset", "value": "svc-ledger-core"},
	])
	not agent.allow with input as bad_warrant_svc
	"ASSET_OUTSIDE_STANDING_WARRANT_SCOPE" in agent.violations with input as bad_warrant_svc

	bad_egress := json.patch(base_input, [
		{"op": "replace", "path": "/requested_egress_profile", "value": "INTERNAL_CLUSTER_ONLY"},
	])
	not agent.allow with input as bad_egress
	"EGRESS_EXCEEDS_AGENT_PROFILE" in agent.violations with input as bad_egress
}

test_autonomous_sponsored_intake_allows_readonly_and_blocks_mutations if {
	intake_ok := json.patch(base_input, [
		{"op": "replace", "path": "/authority_mode", "value": "AUTONOMOUS_WORKLOAD_SPONSORED"},
		{"op": "replace", "path": "/requested_action", "value": "EXTRACT_SARIF_2_1_0"},
		{"op": "replace", "path": "/agent/allow_autonomous_intake", "value": true},
		{"op": "replace", "path": "/standing_warrant/present", "value": false},
	])
	agent.allow with input as intake_ok

	intake_mut := json.patch(intake_ok, [
		{"op": "replace", "path": "/requested_action", "value": "EXTRACT_PATCH_DIFF"},
	])
	not agent.allow with input as intake_mut
	"AUTONOMOUS_MODE_MUTATION_FORBIDDEN" in agent.violations with input as intake_mut
}

test_subagent_attenuation_allows_narrower_scope_and_blocks_escalation_or_grace_redelegation if {
	sub_ok := json.patch(base_input, [
		{"op": "replace", "path": "/delegation_depth", "value": 1},
		{"op": "replace", "path": "/requested_ttl_seconds", "value": 60},
		{"op": "add", "path": "/parent_task", "value": {
			"present": true,
			"target_asset": "*",
			"allowed_action": "EXTRACT_PATCH_DIFF",
			"egress_profile": "INTERNAL_CLUSTER_ONLY",
			"expires_unix": 1795000090,
			"max_delegation_depth": 2,
			"sponsorship_state": "ACTIVE",
		}},
	])
	agent.allow with input as sub_ok
	agent.effective_ttl_seconds == 60 with input as sub_ok

	sub_ttl_esc := json.patch(sub_ok, [
		{"op": "replace", "path": "/requested_ttl_seconds", "value": 120},
	])
	not agent.allow with input as sub_ttl_esc
	"SUBAGENT_PRIVILEGE_ESCALATION_DENIED" in agent.violations with input as sub_ttl_esc

	sub_asset_esc := json.patch(sub_ok, [
		{"op": "replace", "path": "/parent_task/target_asset", "value": "svc-ledger-core"},
	])
	not agent.allow with input as sub_asset_esc
	"SUBAGENT_PRIVILEGE_ESCALATION_DENIED" in agent.violations with input as sub_asset_esc

	sub_during_grace := json.patch(sub_ok, [
		{"op": "replace", "path": "/parent_task/sponsorship_state", "value": "SPONSOR_GRACE_ESCALATED"},
	])
	not agent.allow with input as sub_during_grace
	"GRACE_WINDOW_BLOCKS_SUBAGENT_DELEGATION" in agent.violations with input as sub_during_grace
}
