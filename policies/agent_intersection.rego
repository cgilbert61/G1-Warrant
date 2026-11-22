package warrant.agent

import rego.v1

default allow := false
default effective_ttl_seconds := 0

autonomous_readonly_actions := {
	"EXTRACT_SARIF_2_1_0",
	"EXTRACT_CISA_KEV_CATALOG",
	"EXTRACT_OSV_BATCH",
	"EXTRACT_SECRET_EXPOSURE",
}

egress_rank("ZERO_EGRESS_ISOLATED") := 1

egress_rank("INTERNAL_CLUSTER_ONLY") := 2

egress_rank(other) := 99 if {
	not other in {"ZERO_EGRESS_ISOLATED", "INTERNAL_CLUSTER_ONLY"}
}

req_egress := object.get(input, "requested_egress_profile", "ZERO_EGRESS_ISOLATED")

agent_egress := object.get(input.agent, "allowed_egress_profile", "ZERO_EGRESS_ISOLATED")

delegation_depth := object.get(input, "delegation_depth", 0)

grace_active if {
	object.get(input.agent, "grace_active", false) == true
}

grace_active if {
	object.get(input.agent, "sponsorship_state", "") == "SPONSOR_GRACE_ESCALATED"
}

# 3-Way Separation of Duties: Builder / Artifact Attestor MUST NOT co-sign as Commissioning SO or AO.
builder_matches_commissioner if {
	b_id := trim_space(object.get(input.agent, "builder_principal_id", ""))
	b_id != ""
	b_id in {
		trim_space(object.get(input.agent, "commissioner_so_principal_id", "")),
		trim_space(object.get(input.agent, "commissioner_ao_principal_id", "")),
	}
}

builder_matches_commissioner if {
	b_fp := lower(trim_space(object.get(input.agent, "builder_key_fingerprint", "")))
	b_fp != ""
	b_fp in {
		lower(trim_space(object.get(input.agent, "commissioner_so_key_fingerprint", ""))),
		lower(trim_space(object.get(input.agent, "commissioner_ao_key_fingerprint", ""))),
	}
}

action_in_agent_ceiling if {
	some act in object.get(input.agent, "allowed_actions", [])
	act in {input.requested_action, "*"}
}

asset_in_agent_scope if {
	some svc in object.get(input.agent, "allowed_services", [])
	svc in {input.target_asset, "*"}
}

standing_warrant := object.get(input, "standing_warrant", {})

standing_warrant_valid if {
	object.get(standing_warrant, "present", false) == true
	object.get(standing_warrant, "active", false) == true
	exp := object.get(standing_warrant, "expires_unix", 0)
	exp == 0
}

standing_warrant_valid if {
	object.get(standing_warrant, "present", false) == true
	object.get(standing_warrant, "active", false) == true
	exp := object.get(standing_warrant, "expires_unix", 0)
	exp > input.now_unix
}

asset_in_standing_warrant if {
	some svc in object.get(standing_warrant, "scope_services", [])
	svc in {input.target_asset, "*"}
}

action_in_standing_warrant if {
	allowed := object.get(standing_warrant, "allowed_actions", [])
	count(allowed) == 0
}

action_in_standing_warrant if {
	some act in object.get(standing_warrant, "allowed_actions", [])
	act in {input.requested_action, "*"}
}

parent_task := object.get(input, "parent_task", {})

parent_present if {
	object.get(parent_task, "present", false) == true
}

parent_action_attenuated if {
	p_act := object.get(parent_task, "allowed_action", "")
	p_act in {input.requested_action, "*"}
}

parent_asset_attenuated if {
	p_asset := object.get(parent_task, "target_asset", "")
	p_asset in {input.target_asset, "*"}
}

parent_egress_attenuated if {
	p_egress := object.get(parent_task, "egress_profile", "ZERO_EGRESS_ISOLATED")
	egress_rank(req_egress) <= egress_rank(p_egress)
}

parent_ttl_attenuated if {
	p_exp := object.get(parent_task, "expires_unix", 0)
	rem := p_exp - input.now_unix
	rem > 0
	input.requested_ttl_seconds <= rem
}

subagent_escalation_detected if {
	delegation_depth > 0
	parent_present
	not parent_action_attenuated
}

subagent_escalation_detected if {
	delegation_depth > 0
	parent_present
	not parent_asset_attenuated
}

subagent_escalation_detected if {
	delegation_depth > 0
	parent_present
	not parent_egress_attenuated
}

subagent_escalation_detected if {
	delegation_depth > 0
	parent_present
	not parent_ttl_attenuated
}

# Deterministic TTL Intersection:
# effective_ttl_seconds = min(requested_ttl, agent.max_ttl_seconds, parent_remaining_ttl, grace_remaining_ttl, recertify_remaining_ttl, 300)
ttl_candidates contains 300

ttl_candidates contains input.requested_ttl_seconds if {
	is_number(object.get(input, "requested_ttl_seconds", 0))
}

ttl_candidates contains max_t if {
	max_t := object.get(input.agent, "max_ttl_seconds", 300)
	max_t > 0
}

ttl_candidates contains parent_rem if {
	delegation_depth > 0
	parent_present
	parent_rem := object.get(parent_task, "expires_unix", 0) - input.now_unix
}

ttl_candidates contains grace_rem if {
	grace_active
	grace_exp := object.get(input.agent, "grace_expires_unix", 0)
	grace_exp > 0
	grace_rem := grace_exp - input.now_unix
}

ttl_candidates contains lease_rem if {
	recert_exp := object.get(input.agent, "recertify_expires_unix", 0)
	recert_exp > 0
	lease_rem := recert_exp - input.now_unix
}

ttl_candidates contains warrant_rem if {
	input.authority_mode == "WARRANT_DELEGATED_COMPOSITE"
	w_exp := object.get(standing_warrant, "expires_unix", 0)
	w_exp > 0
	warrant_rem := w_exp - input.now_unix
}

raw_effective_ttl := min(ttl_candidates)

effective_ttl_seconds := raw_effective_ttl if {
	raw_effective_ttl > 0
}

# Violation Rules
violations contains "UNOWNED_AGENT_NO_COMMISSIONING_FUNCTION" if {
	trim_space(object.get(input.agent, "commissioning_function_id", "")) == ""
}

violations contains "SOD_BUILDER_CANNOT_SELF_COMMISSION" if {
	builder_matches_commissioner
}

violations contains "AGENT_REVOKED_KILL_SWITCH" if {
	object.get(input.agent, "revoked", false) == true
}

violations contains "AGENT_REVOKED_KILL_SWITCH" if {
	object.get(input.agent, "sponsorship_state", "") == "REVOKED_KILL_SWITCH"
}

violations contains "SPONSOR_KEY_COMPROMISED_IMMEDIATE_KILL" if {
	object.get(input.agent, "sponsor_compromised", false) == true
}

violations contains "SPONSOR_KEY_COMPROMISED_IMMEDIATE_KILL" if {
	object.get(input.agent, "sponsorship_state", "") == "REVOKED_COMPROMISE"
}

violations contains "GHOST_AGENT_LEASE_EXPIRED" if {
	object.get(input.agent, "sponsorship_state", "") == "LEASE_EXPIRED_QUARANTINED"
}

violations contains "GHOST_AGENT_LEASE_EXPIRED" if {
	recert := object.get(input.agent, "recertify_expires_unix", 0)
	recert > 0
	input.now_unix >= recert
}

violations contains "GHOST_AGENT_ORPHAN_QUARANTINED" if {
	object.get(input.agent, "sponsorship_state", "") == "ORPHAN_QUARANTINED"
}

violations contains "GHOST_AGENT_ORPHAN_QUARANTINED" if {
	grace_active
	input.now_unix >= object.get(input.agent, "grace_expires_unix", 0)
}

violations contains "TTL_CEILING_EXCEEDED" if {
	req_ttl := object.get(input, "requested_ttl_seconds", 0)
	req_ttl <= 0
}

violations contains "TTL_CEILING_EXCEEDED" if {
	req_ttl := object.get(input, "requested_ttl_seconds", 0)
	req_ttl > 300
}

violations contains "ACTION_OUTSIDE_AGENT_CAPABILITY_CEILING" if {
	not action_in_agent_ceiling
}

violations contains "ASSET_OUTSIDE_AGENT_SERVICE_SCOPE" if {
	not asset_in_agent_scope
}

violations contains "EGRESS_EXCEEDS_AGENT_PROFILE" if {
	egress_rank(req_egress) > egress_rank(agent_egress)
}

violations contains "EGRESS_EXCEEDS_AGENT_PROFILE" if {
	egress_rank(req_egress) > 2
}

violations contains "INVALID_AUTHORITY_MODE" if {
	not input.authority_mode in {"WARRANT_DELEGATED_COMPOSITE", "AUTONOMOUS_WORKLOAD_SPONSORED"}
}

violations contains "WARRANT_COMPOSITE_MISSING_STANDING_WARRANT" if {
	input.authority_mode == "WARRANT_DELEGATED_COMPOSITE"
	not standing_warrant_valid
}

violations contains "ASSET_OUTSIDE_STANDING_WARRANT_SCOPE" if {
	input.authority_mode == "WARRANT_DELEGATED_COMPOSITE"
	object.get(standing_warrant, "present", false) == true
	not asset_in_standing_warrant
}

violations contains "ACTION_OUTSIDE_STANDING_WARRANT_SCOPE" if {
	input.authority_mode == "WARRANT_DELEGATED_COMPOSITE"
	object.get(standing_warrant, "present", false) == true
	not action_in_standing_warrant
}

violations contains "AUTONOMOUS_INTAKE_NOT_PERMITTED" if {
	input.authority_mode == "AUTONOMOUS_WORKLOAD_SPONSORED"
	object.get(input.agent, "allow_autonomous_intake", false) != true
}

violations contains "AUTONOMOUS_MODE_MUTATION_FORBIDDEN" if {
	input.authority_mode == "AUTONOMOUS_WORKLOAD_SPONSORED"
	not input.requested_action in autonomous_readonly_actions
}

violations contains "SUBAGENT_MISSING_PARENT_TASK" if {
	delegation_depth > 0
	not parent_present
}

violations contains "GRACE_WINDOW_BLOCKS_SUBAGENT_DELEGATION" if {
	delegation_depth > 0
	grace_active
}

violations contains "GRACE_WINDOW_BLOCKS_SUBAGENT_DELEGATION" if {
	delegation_depth > 0
	object.get(parent_task, "sponsorship_state", "") == "SPONSOR_GRACE_ESCALATED"
}

violations contains "SUBAGENT_DEPTH_EXCEEDED" if {
	delegation_depth > 0
	delegation_depth > object.get(input.agent, "max_delegation_depth", 0)
}

violations contains "SUBAGENT_DEPTH_EXCEEDED" if {
	delegation_depth > 0
	parent_present
	delegation_depth > object.get(parent_task, "max_delegation_depth", 0)
}

violations contains "SUBAGENT_DEPTH_EXCEEDED" if {
	delegation_depth > 3
}

violations contains "SUBAGENT_PRIVILEGE_ESCALATION_DENIED" if {
	subagent_escalation_detected
}

allow if {
	count(violations) == 0
	effective_ttl_seconds > 0
}
