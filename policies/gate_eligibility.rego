package warrant.gate

import rego.v1

default service_eligible := false
default guarded_canary_eligible := false
default autonomy_tier := "TIER_3_CONTAIN_AND_CAB"
default patch_stateless := false
default shadow_safe := false
default freeze_blocked := false
default trigger_canary_rollback := false
default route_to_exception_cockpit := false
default allow_autonomous_rollout := false

# Tier 1: Greenfield full shadow + canary autonomous eligibility
tier1_ready if {
	input.service.test_coverage_pct >= 80
	input.service.otel_health_probes == true
	input.service.readonly_shadow_replica == true
	input.service.rollback_automation_verified == true
}

# Tier 2: Brownfield guarded canary eligibility (OTel SLI probes + verified <60s rollback hook)
guarded_canary_eligible if {
	not tier1_ready
	input.service.otel_health_probes == true
	input.service.rollback_automation_verified == true
	input.allow_guarded_canary == true
}

autonomy_tier := "TIER_1_FULL_AUTONOMOUS" if {
	tier1_ready
} else := "TIER_2_GUARDED_CANARY" if {
	guarded_canary_eligible
}

service_eligible if {
	tier1_ready
}

service_eligible if {
	guarded_canary_eligible
}

patch_stateless if {
	input.patch.ddl_migrations == 0
	input.patch.orm_model_mutations == 0
	input.patch.serialization_breaks == 0
	input.patch.api_backward_compatible == true
}

freeze_blocked if {
	input.freeze_mode == "FREEZE_HOLD"
}

freeze_blocked if {
	input.freeze_mode == "FREEZE_ROLLBACK"
}

baseline_syscall_set contains sc if {
	some sc in input.shadow.baseline_syscalls
}

unauthorized_syscalls contains sc if {
	some sc in input.shadow.canary_syscalls
	not sc in baseline_syscall_set
}

sensitive_file_violation if {
	count(object.get(input.shadow, "sensitive_files_accessed", [])) > 0
}

unexpected_egress_violation if {
	count(object.get(input.shadow, "unexpected_egress_endpoints", [])) > 0
}

mutating_on_readonly_violation if {
	object.get(input.shadow, "has_mutating_traffic", false) == true
	object.get(input.service, "shadow_db_mode", "EPHEMERAL_COW_BRANCH") == "READONLY_REPLICA"
}

shadow_safe if {
	input.shadow.schema_breaking_diffs == 0
	input.shadow.status_code_drift_pct <= 0.5
	input.shadow.p99_latency_ms <= input.shadow.max_p99_latency_ms
	count(unauthorized_syscalls) == 0
	not sensitive_file_violation
	not unexpected_egress_violation
	not mutating_on_readonly_violation
}

trigger_canary_rollback if {
	input.shadow_evaluated == true
	not shadow_safe
}

trigger_canary_rollback if {
	input.freeze_mode == "FREEZE_ROLLBACK"
}

route_to_exception_cockpit if {
	not service_eligible
}

route_to_exception_cockpit if {
	not patch_stateless
}

route_to_exception_cockpit if {
	input.blast_radius_exceeded == true
}

allow_autonomous_rollout if {
	service_eligible
	patch_stateless
	not freeze_blocked
	input.blast_radius_exceeded != true
	shadow_safe
}

reasons contains "SERVICE_INELIGIBLE_COVERAGE" if {
	input.service.test_coverage_pct < 80
	not guarded_canary_eligible
}

reasons contains "SERVICE_MISSING_OTEL_PROBES" if {
	input.service.otel_health_probes != true
}

reasons contains "SERVICE_MISSING_SHADOW_REPLICA" if {
	input.service.readonly_shadow_replica != true
	not guarded_canary_eligible
}

reasons contains "SERVICE_UNVERIFIED_ROLLBACK" if {
	input.service.rollback_automation_verified != true
}

reasons contains "STATEFUL_PATCH_DDL_DETECTED" if {
	input.patch.ddl_migrations > 0
}

reasons contains "STATEFUL_PATCH_ORM_MUTATION" if {
	input.patch.orm_model_mutations > 0
}

reasons contains "STATEFUL_PATCH_SERIALIZATION_BREAK" if {
	input.patch.serialization_breaks > 0
}

reasons contains "STATEFUL_PATCH_WIRE_INCOMPATIBLE" if {
	input.patch.api_backward_compatible != true
}

reasons contains "SHADOW_UNAUTHORIZED_SYSCALL" if {
	count(unauthorized_syscalls) > 0
}

reasons contains "SHADOW_SENSITIVE_FILE_READ_DETECTED" if {
	sensitive_file_violation
}

reasons contains "SHADOW_UNEXPECTED_EGRESS_EXFILTRATION" if {
	unexpected_egress_violation
}

reasons contains "SHADOW_MUTATING_TRAFFIC_REQUIRES_COW_BRANCH" if {
	mutating_on_readonly_violation
}

reasons contains "SHADOW_SCHEMA_DRIFT" if {
	input.shadow.schema_breaking_diffs > 0
}

reasons contains "SHADOW_LATENCY_EXCEEDED" if {
	input.shadow.p99_latency_ms > input.shadow.max_p99_latency_ms
}

reasons contains "EMERGENCY_FREEZE_ACTIVE" if {
	freeze_blocked
}

reasons contains "BLAST_RADIUS_CEILING_EXCEEDED" if {
	input.blast_radius_exceeded == true
}
