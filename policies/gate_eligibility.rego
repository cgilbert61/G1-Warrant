package warrant.gate

import rego.v1

default service_eligible := false
default patch_stateless := false
default shadow_safe := false
default freeze_blocked := false
default trigger_canary_rollback := false
default route_to_exception_cockpit := false
default allow_autonomous_rollout := false

service_eligible if {
	input.service.test_coverage_pct >= 80
	input.service.otel_health_probes == true
	input.service.readonly_shadow_replica == true
	input.service.rollback_automation_verified == true
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

shadow_safe if {
	input.shadow.schema_breaking_diffs == 0
	input.shadow.status_code_drift_pct <= 0.5
	input.shadow.p99_latency_ms <= input.shadow.max_p99_latency_ms
	count(unauthorized_syscalls) == 0
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
}

reasons contains "SERVICE_MISSING_OTEL_PROBES" if {
	input.service.otel_health_probes != true
}

reasons contains "SERVICE_MISSING_SHADOW_REPLICA" if {
	input.service.readonly_shadow_replica != true
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
