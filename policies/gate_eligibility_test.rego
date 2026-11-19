package warrant.gate_test

import data.warrant.gate
import rego.v1

clean_gate_input := {
	"freeze_mode": "OPERATIONAL",
	"blast_radius_exceeded": false,
	"shadow_evaluated": true,
	"service": {
		"test_coverage_pct": 91.5,
		"otel_health_probes": true,
		"readonly_shadow_replica": true,
		"rollback_automation_verified": true,
	},
	"patch": {
		"ddl_migrations": 0,
		"orm_model_mutations": 0,
		"serialization_breaks": 0,
		"api_backward_compatible": true,
	},
	"shadow": {
		"schema_breaking_diffs": 0,
		"status_code_drift_pct": 0.0,
		"p99_latency_ms": 42.0,
		"max_p99_latency_ms": 120.0,
		"baseline_syscalls": ["read", "write", "futex", "epoll_wait", "accept4"],
		"canary_syscalls": ["read", "write", "futex", "epoll_wait", "accept4"],
	},
}

test_clean_stateless_patch_autonomous_allowed if {
	gate.allow_autonomous_rollout with input as clean_gate_input
	not gate.route_to_exception_cockpit with input as clean_gate_input
	not gate.trigger_canary_rollback with input as clean_gate_input
}

test_execve_syscall_triggers_rollback if {
	bad := object.union(clean_gate_input, {
		"shadow": object.union(clean_gate_input.shadow, {
			"canary_syscalls": ["read", "write", "futex", "execve"],
		}),
	})
	not gate.allow_autonomous_rollout with input as bad
	gate.trigger_canary_rollback with input as bad
	"execve" in gate.unauthorized_syscalls with input as bad
	"SHADOW_UNAUTHORIZED_SYSCALL" in gate.reasons with input as bad
}

test_ddl_migration_routes_to_exception_cockpit if {
	stateful := object.union(clean_gate_input, {
		"patch": object.union(clean_gate_input.patch, {"ddl_migrations": 1}),
	})
	not gate.patch_stateless with input as stateful
	gate.route_to_exception_cockpit with input as stateful
	not gate.allow_autonomous_rollout with input as stateful
	"STATEFUL_PATCH_DDL_DETECTED" in gate.reasons with input as stateful
}

test_freeze_rollback_blocks_and_rolls_back if {
	frozen := object.union(clean_gate_input, {"freeze_mode": "FREEZE_ROLLBACK"})
	gate.freeze_blocked with input as frozen
	gate.trigger_canary_rollback with input as frozen
	not gate.allow_autonomous_rollout with input as frozen
}
