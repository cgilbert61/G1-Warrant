package warrant.gate_test

import data.warrant.gate
import rego.v1

clean_gate_input := {
	"freeze_mode": "OPERATIONAL",
	"blast_radius_exceeded": false,
	"allow_guarded_canary": true,
	"shadow_evaluated": true,
	"service": {
		"test_coverage_pct": 91.5,
		"otel_health_probes": true,
		"readonly_shadow_replica": true,
		"shadow_db_mode": "EPHEMERAL_COW_BRANCH",
		"rollback_automation_verified": true,
		"readonly_root_filesystem": true,
		"noexec_tmp_mounts": true,
	},
	"patch": {
		"ddl_migrations": 0,
		"orm_model_mutations": 0,
		"serialization_breaks": 0,
		"api_backward_compatible": true,
		"forbidden_config_touches": [],
	},
	"shadow": {
		"schema_breaking_diffs": 0,
		"status_code_drift_pct": 0.0,
		"p99_latency_ms": 42.0,
		"max_p99_latency_ms": 120.0,
		"baseline_syscalls": ["read", "write", "futex", "epoll_wait", "accept4"],
		"canary_syscalls": ["read", "write", "futex", "epoll_wait", "accept4"],
		"sensitive_files_accessed": [],
		"unexpected_egress_endpoints": [],
	},
}

test_clean_stateless_patch_autonomous_allowed if {
	gate.allow_autonomous_rollout with input as clean_gate_input
	gate.autonomy_tier == "TIER_1_FULL_AUTONOMOUS" with input as clean_gate_input
	not gate.route_to_exception_cockpit with input as clean_gate_input
	not gate.trigger_canary_rollback with input as clean_gate_input
}

test_mutable_rootfs_blocks_autonomous_rollout if {
	mutable_fs := object.union(clean_gate_input, {
		"service": object.union(clean_gate_input.service, {
			"readonly_root_filesystem": false,
		}),
	})
	not gate.allow_autonomous_rollout with input as mutable_fs
	gate.autonomy_tier == "TIER_3_CONTAIN_AND_CAB" with input as mutable_fs
	"SERVICE_MUTABLE_ROOTFS_OR_EXEC_TMP" in gate.reasons with input as mutable_fs
}

test_forbidden_agent_or_workflow_config_blocks_rollout if {
	poisoned := object.union(clean_gate_input, {
		"patch": object.union(clean_gate_input.patch, {
			"forbidden_config_touches": [".github/workflows/ci.yml", "AGENTS.md"],
		}),
	})
	not gate.patch_stateless with input as poisoned
	not gate.allow_autonomous_rollout with input as poisoned
	"FORBIDDEN_BUILD_OR_AGENT_CONFIG_TOUCHED" in gate.reasons with input as poisoned
}

test_brownfield_service_qualifies_for_tier2_guarded_canary if {
	brownfield := object.union(clean_gate_input, {
		"allow_guarded_canary": true,
		"service": {
			"test_coverage_pct": 58.0,
			"otel_health_probes": true,
			"readonly_shadow_replica": false,
			"shadow_db_mode": "NONE",
			"rollback_automation_verified": true,
			"readonly_root_filesystem": true,
			"noexec_tmp_mounts": true,
		},
	})
	gate.autonomy_tier == "TIER_2_GUARDED_CANARY" with input as brownfield
	gate.allow_autonomous_rollout with input as brownfield
	not gate.route_to_exception_cockpit with input as brownfield
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

test_in_process_sa_token_read_triggers_rollback_without_new_syscall if {
	exfil := object.union(clean_gate_input, {
		"shadow": object.union(clean_gate_input.shadow, {
			"sensitive_files_accessed": ["/var/run/secrets/kubernetes.io/serviceaccount/token"],
			"unexpected_egress_endpoints": ["198.51.100.42:443"],
		}),
	})
	not gate.allow_autonomous_rollout with input as exfil
	gate.trigger_canary_rollback with input as exfil
	"SHADOW_SENSITIVE_FILE_READ_DETECTED" in gate.reasons with input as exfil
	"SHADOW_UNEXPECTED_EGRESS_EXFILTRATION" in gate.reasons with input as exfil
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
