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

test_wn8_full_per_asset_distributor_closure_allows_retirement_and_mint if {
	full_dist := object.union(verified_input, {
		"evidence_granularity": "PER_ASSET_VERIFIED",
		"targeted_assets": 6,
		"landed_assets": 6,
		"reboot_waiting_assets": 0,
		"failed_assets": 0,
	})
	verify.allow_bridge_retirement with input as full_dist
	verify.allow_attestation_mint with input as full_dist
	not verify.allow_partial_attestation_mint with input as full_dist
	verify.closure_completeness == "FULL" with input as full_dist
	verify.assurance_tier == "ASSURANCE_TIER_2_DIFFERENTIAL_TWIN" with input as full_dist
}

test_wn8_partial_fleet_landing_mints_partial_attestation_and_holds_bridge if {
	partial_dist := object.union(verified_input, {
		"evidence_granularity": "PER_ASSET_VERIFIED",
		"targeted_assets": 6,
		"landed_assets": 4,
		"reboot_waiting_assets": 2,
		"failed_assets": 0,
	})
	not verify.allow_bridge_retirement with input as partial_dist
	not verify.allow_attestation_mint with input as partial_dist
	verify.allow_partial_attestation_mint with input as partial_dist
	verify.closure_completeness == "PARTIAL" with input as partial_dist
	"PARTIAL_FLEET_LANDING_BRIDGE_HELD" in verify.blockers with input as partial_dist
}

test_wn8_dispatch_ack_only_assigns_tier0_and_blocks_bridge_retirement if {
	dispatch_only := object.union(verified_input, {
		"evidence_granularity": "DISPATCH_ACK_ONLY",
		"targeted_assets": 6,
		"landed_assets": 0,
	})
	not verify.allow_bridge_retirement with input as dispatch_only
	not verify.allow_attestation_mint with input as dispatch_only
	not verify.allow_partial_attestation_mint with input as dispatch_only
	verify.allow_dispatch_only_record with input as dispatch_only
	verify.closure_completeness == "DISPATCH_ONLY" with input as dispatch_only
	verify.assurance_tier == "ASSURANCE_TIER_0_DISTRIBUTOR_DISPATCH_ONLY" with input as dispatch_only
	"DISTRIBUTOR_LACKS_PER_ASSET_EVIDENCE" in verify.blockers with input as dispatch_only
}

test_v130_clone_twin_proving_3_clones_userspace_allows_closure if {
	proved := object.union(verified_input, {
		"clone_twin_proving_present": true,
		"patch_target_layer": "USERSPACE_SOFTWARE",
		"twin_runtime": "CONTAINER_TWIN",
		"clone_twin_count": 3,
		"clone_twin_all_passed": true,
	})
	verify.allow_bridge_retirement with input as proved
	verify.allow_attestation_mint with input as proved
}

test_v130_kernel_patch_on_container_twin_fails_closed_requires_vm_twin if {
	kernel_on_container := object.union(verified_input, {
		"clone_twin_proving_present": true,
		"patch_target_layer": "KERNEL",
		"twin_runtime": "CONTAINER_TWIN",
		"clone_twin_count": 3,
		"clone_twin_all_passed": true,
	})
	not verify.allow_bridge_retirement with input as kernel_on_container
	not verify.allow_attestation_mint with input as kernel_on_container
	"KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME" in verify.blockers with input as kernel_on_container
}

test_v130_kernel_patch_on_vm_twin_succeeds_and_failed_clone_blocks if {
	kernel_on_vm := object.union(verified_input, {
		"clone_twin_proving_present": true,
		"patch_target_layer": "KERNEL",
		"twin_runtime": "VM_TWIN",
		"clone_twin_count": 3,
		"clone_twin_all_passed": true,
	})
	verify.allow_bridge_retirement with input as kernel_on_vm
	verify.allow_attestation_mint with input as kernel_on_vm

	failed_clone := object.union(verified_input, {
		"clone_twin_proving_present": true,
		"patch_target_layer": "USERSPACE_SOFTWARE",
		"twin_runtime": "CONTAINER_TWIN",
		"clone_twin_count": 3,
		"clone_twin_all_passed": false,
	})
	not verify.allow_bridge_retirement with input as failed_clone
	"CLONE_TWIN_PROVING_FAILED" in verify.blockers with input as failed_clone
}
