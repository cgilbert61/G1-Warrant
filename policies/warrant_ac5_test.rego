package warrant.ac5_test

import data.warrant.ac5
import rego.v1

valid_input := {
	"slot1": {
		"principal_id": "usr-alice-so",
		"email": "alice.vance@g1163rt.sec",
		"key_fingerprint": "fp-alice-111",
		"role": "SERVICE_OWNER",
		"revoked": false,
	},
	"slot2": {
		"principal_id": "usr-bob-ao",
		"email": "bob.sterling@g1163rt.sec",
		"key_fingerprint": "fp-bob-222",
		"role": "AUTHORIZING_OFFICIAL",
		"revoked": false,
	},
	"now_unix": 1700000000,
	"expires_unix": 1800000000,
	"scope_services": ["payments-ledger-api", "identity-sso-gateway"],
	"target_service": "payments-ledger-api",
	"max_cvss": 10.0,
	"finding_cvss": 9.8,
	"max_blast_radius_replicas": 12,
	"target_replicas": 6,
}

test_valid_dual_warrant_allowed if {
	ac5.allow with input as valid_input
}

test_chained_medium_cwe209_allowed_above_min_cvss_floor if {
	medium_cwe209 := object.union(valid_input, {
		"min_cvss": 7.0,
		"finding_cvss": 5.3,
		"finding_is_kev": false,
		"finding_cwe": "CWE-209",
		"auto_remediate_cwes": ["CWE-209", "CWE-918", "CWE-434"],
	})
	ac5.allow with input as medium_cwe209
	ac5.chained_cwe_elevated with input as medium_cwe209

	non_chained_medium := object.union(medium_cwe209, {
		"finding_cwe": "CWE-476",
	})
	not ac5.allow with input as non_chained_medium
	"FINDING_BELOW_PRIORITY_FLOOR_UNLESS_CHAINED_CWE" in ac5.violations with input as non_chained_medium
}

test_secret_rotation_requires_secret_warrant_class_or_flag if {
	denied := object.union(valid_input, {
		"action_kind": "SECRET_ROTATION",
		"warrant_class": "KEV-TIER1-STATELESS",
		"allow_secret_rotation": false,
	})
	not ac5.allow with input as denied
	"SECRET_ROTATION_NOT_AUTHORIZED_BY_WARRANT" in ac5.violations with input as denied

	allowed := object.union(valid_input, {
		"action_kind": "SECRET_ROTATION",
		"warrant_class": "SECRET-ROTATION-STATELESS",
	})
	ac5.allow with input as allowed
}

test_reject_same_principal if {
	bad := object.union(valid_input, {
		"slot2": {
			"principal_id": "usr-alice-so",
			"email": "alice.vance@g1163rt.sec",
			"key_fingerprint": "fp-alice-111",
			"role": "AUTHORIZING_OFFICIAL",
			"revoked": false,
		},
	})
	not ac5.allow with input as bad
	"AC5_IDENTICAL_PRINCIPAL" in ac5.violations with input as bad
	"AC5_IDENTICAL_KEY_FINGERPRINT" in ac5.violations with input as bad
}

test_reject_system_admin_signer if {
	bad := object.union(valid_input, {
		"slot2": {
			"principal_id": "usr-carol-sysadmin",
			"email": "carol.root@g1163rt.sec",
			"key_fingerprint": "fp-carol-999",
			"role": "SYSTEM_ADMIN",
			"revoked": false,
		},
	})
	not ac5.allow with input as bad
	"AC5_SYSADMIN_PROHIBITED" in ac5.violations with input as bad
}

test_reject_revoked_signer if {
	bad := object.union(valid_input, {
		"slot2": object.union(valid_input.slot2, {"revoked": true}),
	})
	not ac5.allow with input as bad
	"REVOKED_SLOT2_SIGNER" in ac5.violations with input as bad
}

test_reject_expired_warrant if {
	bad := object.union(valid_input, {"now_unix": 1900000000})
	not ac5.allow with input as bad
	"WARRANT_EXPIRED" in ac5.violations with input as bad
}

test_v140_reject_tier_c_scanner_clone_source_and_fabricated_manual_hash if {
	bad_scanner := object.union(valid_input, {
		"clone_sources": [{
			"source_system": "tenable",
			"image_identity": "fake-scanner-img",
			"source_mode": "ESTATE_LOADER",
			"snapshot_sha256": "abcd1234",
		}],
	})
	not ac5.allow with input as bad_scanner
	"TIER_C_SCANNER_CANNOT_DECLARE_CLONE_SOURCE" in ac5.violations with input as bad_scanner

	bad_manual := object.union(valid_input, {
		"clone_sources": [{
			"source_system": "ms-mecm",
			"image_identity": "wim://win2022-qa",
			"source_mode": "MANUAL",
			"snapshot_sha256": "fabricated1234",
		}],
	})
	not ac5.allow with input as bad_manual
	"MANUAL_CLONE_SOURCE_FORBIDS_FABRICATED_SNAPSHOT_HASH" in ac5.violations with input as bad_manual

	good_estate := object.union(valid_input, {
		"clone_sources": [{
			"source_system": "ms-mecm",
			"image_identity": "wim://win2022-qa",
			"source_mode": "ESTATE_LOADER",
			"snapshot_sha256": "99887766554433221100",
		}],
		"estate_drift_policy": "FAIL_CLOSED",
	})
	ac5.allow with input as good_estate
}
