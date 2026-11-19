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
