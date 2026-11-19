package warrant.ac5

import rego.v1

default allow := false

allow if {
	count(violations) == 0
}

violations contains "AC5_SYSADMIN_PROHIBITED" if {
	input.slot1.role == "SYSTEM_ADMIN"
}

violations contains "AC5_SYSADMIN_PROHIBITED" if {
	input.slot2.role == "SYSTEM_ADMIN"
}

violations contains "AC5_SLOT1_MUST_BE_SERVICE_OWNER" if {
	input.slot1.role != "SERVICE_OWNER"
}

violations contains "AC5_SLOT2_MUST_BE_AUTHORIZING_OFFICIAL" if {
	input.slot2.role != "AUTHORIZING_OFFICIAL"
}

violations contains "AC5_IDENTICAL_PRINCIPAL" if {
	input.slot1.principal_id == input.slot2.principal_id
}

violations contains "AC5_IDENTICAL_EMAIL" if {
	lower(input.slot1.email) == lower(input.slot2.email)
}

violations contains "AC5_IDENTICAL_KEY_FINGERPRINT" if {
	lower(input.slot1.key_fingerprint) == lower(input.slot2.key_fingerprint)
}

violations contains "REVOKED_SLOT1_SIGNER" if {
	input.slot1.revoked == true
}

violations contains "REVOKED_SLOT2_SIGNER" if {
	input.slot2.revoked == true
}

violations contains "WARRANT_EXPIRED" if {
	input.expires_unix > 0
	input.now_unix >= input.expires_unix
}

service_in_scope if {
	some svc in input.scope_services
	svc == "*"
}

service_in_scope if {
	some svc in input.scope_services
	svc == input.target_service
}

violations contains "SCOPE_SERVICE_NOT_COVERED" if {
	input.target_service != ""
	not service_in_scope
}

violations contains "CVSS_EXCEEDS_WARRANT_CEILING" if {
	input.max_cvss > 0
	input.finding_cvss > input.max_cvss
}

violations contains "BLAST_RADIUS_EXCEEDS_CEILING" if {
	input.max_blast_radius_replicas > 0
	input.target_replicas > input.max_blast_radius_replicas
}
