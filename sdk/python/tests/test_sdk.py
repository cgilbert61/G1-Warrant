"""Automated unit & live integration tests for the G1-Warrant Python SDK (`g1_warrant`)."""

from __future__ import annotations

import base64
import json
import unittest

from g1_warrant import (
    PAYLOAD_TYPE_ATTESTATION,
    ROLE_AUTHORIZING_OFFICIAL,
    ROLE_SERVICE_OWNER,
    AuditorScopeViolationError,
    WarrantClient,
    canonicalize_jcs,
    draft_warrant_envelope,
    dsse_pae,
    generate_ed25519_signer_bundle,
    verify_oscal_bundle_offline,
    verify_oscal_bundle_with_keyring,
)
from g1_warrant.crypto import draft_unsigned_envelope


class TestG1WarrantCryptoAndSDK(unittest.TestCase):
    def test_jcs_canonicalization_deterministic_key_order(self) -> None:
        raw = {"z_key": [3, 1, 2], "a_key": True, "m_float": 10.0, "nested": {"b": "ok", "a": None}}
        canon = canonicalize_jcs(raw)
        self.assertEqual(
            canon.decode("utf-8"),
            '{"a_key":true,"m_float":10,"nested":{"a":null,"b":"ok"},"z_key":[3,1,2]}',
        )

    def test_dual_key_signing_and_offline_oscal_verification(self) -> None:
        so = generate_ed25519_signer_bundle("usr-so", "so@agency.gov", "Alice SO", ROLE_SERVICE_OWNER)
        ao = generate_ed25519_signer_bundle("usr-ao", "ao@agency.gov", "Bob AO", ROLE_AUTHORIZING_OFFICIAL)

        env = draft_warrant_envelope(scope_services=["payments-ledger-api"], max_cvss=9.8)
        so.sign_envelope(1, env)
        ao.sign_envelope(2, env)
        self.assertEqual(len(env["signatures"]), 2)

        # Sign a synthetic OSCAL attestation envelope and verify offline
        kernel = generate_ed25519_signer_bundle("sys-kernel", "kernel@g1163rt.sec", "Kernel Seal", ROLE_SERVICE_OWNER)
        att_env = draft_unsigned_envelope(
            PAYLOAD_TYPE_ATTESTATION,
            {"attestation_id": "att-py-001", "cve_id": "CVE-2026-41001", "service_id": "payments-ledger-api"},
        )
        kernel.sign_envelope(1, att_env)
        bundle = {
            "attestation_id": "att-py-001",
            "cve_id": "CVE-2026-41001",
            "service_id": "payments-ledger-api",
            "warrant_id": "wrt-py-001",
            "dsse_envelope": att_env,
            "entry_hash": "f" * 64,
        }
        verified = verify_oscal_bundle_offline(bundle, kernel.public_key_b64)
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["jcs_canonical_match"])

        ring_verified = verify_oscal_bundle_with_keyring(
            bundle, [{"key_id": kernel.key_id, "public_key_b64": kernel.public_key_b64}]
        )
        self.assertTrue(ring_verified["valid"])

        # Tampering with public key must reject
        other = generate_ed25519_signer_bundle("usr-other", "other@agency.gov", "Other", ROLE_AUTHORIZING_OFFICIAL)
        with self.assertRaises(ValueError):
            verify_oscal_bundle_offline(bundle, other.public_key_b64)

    def test_secret_rotation_and_chained_cwe_warrant_draft(self) -> None:
        env = draft_warrant_envelope(
            scope_services=["payments-ledger-api"],
            warrant_class="SECRET-ROTATION-STATELESS",
            auto_remediate_cwes=["CWE-209", "CWE-918", "CWE-434"],
        )
        decoded = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
        self.assertTrue(decoded["allow_secret_rotation"])
        self.assertEqual(decoded["auto_remediate_cwes"], ["CWE-209", "CWE-918", "CWE-434"])

    def test_live_server_integration_if_running(self) -> None:
        cli = WarrantClient("http://localhost:8080", timeout=2.0)
        try:
            health = cli.health()
        except Exception:
            self.skipTest("Live warrantd not running on localhost:8080")
            return

        self.assertEqual(health["status"], "OK")
        sb = cli.scoreboard()
        self.assertIn("active_warrants_count", sb)

        # Verify real OSCAL export + offline cryptographic verification end-to-end!
        atts = cli.list_attestations()
        if atts:
            bundle = cli.export_oscal_bundle(atts[0]["attestation_id"])
            pk = cli.kernel_public_key_b64()
            verified = verify_oscal_bundle_offline(bundle, pk)
            self.assertTrue(verified["valid"])

        # Verify auditor token scope isolation end-to-end!
        minted = cli.mint_auditor_token(label="Python SDK E2E Test", ttl_hours=1)
        vault = cli.get_auditor_vault(bearer_token=minted["bearer"])
        self.assertIn("attestations", vault)

        scoped_cli = WarrantClient("http://localhost:8080", auditor_token=minted["bearer"])
        with self.assertRaises(AuditorScopeViolationError):
            scoped_cli.scoreboard()


if __name__ == "__main__":
    unittest.main()
