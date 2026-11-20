"""Automated unit & live integration tests for the G1-Warrant Python SDK (`g1_warrant`)."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from g1_warrant import (
    PAYLOAD_TYPE_ATTESTATION,
    ROLE_AUTHORIZING_OFFICIAL,
    ROLE_SERVICE_OWNER,
    WarrantAPIError,
    WarrantClient,
    canonicalize_jcs,
    draft_principal_enroll_envelope,
    draft_principal_revoke_envelope,
    draft_principal_rotate_and_revoke_envelope,
    draft_thaw_envelope,
    draft_warrant_envelope,
    generate_ed25519_signer_bundle,
    load_public_identity_file,
    verify_oscal_bundle_offline,
    verify_oscal_bundle_with_keyring,
    write_split_keypair_files,
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

    def test_split_keygen_hygiene_and_governance_envelopes(self) -> None:
        so = generate_ed25519_signer_bundle("usr-so", "so@agency.gov", "Alice SO", ROLE_SERVICE_OWNER)
        ao = generate_ed25519_signer_bundle("usr-ao", "ao@agency.gov", "Bob AO", ROLE_AUTHORIZING_OFFICIAL)
        so2 = generate_ed25519_signer_bundle("usr-so2", "so2@agency.gov", "Carol SO2", ROLE_SERVICE_OWNER)

        with tempfile.TemporaryDirectory() as tmp:
            priv_path, pub_path = write_split_keypair_files(Path(tmp) / "so-key", so)
            self.assertTrue(priv_path.exists())
            self.assertTrue(pub_path.exists())
            self.assertNotIn("private_key", pub_path.read_text(encoding="utf-8"))

            pub_ident = load_public_identity_file(pub_path)
            self.assertEqual(pub_ident.principal_id, "usr-so")

            # Passing .priv.json to load_public_identity_file must fail closed client-side!
            with self.assertRaises(ValueError):
                load_public_identity_file(priv_path)

            # 2-of-2 ENROLL_PRINCIPAL & 1-of-2 REVOKE_PRINCIPAL DSSE envelopes
            enroll_env = draft_principal_enroll_envelope(so2.to_public_identity())
            so.sign_envelope(1, enroll_env)
            ao.sign_envelope(2, enroll_env)
            self.assertEqual(len(enroll_env["signatures"]), 2)

            revoke_env = draft_principal_revoke_envelope(target_principal_id="usr-so2")
            so.sign_envelope(1, revoke_env)
            self.assertEqual(len(revoke_env["signatures"]), 1)

            rot_env = draft_principal_rotate_and_revoke_envelope(
                so2.to_public_identity(), target_principal_id="usr-so"
            )
            so.sign_envelope(1, rot_env)
            ao.sign_envelope(2, rot_env)
            self.assertEqual(len(rot_env["signatures"]), 2)
            rot_payload = json.loads(base64.b64decode(rot_env["payload"]).decode("utf-8"))
            self.assertEqual(rot_payload["action"], "ROTATE_AND_REVOKE_PRINCIPAL")

            thaw_env = draft_thaw_envelope(freeze_epoch=9)
            thaw_payload = json.loads(base64.b64decode(thaw_env["payload"]).decode("utf-8"))
            self.assertEqual(thaw_payload["freeze_epoch"], 9)
            self.assertIn("envelope_id", thaw_payload)

    def test_dual_key_signing_and_offline_oscal_verification(self) -> None:
        so = generate_ed25519_signer_bundle("usr-so", "so@agency.gov", "Alice SO", ROLE_SERVICE_OWNER)
        ao = generate_ed25519_signer_bundle("usr-ao", "ao@agency.gov", "Bob AO", ROLE_AUTHORIZING_OFFICIAL)

        env = draft_warrant_envelope(scope_services=["payments-ledger-api"], max_cvss=9.8)
        so.sign_envelope(1, env)
        ao.sign_envelope(2, env)
        self.assertEqual(len(env["signatures"]), 2)

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

        # Verify 6-chain ledger verification passes on live server
        chain_rep = cli.verify_ledger_chains()
        self.assertTrue(chain_rep["all_valid"])
        self.assertEqual(len(chain_rep["tables"]), 6)

        # Verify simulator clean-room estate seeding (6 workloads)
        estate = cli.list_estate()
        self.assertGreaterEqual(len(estate), 6)

        # Verify unauthenticated mutating operator endpoints reject anonymous calls with 401!
        unauth_cli = WarrantClient("http://localhost:8080", timeout=2.0, operator_token="")
        with self.assertRaises(WarrantAPIError) as ctx:
            unauth_cli.mint_auditor_token(label="Unauthorized Attempt", ttl_hours=1)
        self.assertEqual(ctx.exception.status_code, 401)

        atts = cli.list_attestations()
        if atts:
            bundle = cli.export_oscal_bundle(atts[0]["attestation_id"])
            verified = verify_oscal_bundle_with_keyring(bundle, cli.kernel_public_key_ring())
            self.assertTrue(verified["valid"])


if __name__ == "__main__":
    unittest.main()
