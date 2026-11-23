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
    TRUST_BASIS_EMBEDDED_KEYRING_OPT_IN,
    TRUST_BASIS_EXTERNAL_KEYRING,
    TRUST_BASIS_EXTERNAL_PINNED_PUBKEY,
    WarrantAPIError,
    WarrantClient,
    __version__,
    build_agent_pop_headers,
    canonicalize_jcs,
    draft_agent_enroll_envelope,
    draft_commissioning_function_envelope,
    draft_principal_enroll_envelope,
    draft_principal_revoke_envelope,
    draft_principal_rotate_and_revoke_envelope,
    draft_thaw_envelope,
    draft_warrant_envelope,
    dsse_pae,
    generate_agent_key_bundle,
    generate_ed25519_signer_bundle,
    load_public_identity_file,
    sign_builder_provenance,
    sign_token_exchange_request,
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

    def test_shared_rfc8785_jcs_and_cross_language_dsse_vectors_wn2(self) -> None:
        import hashlib

        repo_root = Path(__file__).resolve().parents[3]
        vec_file = repo_root / "testdata" / "rfc8785_jcs_vectors.json"
        suite = json.loads(vec_file.read_text(encoding="utf-8"))
        self.assertGreater(len(suite["jcs_vectors"]), 0)
        for vec in suite["jcs_vectors"]:
            parsed = json.loads(vec["input_json"])
            got = canonicalize_jcs(parsed)
            self.assertEqual(got.decode("utf-8"), vec["expected_canonical_json"], msg=vec["name"])
            self.assertEqual(hashlib.sha256(got).hexdigest(), vec["expected_sha256"], msg=vec["name"])

        dsse = suite["cross_language_dsse_vector"]
        got_payload = canonicalize_jcs(json.loads(dsse["input_payload_json"]))
        self.assertEqual(got_payload.decode("utf-8"), dsse["expected_canonical_payload"])
        self.assertEqual(hashlib.sha256(got_payload).hexdigest(), dsse["expected_payload_sha256"])
        pae = dsse_pae(dsse["payload_type"], got_payload)
        self.assertEqual(hashlib.sha256(pae).hexdigest(), dsse["expected_pae_sha256"])
        verified = verify_oscal_bundle_offline({"dsse_envelope": dsse["dsse_envelope"]}, dsse["public_key_b64"])
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["cve_id"], "CVE-2026-41001")
        self.assertEqual(verified["trust_basis"], TRUST_BASIS_EXTERNAL_PINNED_PUBKEY)

    def test_split_keygen_hygiene_and_governance_envelopes(self) -> None:
        self.assertEqual(__version__, "1.3.1")
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
            {
                "attestation_id": "att-py-001",
                "cve_id": "CVE-2026-41001",
                "service_id": "payments-ledger-api",
                "warrant_id": "wrt-py-001",
            },
        )
        kernel.sign_envelope(1, att_env)
        bundle = {
            "attestation_id": "att-py-001",
            "cve_id": "CVE-2026-41001",
            "service_id": "payments-ledger-api",
            "warrant_id": "wrt-py-001",
            "dsse_envelope": att_env,
            "entry_hash": "f" * 64,
            "kernel_public_key_ring": [{"key_id": kernel.key_id, "public_key_b64": kernel.public_key_b64}],
        }
        verified = verify_oscal_bundle_offline(bundle, kernel.public_key_b64)
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["jcs_canonical_match"])
        self.assertEqual(verified["trust_basis"], TRUST_BASIS_EXTERNAL_PINNED_PUBKEY)
        self.assertEqual(verified["warrant_id"], "wrt-py-001")

        # WN-3a: Stripping unsigned outer wrapper still extracts identity from signed DSSE payload
        stripped = verify_oscal_bundle_offline({"dsse_envelope": att_env}, kernel.public_key_b64)
        self.assertEqual(stripped["attestation_id"], "att-py-001")
        self.assertEqual(stripped["cve_id"], "CVE-2026-41001")
        self.assertEqual(stripped["service_id"], "payments-ledger-api")
        self.assertEqual(stripped["warrant_id"], "wrt-py-001")

        # WN-3b: Tampering unsigned outer wrapper field MUST fail closed with UNSIGNED_WRAPPER_MISMATCH
        tampered = dict(bundle, cve_id="CVE-2099-99999")
        with self.assertRaisesRegex(ValueError, "UNSIGNED_WRAPPER_MISMATCH"):
            verify_oscal_bundle_offline(tampered, kernel.public_key_b64)

        # WN-4a: verify_oscal_bundle_with_keyring with None/empty ring MUST fail closed even when embedded ring exists!
        with self.assertRaisesRegex(ValueError, "UNTRUSTED_KEYRING_EMPTY"):
            verify_oscal_bundle_with_keyring(bundle, None)
        with self.assertRaisesRegex(ValueError, "UNTRUSTED_KEYRING_EMPTY"):
            verify_oscal_bundle_with_keyring(bundle, [])

        # WN-4b: External keyring succeeds with TRUST_BASIS_EXTERNAL_KEYRING
        ring_verified = verify_oscal_bundle_with_keyring(
            bundle, [{"key_id": kernel.key_id, "public_key_b64": kernel.public_key_b64}]
        )
        self.assertTrue(ring_verified["valid"])
        self.assertEqual(ring_verified["trust_basis"], TRUST_BASIS_EXTERNAL_KEYRING)

        # WN-4c: Explicit opt-in embedded keyring succeeds with TRUST_BASIS_EMBEDDED_KEYRING_OPT_IN
        opt_in_verified = verify_oscal_bundle_with_keyring(bundle, None, allow_embedded_keyring_opt_in=True)
        self.assertTrue(opt_in_verified["valid"])
        self.assertEqual(opt_in_verified["trust_basis"], TRUST_BASIS_EMBEDDED_KEYRING_OPT_IN)

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

    def test_v1_1_0_agent_provenance_token_exchange_and_wire_pop(self) -> None:
        so = generate_ed25519_signer_bundle("usr-so", "so@agency.gov", "Alice SO", ROLE_SERVICE_OWNER)
        ao = generate_ed25519_signer_bundle("usr-ao", "ao@agency.gov", "Bob AO", ROLE_AUTHORIZING_OFFICIAL)
        builder = generate_agent_key_bundle("bld-ci", "CI Builder")
        agent = generate_agent_key_bundle("agt-worker", "Autonomous Worker")

        cf_env = draft_commissioning_function_envelope(
            function_id="fn-fin-core",
            display_name="Fin Core",
            owning_org_unit="FIN_SEC",
            primary_so_principal_id=so.principal_id,
            primary_ao_principal_id=ao.principal_id,
            escalation_contact="oncall@agency.gov",
        )
        so.sign_envelope(1, cf_env)
        ao.sign_envelope(2, cf_env)
        self.assertEqual(len(cf_env["signatures"]), 2)

        digest = "sha256:" + ("a" * 64)
        prov_sig = sign_builder_provenance(agent.agent_id, digest, agent.public_key_b64, builder.private_key_b64)
        ag_env = draft_agent_enroll_envelope(
            agent_id=agent.agent_id,
            commissioning_function_id="fn-fin-core",
            public_key_b64=agent.public_key_b64,
            artifact_digest=digest,
            builder_principal_id=builder.agent_id,
            builder_public_key_b64=builder.public_key_b64,
            builder_key_fingerprint=builder.key_fingerprint,
            builder_provenance_sig_b64=prov_sig,
            allowed_actions=["EXTRACT_SARIF_2_1_0"],
            allowed_services=["*"],
        )
        so.sign_envelope(1, ag_env)
        ao.sign_envelope(2, ag_env)
        self.assertEqual(len(ag_env["signatures"]), 2)

        xch = sign_token_exchange_request(
            agent,
            target_asset="payments-ledger-api",
            requested_action="EXTRACT_SARIF_2_1_0",
            authority_mode="AUTONOMOUS_WORKLOAD_SPONSORED",
        )
        self.assertEqual(len(xch["signatures"]), 1)

        fake_task_dsse = draft_unsigned_envelope(
            "application/vnd.g1163rt.task-warrant.v1+json",
            {"task_token_id": "tsk-py-001", "allowed_action": "EXTRACT_SARIF_2_1_0"},
        )
        hdrs = build_agent_pop_headers("POST", "/extract/sarif", b'{"version":"2.1.0"}', fake_task_dsse, agent, unix_ts=1795000000)
        self.assertIn("X-Warrant-Task-DSSE", hdrs)
        self.assertTrue(hdrs["X-Warrant-Agent-PoP"].startswith("1795000000."))

    def test_v1_2_0_finder_and_distributor_contracts(self) -> None:
        env = draft_warrant_envelope(
            scope_services=["payments-ledger-api"],
            scope_assets=["payments-ledger-api", "srv-win-01"],
            authorized_vendor_detections=["QID-99101"],
        )
        decoded = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
        self.assertEqual(decoded["scope_assets"], ["payments-ledger-api", "srv-win-01"])
        self.assertEqual(decoded["authorized_vendor_detections"], ["QID-99101"])

        cli = WarrantClient("http://localhost:8080")
        with self.assertRaises(ValueError):
            cli.submit_finder_intake("unsupported-scanner", b"{}")

        sdk_root = Path(__file__).resolve().parents[1]
        self.assertTrue((sdk_root / "LICENSE").is_file())
        self.assertTrue((sdk_root / "NOTICE").is_file())
        pyproject_text = (sdk_root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("LICENSE", pyproject_text)
        self.assertIn("NOTICE", pyproject_text)

    def test_v1_3_0_cli_finder_intake_token_only_zero_signer_keys(self) -> None:
        import http.server
        import threading
        from g1_warrant.cli import main as cli_main

        captured: dict[str, str] = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                captured["path"] = self.path
                captured["intake_token"] = self.headers.get("X-Warrant-Intake-Token", "")
                captured["gov_dsse"] = self.headers.get("X-Warrant-Governance-DSSE", "")
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length)
                body = json.dumps(
                    [
                        {
                            "remediation_id": "rem-py-intake-1",
                            "cve_id": "UNMAPPED-QID-99881",
                            "cve_mapping_status": "UNMAPPED_VENDOR_ADVISORY",
                            "class_binding_status": "UNBOUND",
                            "status_health": "BRIDGED",
                        }
                    ]
                ).encode("utf-8")
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                qfile = Path(tmp) / "qualys.json"
                qfile.write_text('{"hosts":[]}', encoding="utf-8")
                rc = cli_main(
                    [
                        "--url",
                        f"http://127.0.0.1:{port}",
                        "finder-intake",
                        "qualys",
                        str(qfile),
                        "--service",
                        "payments-ledger-api",
                        "--intake-token",
                        "g1int_pycli_token_only",
                    ]
                )
                self.assertEqual(rc, 0)
                self.assertEqual(captured["intake_token"], "g1int_pycli_token_only")
                self.assertEqual(captured["gov_dsse"], "")
                self.assertIn("/api/v1/intake/qualys", captured["path"])
        finally:
            srv.shutdown()
            srv.server_close()

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

        # Verify ledger hash-chain verification passes on live server
        chain_rep = cli.verify_ledger_chains()
        self.assertTrue(chain_rep["all_valid"])
        self.assertGreaterEqual(len(chain_rep["tables"]), 6)

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
