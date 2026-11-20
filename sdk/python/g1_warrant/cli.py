"""Command-Line Interface (`g1-warrant`) for the G1-Warrant Python SDK."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .client import WarrantAPIError, WarrantClient
from .crypto import (
    ROLE_AUTHORIZING_OFFICIAL,
    ROLE_SERVICE_OWNER,
    SignerKeyBundle,
    draft_thaw_envelope,
    draft_warrant_envelope,
    generate_ed25519_signer_bundle,
    load_public_identity_file,
    verify_oscal_bundle_offline,
    verify_oscal_bundle_with_keyring,
    write_split_keypair_files,
)


def _dump(obj: object) -> None:
    print(json.dumps(obj, indent=2))


def _load_priv_key(path: Path | None) -> SignerKeyBundle | None:
    if path is None:
        return None
    return SignerKeyBundle.from_dict(json.loads(path.read_text(encoding="utf-8")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="g1-warrant",
        description="G1-Warrant Python SDK & Operator/Auditor CLI — G1163RT Security Labs",
    )
    parser.add_argument("--url", default=None, help="G1-Warrant server URL (default: $WARRANT_API_URL or http://localhost:8080)")
    parser.add_argument("--signer-key", type=Path, default=None, help="Active principal .priv.json for 1-of-2 DSSE emergency/governance actions")
    parser.add_argument("--operator-token", default=None, help="Optional WARRANT_OPERATOR_TOKEN")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--version", action="version", version=f"g1-warrant-sdk v{__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Show live fleet remediation scoreboard and freeze posture")
    sub.add_parser("warrants", help="List Standing Warrants and live AC-5 status")

    p_verify_w = sub.add_parser("warrant-verify", help="Re-verify a Standing Warrant live in N1")
    p_verify_w.add_argument("warrant_id")

    p_mint = sub.add_parser("warrant-mint", help="Draft and 2-of-2 co-sign a Standing Warrant using explicit Slot 1 & Slot 2 keys")
    p_mint.add_argument("--slot1-key", type=Path, required=True, help="Slot 1 (SERVICE_OWNER) .priv.json")
    p_mint.add_argument("--slot2-key", type=Path, required=True, help="Slot 2 (AUTHORIZING_OFFICIAL) .priv.json")
    p_mint.add_argument("--warrant-class", default="KEV-TIER1-STATELESS")
    p_mint.add_argument("--services", default="payments-ledger-api,identity-sso-gateway")

    p_keygen = sub.add_parser("keygen", help="Generate split Ed25519 AC-5 keypair (<name>.priv.json + <name>.pub.json)")
    p_keygen.add_argument("--id", required=True)
    p_keygen.add_argument("--email", required=True)
    p_keygen.add_argument("--name", default="G1 Signer")
    p_keygen.add_argument("--role", choices=[ROLE_SERVICE_OWNER, ROLE_AUTHORIZING_OFFICIAL], default=ROLE_SERVICE_OWNER)
    p_keygen.add_argument("--out", default=None, help="Output prefix (writes <name>.priv.json [0600] and <name>.pub.json [0644])")

    p_preg = sub.add_parser("principals-register", help="Enroll a <name>.pub.json public key in N1")
    p_preg.add_argument("--pub", type=Path, required=True, help="Path to <name>.pub.json (private keys rejected)")
    p_preg.add_argument("--admin-token", default=None, help="One-shot genesis WARRANT_BOOTSTRAP_ADMIN_TOKEN")
    p_preg.add_argument("--slot1-key", type=Path, default=None, help="Post-seal Slot 1 (SERVICE_OWNER) .priv.json")
    p_preg.add_argument("--slot2-key", type=Path, default=None, help="Post-seal Slot 2 (AUTHORIZING_OFFICIAL) .priv.json")

    p_pseal = sub.add_parser("principals-seal", help="Permanently seal genesis bootstrap enrollment")
    p_pseal.add_argument("--admin-token", default=None)
    p_pseal.add_argument("--key", type=Path, default=None)

    p_prev = sub.add_parser("principals-revoke", help="Revoke a principal using a 1-of-2 DSSE active principal signature")
    p_prev.add_argument("--principal", required=True)
    p_prev.add_argument("--reason", default="CLI_KEY_REVOCATION")
    p_prev.add_argument("--key", type=Path, default=None, help="Active principal .priv.json signing REVOKE_PRINCIPAL")

    sub.add_parser("pipeline", help="List 5-stage Race Pipeline remediations")
    p_trace = sub.add_parser("traces", help="Show millisecond execution traces for a remediation")
    p_trace.add_argument("remediation_id")

    sub.add_parser("estate", help="Show N2 Estate Autonomous Eligibility Scorecard")
    sub.add_parser("exceptions", help="List Four-Eyes Ceiling Exceptions")
    sub.add_parser("attestations", help="List signed NIST OSCAL 1.1.2 POA&M closure attestations")

    p_sarif = sub.add_parser("intake-sarif", help="Submit an untrusted SARIF 2.1.0 report into G1-Warrant")
    p_sarif.add_argument("sarif_file", type=Path)
    p_sarif.add_argument("--service", default=None)
    p_sarif.add_argument("--profile", default=None)

    p_secrets = sub.add_parser("intake-secrets", help="Submit Gitleaks/GitGuardian secret-exposure scan for SECRET-ROTATION-STATELESS")
    p_secrets.add_argument("scan_file", type=Path)
    p_secrets.add_argument("--service", default=None)

    p_sim = sub.add_parser("simulate", help="Trigger a deterministic control-plane scenario")
    p_sim.add_argument(
        "scenario",
        choices=[
            "inject-kev",
            "bad-syscall",
            "stateful-ddl",
            "runtime-drift",
            "secret-exposure",
            "in-pod-webshell",
            "poisoned-config",
        ],
    )

    p_freeze = sub.add_parser("freeze", help="Activate or thaw Asymmetric Emergency Freeze")
    p_freeze.add_argument("action", choices=["hold", "rollback", "thaw"])
    p_freeze.add_argument("--actor", default="g1-warrant-pycli")
    p_freeze.add_argument("--reason", default="CLI_EMERGENCY_ACTION")
    p_freeze.add_argument("--key", type=Path, default=None, help="Active principal .priv.json for hold/rollback")
    p_freeze.add_argument("--slot1-key", type=Path, default=None, help="Slot 1 (SERVICE_OWNER) .priv.json for thaw")
    p_freeze.add_argument("--slot2-key", type=Path, default=None, help="Slot 2 (AUTHORIZING_OFFICIAL) .priv.json for thaw")

    p_qrb = sub.add_parser("pipeline-rollback", help="Execute atomic 3-step Quarantined Rollback (Contain-Before-Unban)")
    p_qrb.add_argument("remediation_id")
    p_qrb.add_argument("--actor", default="g1-warrant-pycli")
    p_qrb.add_argument("--reason", default="POST_PROMOTION_REGRESSION")
    p_qrb.add_argument("--key", type=Path, default=None, help="Active principal .priv.json")

    p_feeds = sub.add_parser("feeds", help="Inspect or sync CISA KEV & Google OSV.dev live feeds")
    p_feeds.add_argument("action", choices=["status", "live", "offline", "sync-kev", "sync-osv"])

    p_oscal_exp = sub.add_parser("oscal-export", help="Export a signed NIST OSCAL 1.1.2 POA&M bundle")
    p_oscal_exp.add_argument("id")
    p_oscal_exp.add_argument("--out", type=Path, default=None)

    p_oscal_ver = sub.add_parser("oscal-verify", help="Offline cryptographic verification of an OSCAL POA&M bundle")
    p_oscal_ver.add_argument("bundle_file", type=Path)
    p_oscal_ver.add_argument("--pubkey", default=None, help="Base64 Ed25519 kernel public key (auto-fetched if omitted)")

    sub.add_parser("ledger-verify", help="Verify SHA-256 hash chains across all 6 immutable PostgreSQL tables")

    p_aud_mint = sub.add_parser("auditor-mint", help="Mint a scoped read-only 3PAO auditor bearer token")
    p_aud_mint.add_argument("--label", default="External 3PAO Assessment")
    p_aud_mint.add_argument("--ttl-hours", type=int, default=24)
    p_aud_mint.add_argument("--key", type=Path, default=None, help="Active principal .priv.json")

    p_aud_vault = sub.add_parser("auditor-vault", help="Inspect the read-only /auditor vault with a g1aud_* token")
    p_aud_vault.add_argument("--token", default=None)

    args = parser.parse_args(argv)

    try:
        if args.command == "keygen":
            bundle = generate_ed25519_signer_bundle(args.id, args.email, args.name, args.role)
            if args.out:
                priv_p, pub_p = write_split_keypair_files(args.out, bundle)
                print(f"Generated split Ed25519 AC-5 keypair ({bundle.role} | {bundle.key_id}):")
                print(f"  Private Signing Key (0600): {priv_p}")
                print(f"  Public Identity   (0644): {pub_p}")
            else:
                _dump(bundle.to_public_identity().to_dict())
            return 0

        global_signer = _load_priv_key(args.signer_key)
        cli = WarrantClient(base_url=args.url, operator_token=args.operator_token, signer_bundle=global_signer)

        if args.command == "status":
            sb = cli.scoreboard()
            if args.json:
                _dump(sb)
            else:
                fs = sb["freeze_state"]
                print(f"G1-WARRANT CONTROL PLANE STATUS ({cli.base_url})")
                print(f"  Posture:               {fs['mode']} (Actor: {fs['actor']} | Reason: {fs['reason_code']})")
                print(f"  Active Warrants:       {sb['active_warrants_count']}")
                print(f"  30d Fleet Median TTVR: {sb['fleet_median_ttvr_seconds']}s")
                print(f"  Active Bridges Armed:  {sb['active_bridges_armed']} (Median Age: {sb['median_bridge_age_seconds']}s)")
                print(f"  Estate Eligibility:    {sb['autonomous_eligibility_pct']:.1f}% ({sb['eligible_services_count']}/{sb['total_services_count']})")
                print(f"  Awaiting Dual-Key:     {sb['awaiting_dual_key_inbox_count']}")
                print(f"  Drift Violations:      {sb['active_drift_violations_count']}")
            return 0

        if args.command == "principals-register":
            pub_ident = load_public_identity_file(args.pub)
            s1 = _load_priv_key(args.slot1_key)
            s2 = _load_priv_key(args.slot2_key)
            _dump(cli.register_principal(pub_ident, admin_token=args.admin_token, slot1_signer=s1, slot2_signer=s2))
            return 0

        if args.command == "principals-seal":
            _dump(cli.seal_bootstrap(admin_token=args.admin_token, signer_bundle=_load_priv_key(args.key)))
            return 0

        if args.command == "principals-revoke":
            _dump(cli.revoke_principal(principal_id=args.principal, reason_code=args.reason, signer_bundle=_load_priv_key(args.key)))
            return 0

        if args.command == "warrants":
            _dump(cli.list_warrants())
            return 0

        if args.command == "warrant-verify":
            res = cli.verify_warrant(args.warrant_id)
            _dump(res)
            return 0 if res.get("valid") else 2

        if args.command == "warrant-mint":
            svcs = [s.strip() for s in args.services.split(",") if s.strip()]
            env = draft_warrant_envelope(scope_services=svcs, warrant_class=args.warrant_class)
            s1 = SignerKeyBundle.from_dict(json.loads(args.slot1_key.read_text(encoding="utf-8")))
            s2 = SignerKeyBundle.from_dict(json.loads(args.slot2_key.read_text(encoding="utf-8")))
            s1.sign_envelope(1, env)
            s2.sign_envelope(2, env)
            _dump(cli.create_warrant(env))
            return 0

        if args.command == "pipeline":
            _dump(cli.list_pipeline())
            return 0

        if args.command == "traces":
            _dump(cli.list_traces(args.remediation_id))
            return 0

        if args.command == "estate":
            _dump(cli.list_estate())
            return 0

        if args.command == "exceptions":
            _dump(cli.list_exceptions())
            return 0

        if args.command == "attestations":
            _dump(cli.list_attestations())
            return 0

        if args.command == "intake-sarif":
            _dump(cli.ingest_sarif(args.sarif_file, target_service=args.service, profile=args.profile))
            return 0

        if args.command == "intake-secrets":
            _dump(cli.ingest_secret_scan(args.scan_file, target_service=args.service))
            return 0

        if args.command == "simulate":
            _dump(cli.simulate(args.scenario))
            return 0

        if args.command == "freeze":
            if args.action in ("hold", "rollback"):
                mode = "FREEZE_HOLD" if args.action == "hold" else "FREEZE_ROLLBACK"
                _dump(cli.trigger_freeze(mode=mode, actor=args.actor, reason_code=args.reason, signer_bundle=_load_priv_key(args.key)))
            else:
                if not args.slot1_key or not args.slot2_key:
                    raise ValueError("--slot1-key and --slot2-key are required for 2-of-2 fleet thaw")
                env = draft_thaw_envelope()
                s1 = SignerKeyBundle.from_dict(json.loads(args.slot1_key.read_text(encoding="utf-8")))
                s2 = SignerKeyBundle.from_dict(json.loads(args.slot2_key.read_text(encoding="utf-8")))
                s1.sign_envelope(1, env)
                s2.sign_envelope(2, env)
                _dump(cli.thaw_freeze(env))
            return 0

        if args.command == "pipeline-rollback":
            _dump(cli.emergency_rollback(args.remediation_id, actor=args.actor, reason=args.reason, signer_bundle=_load_priv_key(args.key)))
            return 0

        if args.command == "feeds":
            if args.action == "status":
                _dump(cli.get_feed_status())
            elif args.action in ("live", "offline"):
                _dump(cli.set_feed_mode(args.action))
            elif args.action == "sync-kev":
                _dump(cli.sync_cisa_kev())
            elif args.action == "sync-osv":
                _dump(cli.sync_osv())
            return 0

        if args.command == "oscal-export":
            bundle = cli.export_oscal_bundle(args.id)
            if args.out:
                args.out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
                print(f"Exported signed NIST OSCAL 1.1.2 POA&M bundle -> {args.out}")
            else:
                _dump(bundle)
            return 0

        if args.command == "oscal-verify":
            raw_text = args.bundle_file.read_text(encoding="utf-8")
            if args.pubkey:
                res = verify_oscal_bundle_offline(raw_text, args.pubkey)
            else:
                res = verify_oscal_bundle_with_keyring(raw_text, cli.kernel_public_key_ring())
            _dump(res)
            return 0

        if args.command == "ledger-verify":
            rep = cli.verify_ledger_chains()
            _dump(rep)
            return 0 if rep.get("all_valid") else 2

        if args.command == "auditor-mint":
            _dump(cli.mint_auditor_token(label=args.label, ttl_hours=args.ttl_hours, signer_bundle=_load_priv_key(args.key)))
            return 0

        if args.command == "auditor-vault":
            _dump(cli.get_auditor_vault(bearer_token=args.token))
            return 0

    except WarrantAPIError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
