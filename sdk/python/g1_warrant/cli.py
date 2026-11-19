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
    draft_thaw_envelope,
    draft_warrant_envelope,
    generate_ed25519_signer_bundle,
    verify_oscal_bundle_offline,
)


def _dump(obj: object) -> None:
    print(json.dumps(obj, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="g1-warrant",
        description="G1-Warrant Python SDK & Operator/Auditor CLI — G1163RT Security Labs",
    )
    parser.add_argument("--url", default=None, help="G1-Warrant server URL (default: $WARRANT_API_URL or http://localhost:8080)")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--version", action="version", version=f"g1-warrant-sdk v{__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Show live fleet remediation scoreboard and freeze posture")
    sub.add_parser("warrants", help="List Standing Warrants and live AC-5 status")

    p_verify_w = sub.add_parser("warrant-verify", help="Re-verify a Standing Warrant live in N1")
    p_verify_w.add_argument("warrant_id")

    p_mint = sub.add_parser("warrant-mint-demo", help="Draft and 2-of-2 co-sign a demo Standing Warrant")
    p_mint.add_argument("--warrant-class", default="KEV-TIER1-STATELESS")
    p_mint.add_argument("--services", default="payments-ledger-api,identity-sso-gateway")

    p_keygen = sub.add_parser("keygen", help="Generate an offline Ed25519 AC-5 SignerKeyBundle")
    p_keygen.add_argument("--id", required=True)
    p_keygen.add_argument("--email", required=True)
    p_keygen.add_argument("--name", default="G1 Signer")
    p_keygen.add_argument("--role", choices=[ROLE_SERVICE_OWNER, ROLE_AUTHORIZING_OFFICIAL], default=ROLE_SERVICE_OWNER)
    p_keygen.add_argument("--out", default=None)

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

    p_sim = sub.add_parser("simulate", help="Trigger a deterministic control-plane scenario")
    p_sim.add_argument("scenario", choices=["inject-kev", "bad-syscall", "stateful-ddl", "runtime-drift"])

    p_freeze = sub.add_parser("freeze", help="Activate or thaw Asymmetric Emergency Freeze")
    p_freeze.add_argument("action", choices=["hold", "rollback", "thaw"])
    p_freeze.add_argument("--actor", default="g1-warrant-pycli")
    p_freeze.add_argument("--reason", default="CLI_EMERGENCY_ACTION")

    p_feeds = sub.add_parser("feeds", help="Inspect or sync CISA KEV & Google OSV.dev live feeds")
    p_feeds.add_argument("action", choices=["status", "live", "offline", "sync-kev", "sync-osv"])

    p_oscal_exp = sub.add_parser("oscal-export", help="Export a signed NIST OSCAL 1.1.2 POA&M bundle")
    p_oscal_exp.add_argument("id")
    p_oscal_exp.add_argument("--out", type=Path, default=None)

    p_oscal_ver = sub.add_parser("oscal-verify", help="Offline cryptographic verification of an OSCAL POA&M bundle")
    p_oscal_ver.add_argument("bundle_file", type=Path)
    p_oscal_ver.add_argument("--pubkey", default=None, help="Base64 Ed25519 kernel public key (auto-fetched if omitted)")

    sub.add_parser("ledger-verify", help="Verify SHA-256 hash chains across all 3 PostgreSQL WORM tables")

    p_aud_mint = sub.add_parser("auditor-mint", help="Mint a scoped read-only 3PAO auditor bearer token")
    p_aud_mint.add_argument("--label", default="External 3PAO Assessment")
    p_aud_mint.add_argument("--ttl-hours", type=int, default=24)

    p_aud_vault = sub.add_parser("auditor-vault", help="Inspect the read-only /auditor vault with a g1aud_* token")
    p_aud_vault.add_argument("--token", default=None)

    args = parser.parse_args(argv)

    try:
        if args.command == "keygen":
            bundle = generate_ed25519_signer_bundle(args.id, args.email, args.name, args.role)
            if args.out:
                Path(args.out).write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")
                print(f"Wrote Ed25519 SignerKeyBundle ({bundle.role} | {bundle.key_id}) -> {args.out}")
            else:
                _dump(bundle.to_dict())
            return 0

        cli = WarrantClient(base_url=args.url)

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

        if args.command == "warrants":
            _dump(cli.list_warrants())
            return 0

        if args.command == "warrant-verify":
            res = cli.verify_warrant(args.warrant_id)
            _dump(res)
            return 0 if res.get("valid") else 2

        if args.command == "warrant-mint-demo":
            svcs = [s.strip() for s in args.services.split(",") if s.strip()]
            env = draft_warrant_envelope(scope_services=svcs, warrant_class=args.warrant_class)
            alice = cli.builtin_demo_signer("usr-alice-so")
            bob = cli.builtin_demo_signer("usr-bob-ao")
            alice.sign_envelope(1, env)
            bob.sign_envelope(2, env)
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

        if args.command == "simulate":
            _dump(cli.simulate(args.scenario))
            return 0

        if args.command == "freeze":
            if args.action in ("hold", "rollback"):
                mode = "FREEZE_HOLD" if args.action == "hold" else "FREEZE_ROLLBACK"
                _dump(cli.trigger_freeze(mode=mode, actor=args.actor, reason_code=args.reason))
            else:
                env = draft_thaw_envelope()
                cli.builtin_demo_signer("usr-alice-so").sign_envelope(1, env)
                cli.builtin_demo_signer("usr-bob-ao").sign_envelope(2, env)
                _dump(cli.thaw_freeze(env))
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
            pk = args.pubkey or cli.kernel_public_key_b64()
            res = verify_oscal_bundle_offline(args.bundle_file.read_text(encoding="utf-8"), pk)
            _dump(res)
            return 0

        if args.command == "ledger-verify":
            rep = cli.verify_ledger_chains()
            _dump(rep)
            return 0 if rep.get("all_valid") else 2

        if args.command == "auditor-mint":
            _dump(cli.mint_auditor_token(label=args.label, ttl_hours=args.ttl_hours))
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
