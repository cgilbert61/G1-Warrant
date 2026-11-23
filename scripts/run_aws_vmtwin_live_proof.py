#!/usr/bin/env python3
"""
G1-Warrant Live AWS EC2 + Systems Manager (SSM) 3-Clone VM_TWIN Proving Harness.

Executes a real, non-simulated 3-clone AWS EC2 + SSM reboot-and-verify proving run
against an isolated PrivateLink VPC enclave deployed from:
    deploy/aws/vm_twin_proving_enclave.cfn.yaml

Prerequisites (never fabricated — fails closed immediately if missing):
  - WARRANT_AWS_REGION
  - WARRANT_AWS_ACCESS_KEY_ID / AWS_ACCESS_KEY_ID
  - WARRANT_AWS_SECRET_ACCESS_KEY / AWS_SECRET_ACCESS_KEY
  - WARRANT_AWS_TWIN_AMI_ID
  - WARRANT_AWS_TWIN_SUBNET_ID
  - WARRANT_AWS_TWIN_ISOLATED_SG_ID
  - WARRANT_AWS_TWIN_IAM_INSTANCE_PROFILE

When executed against live AWS credentials, writes a timestamped execution receipt to:
    reports/aws-vmtwin-live-proof-transcript.txt
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REQUIRED_ENV = [
    "WARRANT_AWS_REGION",
    "WARRANT_AWS_TWIN_AMI_ID",
    "WARRANT_AWS_TWIN_SUBNET_ID",
    "WARRANT_AWS_TWIN_ISOLATED_SG_ID",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    ak = (os.environ.get("WARRANT_AWS_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID") or "").strip()
    sk = (os.environ.get("WARRANT_AWS_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY") or "").strip()
    missing = [k for k in REQUIRED_ENV if not os.environ.get(k, "").strip()]
    if not ak or not sk:
        missing.append("WARRANT_AWS_ACCESS_KEY_ID / WARRANT_AWS_SECRET_ACCESS_KEY")
    if missing:
        print(
            f"[{utc_now()}] FAIL-CLOSED: Live AWS VM_TWIN proof cannot run without real AWS enclave configuration.\n"
            f"  Missing variables: {', '.join(missing)}\n"
            f"  1. Deploy deploy/aws/vm_twin_proving_enclave.cfn.yaml in your AWS account.\n"
            f"  2. Export the CloudFormation stack outputs + STS credentials and re-run this script.\n"
            f"  (No receipt was written; G1-Warrant never fabricates live cloud execution transcripts.)",
            file=sys.stderr,
        )
        return 2

    env = dict(os.environ)
    env["WARRANT_VM_TWIN_DRIVER"] = "aws-ec2"
    env["WARRANT_LIVE_AWS_PROOF"] = "1"

    lines: list[str] = [
        f"[{utc_now()}] === G1-WARRANT LIVE AWS EC2 + SSM 3-CLONE VM_TWIN PROOF ===",
        f"[{utc_now()}] Region={env['WARRANT_AWS_REGION']} AMI={env['WARRANT_AWS_TWIN_AMI_ID']} Subnet={env['WARRANT_AWS_TWIN_SUBNET_ID']} SG={env['WARRANT_AWS_TWIN_ISOLATED_SG_ID']}",
    ]

    proc = subprocess.run(
        ["go", "test", "-v", "-count=1", "./internal/adapters/vmtwins", "-run", "TestLiveAWSEC2VMTwinProofIfConfigured"],
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    lines.append(proc.stdout.strip())
    if proc.stderr.strip():
        lines.append(proc.stderr.strip())
    if proc.returncode != 0:
        print("\n".join(lines), file=sys.stderr)
        return proc.returncode

    lines.append(f"[{utc_now()}] === LIVE AWS EC2 + SSM 3-CLONE VM_TWIN PROOF PASSED ===")
    receipt = repo_root / "reports" / "aws-vmtwin-live-proof-transcript.txt"
    receipt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote live AWS VM_TWIN receipt -> {receipt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
