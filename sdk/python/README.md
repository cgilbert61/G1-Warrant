# `g1-warrant-sdk` — Official Python Client SDK & CLI for G1-Warrant

> **Client-Side SDK & Offline Cryptographic Verifier:** `g1-warrant-sdk` provides a lightweight Python client library (`WarrantClient`), an offline RFC 8785 JCS + DSSEv1 + Ed25519 ceremony & NIST OSCAL `1.1.2` POA&M verifier, and the `g1-warrant` CLI for SecOps engineers, CI/CD pipelines, governed remediation workers, and external 3PAO auditors.

## Installation

```bash
pip install -e sdk/python
```

## Quick Python Usage

```python
from pathlib import Path
from g1_warrant import (
    WarrantClient,
    draft_warrant_envelope,
    verify_oscal_bundle_offline,
)

client = WarrantClient("http://localhost:8080")

# 1. Inspect live fleet posture & remediation KPIs
sb = client.scoreboard()
print(f"Posture: {sb['freeze_state']['mode']} | Median TTVR: {sb['fleet_median_ttvr_seconds']}s")

# 2. Submit a Trivy / Semgrep SARIF 2.1.0 report (sanitized via zero-egress warrant-extractor)
items = client.ingest_sarif("./trivy-scan.sarif", target_service="payments-ledger-api")

# 3. Genuine air-gapped offline DSSE + RFC 8785 JCS verification using a locally pinned kernel public key file
pinned_pubkey_b64 = Path("./kernel-seal.pub").read_text(encoding="utf-8").strip()
bundle_raw = Path("./poam-bundle.json").read_text(encoding="utf-8")
proof = verify_oscal_bundle_offline(bundle_raw, pinned_pubkey_b64)
print("Offline DSSE + RFC 8785 JCS Verified:", proof["valid"], proof["trust_basis"], proof["pae_sha256"])
```

## CLI Usage (`g1-warrant`)

```bash
g1-warrant status
g1-warrant warrants
g1-warrant pipeline
g1-warrant estate
g1-warrant finder-intake qualys ./reports/qualys-vmdr.xml --intake-token "$WARRANT_INTAKE_TOKEN" --service payments-ledger-api
g1-warrant intake-sarif ./reports/trivy-fs.sarif --intake-token "$WARRANT_INTAKE_TOKEN" --service payments-ledger-api
g1-warrant feeds status
g1-warrant ledger-verify
g1-warrant oscal-export <attestation-id> --out poam-bundle.json
g1-warrant oscal-verify poam-bundle.json --pubkey-file ./kernel-seal.pub
```
