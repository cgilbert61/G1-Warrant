# `g1-warrant-sdk` — Official Python Client SDK & CLI for G1-Warrant

> **Client-Side SDK & Offline Cryptographic Verifier:** `g1-warrant-sdk` provides a lightweight Python client library (`WarrantClient`), an offline RFC 8785 JCS + DSSEv1 + Ed25519 ceremony & NIST OSCAL `1.1.2` POA&M verifier, and the `g1-warrant` CLI for SecOps engineers, CI/CD pipelines, governed remediation workers, and external 3PAO auditors.

## Installation

```bash
pip install -e sdk/python
```

## Quick Python Usage

```python
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

# 3. Export a closed NIST OSCAL 1.1.2 POA&M bundle & verify DSSE + JCS offline
atts = client.list_attestations()
if atts:
    bundle = client.export_oscal_bundle(atts[0]["attestation_id"])
    proof = verify_oscal_bundle_offline(bundle, client.kernel_public_key_b64())
    print("Offline DSSE + RFC 8785 JCS Verified:", proof["valid"], proof["pae_sha256"])
```

## CLI Usage (`g1-warrant`)

```bash
g1-warrant status
g1-warrant warrants
g1-warrant pipeline
g1-warrant estate
g1-warrant intake-sarif ./reports/trivy-fs.sarif --service payments-ledger-api
g1-warrant feeds status
g1-warrant ledger-verify
g1-warrant oscal-export <attestation-id> --out poam-bundle.json
g1-warrant oscal-verify poam-bundle.json
```
