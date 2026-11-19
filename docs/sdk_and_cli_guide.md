# G1-Warrant — Official SDKs & CLI Reference Guide

G1-Warrant ships with two first-class client SDKs and two command-line interfaces so Go microservices, Kubernetes operators, Python SecOps pipelines, CI/CD runners, and air-gapped 3PAO compliance auditors can drive and cryptographically verify the control plane without touching raw HTTP JSON:

1. **Go Client SDK (`pkg/warrantsdk`) & Native `warrant` CLI (`cmd/warrant`)** — Pure-Go client library and single-binary operator/auditor CLI (embedded inside the `warrantd` container image and buildable standalone on Windows, Linux, and macOS).
2. **Python Client SDK & CLI (`sdk/python` — `g1-warrant-sdk` / `g1-warrant`)** — Lightweight Python package providing `WarrantClient`, byte-exact RFC 8785 JCS + DSSEv1 + Ed25519 ceremony helpers, offline NIST OSCAL `1.1.2` POA&M verification, and the `g1-warrant` CLI.

---

## 1. Go Client SDK (`pkg/warrantsdk`)

### Installation

```bash
go get github.com/g1163rt-labs/g1-warrant/pkg/warrantsdk
```

### Programmatic Go Example

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/g1163rt-labs/g1-warrant/pkg/warrantsdk"
)

func main() {
	ctx := context.Background()
	cli := warrantsdk.NewClient("http://localhost:8080")

	// 1. Query fleet posture & live SLA metrics
	sb, err := cli.Scoreboard(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Posture=%s | ActiveWarrants=%d | MedianTTVR=%ds\n",
		sb.FreezeState.Mode, sb.ActiveWarrantsCount, sb.FleetMedianTTVRSeconds)

	// 2. Submit an untrusted SARIF 2.1.0 scan (sanitized via zero-egress warrant-extractor)
	sarifBytes, err := os.ReadFile("./reports/trivy-fs.sarif")
	if err == nil {
		items, _ := cli.IngestSARIF(ctx, sarifBytes, warrantsdk.SARIFIntakeOptions{
			TargetService: "payments-ledger-api",
			Profile:       "STATELESS_CLEAN",
		})
		fmt.Printf("Ingested %d remediation items\n", len(items))
	}

	// 3. Export a closed NIST OSCAL 1.1.2 POA&M bundle & verify offline
	atts, err := cli.ListAttestations(ctx)
	if err == nil && len(atts) > 0 {
		bundle, _ := cli.ExportOSCALBundle(ctx, atts[0].AttestationID)
		_, pubB64, _, _ := cli.KernelPublicKey(ctx)

		proof, err := warrantsdk.VerifyOSCALBundleOffline(bundle, pubB64)
		if err != nil {
			log.Fatalf("Offline verification failed: %v", err)
		}
		fmt.Printf("Offline OSCAL Verified: valid=%t jcs_match=%t pae_sha256=%s\n",
			proof.Valid, proof.JCSCanonicalMatch, proof.PAESHA256)
	}
}
```

---

## 2. Native Go Operator & Auditor CLI (`warrant`)

### Build or Run via Container

```bash
# Build standalone binary locally
go build -o warrant ./cmd/warrant

# Or execute directly inside the running warrantd container
docker compose exec warrantd /warrant status
```

### Multi-Party Offline Dual-Key Warrant Ceremony (`NIST SP 800-53 AC-5`)

```bash
# Step 1: Draft an unsigned RFC 8785 JCS Standing Warrant DSSE envelope
./warrant warrants draft \
  --class KEV-TIER1-STATELESS \
  --services payments-ledger-api,identity-sso-gateway \
  --max-cvss 10.0 --max-replicas 8 --sla-minutes 60 --ttl-days 30 \
  --out warrant-draft.dsse.json

# Step 2: Slot 1 (Service Owner) signs over DSSEv1 PAE bytes
./warrant warrants sign --in warrant-draft.dsse.json --slot 1 --demo-persona usr-alice-so

# Step 3: Slot 2 (Authorizing Official) co-signs over identical DSSEv1 PAE bytes
./warrant warrants sign --in warrant-draft.dsse.json --slot 2 --demo-persona usr-bob-ao

# Step 4: Submit the 2-of-2 DSSE envelope to N1 (verified by OPA warrant_ac5.rego + PostgreSQL WORM trigger)
./warrant warrants submit warrant-draft.dsse.json
```

### Full `warrant` Command Reference

| Command | Purpose |
| :--- | :--- |
| `warrant status [--json]` | Live control-plane posture, active warrants, 30d median TTVR, armed bridges, and estate eligibility. |
| `warrant keygen --id <id> --email <e> --role <SO\|AO>` | Generate a portable Ed25519 AC-5 signing key bundle (`0600` JSON). |
| `warrant principals [list \| revoke]` | List registered PIV/WebAuthn principals or revoke a key to trigger instant fail-closed invalidation. |
| `warrant warrants [list \| verify \| draft \| sign \| submit \| mint-demo]` | Inspect, verify, or execute `2-of-2` Standing Warrant ceremonies. |
| `warrant exceptions [list \| approve <id> \| reject <id>]` | Inspect or dual-key resolve stateful/above-ceiling remediation exceptions. |
| `warrant pipeline [list \| trace <remediation-id>]` | View 5-stage Race Pipeline items or millisecond deterministic state transition traces. |
| `warrant estate` / `warrant shadow` | Inspect N2 Estate Readiness Scorecard and Differential Shadow canary reports. |
| `warrant bridges` / `warrant lockouts` / `warrant drift` | Inspect Cilium containment shields, `ValidatingAdmissionPolicy` lockouts, and drift re-arm events. |
| `warrant simulate <scenario>` | Run deterministic drills: `inject-kev`, `bad-syscall`, `stateful-ddl`, or `runtime-drift`. |
| `warrant intake sarif <file.sarif>` | Submit an untrusted `SARIF 2.1.0` report through `warrant-extractor` into the Race Pipeline. |
| `warrant feeds [status \| mode \| sync-kev \| sync-osv \| ingest-osv]` | Toggle `offline` vs `live` feeds and sync real CISA KEV & Google OSV.dev advisories. |
| `warrant freeze [hold \| rollback \| thaw]` | Trigger single-operator emergency freeze/rollback or `2-of-2` DSSE fleet thaw. |
| `warrant oscal [export <id> \| verify-offline <bundle.json>]` | Export DSSE-signed NIST OSCAL `1.1.2` POA&M packages and verify signatures air-gapped. |
| `warrant auditor [mint-token \| inspect]` | Mint or test a scoped read-only `g1aud_*` external 3PAO auditor bearer link. |
| `warrant ledger [verify \| actions]` | Verify genesis-to-tip SHA-256 hash chains across all 3 PostgreSQL WORM tables. |
| `warrant events` | Stream real-time Server-Sent Events (`SSE`) from `warrantd` in the terminal. |

---

## 3. Python Client SDK & CLI (`sdk/python` — `g1-warrant-sdk`)

### Installation

```bash
pip install -e sdk/python
```

### Python SDK & Offline Verification Example

```python
from g1_warrant import (
    AuditorScopeViolationError,
    WarrantClient,
    draft_warrant_envelope,
    verify_oscal_bundle_offline,
)

cli = WarrantClient("http://localhost:8080")

# 1. Mint a 2-of-2 Standing Warrant from Python
env = draft_warrant_envelope(scope_services=["payments-ledger-api"], max_cvss=10.0)
cli.builtin_demo_signer("usr-alice-so").sign_envelope(1, env)
cli.builtin_demo_signer("usr-bob-ao").sign_envelope(2, env)
warrant = cli.create_warrant(env)

# 2. Mint a scoped 3PAO Auditor Token & confirm HTTP 403 Operational Isolation
minted = cli.mint_auditor_token(label="FedRAMP 3PAO Audit", ttl_hours=12)
auditor_cli = WarrantClient("http://localhost:8080", auditor_token=minted["bearer"])
vault = auditor_cli.get_auditor_vault()  # Allowed: Read-Only /api/v1/auditor/vault

try:
    auditor_cli.scoreboard()  # Blocked: Operational endpoint -> HTTP 403!
except AuditorScopeViolationError as exc:
    print("Operational isolation enforced:", exc)

# 3. Verify exported NIST OSCAL 1.1.2 POA&M bundle offline
if vault["attestations"]:
    att_id = vault["attestations"][0]["attestation_id"]
    bundle = cli.export_oscal_bundle(att_id)
    proof = verify_oscal_bundle_offline(bundle, cli.kernel_public_key_b64())
    assert proof["valid"] and proof["jcs_canonical_match"]
```
