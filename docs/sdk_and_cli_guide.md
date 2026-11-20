# G1-Warrant — Official SDKs & CLI Reference Guide

G1-Warrant ships with two first-class client SDKs and two command-line interfaces so Go microservices, Kubernetes operators, Python SecOps pipelines, CI/CD runners, and air-gapped 3PAO compliance auditors can drive and cryptographically verify the control plane without touching raw HTTP JSON:

1. **Go Client SDK (`pkg/warrantsdk`) & Native `warrant` CLI (`cmd/warrant`)** — Pure-Go client library and single-binary operator/auditor CLI (embedded inside the `warrantd` container image and buildable standalone on Windows, Linux, and macOS).
2. **Python Client SDK & CLI (`sdk/python` — `g1-warrant-sdk` / `g1-warrant`)** — Lightweight Python package providing `WarrantClient`, byte-exact RFC 8785 JCS + DSSEv1 + Ed25519 ceremony helpers, offline NIST OSCAL `1.1.2` POA&M verification, and the `g1-warrant` CLI.

---

## 1. Go Client SDK (`pkg/warrantsdk`)

### Installation

```bash
go get github.com/cgilbert61/G1-Warrant/pkg/warrantsdk@v1.0.3
```

### Programmatic Go Example

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
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

### Multi-Party Offline Dual-Key Warrant Ceremony (`NIST SP 800-53 Rev 5 AC-5`)

Production SDKs and CLIs ship **zero built-in demo signers**. Operators generate or load explicit `SignerKeyBundle` files (or authenticate via hardware WebAuthn PIV/FIDO2 in the Console):

```bash
# Step 1: Generate split AC-5 signing keypairs (<name>.priv.json [0600] + <name>.pub.json [0644 public-only])
./warrant keygen --id usr-so-01 --email so@agency.gov --role SERVICE_OWNER --out so-key
./warrant keygen --id usr-ao-01 --email ao@agency.gov --role AUTHORIZING_OFFICIAL --out ao-key

# Step 2: One-shot genesis enrollment using ONLY .pub.json (private keys never pass to network subcommands)
./warrant principals register --pub so-key.pub.json --admin-token "$WARRANT_BOOTSTRAP_ADMIN_TOKEN"
./warrant principals register --pub ao-key.pub.json --admin-token "$WARRANT_BOOTSTRAP_ADMIN_TOKEN"
./warrant principals seal --admin-token "$WARRANT_BOOTSTRAP_ADMIN_TOKEN"

# Step 3: Draft an unsigned RFC 8785 JCS Standing Warrant DSSE envelope
./warrant warrants draft \
  --class KEV-TIER1-STATELESS \
  --services payments-ledger-api,identity-sso-gateway \
  --max-cvss 10.0 --max-replicas 8 --sla-minutes 60 --ttl-days 30 \
  --out warrant-draft.dsse.json

# Step 4: Slot 1 (Service Owner) signs over DSSEv1 PAE bytes
./warrant warrants sign --in warrant-draft.dsse.json --slot 1 --key so-key.priv.json

# Step 5: Slot 2 (Authorizing Official) co-signs over identical DSSEv1 PAE bytes
./warrant warrants sign --in warrant-draft.dsse.json --slot 2 --key ao-key.priv.json

# Step 6: Submit the 2-of-2 DSSE envelope to N1 (auto-seals genesis bootstrap if not yet sealed)
./warrant warrants submit warrant-draft.dsse.json

# Post-Seal Principal Governance (v1.0.3 Self-Revocation & Backup-Assassination Defense):
#   - Enrolling additional keys requires 2-of-2 DSSE co-signatures (--slot1-key + --slot2-key)
#   - 1-of-2 DSSE revocation (--key) is restricted STRICTLY to self-revocation while >=1 active SO & >=1 active AO remain
#   - Revoking any peer principal requires 2-of-2 DSSE (--slot1-key + --slot2-key on revoke or rotate-and-revoke)
./warrant keygen --id usr-so-02 --email so-backup@agency.gov --role SERVICE_OWNER --out so-backup
./warrant principals register --pub so-backup.pub.json --slot1-key so-key.priv.json --slot2-key ao-key.priv.json
./warrant principals revoke --principal usr-so-01 --key so-key.priv.json --reason COMPROMISED_KEY_SELF_REVOKE
./warrant principals rotate-and-revoke --pub ao-replacement.pub.json --principal usr-ao-01 --slot1-key so-backup.priv.json --slot2-key ao-key.priv.json
```

### Full `warrant` Command Reference

| Command | Purpose |
| :--- | :--- |
| `warrant status [--json]` | Live control-plane posture, active warrants, 30d median TTVR, armed bridges, and estate eligibility. |
| `warrant keygen --id <id> --email <e> --role <SO\|AO> --out <prefix>` | Generate split Ed25519 AC-5 key files (`<prefix>.priv.json` `0600` + `<prefix>.pub.json` `0644`). |
| `warrant principals [list \| register --pub <p.pub.json> \| seal \| revoke \| rotate-and-revoke]` | List principals, enroll `.pub.json` (genesis token or post-seal `2-of-2` DSSE), seal bootstrap (`Checkpoint #0`), `1-of-2` self-revoke (`--key`), `2-of-2` peer revoke (`--slot1-key` + `--slot2-key`), or atomic `2-of-2` rotation+revocation. |
| `warrant warrants [list \| verify \| draft \| sign --key <k.priv.json> \| submit]` | Inspect, verify, or execute `2-of-2` Standing Warrant ceremonies. |
| `warrant exceptions [list \| approve <id> --slot1-key <so> --slot2-key <ao> \| reject <id> ...]` | Inspect or dual-key resolve stateful/above-ceiling remediation exceptions (single-use `envelope_id` + `exception_id` bound). |
| `warrant pipeline [list \| trace <id> \| rollback <id> --key <k.priv.json>]` | View Race Pipeline items, millisecond traces, or execute request-scoped `1-of-2` atomic 3-step `QUARANTINED_ROLLBACK`. |
| `warrant estate` / `warrant shadow` | Inspect 3-Tier Graduated Fleet Autonomy Scorecard (5 mandatory gates incl. `readOnlyRootFilesystem` + `noexec /tmp`) and Differential Shadow canary reports. |
| `warrant bridges` / `warrant lockouts` / `warrant drift` | Inspect Zero-Prose vs. Signed-Rulepack shields (`169.254.169.254` metadata quarantine), `ValidatingAdmissionPolicy` lockouts, and Tetragon/image drift events. |
| `warrant simulate <scenario>` | Run deterministic drills (`simulator` + `offline` mode only; disabled on `kubernetes` or `live` feeds). |
| `warrant intake [sarif\|secrets] <file> [--intake-token <tok>]` | Submit untrusted `SARIF 2.1.0` vulnerability scans or Gitleaks/GitGuardian secret-exposure findings (`WARRANT_INTAKE_TOKEN` required in `live` / `kubernetes` modes; `HTTP 413` on oversized bodies). |
| `warrant feeds [status \| mode \| sync-kev \| sync-osv \| ingest-osv] [--automation-token <tok>]` | Toggle `offline` vs `live` feeds and sync real CISA KEV & Google OSV.dev advisories (`WARRANT_AUTOMATION_TOKEN` or `1-of-2` DSSE). |
| `warrant freeze [hold \| rollback --key <k.priv.json> \| thaw --slot1-key <so> --slot2-key <ao>]` | Trigger request-scoped `1-of-2` emergency freeze/rollback or `freeze_epoch`-bound `2-of-2` DSSE fleet thaw. |
| `warrant oscal [export <id> \| verify-offline <bundle.json>]` | Export DSSE-signed NIST OSCAL `1.1.2` POA&M packages and verify signatures air-gapped. |
| `warrant auditor [mint-token --key <k.priv.json> \| inspect]` | Mint (request-scoped `1-of-2` DSSE) or test a scoped read-only `g1aud_*` external 3PAO auditor bearer link. |
| `warrant ledger [verify \| actions \| checkpoints \| anchor]` | Verify SHA-256 hash chains + Authority Lineage Attestations + External Merkle Checkpoints across all 6 immutable tables. |
| `warrant events` | Stream real-time Server-Sent Events (`SSE`) from `warrantd` in the terminal. |

---

## 3. Python Client SDK & CLI (`sdk/python` — `g1-warrant-sdk`)

### Installation

```bash
pip install -e sdk/python
```

### Python SDK & Offline Verification Example

```python
import os
from g1_warrant import (
    ROLE_AUTHORIZING_OFFICIAL,
    ROLE_SERVICE_OWNER,
    AuditorScopeViolationError,
    WarrantClient,
    draft_warrant_envelope,
    generate_ed25519_signer_bundle,
    verify_oscal_bundle_with_keyring,
)

cli = WarrantClient("http://localhost:8080")
admin_tok = os.environ["WARRANT_BOOTSTRAP_ADMIN_TOKEN"]

# 1. Generate keys, enroll public-only identities during genesis, and 2-of-2 co-sign + submit a Standing Warrant
#    (submitting the first Standing Warrant automatically seals genesis bootstrap!)
so = generate_ed25519_signer_bundle("usr-so-01", "so@agency.gov", "Service Owner", ROLE_SERVICE_OWNER)
ao = generate_ed25519_signer_bundle("usr-ao-01", "ao@agency.gov", "Authorizing Official", ROLE_AUTHORIZING_OFFICIAL)
cli.register_principal(so.to_public_identity(), admin_token=admin_tok)
cli.register_principal(ao.to_public_identity(), admin_token=admin_tok)

env = draft_warrant_envelope(scope_services=["payments-ledger-api"], max_cvss=10.0)
so.sign_envelope(1, env)
ao.sign_envelope(2, env)
warrant = cli.create_warrant(env)

# 2. Mint a scoped 3PAO Auditor Token (1-of-2 active principal DSSE signed) & confirm HTTP 403 Operational Isolation
minted = cli.mint_auditor_token(label="FedRAMP 3PAO Audit", ttl_hours=12, signer_bundle=so)
auditor_cli = WarrantClient("http://localhost:8080", auditor_token=minted["bearer"])
vault = auditor_cli.get_auditor_vault()  # Allowed: Read-Only /api/v1/auditor/vault

try:
    auditor_cli.scoreboard()  # Blocked: Operational endpoint -> HTTP 403!
except AuditorScopeViolationError as exc:
    print("Operational isolation enforced:", exc)

# 3. Verify exported NIST OSCAL 1.1.2 POA&M bundle offline against append-only kernel public-key ring
if vault["attestations"]:
    att_id = vault["attestations"][0]["attestation_id"]
    bundle = cli.export_oscal_bundle(att_id)
    proof = verify_oscal_bundle_with_keyring(bundle, cli.kernel_public_key_ring())
    assert proof["valid"] and proof["jcs_canonical_match"]
```
