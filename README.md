<p align="center">
  <img src="docs/assets/g1_logo.jpg" alt="G1-Warrant Logo" width="110" />
</p>

# G1-Warrant — by G1163RT Security Labs

[![CI](https://github.com/cgilbert61/G1-Warrent/actions/workflows/ci.yml/badge.svg)](https://github.com/cgilbert61/G1-Warrent/actions/workflows/ci.yml)
[![Federal DevSecOps](https://github.com/cgilbert61/G1-Warrent/actions/workflows/federal-devsecops.yml/badge.svg)](https://github.com/cgilbert61/G1-Warrent/actions/workflows/federal-devsecops.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.23%20(pure--go%20%2F%20zero--llm)-00ADD8.svg)](go.mod)
[![OPA Rego](https://img.shields.io/badge/OPA%20Rego-NIST%20AC--5%202--of--2-7D9199.svg)](policies/)
[![GovReady-Q](https://img.shields.io/badge/NIST%20SP%20800--53-14%2F14%20PASS-success.svg)](docs/govready_compliance_assessment_report.md)
[![Federal Compliance](https://img.shields.io/badge/9--Gate%20DevSecOps-100%25%20COMPLIANT-success.svg)](docs/federal_devsecops_compliance_report.md)
[![Section 508](https://img.shields.io/badge/Section%20508%20%2F%20WCAG%202.1%20AA-PASS-success.svg)](reports/axe-accessibility.json)

**Deterministic Autonomous Remediation, Containment & NIST OSCAL 1.1.2 Attestation Control Plane (`v1.0`) — G1163RT Security Labs, Inc.**

Enterprise and federal remediation of known-exploited vulnerabilities stalls in a 43-day merge-to-production bottleneck. **G1-Warrant** (`warrantd` server, `warrant` CLI, `warrant-extractor`, `fleet-sim`, and embedded G1-Warrant Console) closes that gap through **five deterministic Pure-Go control-plane engines (`N1–N5`)** with **zero LLM inference inside the safety kernel or Console**:

1. **`N1` — Standing Warrants & AC-5 Dual-Key Separation of Duties (`internal/warrant`, `policies/warrant_ac5.rego`):** Every automated rollout or virtual containment bridge executes solely under a pre-negotiated **Standing Warrant** carrying `2-of-2` human cryptographic signatures (`Slot 1: SERVICE_OWNER` + `Slot 2: AUTHORIZING_OFFICIAL`) over RFC 8785 JCS canonicalized DSSEv1 envelopes via Ed25519 or native W3C WebAuthn hardware authenticators (`YubiKey` / `FIDO2 PIV`), paired with instant principal revocation and asymmetric emergency freeze (`FREEZE_HOLD` / `FREEZE_ROLLBACK`).
2. **`N2` — Shadow Differential Canary & Estate Readiness Gate (`internal/gate`, `policies/gate_eligibility.rego`):** Evaluates workload readiness (`>= 80%` test coverage, OTel health probes, read-only shadow replica, `< 60s` rollback drill), enforces patch statelessness (`ddl_migrations == 0`, `orm_model_mutations == 0`), and executes `5% -> 25% -> 100%` progressive rollouts comparing JCS-normalized HTTP schemas, p50/p95/p99 latency ceilings, and eBPF/seccomp Linux syscall capability sets with instant rollback on drift.
3. **`N3` — Adversary-Twin Replay, Virtual Containment & Permanent Lockout (`internal/verify`, `policies/verify_closure.rego`):** Deploys immediate OpenC2 / Cilium eBPF containment shields within SLA windows for unpatched or above-ceiling CVEs, verifies closure via deterministic HTTP exploit-replay rejection + 100% replica SHA-256 digest convergence, installs permanent `ValidatingAdmissionPolicy` + runtime lockouts before bridge retirement, and continuously sweeps for post-closure drift (`DRIFT_REOPENED`).
4. **`N4` — Zero-Egress Content Isolation & Ephemeral Task Warrants (`cmd/warrant-extractor`, `internal/agentcp`):** Untrusted external text (`SARIF 2.1.0`, `CISA KEV`, `Google OSV.dev`, `CycloneDX/VEX`) traverses an egress-denied, zero-privilege `warrant-extractor` service before typed schemas reach `warrantd`. External workers act strictly under minute-scoped (`TTL <= 300s`) Ed25519 Task Warrants recorded in a PostgreSQL trigger-protected SHA-256 hash-chained ledger.
5. **`N5` — NIST OSCAL 1.1.2 POA&M Vault & Scoped External Auditor Portal (`internal/ledger`, `web/src/components/AuditorPortal.tsx`):** Mints DSSE-sealed NIST OSCAL `1.1.2` Plan of Action & Milestones closure packages with client-side in-browser cryptographic verification and time-bounded, read-only external 3PAO auditor links (`/auditor?token=g1aud_...` — strictly HTTP `403` isolated from all operational endpoints).

---

## Quick Start (Zero Host Toolchains Required)

```bash
# Start all 4 isolated production containers and seed the 6-service enterprise estate
docker compose up --build -d

# Open the G1-Warrant 5-View Console (W3C WebAuthn localhost enabled)
# http://localhost:8080
```

---

## Optional $0 Live Threat & Scanner Feeds (`offline` Enclave Default vs. `live`)

By default, `WARRANT_FEED_MODE=offline` keeps G1-Warrant 100% air-gapped for federal enclaves and deterministic CI tests. To ingest **100% real live US Government CISA KEV bulletins (`cisa.gov`)**, **Google OSV.dev SBOM advisories (`api.osv.dev`)**, and **real `aquasec/trivy` container image `SARIF 2.1.0` scans**—all sanitized through the zero-egress `warrant-extractor`:

```bash
# PowerShell:
$env:WARRANT_FEED_MODE="live"; $env:WARRANT_TRIVY_ENABLED="true"; docker compose --profile live-feeds up --build -d

# POSIX / Bash:
WARRANT_FEED_MODE=live WARRANT_TRIVY_ENABLED=true docker compose --profile live-feeds up --build -d
```

You can also toggle `offline` vs. `live` mode and trigger on-demand CISA KEV / OSV.dev syncs directly from the **`Feeds: OFFLINE | LIVE`** control in the Console header or via the command bar (`/warrant feeds [status | mode live | sync-kev | sync-osv]`).

---

## 9-Gate Federal DevSecOps & NIST SP 800-53 Compliance Harness

G1-Warrant ships with a complete local-first & GitHub Actions **9-Gate Federal DevSecOps Compliance Harness** (`FISMA ID: G1-WARRANT-001`) aligned with NIST SP 800-53 Rev 4, DISA STIG, Executive Order 14028, and Rehabilitation Act Section 508:

| Gate | Toolchain | Governing Standard | Deliverable Artifact |
| :--- | :--- | :--- | :--- |
| **1. SAST & Code Quality** | Semgrep + SonarQube | NIST SP 800-53 SA-11 / OWASP Top 10 | [`reports/semgrep.sarif`](reports/semgrep.sarif) |
| **2. Secrets Detection** | Gitleaks | NIST SP 800-53 IA-5 / DISA STIG | [`reports/gitleaks.sarif`](reports/gitleaks.sarif) |
| **3. IaC Security Scanning** | Checkov | NIST SP 800-53 CM-2 / DISA STIG K8s & Docker | [`reports/checkov.sarif`](reports/checkov.sarif) |
| **4. SBOM Generation** | Syft (CycloneDX 1.5) | Executive Order 14028 / NIST SP 800-161 | [`reports/sbom.cdx.json`](reports/sbom.cdx.json) |
| **5. SCA & Containers** | Trivy | DISA STIG / NIST SP 800-53 SI-2 & RA-5 | [`reports/trivy-fs.sarif`](reports/trivy-fs.sarif) |
| **6. DAST Dynamic Scan** | OWASP ZAP Baseline | NIST SP 800-53 RA-5 / OWASP Top 10 | [`reports/zap_warrantd_report.json`](reports/zap_warrantd_report.json) |
| **7. Section 508 A11y** | axe-core / WCAG 2.1 AA | Section 508 / WCAG 2.1 Level AA | [`reports/axe-accessibility.json`](reports/axe-accessibility.json) |
| **8. Load & SLA Testing** | k6 | Control-Plane API SLA (`p95 <= 35.0ms`) | [`reports/k6-summary.json`](reports/k6-summary.json) |
| **9. Federal GRC Platform** | GovReady-Q | NIST SP 800-53 Rev 4 (14 Controls) | [`docs/g1_warrant_oscal_component.json`](docs/g1_warrant_oscal_component.json) |

```bash
# Run all 9 Federal DevSecOps gates locally
make compliance-check

# Run embedded OPA Rego policy tests + Go -race invariant & live-feed E2E suite
make docker-test
```

### Compliance & Architecture Documentation
- **Federal DevSecOps Audit Report:** [`docs/federal_devsecops_compliance_report.md`](docs/federal_devsecops_compliance_report.md)
- **GovReady-Q NIST SP 800-53 Assessment Report:** [`docs/govready_compliance_assessment_report.md`](docs/govready_compliance_assessment_report.md)
- **System Security Plan (SSP):** [`docs/g1_warrant_system_security_plan.md`](docs/g1_warrant_system_security_plan.md)
- **NIST OSCAL Component Definition:** [`docs/g1_warrant_oscal_component.json`](docs/g1_warrant_oscal_component.json)
- **OpenAPI 3.1 Specification:** [`api/openapi.yaml`](api/openapi.yaml)
- **Architecture Decision Records:** [`docs/adr/`](docs/adr/)

---

## License

Copyright © 2026 **G1163RT Security Labs, Inc.** Licensed under the [Apache License, Version 2.0](LICENSE).
