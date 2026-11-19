# G1-Warrant — System Security Plan (SSP)

**System Name:** G1-Warrant Deterministic Autonomous Remediation, Containment & Attestation Control Plane  
**System Owner:** G1163RT Security Labs, Inc.  
**FISMA / System Identifier:** `G1-WARRANT-001`  
**Security Categorization:** FIPS 199 Moderate / High-Integrity Control Plane  
**Governing Baseline:** NIST SP 800-53 Rev 4, DISA STIG, Executive Order 14028, Rehabilitation Act Section 508  

---

## 1. System Boundary & Operational Purpose

Enterprise and federal vulnerability remediation stalls in a 43-day merge-to-production bottleneck because organizations lack deterministic blast-radius boundaries, cryptographic separation of duties, and verifiable exploit-closure proof.

**G1-Warrant** (`warrantd` server, `warrant` CLI, `warrant-extractor`, `fleet-sim`, and embedded G1-Warrant Console) eliminates that bottleneck via five deterministic Pure-Go engines (`N1–N5`):

1. **Zero LLM Inference Inside the Safety Kernel:** Policy evaluation (`OPA Rego`), rollout gating, progressive canary promotion, adversary-twin replay verification, OSCAL attestation minting, and Console rendering contain zero probabilistic or LLM inference code paths.
2. **Standing Warrants (`N1`):** Autonomous execution is authorized solely under pre-negotiated `2-of-2` DSSEv1 envelopes co-signed over RFC 8785 JCS payloads by disjoint institutional roles (`Slot 1: SERVICE_OWNER`, `Slot 2: AUTHORIZING_OFFICIAL`) via Ed25519 or W3C WebAuthn hardware authenticators.
3. **Zero-Egress Content Isolation (`warrant-extractor`):** Untrusted external inputs (`SARIF 2.1.0`, `CISA KEV`, `Google OSV.dev`, `CycloneDX/VEX`) traverse a network-isolated, read-only parser before typed identifiers reach `warrantd`.
4. **Progressive Differential Canary & Instant Rollback (`N2`):** Enforces stateless patch rules (`ddl_migrations == 0`, `orm_model_mutations == 0`) and compares baseline vs. canary normalized HTTP schemas, p50/p95/p99 latency ceilings, and eBPF/seccomp syscall sets across `5% -> 25% -> 100%` rollout stages.
5. **Adversary-Twin Verification, Containment Lockout & NIST OSCAL 1.1.2 POA&M Closure (`N3` & `N5`):** Deploys immediate Cilium/OpenC2 containment bridges within SLA windows, proves exploit replay rejection + 100% replica digest convergence, installs permanent admission/runtime lockouts, and seals DSSE-signed NIST OSCAL `1.1.2` POA&M attestations into PostgreSQL WORM ledgers.

---

## 2. Architecture Components & Container Hardening

| Component | Binary / Runtime | Network Segment | Hardening Controls |
| :--- | :--- | :--- | :--- |
| **Control Plane & Console** | `warrantd` (`gcr.io/distroless/static:nonroot`) | `control-plane` + `extractor-internal` | Non-root (`65532:65532`), `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, CSP/XFO/XCTO headers |
| **Zero-Privilege Extractor** | `warrant-extractor` (`gcr.io/distroless/static:nonroot`) | `extractor-internal` (`internal: true`, zero egress) | Strict JSON/Regex schema sanitizer, max payload bounds, zero DB credentials, zero internet egress |
| **Immutable State Store** | PostgreSQL 16 (`postgres:16-alpine`) | `control-plane` (internal) | `BEFORE UPDATE OR DELETE` immutability triggers + continuous SHA-256 hash chains across 3 WORM tables |
| **Target Fleet Simulator** | `fleet-sim` (`gcr.io/distroless/static:nonroot`) | `control-plane` (internal) | Simulates Kubernetes Deployments, Cilium NetworkPolicies, ValidatingAdmissionPolicies, and exploit replay |
| **Optional Live Scanner** | `aquasec/trivy` (`--profile live-feeds`) | `control-plane` (opt-in only; `offline` default) | Scans target container images and submits `SARIF 2.1.0` reports sanitized through `warrant-extractor` |

---

## 3. NIST SP 800-53 Rev 4 Control Summary (14 Implemented Controls)

| Control | Title | Implementation Summary |
| :--- | :--- | :--- |
| **AC-3** | Access Enforcement | Fail-closed Standing Warrant verification on all rollouts/bridges; `g1aud_*` bearer tokens isolated strictly to `/api/v1/auditor/*`. |
| **AC-4** | Information Flow Enforcement | Zero-egress `warrant-extractor` network isolation separates untrusted scanner/threat prose from control-plane state. |
| **AC-5** | Separation of Duties | Embedded OPA policy (`policies/warrant_ac5.rego`) enforces `2-of-2` disjoint `SERVICE_OWNER` + `AUTHORIZING_OFFICIAL` co-signatures. |
| **AU-2** | Audit Events | Structured SHA-256 input/output lineage recorded for every warrant, task delegation, shadow run, containment bridge, and closure. |
| **AU-9** | Protection of Audit Information | PostgreSQL `BEFORE UPDATE OR DELETE` triggers block mutation on `standing_warrants`, `agent_action_ledger`, and `oscal_attestations`. |
| **AU-10** | Non-Repudiation | DSSEv1 + RFC 8785 JCS + Ed25519 / W3C WebAuthn signatures with standalone CLI and in-browser verification. |
| **CA-7** | Continuous Monitoring | Sub-second runtime digest & Cilium policy drift sweeper (`DRIFT_REOPENED` auto-re-arming) + optional CISA KEV/OSV polling. |
| **CM-2** | Baseline Configuration | `policies/gate_eligibility.rego` enforces `>= 80%` test coverage, OTel probes, read-only shadow DB, and `< 60s` rollback readiness. |
| **CM-3** | Configuration Change Control | Progressive canary (`5% -> 25% -> 100%`) with stateless patch gate, JCS schema diff, p99 ceiling, and syscall capability diff. |
| **IA-2** | Identification & Authentication | W3C WebAuthn hardware authenticators (`RPID` SHA-256 hash, UP/UV flags, P-256/Ed25519) + live `principal_revocations` checks. |
| **IA-8** | Non-Organizational / Agent Auth | Governed external workers require Ed25519-signed minute-scoped Ephemeral Task Warrants (`TTL <= 300s`). |
| **RA-5** | Vulnerability Scanning | `SARIF 2.1.0`, `CycloneDX/VEX`, `CISA KEV`, and `OSV.dev` intake paired with adversary-twin exploit replay verification. |
| **SC-8** | Transmission Integrity & Containment | OpenC2 / Cilium eBPF virtual containment bridges within SLA windows and permanent post-patch runtime lockouts. |
| **SI-7** | Software & Information Integrity | 100% pod container SHA-256 digest verification (`policies/verify_closure.rego`) and genesis-to-tip WORM ledger hash-chain audits. |
