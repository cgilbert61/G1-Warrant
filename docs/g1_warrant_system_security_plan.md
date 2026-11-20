# G1-Warrant — System Security Plan (SSP)

**System Name:** G1-Warrant Deterministic Autonomous Remediation, Containment & Attestation Control Plane  
**System Owner:** G1163RT Security Labs, Inc.  
**FISMA / System Identifier:** `G1-WARRANT-001`  
**Security Categorization:** FIPS 199 Moderate / High-Integrity Control Plane  
**Governing Baseline:** NIST SP 800-53 Rev 5 (FedRAMP Rev 5 Aligned), DISA STIG, Executive Order 14028, Rehabilitation Act Section 508  

---

## 1. System Boundary & Operational Purpose

Enterprise and federal vulnerability remediation stalls in a 43-day merge-to-production bottleneck because organizations lack pre-negotiated blast-radius boundaries, cryptographic separation of duties, non-disruptive containment during triage, and verifiable closure proof.

**G1-Warrant** (`warrantd` server, `warrant` CLI, `warrant-extractor`, `fleet-sim`, and embedded G1-Warrant Console) eliminates that bottleneck via five deterministic Pure-Go engines (`N1–N5`) operating on a disciplined SRE invariant: **Contain in seconds; verify and roll out safely in minutes.**

1. **Zero LLM Inference Inside the Safety Kernel:** Policy evaluation (`OPA Rego v1`), rollout gating, progressive canary promotion, differential twin replay verification, OSCAL attestation minting, and Console rendering contain zero probabilistic or LLM inference code paths.
2. **Standing Warrants (`N1` — `NIST SP 800-53 Rev 5 AC-5`):** Autonomous execution is authorized solely under pre-negotiated `2-of-2` DSSEv1 envelopes co-signed over RFC 8785 JCS payloads by disjoint institutional roles (`Slot 1: SERVICE_OWNER`, `Slot 2: AUTHORIZING_OFFICIAL`) via Ed25519 or W3C WebAuthn hardware authenticators. Production SDKs and CLIs ship zero demo signers.
3. **Zero-Egress Content Isolation (`warrant-extractor` — `AC-4`):** Untrusted external inputs (`SARIF 2.1.0`, `CISA KEV`, `Google OSV.dev`, `CycloneDX/VEX`, git diffs) traverse a network-isolated, read-only parser before regex-validated typed identifiers reach `warrantd`.
4. **Two-Mode Containment & 3-Tier Graduated Fleet Autonomy (`N2` & `N3`):**
   - **Zero-Prose Quarantine vs. Signed L7 Rulepacks (`SC-7(5)`):** When prose is stripped and no publisher-signed rulepack matches, `N3` applies `ZERO_PROSE_EGRESS_MESH_QUARANTINE` (cutting external world egress to block reverse shells/JNDI callbacks while preserving mTLS mesh traffic without blind HTTP route guesses). `SIGNED_RULEPACK_L7_SHIELD` applies Envoy/Cilium HTTP rules *only* when backed by an Ed25519 publisher-signed CWE/CVE rulepack.
   - **3-Tier Graduated Autonomy (`CM-2`):** Grades workloads into `TIER_1_FULL_AUTONOMOUS` (`>=80%` coverage + OTel + CoW/Shadow DB + `<10s` rollback), `TIER_2_GUARDED_CANARY` (brownfield SLI-guarded canary when authorized by `allow_guarded_canary`), and `TIER_3_CONTAIN_AND_CAB` (automatic containment + Four-Eyes CAB).
   - **Order-Insensitive Canary Diffing & In-Process eBPF Guards (`CM-3(4)`):** Evaluates HTTP JSON responses using order-insensitive array multiset canonicalization, `1e-6` float tolerance, custom volatile path masks, and checks syscalls alongside sensitive file reads (`serviceaccount/token`) and unexpected egress.
5. **Differential Twin Positive Control, Atomic Quarantined Rollback & External Merkle Anchor (`N3` & `N5`):**
   - **Dual Assurance Tiers (`RA-5`):** Requires positive-control exploit confirmation on the unpatched digest (`unpatched_twin_status == "EXPLOIT_SUCCEEDED"`) before accepting `EXPLOIT_BLOCKED` on the patched digest (`ASSURANCE_TIER_2_DIFFERENTIAL_TWIN`), while attesting standard advisories without weaponized PoCs under `ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM`.
   - **Atomic 3-Step `QUARANTINED_ROLLBACK`:** Resolves post-closure latent regressions without deadlocking against `ValidatingAdmissionPolicy` lockouts by (1) re-arming containment *before* unbanning, (2) suspending the lockout (`SUSPENDED_FOR_QUARANTINED_ROLLBACK`), and (3) reverting to the previous digest under active quarantine.
   - **External Transparency Anchor & Non-Exportable KMS (`AU-9(3)`, `SR-11`):** Delegates kernel signing via `crypto.EnvelopeSigner` (`RemoteKMSSigner` or ephemeral memory keys) and ships DSSE-signed binary Merkle Root checkpoints outside PostgreSQL (`WARRANT_EXTERNAL_ANCHOR_PATH` / `WARRANT_EXTERNAL_ANCHOR_URL`) to detect even PostgreSQL superuser trigger-disable rewrites.
6. **Autonomous Intrusion Countermeasures (`N1–N4`):**
   - **`SECRET-ROTATION-STATELESS` Standing Warrant (`AC-5`, `IA-8`):** Zero-prose Gitleaks/GitGuardian intake hashes exposed credentials into SHA-256 fingerprints, strips plaintext secrets, rotates Kubernetes `ExternalSecret` / `ServiceAccount` tokens + triggers rolling restarts in seconds, and mints a DSSE-signed OSCAL 1.1.2 POA&M (`ASSURANCE_TIER_SECRET_ROTATED`).
   - **Default Cloud Metadata & Outbound Callback Quarantine (`SC-7(5)`):** Every `N3` containment bridge blocks `169.254.169.254/32`, `169.254.170.2/32`, `fd00:ec2::254/128`, and external `world` egress while restricting outbound connections strictly to pre-declared internal cluster services.
   - **Immutable RootFS 5th Gate (`CM-2`) & eBPF/Tetragon In-Pod Drift Quarantine (`CA-7`):** Enforces `readOnlyRootFilesystem: true` + `noexec /tmp` on autonomous workloads and catches container filesystem writes (dropped webshells) or untracked processes on valid-digest pods, automatically re-arming quarantine, cordoning the pod, and recycling a clean replica.
   - **Attack-Path Chained CWE Weighting & Build/Agent Config Exclusion (`RA-5`, `SI-7(15)`):** Elevates `CWE-209`, `CWE-918`, and `CWE-434` via `auto_remediate_cwes` and cryptographically blocks patch diffs touching `.github/`, `.gitlab-ci`, `Dockerfile`, `Makefile`, `AGENTS.md`, `CLAUDE.md`, `.cursor`, or `.gemini/`.

---

## 2. NIST SP 800-53 Rev 5 Control Summary (16 Implemented Controls)

| Control | Title | Implementation Summary |
| :--- | :--- | :--- |
| **AC-3** | Access Enforcement | Fail-closed Standing Warrant verification on all rollouts/bridges; `g1aud_*` bearer tokens isolated strictly to `/api/v1/auditor/*`. |
| **AC-4** | Information Flow Enforcement | Zero-egress `warrant-extractor` network isolation separates untrusted scanner/threat prose from control-plane state. |
| **AC-5** | Separation of Duties | Embedded OPA policy (`policies/warrant_ac5.rego`) enforces `2-of-2` disjoint `SERVICE_OWNER` + `AUTHORIZING_OFFICIAL` co-signatures. |
| **AU-2** | Event Logging | Structured SHA-256 input/output lineage recorded for every warrant, task delegation, shadow run, containment bridge, and closure. |
| **AU-9(3)** | Protection of Audit Info (Cryptographic) | PostgreSQL immutability triggers + SHA-256 hash chains + External Merkle Root Transparency Checkpoints (`internal/ledger/anchor.go`). |
| **AU-10** | Non-Repudiation | DSSEv1 + RFC 8785 JCS + KMS/Ed25519/WebAuthn signatures with standalone offline CLI and in-browser verification. |
| **CA-7** | Continuous Monitoring | Event-driven Kubernetes `WATCH` stream (`?watch=true&resourceVersion=...`) + drift re-armer + optional CISA KEV/OSV polling. |
| **CM-2** | Baseline Configuration | 3-Tier Graduated Fleet Autonomy (`TIER_1_FULL_AUTONOMOUS`, `TIER_2_GUARDED_CANARY`, `TIER_3_CONTAIN_AND_CAB`). |
| **CM-3(4)** | Configuration Change Control | Statistical sample/dwell canary gates, multiset JSON diff, eBPF file/egress/syscall checks, and Atomic Quarantined Rollback. |
| **IA-2(1)** | Multi-Factor Hardware Auth | W3C WebAuthn hardware authenticators (`RPID` SHA-256 hash, UP/UV flags, P-256/Ed25519) + live `principal_revocations` checks. |
| **IA-8** | Non-Organizational / Delegate Auth | Governed external workers require DSSE-signed minute-scoped Ephemeral Task Warrants (`TTL <= 300s`). |
| **RA-5** | Vulnerability Monitoring & Scanning | Differential Twin positive-control verification (`ASSURANCE_TIER_2`) and passive provenance/digest closure (`ASSURANCE_TIER_1`). |
| **SC-7(5)** | Boundary Protection (Deny by Default) | `ZERO_PROSE_EGRESS_MESH_QUARANTINE` (world egress deny + mTLS mesh) vs. Ed25519 publisher-signed `SIGNED_RULEPACK_L7_SHIELD`. |
| **SI-7(15)** | Code Authentication & Integrity | Publisher Ed25519 provenance verification + 100% live pod `imageID` SHA-256 digest & unloaded symbol sweep. |
| **SR-3** | Supply Chain Controls & Processes | CycloneDX 1.5 SBOM (`48/48` SPDX-attributed permissive packages, `0` copyleft violations) + SHA-pinned CI workflows. |
| **SR-11** | Component Authenticity | Non-exportable external KMS/HSM `EnvelopeSigner` + permanent Kubernetes `ValidatingAdmissionPolicy` digest lockouts. |
