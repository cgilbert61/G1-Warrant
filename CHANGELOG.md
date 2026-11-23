# Changelog

All notable changes to **G1-Warrant** are documented in this file.
Published Git tags (`v1.0.0`, `v1.0.1`, `v1.0.2`, `v1.0.3`, `v1.0.4`, `v1.1.0`, `v1.2.0`, ...) are immutable to preserve Go Checksum Database (`sum.golang.org`) reproducibility for `github.com/cgilbert61/G1-Warrant/pkg/warrantsdk`.

---

## [v1.2.1] - 2026-11-23

### Complete R2 Remediation Closure (`WN-1`–`WN-6` 100% Closed) & Vendor Configuration Reference

1. **`WN-1` — Tier-Honest OSCAL Closure Prose & Evidence-Derived Artifact Provenance (`internal/ledger/engine.go`, `internal/verify/`):**
   - Gated the `N3` verification observation and risk `statement` inside `MintOSCALAttestation` strictly on whether a publisher-signed exploit probe ran (`hasSignedProbe == true` -> `"N3 Isolated Ephemeral Twin Exploit Replay"`; `hasSignedProbe == false` -> `"N3 Passive Artifact Provenance & SBOM Absence Verification"`; `SECRET_ROTATION` -> `"N3 Cryptographic Credential Rotation & Metadata Severance"`), eliminating false `"verified in isolated twin"` or `EXPLOIT_BLOCKED` claims on passive-only closures.
   - Replaced hardcoded `ProvenanceVerified: true` in `internal/verify/engine.go`, `internal/verify/distributor_verify.go`, and `internal/ledger/engine.go` with `DeriveVerifiedArtifactProvenance`, deriving provenance strictly from recorded `ARTIFACT_PROVENANCE_VERIFIED` traces matching `item.PatchedDigest` (`PASSIVE_CLOSURE_MISSING_PROVENANCE` fail-closed in OPA when absent).
2. **`WN-2` — Cross-Language RFC 8785 Section 3.2.2.3 IEEE-754 Number Formatting & Shared Go/Python Test Vectors:**
   - Implemented ECMA-262 / RFC 8785 Section 3.2.2.3 IEEE-754 float canonicalization (`_format_jcs_float` in `sdk/python/g1_warrant/crypto.py`) so `1e-6 -> "0.000001"`, `1e-7 -> "1e-7"`, `1e20 -> "100000000000000000000"`, `1e21 -> "1e+21"`, and `-0.0 -> "0"` match Go's `internal/crypto/jcs.go` byte-for-byte.
   - Added shared cross-language test suite `testdata/rfc8785_jcs_vectors.json` executed by both Go (`TestSharedRFC8785JCSAndCrossLanguageDSSEVectors_WN2`) and Python (`test_shared_rfc8785_jcs_and_cross_language_dsse_vectors_wn2`), verifying identical JCS bytes, PAE SHA-256 digests, and Ed25519 DSSE signatures across runtimes.
3. **`WN-3` — Signed-Payload Identity Extraction & Unsigned Outer-Wrapper Reconciliation (`pkg/warrantsdk`, `sdk/python`):**
   - Updated both `VerifyOSCALBundleOffline` (Go) and `verify_oscal_bundle_offline` (Python) to parse `attestation_id`, `cve_id`, `service_id`, and `warrant_id` directly from the signed DSSE payload (supporting both full NIST OSCAL `1.1.2` `plan-of-action-and-milestones` documents and direct attestation payloads), reconciling against any outer wrapper fields and failing closed with `UNSIGNED_WRAPPER_MISMATCH` on any discrepancy.
4. **`WN-4` — Fail-Closed Keyring Verification, Explicit Opt-In & `TrustBasis` Reporting (`pkg/warrantsdk`, `sdk/python`, CLIs):**
   - Changed `VerifyOSCALBundleWithKeyRing` / `verify_oscal_bundle_with_keyring` to fail closed (`UNTRUSTED_KEYRING_EMPTY`) when no external keyring is supplied, even when `kernel_public_key_ring` is embedded in the exported bundle.
   - Gated embedded-ring inspection strictly behind explicit opt-in (`VerifyOSCALBundleWithKeyRingOpts(..., KeyRingVerificationOptions{AllowEmbeddedKeyRingOptIn: true})` in Go; `allow_embedded_keyring_opt_in=True` in Python; `--trust-embedded-keyring` in `warrant` and `g1-warrant`), and added `trust_basis` (`EXTERNAL_PINNED_PUBKEY`, `EXTERNAL_KEYRING`, or `EMBEDDED_BUNDLE_KEYRING_UNTRUSTED_OPT_IN`) to verification results with zero network calls in offline CLI subcommands.
5. **`WN-5` — Genuine Air-Gapped Verification Docs & Complete 18-Vendor Configuration Reference:**
   - Updated `README.md`, `docs/sdk_and_cli_guide.md`, and `sdk/python/README.md` so all offline verification examples read locally pinned `--pubkey-file` / `--keyring-file` artifacts with zero server calls.
   - Added [`docs/vendor_integration_reference.md`](docs/vendor_integration_reference.md) and expanded `.env.example` documenting the real push-export intake configuration for all 3 `WN-7` scanners (where Warrant holds zero scanner credentials) and all 15 `WN-8` distributor environment variables, native API routes, ring vs. wave-slicing capabilities, simulated-results fallback, and proof fence (`TestInvariant17_V121RemediationWN1ToWN5`).

---

## [v1.2.0] - 2026-11-22

### Proof Tier & Verification Fence (Plain-Words Statement)
- **Built and Wired; Not Yet Vendor-Proven:** The 3 `WN-7` Finder translators (`qualys_vmdr`, `tenable`, `rapid7_insightvm`) and all 15 `WN-8` Distributor translators (`k8s-cilium-native`, `argocd`, `flux`, `ms-intune`, `ms-mecm`, `ms-wsus`, `ansible-awx`, `redhat-satellite`, `jamf-pro`, `aws-ssm`, `azure-update-manager`, `gcp-os-config`, `tanium-patch`, `ivanti-neurons`, `automox`) are verified against deterministic invariant tests (`TestInvariant15`, `TestInvariant16`), wire-PoP mock HTTP servers, and recorded/sandbox sessions. **None has yet run against a live vendor API.** They stand behind the same proof fence as `LiveKubernetesAdapter`: built and wired behind the typed contracts, not yet vendor-proven. Output from `/warrant distributors list` (and `GET /api/v1/distributors`) confirms translator registration in the control-plane registry; it does **not** confirm a live vendor conversation.

### `WN-1`–`WN-6` Release Sequencing Note
- `v1.2.0` shipped `WN-6` (checksummed GitHub Release artifacts + PEP 639 Python wheel/sdist embedding `LICENSE` and `NOTICE`) alongside `WN-7` and `WN-8`; items `WN-1` through `WN-5` were completed immediately afterward in `[v1.2.1]` above.

### Incumbent Integration Architecture (`WN-7` & `WN-8`)
1. **`WN-7` — Zero-Egress Finder Translation Layer & Fail-Visible Unmapped Advisories:**
   - Added `FinderTranslator` implementations (`internal/extractor/finders/{qualys_vmdr,tenable,rapid7_insightvm}.go`) terminating untrusted Qualys VMDR (XXE-hardened XML + JSON v2), Tenable.io/sc (JSON), and Rapid7 InsightVM v3 (JSON) payloads inside zero-egress `warrant-extractor` (`POST /extract/{qualys,tenable,rapid7}` under `X-Warrant-Task-DSSE` + `X-Warrant-Agent-PoP`), stripping 100% of prose/HTML/XSS/prompt-injection fields.
   - Added `asset_identity_aliases` (`009_v1_2_0_finders_and_distributors.sql`) and fail-visible `UNMAPPED_VENDOR_ADVISORY` handling (`UNMAPPED_FINDING_REQUIRES_CLASS_BINDING`), arming containment immediately while refusing autonomous execution unless explicitly bound in `AuthorizedVendorDetections`.
2. **`WN-8` — Governed Distributor Translation Layer, Wave Sequencer & Honest Per-Asset Closure:**
   - Added canonical `DeploymentOrder` (outbound) + `DeploymentResult` (inbound mirror), WORM-protected `deployment_orders` & `deployment_results` tables, `DistributorRegistry` with 15 translators across 6 enterprise families, and `wave_sequencer.go` (`SupportsNativeRings` pass-through vs. `5% -> 25% -> 100%` `N2`-gated waves).
   - Enforced `TargetAssets ⊆ WarrantScope` (`TARGET_ASSET_OUTSIDE_WARRANT_SCOPE`), `NO_PROOF_NO_DEPLOYMENT_ORDER`, immutable pre-Wave-1 `NativeRollbackSpec` persistence, symmetric `ExecuteRollback` on wave failure/stall, and honest `FULL` / `PARTIAL` (bridge held active) / `DISPATCH_ONLY` (`ASSURANCE_TIER_0_DISTRIBUTOR_DISPATCH_ONLY`, bridge held active) OSCAL `1.1.2` closure tiering in `policies/verify_closure.rego`.
3. **Go SDK (`pkg/warrantsdk` `1.2.0`), Python SDK (`g1-warrant-sdk` `1.2.0`), CLI & Console:**
   - Bumped both SDKs to `1.2.0` with 100% backwards-compatible exported Go signatures, added `warrant intake [qualys|tenable|rapid7]` and `warrant distributors [list|orders|results|aliases|dispatch|rollback]`, and updated the React 19 Console.

---

## [v1.1.0] - 2026-11-21 (`64f2d9f`)

- **Agent Workload Identity, Commissioning Function Governance, IGA Orphan Quarantine & RFC 8693 Wire-Level Permission Intersection (`A1`–`A6`):** Added `008_v1_1_0_agent_identities.sql`, 3-Way `Builder != Commissioner` SoD (`G1_AGENT_PROVENANCE_V1`), `CommissioningFunction` sponsor continuity + bounded orphan grace windows + `0s` `KEY_COMPROMISE` cutoff, `data.warrant.agent` permission intersection (`StandingWarrantScope ∩ AgentCapabilityCeiling ∩ ParentTaskScope ∩ RequestedTask`), `cnf` + `act` `EphemeralTaskWarrant` token exchange, wire-level `X-Warrant-Task-DSSE` + `X-Warrant-Agent-PoP` verification, and 9-table Merkle v3 anchoring (`TestInvariant14`).

---

## [v1.0.4] - 2026-11-20 (`d8f21cd`)

- **Consolidated Integrity & Security Remediation (`F1`–`F6`):** Publisher & rulepack authority custody ladder (`F1`), database credential hygiene (`F2`), `LiveKubernetesAdapter` isolated twin `batch/v1` Job execution (`F3`), canary sample/dwell floors & measured telemetry (`F4`), public-only persona serialization (`F5`), and external notary witness posture reporting (`F6`) (`TestInvariant13`).

---

## [v1.0.3] - 2026-11-20 (`a8e35cc`)

### Security & Governance Hardening

1. **Block Stolen-Key Backup Assassination on Revocation (`NIST SP 800-53 Rev 5 AC-5`):**
   - Restricted `1-of-2` `REVOKE_PRINCIPAL` (`POST /api/v1/principals/revoke`) strictly to **self-revocation** (`signer.PrincipalID == target.PrincipalID`, while preserving the `>= 1` active `SERVICE_OWNER` and `>= 1` active `AUTHORIZING_OFFICIAL` survivor floor) so a stolen primary key cannot burn cold-storage vault backup keys.
   - Required a **`2-of-2` DSSE ceremony** (`REVOKE_PRINCIPAL` or `ROTATE_AND_REVOKE_PRINCIPAL` co-signed by active `SERVICE_OWNER` + active `AUTHORIZING_OFFICIAL`) whenever `signer.PrincipalID != target.PrincipalID`, rejecting `1-of-2` peer revocation with **`HTTP 403 PEER_REVOCATION_REQUIRES_DUAL_KEY_DSSE`**.
   - Enforced `>= 2` active `SERVICE_OWNER` and `>= 2` active `AUTHORIZING_OFFICIAL` principals before `POST /api/v1/bootstrap/seal` (or first-warrant auto-seal) succeeds when `WARRANT_CLUSTER_DRIVER=kubernetes` or `WARRANT_FEED_MODE=live` (retaining `>= 1 SO + >= 1 AO` in offline `simulator` mode).
2. **Persisted `WARRANT_KERNEL_KEY_PATH`, Zero-Exemption Kernel Lineage & Immediate `Checkpoint #0`:**
   - Persisted local non-KMS kernel key material on a `0600` volume-backed path (`WARRANT_KERNEL_KEY_PATH`, mounted to `warrant_anchor` in `docker-compose.yml` with NTFS-safe Windows handling) so routine container restarts retain `seq_no = 1` without unattested key churn.
   - Enforced with **zero exemptions** (including ephemeral and KMS modes) across `lineage.go` and `queries.go` that every `kernel_public_keys` row with `seq_no > 1` carries a valid `rotation_dsse` signed by `seq_no - 1` OR a `2-of-2` human Principal Governance `ROTATE_KERNEL_KEY` DSSE envelope.
   - Wired immediate `AnchorCheckpoint` (**`Checkpoint #0`**) directly inside `Store.SealBootstrap` (`POST /api/v1/bootstrap/seal` and first-warrant auto-seal) so the Genesis Seal Manifest and initial authority chains are externally anchored the instant sealing completes.
3. **WebAuthn P-256 Parity & Raw-Byte Body Hashing on `1-of-2` Operator Routes:**
   - Hardened `VerifySingleActivePrincipalCeremony` and `VerifySingleSignature` (plus `StoreKeyResolver` credential lookup and Console `App.tsx` / `crypto.ts`) to validate both `Ed25519` and **`W3C WebAuthn P-256` (`ES256`)** hardware assertions (`authenticatorData` + `clientDataJSON`) across `freeze`, `emergency-rollback`, `auditor-tokens`, and self-revocation while blocking algorithm-downgrade bypasses.
   - Verified and buffered exact raw wire bytes from `http.MaxBytesReader` prior to JSON unmarshaling across `api.go` so `request_body_sha256` signatures never fail due to key ordering or whitespace.

---

## [v1.0.2] - 2026-11-20 (`097469b`)

### Security & Governance Hardening

1. **Quorum Survivor Floor & Atomic `2-of-2` Key Rotation (`NIST SP 800-53 Rev 5 AC-5`):**
   - Restricted `1-of-2` `REVOKE_PRINCIPAL` (`POST /api/v1/principals/revoke`) inside serialized `pg_advisory_xact_lock` transactions so a single active key can only revoke **itself** (compromised-key self-revocation) or a **same-role peer**, and verified that `>= 1` active `SERVICE_OWNER` and `>= 1` active `AUTHORIZING_OFFICIAL` remain unrevoked after revocation (`HTTP 409 QUORUM_SURVIVOR_FLOOR_VIOLATION`).
   - Added atomic **`2-of-2` `ROTATE_AND_REVOKE_PRINCIPAL`** (`POST /api/v1/principals/rotate-and-revoke`, `Client.RotateAndRevokePrincipal`, `warrant principals rotate-and-revoke`, `g1-warrant principals-rotate-revoke`) to enroll a replacement key and revoke the target key (including replacing the last surviving principal of a role or rotating under the same corporate email) in one serialized transaction.
2. **Attested Authority Lineage & Pre-Checkpoint SQL `INSERT` Defense (`AU-9(3)` / `SR-11`):**
   - Added migration `007_v1_0_2_lineage_attestation.sql` introducing shared causal `authority_event_seq` (`authority_seq`), `lineage_mode`, and full `governance_dsse` columns on `principals` and `principal_revocations`, `rotation_dsse` on `kernel_public_keys`, and a kernel-signed **Genesis Seal Manifest** (`genesis_seal_dsse` + `genesis_manifest_sha256`) on `bootstrap_state`.
   - Required any `kernel_public_keys` row beyond `seq_no = 1` to carry a valid `rotation_dsse` signed by the preceding (`seq_no - 1`) kernel key or `2-of-2` active `SO + AO` principals (or match configured external KMS public key).
   - Wired full causal authority-lineage replay (`VerifyAuthorityLineageAttestations`) into both `VerifyAllLedgerChains` and `AnchorCheckpoint` *before* `ComputeCombinedMerkleRootV2` hashes or signs any checkpoint, failing closed with `UNATTESTED_AUTHORITY_LINEAGE_INSERT_DETECTED` on raw SQL `INSERT`s.
3. **Request-Scope DSSE Binding & Monotonic `freeze_epoch` Replay Protection:**
   - Required all `1-of-2` DSSE Principal Governance headers/envelopes on operational routes to sign canonical `http_method`, `canonical_path`, `request_body_sha256` (when header-detached), `expires_at` (`<= 5m` ceiling), and single-use `envelope_id` recorded in `governance_envelope_nonces` (`HTTP 401 DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION`).
   - Added monotonic `system_freeze_state.freeze_epoch` (incremented on every freeze transition) + single-use nonce tracking on `2-of-2` `THAW` ceremonies, and `exception_id` + single-use `envelope_id` verification on `2-of-2` Four-Eyes Exception resolutions.
4. **Automation Token Isolation vs. Human Non-Repudiation (`NIST SP 800-53 Rev 5 IA-2` & `AU-10`):**
   - Added `WARRANT_AUTOMATION_TOKEN` (`WithAutomationToken` / `automation_token`) scoped strictly to `POST /api/v1/feeds/*` and `POST /api/v1/ledger/checkpoints`, returning `HTTP 403 AUTOMATION_TOKEN_FORBIDDEN_ON_HUMAN_GOVERNANCE_ROUTE` on human governance routes.
   - Required individual `1-of-2` DSSE / WebAuthn principal signatures on `POST /api/v1/freeze`, `POST /api/v1/pipeline/{id}/emergency-rollback`, and `POST /api/v1/auditor-tokens` whenever `WARRANT_CLUSTER_DRIVER=kubernetes` or runtime feed mode is `live` (restricting static `WARRANT_OPERATOR_TOKEN` fallback strictly to offline `simulator` sandboxes).
5. **Embedded React 19 Console (`web/`) Auth Parity & Intake Body Caps:**
   - Wired all mutating Console actions (`FREEZE_HOLD`/`FREEZE_ROLLBACK`, `freeze_epoch`-bound `2-of-2` `THAW`, `[Quarantined Rollback]`, WebAuthn genesis token + post-seal `2-of-2` DSSE enrollment, same-role `1-of-2` revocation, `Auditor Token` minting, and `Live Feeds` modal with optional `WARRANT_AUTOMATION_TOKEN`) with `role="alert"` error banners and hid simulation drill controls when feed mode is `live`.
   - Enforced `WARRANT_INTAKE_TOKEN` on `POST /api/v1/intake/sarif` and `POST /api/v1/intake/secrets` whenever `WARRANT_CLUSTER_DRIVER=kubernetes` or feed mode is `live`, and mapped `*http.MaxBytesError` to explicit **`HTTP 413 Payload Too Large`** across `warrantd` and `warrant-extractor`.

---

## [v1.0.1] - 2026-11-20 (`baebcc2`)

- **One-Shot Genesis Bootstrap Seal & Asymmetric Principal Governance (`006_v1_0_1_security_hardening.sql`):** Added `bootstrap_state` seal (`POST /api/v1/bootstrap/seal` + auto-seal on first `POST /api/v1/warrants`), post-seal `2-of-2` DSSE `ENROLL_PRINCIPAL` across Ed25519 and WebAuthn, `1-of-2` DSSE `REVOKE_PRINCIPAL`, unique `fingerprint_sha256` / `public_key_b64` constraints, and single-use `governance_envelope_nonces`.
- **Authenticated Operational Mutation Endpoints:** Gated `/api/v1/freeze`, `/api/v1/pipeline/{id}/emergency-rollback`, `/api/v1/auditor-tokens`, `/api/v1/feeds/*`, `/api/v1/ledger/checkpoints`, and `/api/v1/intake/*`; completely disabled `/api/v1/simulate/*` in `kubernetes` and `live` feed modes.
- **6-Chain Combined Merkle Root (`v2.0`):** Expanded `TransparencyAnchor` Merkle checkpoints and PostgreSQL immutability triggers across `principals`, `principal_revocations`, and `kernel_public_keys`, plus `VerifyOSCALBundleWithKeyRing` multi-key verification.
- **Split Keygen Hygiene:** Updated `warrant keygen` and `g1-warrant keygen` to emit split `<prefix>.priv.json` (`0600`) and `<prefix>.pub.json` (`0644` public-only) files and reject private-key JSON inside `RegisterPrincipal`.

---

## [v1.0.0] - 2026-11-19 (`c56a2db`)

- Initial open-source release of **G1-Warrant** (`warrantd` control plane, `N1–N5` deterministic engines, `warrant` Go CLI, `pkg/warrantsdk` Go SDK, `g1-warrant-sdk` Python SDK/CLI, zero-egress `warrant-extractor`, `fleet-sim`, embedded React 19 Section 508 Console, OPA Rego v1 policy suite, NIST OSCAL `1.1.2` POA&M attestation vault, and 9-Gate Federal DevSecOps harness).
