# Changelog

All notable changes to **G1-Warrant** are documented in this file.
Published Git tags (`v1.0.0`, `v1.0.1`, `v1.0.2`, `v1.0.3`, ...) are immutable to preserve Go Checksum Database (`sum.golang.org`) reproducibility for `github.com/cgilbert61/G1-Warrant/pkg/warrantsdk`.

---

## [v1.0.3] - 2026-11-20

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
