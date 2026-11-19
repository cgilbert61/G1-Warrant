# ADR-0002: Dual-Signed DSSE Standing Warrants & Asymmetric Emergency Freeze (NIST SP 800-53 AC-5)

- **Status:** Accepted
- **Organization:** G1163RT Security Labs, Inc.

## Context
Autonomous remediation must never act as a self-authorizing principal, and compromised or departing personnel keys must revoke autonomous authority immediately.

## Decision
1. Every Standing Warrant is an RFC-compliant DSSE v1.0 envelope carrying an RFC 8785 JCS payload co-signed across two distinct cryptographic slots:
   - **Slot 1:** `SERVICE_OWNER`
   - **Slot 2:** `AUTHORIZING_OFFICIAL`
2. Separation of duties (`NIST SP 800-53 AC-5`) is enforced across four layers (Go verifier, OPA Rego `data.warrant.ac5`, PostgreSQL `CHECK` constraints, and Console UI): identical principal IDs, emails, or public key fingerprints across Slot 1 and Slot 2 are rejected, and `SYSTEM_ADMIN` principals are prohibited from signing Warrant slots.
3. `N2` and `N5` re-verify both signatures against the live `principal_revocations` table before every canary stage and before minting any OSCAL attestation.
4. Emergency Freeze is intentionally asymmetric: triggering `FREEZE_HOLD` or `FREEZE_ROLLBACK` is single-operator hold-to-activate (propagated sub-second via memory + PostgreSQL `LISTEN/NOTIFY`) and halts `N2` rollouts while preserving active `Shield` bridges and `N3` drift re-arming; thawing requires a live `2-of-2` DSSE signature ceremony.
