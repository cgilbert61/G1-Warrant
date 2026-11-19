# Security Policy — G1-Warrant

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | :white_check_mark: |

## Architectural Security Guarantees

1. **Zero LLM Inference in the Safety Kernel (`warrantd` & Console):** Policy evaluation (`OPA Rego`), cryptographic envelope verification (`DSSE` + `RFC 8785 JCS`), progressive rollout gating, adversary-twin closure verification, and Console rendering are 100% deterministic.
2. **Strict Separation of Duties (NIST SP 800-53 AC-5):** Every Standing Warrant and Ceiling Exception requires `2-of-2` distinct cryptographic signatures from a `SERVICE_OWNER` (Slot 1) and an `AUTHORIZING_OFFICIAL` (Slot 2) via Ed25519 or W3C WebAuthn hardware authenticators.
3. **Zero-Egress Untrusted Content Isolation:** Untrusted external payloads (`SARIF 2.1.0`, `CISA KEV`, `Google OSV.dev`, `CycloneDX`) are parsed exclusively inside `warrant-extractor` running on an isolated `internal: true` network with `readOnlyRootFilesystem: true` and `capabilities.drop: ["ALL"]`.
4. **Tamper-Evident Append-Only Ledgers (NIST SP 800-53 AU-9):** PostgreSQL `BEFORE UPDATE OR DELETE` triggers block mutation across `standing_warrants`, `agent_action_ledger`, and `oscal_attestations`, reinforced by continuous SHA-256 hash chaining.

## Reporting a Vulnerability

Please report security vulnerabilities responsibly to **security@g1163rt.sec** or via GitHub Private Vulnerability Reporting on `cgilbert61/G1-Warrant`. Do not open public issues for undisclosed vulnerabilities.
