# ADR-0001: 100% Deterministic Safety Kernel (Zero LLM Inference in N1–N5 & Console)

- **Status:** Accepted
- **Organization:** G1163RT Security Labs, Inc.

## Context
Enterprise and federal production networks cannot delegate rollout gating, containment enforcement, or FedRAMP/NIST OSCAL POA&M attestation minting to probabilistic language models susceptible to non-determinism or prompt injection.

## Decision
Engines `N1` through `N5`, `warrant-extractor`, and the embedded React 19 Console contain **zero LLM API calls, zero prompt templates, and zero probabilistic inference**. Every transition is governed by precompiled in-process Open Policy Agent (`OPA`) Rego modules, RFC 8785 JCS canonicalization, DSSE cryptographic verifiers, deterministic HTTP/syscall set comparators, and typed string templates.

## Consequences
- Identical inputs produce bit-identical policy decisions, execution traces, and JCS-canonicalized OSCAL 1.1.2 POA&M packages.
- External upstream fix generators (if any) are treated strictly as untrusted inputs governed by `N4` publisher provenance checks and `N2` differential shadow gating.
