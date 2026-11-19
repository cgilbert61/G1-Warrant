# ADR-0003: Zero-Privilege Egress-Denied Extractor (`warrant-extractor`)

- **Status:** Accepted
- **Organization:** G1163RT Security Labs, Inc.

## Context
Scanner outputs (`SARIF 2.1.0`), vulnerability advisories, and git diffs contain untrusted attacker-influenced strings (commit messages, rule markdown, file annotations). Allowing raw untrusted text into the privileged `warrantd` kernel expands parsing and injection attack surface.

## Decision
Untrusted text is parsed exclusively by `warrant-extractor`, a dedicated `CGO_ENABLED=0` static Go binary running in `gcr.io/distroless/static:nonroot` with `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, and attached *only* to an `internal: true` Docker bridge network (`extractor_net`) with zero external egress route. It strips all free-form prose and emits bounded, regex-validated typed structs whose `raw_input_sha256`, `extractor_digest`, and JCS `typed_output_sha256` are hash-chained into `agent_action_ledger`.
