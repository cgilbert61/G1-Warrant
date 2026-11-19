# ADR-0004: Bridge Before Patch; Admission Lockout Before Bridge Retirement

- **Status:** Accepted
- **Organization:** G1163RT Security Labs, Inc.

## Context
Retiring temporary network containment before banning the vulnerable image digest allows CI pipelines or autoscalers to re-instantiate vulnerable containers and reopen the exploit window.

## Decision
1. Upon KEV/CVE intake, `warrantd` immediately compiles and enforces a declarative `CiliumNetworkPolicy`, Kubernetes `NetworkPolicy`, and Envoy SPIFFE mTLS filter (`Bridge Before Patch`).
2. `N3` prohibits retiring an active containment bridge until:
   - Isolated ephemeral Shadow Twin Exploit Replay returns `EXPLOIT_BLOCKED`;
   - 100% of live pods passively attest the patched OCI SHA-256 digest with vulnerable symbols unloaded; and
   - A permanent `ValidatingAdmissionPolicy` + OPA Gatekeeper constraint (`Admission Lockout`) is enforced on the cluster.
3. A continuous sub-second `N3` runtime drift watcher monitors live pods and automatically re-arms the `CiliumNetworkPolicy` containment bridge within milliseconds if a banned digest ever reappears.
