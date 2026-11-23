# G1-Warrant — Vendor Integration Configuration Reference (`WN-7` Finders & `WN-8` Distributors)

> **Proof Tier & Verification Fence (Plain-Words Statement):**
> All **3** `WN-7` Finder translators (`qualys_vmdr`, `tenable`, `rapid7_insightvm`) and all **15** `WN-8` Distributor translators across 6 enterprise families are implemented against real vendor payload schemas and REST API route shapes, and are verified against deterministic invariant tests (`TestInvariant15`, `TestInvariant16`, `TestInvariant17`), wire-level `N4` Proof-of-Possession (`X-Warrant-Task-DSSE` + `X-Warrant-Agent-PoP`) mock HTTP servers, and recorded/sandbox sessions. **None has yet run against a live customer tenant.** Listing registered translators via `warrant distributors list` or `GET /api/v1/distributors` confirms registry wiring; it does **not** confirm a live vendor conversation.

---

## 1. Architectural Asymmetry: Push-Only Intake (`WN-7`) vs. Governed Outbound Execution (`WN-8`)

G1-Warrant intentionally separates **inbound vulnerability discovery** from **outbound patch execution** across two distinct credential and network models:

1. **`WN-7` Inbound Finders (Zero-Egress Push Model — Warrant Holds Zero Scanner Credentials):**
   - G1-Warrant **never** stores Qualys, Tenable, or Rapid7 API keys and **never** polls external scanner clouds.
   - Instead, your existing scanner scheduled export, CI runner, or internal collector pushes raw reports (`XML` or `JSON`, up to `16 MiB`) to `POST /api/v1/intake/{qualys,tenable,rapid7}` authenticated with `X-Warrant-Intake-Token` (`WARRANT_INTAKE_TOKEN`).
   - `warrantd` mints a short-lived `N4` Ephemeral Task Warrant (`X-Warrant-Task-DSSE` + `X-Warrant-Agent-PoP`) and forwards the raw bytes into the **zero-egress** `warrant-extractor` container (`POST /extract/{qualys,tenable,rapid7}`).
   - `warrant-extractor` parses strict numeric/enum fields (with XXE entity expansion disabled on XML) and strips 100% of prose, HTML, solution text, and plugin output before `ExtractedFindingSet` crosses back into `warrantd`.
2. **`WN-8` Outbound Distributors (Governed Privileged Mutation Model):**
   - Each distributor translator is configured via `WARRANT_<VENDOR>_URL` and `WARRANT_<VENDOR>_TOKEN` (`Authorization: Bearer <token>`), plus automatic `N4` wire-level `X-Warrant-Task-DSSE` + `X-Warrant-Agent-PoP` headers bound to `agt-distributor-gateway` (`DISPATCH_DEPLOYMENT_ORDER`).
   - Outbound calls fire **only** under an active `2-of-2` Standing Warrant (`TargetAssets ⊆ WarrantScope`) and **only** after `N3` twin/provenance verification succeeds (`NO_PROOF_NO_DEPLOYMENT_ORDER`).
   - **Unconfigured Simulated Fallback:** When `WARRANT_<VENDOR>_URL` is empty (default in local evaluation sandboxes), the translator operates in deterministic simulated-results mode (`EndpointConfigured() == false`) so pipeline, wave-sequencing, and OSCAL closure workflows can be exercised offline without external credentials.

---

## 2. `WN-7` Inbound Finder Configurations (3 Scanners + Asset Alias Resolution)

### Control-Plane Environment Variable

```dotenv
# Required in live/Kubernetes posture on POST /api/v1/intake/{qualys,tenable,rapid7,sarif,secrets}
WARRANT_INTAKE_TOKEN=<generate-with-openssl-rand-hex-24>
```

### Scanner Export -> Warrant Push Wiring

Because Warrant holds zero scanner credentials, configure a thin internal cron/forwarder (or use `warrant intake <vendor> <file>`) to pull from your scanner tenant and push into Warrant:

| Vendor (`source_system`) | Warrant Push Route | Zero-Egress Extractor Route | Accepted Formats | Native Vendor Export API / Source |
| :--- | :--- | :--- | :--- | :--- |
| **Qualys VMDR** (`qualys_vmdr`) | `POST /api/v1/intake/qualys` | `POST /extract/qualys` | Qualys VMDR Host Detection `XML` (XXE-blocked) or `JSON` | `POST https://qualysapi.<pod>.apps.qualys.com/api/2.0/fo/asset/host/vm/detection/?action=list&truncation_limit=0&show_igs=1` (`X-Requested-With: curl`) |
| **Tenable.io / Tenable.sc** (`tenable`) | `POST /api/v1/intake/tenable` | `POST /extract/tenable` | Tenable Vulnerability Export `JSON` (`findings` array or workbench `vulnerabilities`) | `POST https://cloud.tenable.com/vulns/export` -> `GET /vulns/export/{export_uuid}/chunks/{chunk_id}` (`X-ApiKeys: accessKey=...;secretKey=...`) |
| **Rapid7 InsightVM** (`rapid7_insightvm`) | `POST /api/v1/intake/rapid7` | `POST /extract/rapid7` | InsightVM v3 Asset Vulnerabilities `JSON` (`resources` array) | `GET https://<insightvm-console>:3780/api/3/assets/{id}/vulnerabilities` or Data Warehouse JSON export (`X-Api-Key: ...`) |

#### Example Forwarder Invocations

```bash
# 1. Qualys VMDR XML export -> G1-Warrant WN-7 intake
curl -fsSL -u "$QUALYS_USER:$QUALYS_PASS" -H "X-Requested-With: warrant-forwarder" \
  "https://qualysapi.qg2.apps.qualys.com/api/2.0/fo/asset/host/vm/detection/?action=list&status=New,Active,Re-Opened" \
  -o /tmp/qualys-detections.xml

./warrant intake qualys /tmp/qualys-detections.xml --service payments-ledger-api --distributor ms-intune
# (or direct HTTP: curl -H "X-Warrant-Intake-Token: $WARRANT_INTAKE_TOKEN" --data-binary @/tmp/qualys-detections.xml \
#   "http://localhost:8080/api/v1/intake/qualys?service_id=payments-ledger-api&distributor_id=ms-intune")

# 2. Tenable.io JSON chunk -> G1-Warrant WN-7 intake
./warrant intake tenable /tmp/tenable-chunk-01.json --service payments-ledger-api --distributor ansible-awx

# 3. Rapid7 InsightVM v3 JSON -> G1-Warrant WN-7 intake
./warrant intake rapid7 /tmp/rapid7-assets-vulns.json --service identity-sso-gateway --distributor redhat-satellite
```

### Asset Identity Alias Mapping (`POST /api/v1/finders/aliases`)

Scanner host identifiers (`Qualys Host ID`, `Tenable Asset UUID`, `Rapid7 Asset ID`, `FQDN`, `IP`, `Cloud Instance ID`) are mapped deterministically to Warrant `service_id` and `asset_key` scopes via `asset_identity_aliases` (before falling back to deterministic hostname/tag matching):

```bash
curl -X POST http://localhost:8080/api/v1/finders/aliases \
  -H "Content-Type: application/json" \
  -H "X-Warrant-Operator-Token: $WARRANT_OPERATOR_TOKEN" \
  -d '{
    "alias_type": "QUALYS_HOST_ID",
    "alias_value": "9981204",
    "canonical_asset_key": "win-pay-01",
    "service_id": "payments-ledger-api"
  }'
```

> **Fail-Visible Unmapped Vendor Advisories:** When a Qualys `QID`, Tenable `PluginID`, or Rapid7 `VulnID` carries **no CVE mapping**, `warrant-extractor` emits `UNMAPPED_VENDOR_ADVISORY` (`CVE-UNMAPPED-<VENDOR>-<ID>`). `warrantd` immediately arms containment and holds execution at `UNMAPPED_FINDING_REQUIRES_CLASS_BINDING` unless the Standing Warrant explicitly authorizes that vendor detection ID in `authorized_vendor_detections`.

---

## 3. `WN-8` Outbound Distributor Configurations (15 Translators Across 6 Families)

Every `WN-8` translator implements `DistributorTranslator` (`internal/adapters/distributors/`):
- **Capabilities:**
  - `SupportsNativeRings = true`: Warrant passes its progressive ring definitions (`5% -> 25% -> 100%`) directly to the vendor's native ring/concurrency engine in a single `DeploymentOrder`.
  - `SupportsNativeRings = false`: Warrant's `N2` Wave Sequencer (`internal/gate/wave_sequencer.go`) deterministically slices `TargetAssets` into `5% -> 25% -> 100%` waves, gating each wave on `N2` OPA policy + active freeze state + per-wave failure/stall thresholds.
  - `ReportsPerAssetState = false` (`flux`): Classified honestly as `DISPATCH_ACK_ONLY` -> `ASSURANCE_TIER_0_DISTRIBUTOR_DISPATCH_ONLY` (`closure_completeness = DISPATCH_ONLY`), keeping the `N3` containment bridge **ARMED** until per-asset convergence is independently attested.
- **Symmetric Pre-Recorded Rollback:** Before Wave 1 dispatches, `NativeRollbackSpec` is persisted immutably in WORM `deployment_orders`. Any wave failure-rate breach, timeout stall, or operator `warrant distributors rollback <order-id>` invokes `ExecuteRollback`.

### Complete 15-Distributor Environment & API Route Matrix

| Family | Distributor ID | Environment Variables (`URL` / `Bearer Token`) | Native Rings | Per-Asset State | Dispatch API Route | Poll Result API Route | Native Rollback API Route |
| :--- | :--- | :--- | :---: | :---: | :--- | :--- | :--- |
| **1. Containers & GitOps** | `k8s-cilium-native` | `WARRANT_CLUSTER_DRIVER=kubernetes` + `WARRANT_KUBE_API_URL` / in-cluster SA | Yes | Yes | `PATCH /apis/apps/v1/namespaces/{ns}/deployments/{svc}` | `GET /api/v1/namespaces/{ns}/pods` (`imageID` digest sweep) | `PATCH` Deployment digest revert + `ValidatingAdmissionPolicy` |
| **1. Containers & GitOps** | `argocd` | `WARRANT_ARGOCD_URL` / `WARRANT_ARGOCD_TOKEN` | Yes | Yes | `POST /api/v1/applications/{service_id}/sync` | `GET /api/v1/applications/{service_id}?operation={ref}&order_id={id}` | `POST /api/v1/applications/{service_id}/rollback` |
| **1. Containers & GitOps** | `flux` | `WARRANT_FLUX_URL` / `WARRANT_FLUX_TOKEN` | No | **No** (`DISPATCH_ACK_ONLY`) | `POST /v1/flux/reconcile` | `GET /v1/flux/status?commit={ref}&order_id={id}` | `POST /v1/flux/revert` |
| **2. Microsoft Estate** | `ms-intune` | `WARRANT_MS_INTUNE_URL` (e.g. `https://graph.microsoft.com`) / `WARRANT_MS_INTUNE_TOKEN` | Yes | Yes (+ Reboot) | `POST /beta/deviceManagement/windowsQualityUpdateProfiles` | `GET /beta/deviceManagement/windowsQualityUpdateProfiles/{id}/deviceUpdateStates` | `POST /beta/deviceManagement/windowsQualityUpdateProfiles/{id}/uninstall` |
| **2. Microsoft Estate** | `ms-mecm` | `WARRANT_MS_MECM_URL` (SMS Provider host) / `WARRANT_MS_MECM_TOKEN` | Yes | Yes (+ Reboot) | `POST /AdminService/v1.0/SMS_UpdateGroupAssignment` | `GET /AdminService/v1.0/SMS_UpdateGroupAssignment/{id}/Compliance` | `POST /AdminService/v1.0/SMS_UpdateGroupAssignment/{id}/Rollback` (`wusa.exe /uninstall`) |
| **2. Microsoft Estate** | `ms-wsus` | `WARRANT_MS_WSUS_URL` / `WARRANT_MS_WSUS_TOKEN` | **No** (N2 Wave-Sliced) | Yes (+ Reboot) | `POST /wsus/v1/approvals` | `GET /wsus/v1/approvals/{id}/summaries` | `POST /wsus/v1/approvals/uninstall` (`wusa /uninstall /kb:...`) |
| **3. Linux Automation** | `ansible-awx` | `WARRANT_ANSIBLE_AWX_URL` / `WARRANT_ANSIBLE_AWX_TOKEN` | **No** (N2 Wave-Sliced) | Yes (+ Reboot) | `POST /api/v2/job_templates/patch/launch/` | `GET /api/v2/jobs/{id}/job_events/` | `POST /api/v2/job_templates/{rollback_playbook}/launch/` |
| **3. Linux Automation** | `redhat-satellite` | `WARRANT_REDHAT_SATELLITE_URL` / `WARRANT_REDHAT_SATELLITE_TOKEN` | **No** (N2 Wave-Sliced) | Yes (+ Reboot) | `POST /api/job_invocations` | `GET /api/job_invocations/{id}` | `POST /api/job_invocations/rollback` (`dnf history undo last -y`) |
| **4. Apple Estate** | `jamf-pro` | `WARRANT_JAMF_PRO_URL` / `WARRANT_JAMF_PRO_TOKEN` | **No** (N2 Wave-Sliced) | Yes (+ Reboot) | `POST /api/v2/patch-policies` | `GET /api/v2/patch-policies/{id}/logs` | `POST /api/v2/patch-policies/{id}/revert` |
| **5. Cloud Patchers** | `aws-ssm` | `WARRANT_AWS_SSM_URL` / `WARRANT_AWS_SSM_TOKEN` | Yes (`MaxConcurrency`) | Yes (`rc=194` Reboot) | `POST /ssm/SendCommand` (`AWS-RunPatchBaseline`) | `GET /ssm/ListCommandInvocations?CommandId={id}` | `POST /ssm/SendCommand` (`G1-RollbackPatchBaseline`) |
| **5. Cloud Patchers** | `azure-update-manager` | `WARRANT_AZURE_UPDATE_URL` / `WARRANT_AZURE_UPDATE_TOKEN` | Yes | Yes (+ Reboot) | `POST /azure/update-manager/installPatches` | `GET /azure/update-manager/operations/{id}` | `POST /azure/update-manager/rollback` |
| **5. Cloud Patchers** | `gcp-os-config` | `WARRANT_GCP_OSCONFIG_URL` / `WARRANT_GCP_OSCONFIG_TOKEN` | Yes | Yes (+ Reboot) | `POST /v1/projects/default/patchJobs:execute` | `GET /v1/projects/default/patchJobs/{id}/instanceDetails` | `POST /v1/projects/default/patchJobs:rollback` |
| **6. Multi-Platform** | `tanium-patch` | `WARRANT_TANIUM_URL` / `WARRANT_TANIUM_TOKEN` | Yes | Yes (+ Reboot) | `POST /plugin/products/patch/v2/deployments` | `GET /plugin/products/patch/v2/deployments/{id}/endpoints` | `POST /plugin/products/patch/v2/deployments/rollback` |
| **6. Multi-Platform** | `ivanti-neurons` | `WARRANT_IVANTI_URL` / `WARRANT_IVANTI_TOKEN` | Yes | Yes (+ Reboot) | `POST /api/patch/v1/deployments` | `GET /api/patch/v1/deployments/{id}/devices` | `POST /api/patch/v1/deployments/rollback` |
| **6. Multi-Platform** | `automox` | `WARRANT_AUTOMOX_URL` / `WARRANT_AUTOMOX_TOKEN` | **No** (N2 Wave-Sliced) | Yes (+ Reboot) | `POST /api/policies/execute` | `GET /api/events?job_ref={id}` | `POST /api/worklets/rollback` |

### Verifying Registered Translators & Per-Order Closure State

```bash
# List all 15 registered WN-8 translators and their declared capabilities
./warrant distributors list

# Inspect WORM deployment_orders (including pre-recorded rollback_instruction) and per-asset deployment_results
./warrant distributors orders --remediation <remediation-id>
./warrant distributors results --order <order-id>

# Trigger symmetric 1-of-2 DSSE-authenticated native rollback on an active order
./warrant distributors rollback <order-id> --key so-key.priv.json --reason OPERATOR_CHANGE_FREEZE
```
