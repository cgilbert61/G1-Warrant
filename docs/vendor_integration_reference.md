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

---

## 3. Non-Docker `VM_TWIN` QA Clone Proving Ground (`Hyper-V`, `AWS EC2`, `Azure`, `GCP`)

When patching non-container estates (Windows `.msu` KBs, RHEL/Ubuntu `.rpm`/`.deb` packages on services listed in `WARRANT_VM_TWIN_SERVICES`) or **`KERNEL` / `BOOT_LAYER`** packages (`kernel-core-*`, `linux-image-*`, `grub2`, `shim-*`), container twins are insufficient because containers share the host kernel and cannot execute real OS reboots.

Configure `WARRANT_VM_TWIN_DRIVER` (`hyperv` | `aws-ec2` | `azure-vm` | `gcp-gce`) to spin up **3 isolated QA VM clones** (`zero_production_egress = true`), apply the candidate patch, reboot, verify **(a)** services-up, **(b)** QA smoke tests, and **(c)** Standing Warrant class acceptance checks, and guarantee clone deletion in `defer`:

| Driver (`WARRANT_VM_TWIN_DRIVER`) | Auth & Wire Protocol | Clone Mechanism | Zero-Egress Isolation Boundary | Out-of-Band Patch, Reboot & Teardown |
| :--- | :--- | :--- | :--- | :--- |
| **`hyperv`** (`scripts/hyperv_vm_twin_agent.ps1`) | Bearer token over loopback/mTLS (`Hyper-V Administrators` group) | 3 Copy-on-Write Differencing `.vhdx` VMs (`New-VHD -Differencing`, `Set-VMFirmware` Windows/Linux UEFI) | Hyper-V `Private` Virtual Switch (`g1-twin-proving-private` — zero physical NIC/LAN/internet) | `Copy-VMFile` + PowerShell Direct (`Invoke-Command -VMName`) + `Restart-VM -Wait -For Heartbeat` + `Stop-VM`/`Remove-VM`/delete `.vhdx` |
| **`aws-ec2`** (`internal/adapters/vmtwins/aws_ec2.go`) | Pure-Go **AWS SigV4 (`AWS4-HMAC-SHA256`)** (`EC2` XML `2016-11-15` + `SSM` JSON-RPC 1.1) | `Action=RunInstances` (`MinCount=3`, `AssociatePublicIpAddress=false`) + `Action=DescribeInstances` poll | Dedicated subnet + zero-egress Security Group (`WARRANT_AWS_TWIN_ISOLATED_SG_ID`, VPC SSM endpoints only) | `AmazonSSM.SendCommand` (`AWS-RunShellScript` / `AWS-RunPowerShellScript` `exit 194`/`3010` reboot) + `GetCommandInvocation` poll + `Action=TerminateInstances` |
| **`azure-vm`** (`internal/adapters/vmtwins/azure_vm.go`) | **Entra ID OAuth2** (`/{tenant}/oauth2/v2.0/token`, Commercial & US Gov) + ARM `2024-03-01` | `PUT .../networkInterfaces` (`2023-11-01`) + `PUT .../virtualMachines` (`deleteOption=Delete`) + `202` `Azure-AsyncOperation` LRO poll | Zero `publicIPAddress` + deny-all outbound `NSG` (`WARRANT_AZURE_TWIN_NSG_ID`) | `POST .../runCommand` (stage) + `POST .../restart` + `POST .../runCommand` (post-reboot `value[0].message`) + `DELETE ?forceDeletion=true` |
| **`gcp-gce`** (`internal/adapters/vmtwins/gcp_gce.go`) | **Service Account RS256 JWT** (`jwt-bearer`) or GCE Metadata Server + Compute Engine v1 | `POST .../zones/{zone}/instances` (`sourceMachineImage` / `sourceImage`) + Zone `operations` poll | `accessConfigs=[]` (zero external IP) + isolated VPC firewall tag (`WARRANT_GCP_TWIN_ISOLATED_TAG`) | Two-phase boot-persistent `startup-script` / `windows-startup-script-ps1` + `GET .../serialPort?port=1` (`G1_CLONE_RESULT=`) + `DELETE .../instances/{vm}` |

### One-Command AWS Proving Enclave Stack (`deploy/aws/vm_twin_proving_enclave.cfn.yaml`)

Because `aws-ec2` clones launch with `AssociatePublicIpAddress=false` and zero internet/NAT egress, `amazon-ssm-agent` inside the clones communicates exclusively over **AWS PrivateLink VPC Interface Endpoints** (`ssm`, `ssmmessages`, `ec2messages`) plus an optional regional **S3 Gateway Endpoint** for offline OS package mirrors. Deploy the complete isolated proving enclave + guest SSM Instance Profile + least-privilege `warrantd` IAM policy in one command:

```bash
export AWS_REGION="us-east-1"   # or us-gov-west-1
S3_PL=$(aws ec2 describe-prefix-lists --region "$AWS_REGION" \
  --filters "Name=prefix-list-name,Values=com.amazonaws.${AWS_REGION}.s3" \
  --query "PrefixLists[0].PrefixListId" --output text)

aws cloudformation deploy \
  --region "$AWS_REGION" \
  --stack-name g1-warrant-vm-twin-enclave \
  --template-file deploy/aws/vm_twin_proving_enclave.cfn.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides S3ManagedPrefixListId="$S3_PL"

# Print exact WARRANT_AWS_* values from CloudFormation stack outputs:
aws cloudformation describe-stacks \
  --region "$AWS_REGION" \
  --stack-name g1-warrant-vm-twin-enclave \
  --query "Stacks[0].Outputs" --output table
```

Attach the output `WarrantControllerPolicyArn` to an IAM Role (recommended: assume via short-lived STS `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`) and pass `WARRANT_VM_TWIN_DRIVER=aws-ec2` plus the 4 output IDs (`WARRANT_AWS_REGION`, `WARRANT_AWS_TWIN_AMI_ID`, `WARRANT_AWS_TWIN_SUBNET_ID`, `WARRANT_AWS_TWIN_ISOLATED_SG_ID`, `WARRANT_AWS_TWIN_IAM_INSTANCE_PROFILE`) to `warrantd`.

### Granting Local Windows Hyper-V Rights (No Full Admin Needed After One-Time Grant)

```powershell
# 1. Run ONCE in an elevated ("Run as Administrator") PowerShell window:
Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "$env:USERDOMAIN\$env:USERNAME"
# (Sign out/in of Windows or restart your terminal/IDE so your user token acquires the Hyper-V Administrators SID.)

# 2. Start the local Hyper-V VM_TWIN Agent pointing at your read-only QA base VHDX:
$env:WARRANT_HYPERV_AGENT_TOKEN = "hv-secret-$([guid]::NewGuid().ToString('N'))"
powershell -ExecutionPolicy Bypass -File .\scripts\hyperv_vm_twin_agent.ps1 -ListenPrefix "http://127.0.0.1:8099/"
```

> **Proof Fence (`VM_TWIN` Drivers):** All 4 `VM_TWIN` drivers (`hyperv`, `aws-ec2`, `azure-vm`, `gcp-gce`) are verified end-to-end against wire-level HTTP harnesses, `N4` bearer/PoP headers, OPA `verify_closure.rego`, OSCAL `1.1.2` attestation minting, and fail-closed teardown in `TestInvariant19_NonDockerVMTwinProvidersHyperVAWSGCPAzure`; live execution against an elevated Hyper-V `vmms` administrator session with a golden QA `.vhdx` or live AWS/Azure/GCP cloud credentials has not yet been run in this environment. When `WARRANT_VM_TWIN_DRIVER` is unset, `KERNEL` and `BOOT_LAYER` patches fail closed with `KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME`.

