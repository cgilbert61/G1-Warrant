package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/adapters/vmtwins"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/extractor"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/gate"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/server"
	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestInvariant19_NonDockerVMTwinProvidersHyperVAWSGCPAzure verifies all 4 non-Docker VM_TWIN QA Clone Proving drivers:
//  1. Hyper-V (`hyperv`): 3 Differencing-VHDX Gen2 clones on Private switch + PowerShell Direct reboot + guaranteed teardown.
//  2. AWS EC2 (`aws-ec2`): 3 QA AMI clones in zero-egress Security Group + SSM reboot/prove + TerminateInstances teardown.
//  3. Azure Compute (`azure-vm`): 3 QA Image clones behind Deny-Egress NSG + RunCommand reboot/prove + forceDeletion teardown.
//  4. GCP Compute Engine (`gcp-gce`): 3 QA Machine Image clones with zero external IP + OS Config reboot/prove + instance teardown.
//  5. End-to-end KERNEL patch (`kernel-core-6.8.0-45.el9.x86_64`) + non-Docker Windows KB (`KB5039212` via WARRANT_VM_TWIN_SERVICES)
//     closing through N3 -> OPA verify_closure.rego -> N5 OSCAL 1.1.2 POA&M (`twin-runtime = VM_TWIN`), plus fail-closed rejection
//     with guaranteed VM teardown when a clone fails post-reboot acceptance.
func TestInvariant19_NonDockerVMTwinProvidersHyperVAWSGCPAzure(t *testing.T) {
	ctx := context.Background()

	var mu sync.Mutex
	hypervCreated, hypervDeleted := 0, 0
	awsLaunched, awsTerminated := 0, 0
	azureCreated, azureDeleted := 0, 0
	gcpCreated, gcpDeleted := 0, 0
	failThirdClone := false

	mockVMFabric := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify N4 governed wire headers or Bearer auth when wired through orchestrator
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		mu.Lock()
		shouldFail := failThirdClone
		mu.Unlock()

		makeOutcomes := func(prefix, host string) []map[string]any {
			out := make([]map[string]any, 0, 3)
			for i := 0; i < 3; i++ {
				accOK := !(shouldFail && i == 2)
				exitCode := 0
				if !accOK {
					exitCode = 1
				}
				out = append(out, map[string]any{
					"clone_index":             i,
					"clone_name":              fmt.Sprintf("%s-%d", prefix, i),
					"host_or_zone":            host,
					"private_ip":              fmt.Sprintf("10.254.0.%d", 10+i),
					"booted_kernel_or_build":  "6.8.0-45.el9.x86_64",
					"reboot_verified":         true,
					"service_up_passed":       true,
					"smoke_test_passed":       true,
					"class_acceptance_passed": accOK,
					"observed_latency_ms":     18.4,
					"exit_code":               exitCode,
					"raw_log":                 "QA clone patched, rebooted, and verified in zero-egress enclave",
				})
			}
			return out
		}

		path := r.URL.Path
		switch {
		// 1. Hyper-V Agent routes
		case r.Method == http.MethodPost && path == "/v1/hyperv/clones":
			mu.Lock()
			hypervCreated += 3
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"host_name": "HV-QA-HOST-01",
				"vm_names":  []string{"g1-hv-clone-0", "g1-hv-clone-1", "g1-hv-clone-2"},
			})
		case r.Method == http.MethodPost && path == "/v1/hyperv/prove":
			_ = json.NewEncoder(w).Encode(map[string]any{"clones": makeOutcomes("g1-hv-clone", "HV-QA-HOST-01")})
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "/v1/hyperv/clones/"):
			mu.Lock()
			hypervDeleted += 3
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})

		// 2. AWS EC2 + SSM routes
		case r.Method == http.MethodPost && path == "/ec2/RunInstances":
			mu.Lock()
			awsLaunched += 3
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Instances": []map[string]any{
					{"InstanceId": "i-twin0001", "PrivateIpAddress": "10.254.1.10", "AvailabilityZone": "us-gov-west-1a"},
					{"InstanceId": "i-twin0002", "PrivateIpAddress": "10.254.1.11", "AvailabilityZone": "us-gov-west-1b"},
					{"InstanceId": "i-twin0003", "PrivateIpAddress": "10.254.1.12", "AvailabilityZone": "us-gov-west-1c"},
				},
			})
		case r.Method == http.MethodPost && path == "/ssm/SendCommand":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"CommandId": "cmd-aws-twin-01",
				"Clones":    makeOutcomes("i-twin", "us-gov-west-1a"),
			})
		case r.Method == http.MethodPost && path == "/ec2/TerminateInstances":
			mu.Lock()
			awsTerminated += 3
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"TerminatingInstances": 3})

		// 3. Azure Compute routes
		case r.Method == http.MethodPut && strings.Contains(path, "/providers/Microsoft.Compute/virtualMachines/"):
			mu.Lock()
			azureCreated++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"provisioningState": "Succeeded"})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/runCommand"):
			var reqBody struct {
				CloneIndex int `json:"clone_index"`
			}
			_ = json.NewDecoder(r.Body).Decode(&reqBody)
			ocs := makeOutcomes("g1-az-twin", "usgovvirginia-1")
			_ = json.NewEncoder(w).Encode(ocs[reqBody.CloneIndex])
		case r.Method == http.MethodDelete && strings.Contains(path, "/providers/Microsoft.Compute/virtualMachines/"):
			mu.Lock()
			azureDeleted++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})

		// 4. GCP Compute Engine + OS Config routes
		case r.Method == http.MethodPost && strings.Contains(path, "/compute/v1/projects/") && strings.HasSuffix(path, "/instances"):
			mu.Lock()
			gcpCreated++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "RUNNING"})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/patchJobs:execute"):
			_ = json.NewEncoder(w).Encode(map[string]any{"clones": makeOutcomes("g1-gcp-twin", "us-east4-a")})
		case r.Method == http.MethodDelete && strings.Contains(path, "/compute/v1/projects/"):
			mu.Lock()
			gcpDeleted++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "DONE"})

		default:
			http.Error(w, "unexpected route "+path, http.StatusNotFound)
		}
	}))
	defer mockVMFabric.Close()

	// Part A: Exercise AWS EC2, Azure Compute, and GCP Compute Engine VMTwinProviders directly
	envMap := map[string]string{
		"WARRANT_AWS_TWIN_URL":              mockVMFabric.URL,
		"WARRANT_AWS_TWIN_TOKEN":            "aws-tok-v130",
		"WARRANT_AWS_TWIN_AMI_ID":           "ami-0qa99887766554433",
		"WARRANT_AWS_TWIN_SUBNET_ID":        "subnet-isolated01",
		"WARRANT_AWS_TWIN_ISOLATED_SG_ID":   "sg-zeroegress01",
		"WARRANT_AZURE_TWIN_URL":            mockVMFabric.URL,
		"WARRANT_AZURE_TWIN_TOKEN":          "az-tok-v130",
		"WARRANT_AZURE_TWIN_SUBSCRIPTION_ID": "sub-gov-001",
		"WARRANT_AZURE_TWIN_RESOURCE_GROUP": "rg-qa-twins",
		"WARRANT_AZURE_TWIN_IMAGE_ID":       "/subscriptions/sub-gov-001/images/qa-win2022",
		"WARRANT_AZURE_TWIN_SUBNET_ID":      "subnet-az-isolated",
		"WARRANT_AZURE_TWIN_NSG_ID":         "nsg-deny-egress",
		"WARRANT_GCP_TWIN_URL":              mockVMFabric.URL,
		"WARRANT_GCP_TWIN_TOKEN":            "gcp-tok-v130",
		"WARRANT_GCP_TWIN_PROJECT":          "gov-sec-qa",
		"WARRANT_GCP_TWIN_ZONE":             "us-east4-a",
		"WARRANT_GCP_TWIN_MACHINE_IMAGE":    "projects/gov-sec-qa/global/machineImages/qa-rhel9",
		"WARRANT_GCP_TWIN_SUBNET":           "regions/us-east4/subnetworks/isolated-twin",
	}
	for _, drv := range []string{vmtwins.DriverAWSEC2, vmtwins.DriverAzureVM, vmtwins.DriverGCPGCE} {
		envMap["WARRANT_VM_TWIN_DRIVER"] = drv
		prov, err := vmtwins.NewVMTwinProviderFromEnv(nil, func(k string) string { return envMap[k] })
		if err != nil || prov == nil {
			t.Fatalf("NewVMTwinProviderFromEnv(%s): %v", drv, err)
		}
		m, err := prov.RunVMTwinProving(ctx, adapters.CloneTwinProvingRequest{
			RemediationID:    "rem-" + drv,
			ServiceID:        "payments-ledger-api",
			WarrantID:        "wrt-vm-01",
			WarrantClass:     "KEV-TIER1-STATELESS",
			CVEID:            "CVE-2026-95001",
			CandidateDigest:  "sha256:9999999999999999999999999999999999999999999999999999999999999999",
			PackageNEVRA:     "kernel-core-6.8.0-45.el9.x86_64",
			PatchTargetLayer: models.PatchTargetLayerKernel,
			CloneCount:       3,
			MaxP99LatencyMs:  120.0,
		})
		if err != nil {
			t.Fatalf("RunVMTwinProving(%s) failed: %v", drv, err)
		}
		if m.TwinRuntime != models.TwinRuntimeVM || m.CloneCount != 3 || !m.AllPassed || !m.ZeroProductionEgress {
			t.Fatalf("unexpected manifest for %s: %+v", drv, m)
		}
	}
	if awsLaunched != 3 || awsTerminated != 3 || azureCreated != 3 || azureDeleted != 3 || gcpCreated != 3 || gcpDeleted != 3 {
		t.Fatalf("expected all cloud VM clones created=3 and torn down=3: aws=%d/%d azure=%d/%d gcp=%d/%d",
			awsLaunched, awsTerminated, azureCreated, azureDeleted, gcpCreated, gcpDeleted)
	}

	// Part B: Full End-to-End Orchestrator Flow with Hyper-V VM_TWIN Driver (KERNEL patch + Windows KB on VM service + fail-closed teardown)
	adminDSN := os.Getenv("TEST_DATABASE_URL")
	if adminDSN == "" {
		adminDSN = os.Getenv("DATABASE_URL")
	}
	if adminDSN == "" {
		adminDSN = "postgres://warrant:warrant@localhost:5432/postgres?sslmode=disable"
	}
	adminConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Skipf("PostgreSQL not reachable (%v)", err)
	}
	dbName := "warrant_inv19_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, dbName)); err != nil {
		_ = adminConn.Close(ctx)
		t.Fatalf("create test db: %v", err)
	}
	_ = adminConn.Close(ctx)
	t.Cleanup(func() {
		c, cErr := pgx.Connect(context.Background(), adminDSN)
		if cErr == nil {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, dbName))
			_ = c.Close(context.Background())
		}
	})

	intakeTok := "g1int_inv19_vm_twin_tok"
	adminTok := "g1adm_inv19_vm_twin_admin"
	t.Setenv("WARRANT_ENABLE_TEST_SMARTCARDS", "false")
	t.Setenv("WARRANT_INTAKE_TOKEN", intakeTok)
	t.Setenv("WARRANT_BOOTSTRAP_ADMIN_TOKEN", adminTok)
	t.Setenv("WARRANT_VM_TWIN_DRIVER", "hyperv")
	t.Setenv("WARRANT_HYPERV_AGENT_URL", mockVMFabric.URL)
	t.Setenv("WARRANT_HYPERV_AGENT_TOKEN", "hv-tok-inv19")
	t.Setenv("WARRANT_HYPERV_QA_PARENT_VHDX", `D:\HyperV\Golden\win2022-qa-base.vhdx`)
	t.Setenv("WARRANT_HYPERV_ISOLATED_SWITCH", "g1-twin-proving-private")
	t.Setenv("WARRANT_VM_TWIN_SERVICES", "win-pay-01")

	store, err := db.NewStore(ctx, replaceDBName(adminDSN, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-extractor-inv19"))
	defer extSrv.Close()
	sim := fleetsim.NewClusterSimulator()
	simSrv := httptest.NewServer(sim.Handler())
	defer simSrv.Close()

	orch, err := server.NewOrchestrator(ctx, store, extSrv.URL, simSrv.URL, "inv19-hyperv-seed", crypto.DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("NewOrchestrator with Hyper-V VM_TWIN: %v", err)
	}
	httpSrv := httptest.NewServer(orch.BuildHTTPHandler())
	defer httpSrv.Close()

	svc := models.EstateService{
		ServiceID:                  "payments-ledger-api",
		DisplayName:                "Windows/RHEL Hybrid Payments Service",
		Namespace:                  "fin-core",
		Tier:                       "TIER_1_MISSION_CRITICAL",
		WarrantClass:               "KEV-TIER1-STATELESS",
		CurrentDigest:              "sha256:a100000000000000000000000000000000000000000000000000000000000001",
		CurrentPURL:                "pkg:oci/payments-ledger-api@sha256:a100000000000000000000000000000000000000000000000000000000000001",
		Replicas:                   4,
		TestCoveragePct:            93.0,
		OtelHealthProbes:           true,
		ReadonlyShadowReplica:      true,
		RollbackAutomationVerified: true,
		ReadOnlyRootFilesystem:     true,
		NoExecTmpMounts:            true,
		BaselineSyscalls:           []string{"read", "write", "futex"},
	}
	gate.GradeServiceReadiness(&svc)
	if err := store.UpsertEstateService(ctx, svc); err != nil {
		t.Fatal(err)
	}

	soBundle, _ := warrantsdk.GenerateEd25519SignerBundle("usr-inv19-so", "so@agency.gov", "Inv19 SO", warrantsdk.RoleServiceOwner)
	aoBundle, _ := warrantsdk.GenerateEd25519SignerBundle("usr-inv19-ao", "ao@agency.gov", "Inv19 AO", warrantsdk.RoleAuthorizingOfficial)
	adminCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithAdminToken(adminTok))
	_, _ = adminCli.RegisterPrincipal(ctx, soBundle.ToRegisterRequest())
	_, _ = adminCli.RegisterPrincipal(ctx, aoBundle.ToRegisterRequest())

	wEnv, _, _ := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:              "wrt-inv19-hyperv",
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          []string{"payments-ledger-api"},
		ScopeAssets:            []string{"payments-ledger-api", "win-pay-01"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 8,
		SLABridgeMinutes:       60,
		MaxP99LatencyMs:        120.0,
		TTLDays:                30,
	})
	_ = soBundle.SignEnvelope(1, wEnv)
	_ = aoBundle.SignEnvelope(2, wEnv)
	if _, err := adminCli.CreateWarrant(ctx, *wEnv); err != nil {
		t.Fatalf("CreateWarrant: %v", err)
	}

	intakeCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithIntakeToken(intakeTok))
	qualysKernel := []byte(`{
		"hosts": [{
			"service_id": "payments-ledger-api",
			"asset_key": "win-pay-01",
			"detections": [
				{"qid": 379910, "severity": 5, "cvss3_base": 9.6, "status": "Active", "cisa_kev": true, "cves": ["CVE-2026-95101"]},
				{"qid": 379911, "severity": 5, "cvss3_base": 8.8, "status": "Active", "cisa_kev": true, "cves": ["CVE-2026-95102"]}
			]
		}]
	}`)
	items, err := intakeCli.SubmitFinderIntake(ctx, "qualys", qualysKernel, warrantsdk.FinderIntakeOptions{
		PatchProfile: "UPSTREAM_VENDOR_PENDING",
	})
	if err != nil || len(items) != 2 {
		t.Fatalf("IngestFinderPayload: err=%v items=%+v", err, items)
	}

	// 1. Dispatch KERNEL patch (`kernel-core-6.8.0-45.el9.x86_64`) -> proves on 3 Hyper-V Differencing-VHDX VM clones and closes!
	soCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithSignerBundle(soBundle))
	dispRes, err := soCli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: items[0].RemediationID,
		DistributorID: warrantsdk.DistributorAnsibleAWX,
		FixIdentity: &warrantsdk.FixIdentity{
			CVEID:        "CVE-2026-95101",
			PackageNEVRA: "kernel-core-6.8.0-45.el9.x86_64",
		},
		TargetAssets: []warrantsdk.AssetTarget{{AssetKey: "win-pay-01", ServiceID: "payments-ledger-api"}},
	})
	if err != nil {
		t.Fatalf("expected KERNEL patch to succeed with Hyper-V VM_TWIN registered, got: %v", err)
	}
	if dispRes.Remediation.Stage != models.StageAttestedClosed ||
		dispRes.Remediation.CloneTwinProving == nil ||
		dispRes.Remediation.CloneTwinProving.TwinRuntime != models.TwinRuntimeVM ||
		dispRes.Remediation.CloneTwinProving.PatchTargetLayer != models.PatchTargetLayerKernel ||
		dispRes.Remediation.CloneTwinProving.CloneCount != 3 ||
		!dispRes.Remediation.CloneTwinProving.AllPassed {
		t.Fatalf("expected ATTESTED_CLOSED with 3-clone VM_TWIN manifest, got: %+v", dispRes.Remediation)
	}
	oscalRaw, err := soCli.ExportOSCALBundle(ctx, dispRes.Remediation.AttestationID)
	if err != nil || !strings.Contains(string(oscalRaw), "VM_TWIN") || !strings.Contains(string(oscalRaw), "hyperv://g1-twin-proving-private") {
		t.Fatalf("expected OSCAL bundle to record VM_TWIN + hyperv://g1-twin-proving-private, err=%v raw=%s", err, string(oscalRaw))
	}

	// 2. Inject failure on Clone #2 during post-reboot acceptance on Windows KB -> fail closed & tear down all 3 Hyper-V VMs!
	mu.Lock()
	failThirdClone = true
	mu.Unlock()

	_, failErr := soCli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: items[1].RemediationID,
		DistributorID: warrantsdk.DistributorMSIntune,
		FixIdentity: &warrantsdk.FixIdentity{
			CVEID:       "CVE-2026-95102",
			KBArticleID: "KB5039212",
		},
		TargetAssets: []warrantsdk.AssetTarget{{AssetKey: "win-pay-01", ServiceID: "payments-ledger-api"}},
	})
	if failErr == nil || !strings.Contains(failErr.Error(), "NO_PROOF_NO_DEPLOYMENT_ORDER") {
		t.Fatalf("expected NO_PROOF_NO_DEPLOYMENT_ORDER when Hyper-V clone #2 fails acceptance, got: %v", failErr)
	}
	orders, _ := soCli.ListDeploymentOrders(ctx, items[1].RemediationID)
	if len(orders) != 0 {
		t.Fatalf("expected 0 DeploymentOrders created after failed VM_TWIN proving, got %d", len(orders))
	}

	mu.Lock()
	defer mu.Unlock()
	if hypervCreated != 6 || hypervDeleted != 6 {
		t.Fatalf("expected all 6 Hyper-V clones (2 runs x 3 VMs) torn down cleanly, got created=%d deleted=%d", hypervCreated, hypervDeleted)
	}
}
