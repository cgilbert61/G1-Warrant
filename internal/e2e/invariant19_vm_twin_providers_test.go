package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// TestInvariant19_NonDockerVMTwinProvidersHyperVAWSGCPAzure verifies the real wire protocols of all 4 VM_TWIN drivers:
//  1. AWS EC2 + SSM (`aws-ec2`): AWS4-HMAC-SHA256 SigV4 signing, EC2 2016-11-15 XML RunInstances/DescribeInstances/TerminateInstances,
//     and SSM JSON-RPC 1.1 (`AmazonSSM.SendCommand` + `AmazonSSM.GetCommandInvocation` across `Delayed` reboot -> `Success`).
//  2. Azure ARM (`azure-vm`): Entra ID OAuth2 Client-Credentials token exchange, NIC + VM PUT (`deleteOption=Delete`),
//     HTTP 202 `Azure-AsyncOperation` LRO polling, `runCommand` + `restart` + post-reboot `runCommand` `value[0].message`, and `forceDeletion=true`.
//  3. GCP Compute Engine (`gcp-gce`): Service Account RS256 JWT assertion -> OAuth2 token exchange, `instances.insert` (`accessConfigs=[]`),
//     Zone `operations` polling, `serialPort?port=1` `G1_CLONE_RESULT=` parsing across reboot, and `instances.delete`.
//  4. Hyper-V (`hyperv`): End-to-end orchestrator execution of KERNEL patch (`kernel-core-6.8.0-45.el9.x86_64`) -> OSCAL 1.1.2 `VM_TWIN`
//     closure, plus fail-closed `NO_PROOF_NO_DEPLOYMENT_ORDER` and guaranteed 3-VM teardown when a clone fails post-reboot acceptance.
func TestInvariant19_NonDockerVMTwinProvidersHyperVAWSGCPAzure(t *testing.T) {
	ctx := context.Background()

	// Generate ephemeral RSA-2048 keypair for real GCP Service Account RS256 JWT signing test
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes}))

	var mu sync.Mutex
	hypervCreated, hypervDeleted := 0, 0
	awsLaunched, awsDescribed, awsTerminated, awsSendWarmup := 0, 0, 0, 0
	ssmPollCount := map[string]int{}
	azureOAuthCalls, azureNICsCreated, azureVMsCreated, azureRestarts, azureVMsDeleted, azureLROPolls := 0, 0, 0, 0, 0, 0
	azureRunCmdCount := map[string]int{}
	gcpJWTExchanges, gcpCreated, gcpZoneOpPolls, gcpDeleted := 0, 0, 0, 0
	gcpSerialPolls := map[string]int{}
	failThirdClone := false

	var srvURL string
	mockVMFabric := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ := io.ReadAll(r.Body)
		path := r.URL.Path

		mu.Lock()
		shouldFail := failThirdClone
		mu.Unlock()

		resultMarkerLine := func(fail bool) string {
			acc := "true"
			ec := 0
			if fail {
				acc = "false"
				ec = 1
			}
			return fmt.Sprintf(`G1_CLONE_RESULT={"booted_kernel_or_build":"6.8.0-45.el9.x86_64","reboot_verified":true,"service_up_passed":true,"smoke_test_passed":true,"class_acceptance_passed":%s,"observed_latency_ms":16.5,"exit_code":%d}`, acc, ec)
		}

		// -----------------------------------------------------------------
		// A. AWS EC2 (XML Query + SigV4) & AWS SSM (JSON-RPC 1.1 + SigV4)
		// -----------------------------------------------------------------
		if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			if r.Header.Get("X-Amz-Date") == "" || r.Header.Get("X-Amz-Content-Sha256") == "" {
				http.Error(w, "missing SigV4 X-Amz headers", http.StatusBadRequest)
				return
			}
			if amzTarget := r.Header.Get("X-Amz-Target"); amzTarget != "" {
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				switch amzTarget {
				case "AmazonSSM.SendCommand":
					mu.Lock()
					awsSendWarmup++
					wc := awsSendWarmup
					mu.Unlock()
					if wc == 1 {
						w.WriteHeader(http.StatusBadRequest)
						_ = json.NewEncoder(w).Encode(map[string]any{
							"__type":  "InvalidInstanceId",
							"message": "Instances [[i-0aa111]] not yet registered in SSM Fleet Manager",
						})
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"Command": map[string]any{"CommandId": "cmd-sigv4-001"},
					})
				case "AmazonSSM.GetCommandInvocation":
					var reqObj struct {
						InstanceID string `json:"InstanceId"`
					}
					_ = json.Unmarshal(rawBody, &reqObj)
					mu.Lock()
					ssmPollCount[reqObj.InstanceID]++
					cnt := ssmPollCount[reqObj.InstanceID]
					mu.Unlock()
					if cnt == 1 {
						// Simulate real SSM exit-194 reboot state before final convergence
						_ = json.NewEncoder(w).Encode(map[string]any{"Status": "Delayed", "ResponseCode": 194})
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"Status":                "Success",
						"ResponseCode":          0,
						"StandardOutputContent": "[ssm] reboot complete\n" + resultMarkerLine(false) + "\n",
					})
				default:
					http.Error(w, "unknown SSM target "+amzTarget, http.StatusBadRequest)
				}
				return
			}

			vals, _ := url.ParseQuery(string(rawBody))
			w.Header().Set("Content-Type", "text/xml")
			switch vals.Get("Action") {
			case "RunInstances":
				if vals.Get("NetworkInterface.1.AssociatePublicIpAddress") != "false" {
					http.Error(w, "expected AssociatePublicIpAddress=false", http.StatusBadRequest)
					return
				}
				if vals.Get("InstanceInitiatedShutdownBehavior") != "terminate" {
					http.Error(w, "expected InstanceInitiatedShutdownBehavior=terminate", http.StatusBadRequest)
					return
				}
				mu.Lock()
				awsLaunched += 3
				mu.Unlock()
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<RunInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <instancesSet>
    <item><instanceId>i-0aa111</instanceId><privateIpAddress>10.254.1.10</privateIpAddress><placement><availabilityZone>us-gov-west-1a</availabilityZone></placement></item>
    <item><instanceId>i-0aa222</instanceId><privateIpAddress>10.254.1.11</privateIpAddress><placement><availabilityZone>us-gov-west-1b</availabilityZone></placement></item>
    <item><instanceId>i-0aa333</instanceId><privateIpAddress>10.254.1.12</privateIpAddress><placement><availabilityZone>us-gov-west-1c</availabilityZone></placement></item>
  </instancesSet>
</RunInstancesResponse>`))
			case "DescribeInstances":
				mu.Lock()
				awsDescribed++
				mu.Unlock()
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet><item><instancesSet>
    <item><instanceId>i-0aa111</instanceId><instanceState><name>running</name></instanceState></item>
    <item><instanceId>i-0aa222</instanceId><instanceState><name>running</name></instanceState></item>
    <item><instanceId>i-0aa333</instanceId><instanceState><name>running</name></instanceState></item>
  </instancesSet></item></reservationSet>
</DescribeInstancesResponse>`))
			case "TerminateInstances":
				mu.Lock()
				awsTerminated += 3
				mu.Unlock()
				_, _ = w.Write([]byte(`<TerminateInstancesResponse/>`))
			default:
				http.Error(w, "unknown EC2 Action "+vals.Get("Action"), http.StatusBadRequest)
			}
			return
		}

		// -----------------------------------------------------------------
		// B. Azure Entra ID OAuth2 + GCP Service Account JWT OAuth2
		// -----------------------------------------------------------------
		if r.Method == http.MethodPost && strings.HasSuffix(path, "/oauth2/v2.0/token") {
			mu.Lock()
			azureOAuthCalls++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "az-oauth-jwt-tok", "expires_in": 3600})
			return
		}
		if r.Method == http.MethodPost && path == "/gcp/oauth2/token" {
			vals, _ := url.ParseQuery(string(rawBody))
			if vals.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || strings.Count(vals.Get("assertion"), ".") != 2 {
				http.Error(w, "invalid GCP JWT assertion", http.StatusBadRequest)
				return
			}
			mu.Lock()
			gcpJWTExchanges++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "gcp-sa-oauth-tok", "expires_in": 3600})
			return
		}

		// Require Bearer token on all ARM / GCE / Hyper-V resource routes
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "missing Bearer token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		// -----------------------------------------------------------------
		// C. Azure ARM (NIC + VM + 202 LRO + restart + runCommand + DELETE)
		// -----------------------------------------------------------------
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/azure-lro/"):
			mu.Lock()
			azureLROPolls++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "Succeeded"})
		case r.Method == http.MethodGet && strings.HasPrefix(path, "/azure-run-output/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{{
					"code":    "ComponentStatus/StdOut/succeeded",
					"message": "[azure] post-reboot check\n" + resultMarkerLine(false),
				}},
			})
		case r.Method == http.MethodPut && strings.Contains(path, "/providers/Microsoft.Network/networkInterfaces/"):
			mu.Lock()
			azureNICsCreated++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"properties": map[string]any{"provisioningState": "Succeeded"}})
		case r.Method == http.MethodPut && strings.Contains(path, "/providers/Microsoft.Compute/virtualMachines/"):
			mu.Lock()
			azureVMsCreated++
			mu.Unlock()
			w.Header().Set("Azure-AsyncOperation", srvURL+"/azure-lro/vm-create")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"properties": map[string]any{"provisioningState": "Creating"}})
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/restart"):
			mu.Lock()
			azureRestarts++
			mu.Unlock()
			w.Header().Set("Azure-AsyncOperation", srvURL+"/azure-lro/vm-restart")
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/runCommand"):
			mu.Lock()
			azureRunCmdCount[path]++
			callNum := azureRunCmdCount[path]
			mu.Unlock()
			if callNum == 1 {
				// Pre-reboot patch stage
				_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"message": "staged"}}})
				return
			}
			// Post-reboot check via 202 Async + Location output
			w.Header().Set("Azure-AsyncOperation", srvURL+"/azure-lro/runcmd")
			w.Header().Set("Location", srvURL+"/azure-run-output/runcmd")
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodDelete && strings.Contains(path, "/providers/Microsoft.Compute/virtualMachines/"):
			mu.Lock()
			azureVMsDeleted++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
		case r.Method == http.MethodDelete && strings.Contains(path, "/providers/Microsoft.Network/networkInterfaces/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})

		// -----------------------------------------------------------------
		// D. GCP Compute Engine v1 (instances + Zone operations + serialPort)
		// -----------------------------------------------------------------
		case r.Method == http.MethodPost && strings.Contains(path, "/compute/v1/projects/") && strings.HasSuffix(path, "/instances"):
			mu.Lock()
			gcpCreated++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "op-insert-gce-1", "status": "RUNNING"})
		case r.Method == http.MethodGet && strings.Contains(path, "/operations/op-insert-gce-1"):
			mu.Lock()
			gcpZoneOpPolls++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "op-insert-gce-1", "status": "DONE"})
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/serialPort"):
			mu.Lock()
			gcpSerialPolls[path]++
			cnt := gcpSerialPolls[path]
			mu.Unlock()
			if cnt == 1 {
				// First poll while VM is still rebooting
				_ = json.NewEncoder(w).Encode(map[string]any{"contents": "[gce] applying patch and rebooting...\n"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"contents": "[gce] booted new kernel\n" + resultMarkerLine(false) + "\n"})
		case r.Method == http.MethodDelete && strings.Contains(path, "/compute/v1/projects/"):
			mu.Lock()
			gcpDeleted++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "DONE"})

		// -----------------------------------------------------------------
		// E. Hyper-V Host Agent (`/v1/hyperv/clones` & `/v1/hyperv/prove`)
		// -----------------------------------------------------------------
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
			out := make([]map[string]any, 0, 3)
			for i := 0; i < 3; i++ {
				accOK := !(shouldFail && i == 2)
				ec := 0
				if !accOK {
					ec = 1
				}
				out = append(out, map[string]any{
					"clone_index":             i,
					"clone_name":              fmt.Sprintf("g1-hv-clone-%d", i),
					"host_or_zone":            "HV-QA-HOST-01",
					"private_ip":              "vmbus://powershell-direct",
					"booted_kernel_or_build":  "6.8.0-45.el9.x86_64",
					"reboot_verified":         true,
					"service_up_passed":       true,
					"smoke_test_passed":       true,
					"class_acceptance_passed": accOK,
					"observed_latency_ms":     14.2,
					"exit_code":               ec,
					"raw_log":                 "Heartbeat=OkApplicationsHealthy; Differencing VHDX rebooted on Private switch",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"clones": out})
		case r.Method == http.MethodDelete && strings.HasPrefix(path, "/v1/hyperv/clones/"):
			mu.Lock()
			hypervDeleted += 3
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})

		default:
			http.Error(w, "unexpected route "+r.Method+" "+path, http.StatusNotFound)
		}
	}))
	defer mockVMFabric.Close()
	srvURL = mockVMFabric.URL

	saJSONBytes, _ := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "warrant-twin@gov-sec-qa.iam.gserviceaccount.com",
		"private_key":  privPEM,
		"token_uri":    srvURL + "/gcp/oauth2/token",
	})

	// Part A: Exercise AWS SigV4 (EC2+SSM), Azure OAuth2+ARM+LRO, and GCP RS256-JWT+GCE+SerialPort directly
	envMap := map[string]string{
		"WARRANT_VM_TWIN_POLL_MS":            "5",
		"WARRANT_AWS_REGION":                 "us-gov-west-1",
		"WARRANT_AWS_ACCESS_KEY_ID":          "g1test-aws-access-key-inv19",
		"WARRANT_AWS_SECRET_ACCESS_KEY":      "g1test-aws-secret-key-inv19",
		"WARRANT_AWS_EC2_ENDPOINT":           srvURL,
		"WARRANT_AWS_SSM_ENDPOINT":           srvURL,
		"WARRANT_AWS_TWIN_AMI_ID":            "ami-0qa99887766554433",
		"WARRANT_AWS_TWIN_SUBNET_ID":         "subnet-isolated01",
		"WARRANT_AWS_TWIN_ISOLATED_SG_ID":    "sg-zeroegress01",
		"WARRANT_AZURE_ARM_ENDPOINT":         srvURL,
		"WARRANT_AZURE_AUTH_ENDPOINT":        srvURL,
		"WARRANT_AZURE_TENANT_ID":            "tenant-gov-001",
		"WARRANT_AZURE_CLIENT_ID":            "client-gov-001",
		"WARRANT_AZURE_CLIENT_SECRET":        "secret-gov-001",
		"WARRANT_AZURE_TWIN_SUBSCRIPTION_ID": "sub-gov-001",
		"WARRANT_AZURE_TWIN_RESOURCE_GROUP":  "rg-qa-twins",
		"WARRANT_AZURE_TWIN_IMAGE_ID":        "/subscriptions/sub-gov-001/images/qa-rhel9",
		"WARRANT_AZURE_TWIN_SUBNET_ID":       "/subscriptions/sub-gov-001/subnets/isolated",
		"WARRANT_AZURE_TWIN_NSG_ID":          "/subscriptions/sub-gov-001/networkSecurityGroups/nsg-deny-egress",
		"WARRANT_GCP_COMPUTE_ENDPOINT":       srvURL,
		"WARRANT_GCP_SERVICE_ACCOUNT_JSON":   string(saJSONBytes),
		"WARRANT_GCP_TWIN_PROJECT":           "gov-sec-qa",
		"WARRANT_GCP_TWIN_ZONE":              "us-east4-a",
		"WARRANT_GCP_TWIN_MACHINE_IMAGE":     "projects/gov-sec-qa/global/machineImages/qa-rhel9",
		"WARRANT_GCP_TWIN_SUBNET":            "regions/us-east4/subnetworks/isolated-twin",
	}

	for _, drv := range []string{vmtwins.DriverAWSEC2, vmtwins.DriverAzureVM, vmtwins.DriverGCPGCE} {
		envMap["WARRANT_VM_TWIN_DRIVER"] = drv
		prov, pErr := vmtwins.NewVMTwinProviderFromEnv(nil, func(k string) string { return envMap[k] })
		if pErr != nil || prov == nil {
			t.Fatalf("NewVMTwinProviderFromEnv(%s): %v", drv, pErr)
		}
		m, rErr := prov.RunVMTwinProving(ctx, adapters.CloneTwinProvingRequest{
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
		if rErr != nil {
			t.Fatalf("RunVMTwinProving(%s) failed: %v", drv, rErr)
		}
		if m.TwinRuntime != models.TwinRuntimeVM || m.CloneCount != 3 || !m.AllPassed || !m.ZeroProductionEgress {
			t.Fatalf("unexpected manifest for %s: %+v", drv, m)
		}
	}

	if awsLaunched != 3 || awsDescribed == 0 || awsTerminated != 3 {
		t.Fatalf("AWS SigV4 lifecycle mismatch: launched=%d described=%d terminated=%d", awsLaunched, awsDescribed, awsTerminated)
	}
	if azureOAuthCalls == 0 || azureNICsCreated != 3 || azureVMsCreated != 3 || azureRestarts != 3 || azureLROPolls == 0 || azureVMsDeleted != 3 {
		t.Fatalf("Azure ARM lifecycle mismatch: oauth=%d nics=%d vms=%d restarts=%d lro=%d deleted=%d",
			azureOAuthCalls, azureNICsCreated, azureVMsCreated, azureRestarts, azureLROPolls, azureVMsDeleted)
	}
	if gcpJWTExchanges == 0 || gcpCreated != 3 || gcpZoneOpPolls != 3 || gcpDeleted != 3 {
		t.Fatalf("GCP GCE lifecycle mismatch: jwt=%d created=%d ops=%d deleted=%d",
			gcpJWTExchanges, gcpCreated, gcpZoneOpPolls, gcpDeleted)
	}

	// Part B: Full End-to-End Orchestrator Flow with Hyper-V VM_TWIN Driver
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
	t.Setenv("WARRANT_HYPERV_AGENT_URL", srvURL)
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
		t.Fatalf("SubmitFinderIntake: err=%v items=%+v", err, items)
	}

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
		dispRes.Remediation.CloneTwinProving.CloneCount != 3 ||
		!dispRes.Remediation.CloneTwinProving.AllPassed {
		t.Fatalf("expected ATTESTED_CLOSED with 3-clone VM_TWIN manifest, got: %+v", dispRes.Remediation)
	}
	oscalRaw, err := soCli.ExportOSCALBundle(ctx, dispRes.Remediation.AttestationID)
	if err != nil || !strings.Contains(string(oscalRaw), "VM_TWIN") || !strings.Contains(string(oscalRaw), "hyperv://g1-twin-proving-private") {
		t.Fatalf("expected OSCAL bundle to record VM_TWIN + hyperv://g1-twin-proving-private, err=%v raw=%s", err, string(oscalRaw))
	}

	// Inject failure on Clone #2 during post-reboot acceptance -> fail closed & tear down all 3 Hyper-V VMs!
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
