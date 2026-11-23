package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters/estatereader"
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

// TestInvariant20_EstateLoaderNoReplicationCredentialSeparationAndDriftGate locks the v1.4.0 Estate Loader invariants:
//  1. All 18 connected systems (12 Tier A, 3 Tier B, 3 Tier C returning 0 clone sources) via 5 handler families,
//     plus a 19th proprietary REST endpoint manager added via declarative JSON mapping ONLY (zero Go code).
//  2. Full lifecycle across Tier A (ms-mecm), Tier B (k8s-cilium-native), and Tier C (tenable census cross-check):
//     proposal -> human confirmation -> 2-of-2 DSSE clone_sources[] + estate_snapshot_sha256 binding -> proving-time re-read
//     -> CloneTwinProvingManifest & OSCAL 1.1.2 POA&M snapshot/age/resolution evidence -> RECORD_ONLY vs FAIL_CLOSED drift
//     -> unavailable-at-signing (rejects ESTATE_LOADER, permits explicit MANUAL) & unavailable-at-proving (KERNEL defaults FAIL_CLOSED).
//  3. Structural Assertion (a): Zero per-host or estate mirror tables in PostgreSQL information_schema.tables; only bounded estate_read_evidence rows.
//  4. Structural Assertion (b): Strict Read vs. Dispatch credential separation in both directions.
func TestInvariant20_EstateLoaderNoReplicationCredentialSeparationAndDriftGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var mu sync.Mutex
	mecmMemberCount := 120
	mecmUnavailable := false
	offlineSysUnavailable := true
	hvClonesCreated := 0

	freshISO := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	imgCreatedISO := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)

	estateMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Hyper-V VM_TWIN agent routes (used during proving execution for Tier A VM classes)
		if strings.HasPrefix(path, "/v1/hyperv/") {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodPost && path == "/v1/hyperv/clones":
				var cReq map[string]any
				_ = json.NewDecoder(r.Body).Decode(&cReq)
				if fmt.Sprintf("%v", cReq["parent_vhdx"]) == "" {
					http.Error(w, "missing parent_vhdx", http.StatusBadRequest)
					return
				}
				mu.Lock()
				hvClonesCreated += 3
				mu.Unlock()
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"host_name": "HV-ESTATE-QA-01",
					"vm_names":  []string{"hv-0", "hv-1", "hv-2"},
				})
			case r.Method == http.MethodPost && strings.HasSuffix(path, "/prove"):
				out := make([]map[string]any, 0, 3)
				for i := 0; i < 3; i++ {
					out = append(out, map[string]any{
						"clone_index":             i,
						"clone_name":              fmt.Sprintf("hv-%d", i),
						"host_or_zone":            "HV-ESTATE-QA-01",
						"private_ip":              "vmbus://powershell-direct",
						"booted_kernel_or_build":  "10.0.20348.2700",
						"reboot_verified":         true,
						"service_up_passed":       true,
						"smoke_test_passed":       true,
						"class_acceptance_passed": true,
						"observed_latency_ms":     12.5,
						"exit_code":               0,
					})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"clones": out})
			case r.Method == http.MethodDelete:
				_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
			}
			return
		}

		// WN-8 ms-mecm distributor dispatch & compliance routes (must ONLY see dispatch token, never read token)
		if strings.HasPrefix(path, "/AdminService/v1.0/SMS_UpdateGroupAssignment") {
			if r.Header.Get("Authorization") != "Bearer disp-tok-ms-mecm" {
				http.Error(w, "expected ms-mecm dispatch token", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"AssignmentUniqueID": "mecm-job-inv20"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"DeviceName": "payments-ledger-api", "EnforcementState": "1001", "LastEnforcementMessageTime": time.Now().UTC().Format(time.RFC3339)},
				},
			})
			return
		}

		// Enforce that all EstateReader requests carry X-Warrant-Read-Role: READ_ESTATE_SNAPSHOT
		if r.Header.Get("X-Warrant-Read-Role") != models.AgentActionReadEstateSnapshot {
			http.Error(w, "missing X-Warrant-Read-Role=READ_ESTATE_SNAPSHOT", http.StatusForbidden)
			return
		}

		mu.Lock()
		curMecmCount := mecmMemberCount
		isMecmDown := mecmUnavailable
		isOfflineDown := offlineSysUnavailable
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		// Unreachable source simulation (`ms-wsus` when offline flag enabled)
		case strings.HasPrefix(path, "/offline-wsus/"):
			if isOfflineDown {
				http.Error(w, "WSUS SQL replica offline", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 20, "freshness_at": freshISO})

		// Family (a): Microsoft (ms-intune, azure-update-manager, ms-mecm, ms-wsus)
		case strings.HasPrefix(path, "/v1.0/deviceManagement/managedDevices"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_count":  85,
				"freshness_at": freshISO,
				"os_distribution": []map[string]any{
					{"os_family": "WINDOWS", "os_build": "10.0.22631.4317", "cpe23": "cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*", "count": 85},
				},
				"software_distribution": []map[string]any{
					{"name": "Microsoft.Edge", "version": "130.0.2849.56", "cpe23": "cpe:2.3:a:microsoft:edge:130.0.2849.56:*:*:*:*:*:*:*", "swid_tag_id": "swid:ms-edge-130", "count": 85},
				},
				"images": []map[string]any{
					{"image_id": "autopilot://win11-23h2-qa-gold", "platform_family": "WINDOWS_CLIENT", "created_at": imgCreatedISO},
				},
			})

		case strings.HasPrefix(path, "/providers/Microsoft.ResourceGraph/resources"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_count":  64,
				"freshness_at": freshISO,
				"os_distribution": []map[string]any{
					{"os_family": "LINUX", "os_build": "Ubuntu-22.04", "kernel_release": "6.5.0-1025-azure", "cpe23": "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*", "count": 64},
				},
				"software_distribution": []map[string]any{
					{"name": "openssl", "version": "3.0.2-0ubuntu1.18", "cpe23": "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*", "count": 64},
				},
				"images": []map[string]any{
					{"image_id": "/subscriptions/sub-01/resourceGroups/rg-qa/providers/Microsoft.Compute/images/ubuntu2204-qa", "platform_family": "LINUX_DEB", "created_at": imgCreatedISO},
				},
			})

		case strings.HasPrefix(path, "/AdminService/v1.0/SMS_G_System_OPERATING_SYSTEM"):
			if isMecmDown {
				http.Error(w, "ConfigMgr AdminService unreachable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_count":  curMecmCount,
				"freshness_at": freshISO,
				"os_distribution": []map[string]any{
					{"os_family": "WINDOWS", "os_build": "10.0.20348.2655", "kernel_release": "20348.2655", "cpe23": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", "count": curMecmCount},
				},
				"software_distribution": []map[string]any{
					{"name": "Windows.Server.HTTP.Stack", "version": "10.0.20348.2655", "cpe23": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", "swid_tag_id": "swid:ms-win2022-http", "count": curMecmCount},
				},
				"images": []map[string]any{
					{"image_id": "wim://mecm-win2022-qa-v1", "platform_family": "WINDOWS_SERVER", "created_at": imgCreatedISO},
				},
			})

		case strings.HasPrefix(path, "/wsus/v1/computers/summary"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_count":  40,
				"freshness_at": freshISO,
				"os_distribution": []map[string]any{
					{"os_family": "WINDOWS", "os_build": "10.0.17763", "cpe23": "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*", "count": 40},
				},
				"images": []map[string]any{
					{"image_id": `D:\HyperV\Golden\wsus-win2019-qa.vhdx`, "platform_family": "WINDOWS_SERVER", "created_at": imgCreatedISO},
				},
			})

		// Family (b): Cloud Inventory (aws-ssm, gcp-os-config)
		case path == "/ssm/GetInventory":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_instances": 90,
				"capture_time":    freshISO,
				"os_buckets": []map[string]any{
					{"os_family": "LINUX", "os_build": "AmazonLinux-2023", "kernel_release": "6.1.112-122.189.amzn2023.x86_64", "cpe23": "cpe:2.3:o:amazon:linux:2023:*:*:*:*:*:*:*", "count": 90},
				},
				"packages": []map[string]any{
					{"name": "kernel", "version": "6.1.112", "cpe23": "cpe:2.3:o:linux:linux_kernel:6.1.112:*:*:*:*:*:*:*", "purl": "pkg:rpm/amzn/kernel@6.1.112", "count": 90},
				},
				"candidate_images": []map[string]any{
					{"image_id": "ami-0qa2023golden0001", "platform_family": "LINUX_RPM", "created_at": imgCreatedISO},
				},
			})

		case strings.HasPrefix(path, "/v1/projects/default/locations/global/instanceOSPoliciesCompliances"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_instances": 52,
				"updateTime":      freshISO,
				"os_buckets": []map[string]any{
					{"os_family": "LINUX", "os_build": "Debian-12", "kernel_release": "6.1.0-26-cloud-amd64", "cpe23": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*", "count": 52},
				},
				"candidate_images": []map[string]any{
					{"image_id": "projects/gov-qa/global/machineImages/debian12-qa", "platform_family": "LINUX_DEB", "created_at": imgCreatedISO},
				},
			})

		// Family (c): Unified Kubernetes API (k8s-cilium-native, argocd, flux)
		case strings.HasPrefix(path, "/apis/apps/v1/deployments"),
			strings.HasPrefix(path, "/api/v1/applications"),
			strings.HasPrefix(path, "/v1/flux/inventory"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_pods":   12,
				"freshness_at": freshISO,
				"runtime_buckets": []map[string]any{
					{"os_family": "CONTAINER_LINUX", "os_build": "distroless-debian12", "kernel_release": "6.6.32-k8s", "cpe23": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*", "count": 12},
				},
				"image_digests": []map[string]any{
					{"name": "payments-ledger-api", "version": "sha256:a100000000000000000000000000000000000000000000000000000000000001", "purl": "pkg:oci/payments-ledger-api@sha256:a100000000000000000000000000000000000000000000000000000000000001", "count": 12},
				},
				"staging_clone_sources": []map[string]any{
					{"image_id": "sha256:a100000000000000000000000000000000000000000000000000000000000001", "platform_family": "CONTAINER_LINUX", "created_at": imgCreatedISO},
				},
			})

		// Family (d): Declarative REST Endpoint Managers (6 builtin + 19th zero-code BigFix proof)
		case path == "/plugin/products/asset/v1/assets/summary": // tanium-patch
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"total_count":       150,
					"last_collected_at": freshISO,
					"endpoints": []map[string]any{{
						"count": 150,
						"os":    map[string]any{"platform": "WINDOWS", "generation": "Server-2022", "kernel": "20348", "cpe23": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*"},
						"installed_applications": []map[string]any{{
							"name": "OpenSSH", "version": "9.5p1", "cpe23": "cpe:2.3:a:openbsd:openssh:9.5p1:*:*:*:*:*:*:*", "swid_tag_id": "swid:openssh-9.5",
						}},
					}},
					"golden_images": []map[string]any{{"image_identity": "tanium://qa-win2022-gold", "platform_family": "WINDOWS_SERVER", "created_at": imgCreatedISO}},
				},
			})

		case path == "/api/discovery/v1/devices/summary": // ivanti-neurons
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_devices":       75,
				"inventory_synced_at": freshISO,
				"devices": []map[string]any{{
					"device_count": 75, "os_family": "WINDOWS", "os_build": "22631", "kernel_version": "10.0.22631",
					"software": []map[string]any{{"product_name": "7-Zip", "product_version": "24.08", "swid_id": "swid:7zip-24"}},
				}},
				"provisioning_templates": []map[string]any{{"template_image_id": "ivanti://win11-qa-template", "platform_family": "WINDOWS_CLIENT", "created_at": imgCreatedISO}},
			})

		case path == "/api/servers/summary": // automox
			_ = json.NewEncoder(w).Encode(map[string]any{
				"total_servers":     48,
				"last_refresh_time": freshISO,
				"results": []map[string]any{{
					"count": 48, "os_family": "LINUX", "os_version": "Ubuntu-24.04", "kernel_version": "6.8.0-45-generic",
					"packages": []map[string]any{{"display_name": "curl", "version": "8.5.0", "purl": "pkg:deb/ubuntu/curl@8.5.0"}},
				}},
				"qa_images": []map[string]any{{"image_id": "automox://ubuntu2404-qa", "platform_family": "LINUX_DEB", "created_at": imgCreatedISO}},
			})

		case path == "/api/v1/computers-inventory": // jamf-pro
			_ = json.NewEncoder(w).Encode(map[string]any{
				"totalCount":              33,
				"lastInventoryUpdateDate": freshISO,
				"results": []map[string]any{{
					"count":           33,
					"operatingSystem": map[string]any{"name": "MACOS", "version": "15.1", "build": "24B83", "cpe23": "cpe:2.3:o:apple:macos:15.1:*:*:*:*:*:*:*"},
					"applications":    []map[string]any{{"name": "Safari.app", "version": "18.1", "bundleId": "com.apple.Safari"}},
				}},
				"macosRestoreImages": []map[string]any{{"ipswImageId": "ipsw://macos-15.1-qa.ipsw", "platformFamily": "MACOS", "createdAt": imgCreatedISO}},
			})

		case path == "/api/v2/hosts": // redhat-satellite
			_ = json.NewEncoder(w).Encode(map[string]any{
				"subtotal":    110,
				"reported_at": freshISO,
				"results": []map[string]any{{
					"count": 110, "operatingsystem_name": "RHEL", "operatingsystem_release": "9.4", "kernel_version": "5.14.0-427.el9.x86_64",
					"installed_packages": []map[string]any{{"name": "glibc", "nvra": "glibc-2.34-100.el9.x86_64", "purl": "pkg:rpm/redhat/glibc@2.34-100.el9"}},
				}},
				"compute_images": []map[string]any{{"uuid": "sat-img-rhel94-qa-01", "platform_family": "LINUX_RPM", "created_at": imgCreatedISO}},
			})

		case path == "/api/v2/hosts/": // ansible-awx
			_ = json.NewEncoder(w).Encode(map[string]any{
				"count":              68,
				"last_fact_modified": freshISO,
				"results": []map[string]any{{
					"host_count": 68,
					"ansible_facts": map[string]any{
						"ansible_distribution":         "Rocky",
						"ansible_distribution_version": "9.4",
						"ansible_kernel":               "5.14.0-427.el9.x86_64",
						"packages":                     []map[string]any{{"name": "sudo", "version": "1.9.5p2", "cpe23": "cpe:2.3:a:sudo_project:sudo:1.9.5:p2:*:*:*:*:*:*"}},
					},
				}},
				"golden_templates": []map[string]any{{"image_ref": "awx://rocky94-qa-vm", "platform_family": "LINUX_RPM", "created_at": imgCreatedISO}},
			})

		case path == "/api/bigfix/v1/computers": // 19th zero-code declarative REST system proof!
			_ = json.NewEncoder(w).Encode(map[string]any{
				"computer_total": 95,
				"report_time":    freshISO,
				"computers": []map[string]any{{
					"group_count": 95, "os_type": "AIX_LINUX", "os_rel": "RHEL-9.4", "kern": "5.14.0-427",
					"sw_name": "bash", "sw_ver": "5.1.8", "sw_cpe": "cpe:2.3:a:gnu:bash:5.1.8:*:*:*:*:*:*:*", "sw_swid": "swid:gnu-bash-5.1.8",
				}},
				"vm_templates": []map[string]any{{"tpl_id": "bigfix://rhel94-qa-clone", "plat": "LINUX_RPM", "built_at": imgCreatedISO}},
			})

		// Family (e): Tier C Scanners via WN-7 FinderTranslators (qualys_vmdr, tenable, rapid7_insightvm)
		case strings.HasPrefix(path, "/api/2.0/fo/asset/host/vm/detection"): // qualys_vmdr
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hosts": []map[string]any{
					{"asset_key": "qh-1", "service_id": "payments-ledger-api", "detections": []map[string]any{{"qid": 370001, "severity": 4, "cvss3_base": 8.1, "status": "Active", "cves": []string{"CVE-2026-88001"}}}},
					{"asset_key": "qh-2", "service_id": "payments-ledger-api", "detections": []map[string]any{{"qid": 370001, "severity": 4, "cvss3_base": 8.1, "status": "Active", "cves": []string{"CVE-2026-88001"}}}},
				},
			})

		case strings.HasPrefix(path, "/vulns/export/census"): // tenable (reports 127 assets vs ms-mecm 120 -> +7 unmanaged host gap!)
			findings := make([]map[string]any, 0, 127)
			for i := 0; i < 127; i++ {
				findings = append(findings, map[string]any{
					"state":     "OPEN",
					"last_found": freshISO,
					"asset": map[string]any{
						"asset_key":        fmt.Sprintf("tenable-host-%03d", i),
						"service_id":       "payments-ledger-api",
						"operating_system": []string{"Microsoft Windows Server 2022"},
					},
					"plugin": map[string]any{
						"id":   19506,
						"cve":  []string{"CVE-2026-88002"},
						"cvss3_base_score": 8.5,
					},
				})
			}
			_ = json.NewEncoder(w).Encode(findings)

		case strings.HasPrefix(path, "/api/3/assets"): // rapid7_insightvm
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resources": []map[string]any{{
					"id": 101, "assetKey": "r7-host-01", "serviceId": "payments-ledger-api", "os": "Ubuntu Linux 22.04",
					"vulnerabilities": []map[string]any{{"id": "UBUNTU-CVE-2026-88003", "status": "vulnerable", "cves": []string{"CVE-2026-88003"}, "cvssV3Score": 7.8}},
				}},
			})

		default:
			http.Error(w, "unhandled mock estate route "+r.Method+" "+path, http.StatusNotFound)
		}
	}))
	defer estateMock.Close()

	// =========================================================================
	// PART 1: Verify All 18 Connected Systems (5 Families) + 19th Zero-Code REST System
	// =========================================================================
	env18 := map[string]string{
		"WARRANT_MS_INTUNE_READ_URL":            estateMock.URL,
		"WARRANT_MS_INTUNE_READ_TOKEN":          "read-tok-intune",
		"WARRANT_MS_INTUNE_TOKEN":               "disp-tok-intune",
		"WARRANT_AZURE_UPDATE_READ_URL":         estateMock.URL,
		"WARRANT_AZURE_UPDATE_READ_TOKEN":       "read-tok-azupd",
		"WARRANT_AZURE_UPDATE_TOKEN":            "disp-tok-azupd",
		"WARRANT_MS_MECM_READ_URL":              estateMock.URL,
		"WARRANT_MS_MECM_READ_TOKEN":            "read-tok-ms-mecm",
		"WARRANT_MS_MECM_TOKEN":                 "disp-tok-ms-mecm",
		"WARRANT_MS_WSUS_READ_URL":              estateMock.URL,
		"WARRANT_MS_WSUS_READ_TOKEN":            "read-tok-wsus",
		"WARRANT_MS_WSUS_TOKEN":                 "disp-tok-wsus",
		"WARRANT_AWS_SSM_READ_URL":              estateMock.URL,
		"WARRANT_AWS_SSM_READ_TOKEN":            "read-tok-awsssm",
		"WARRANT_AWS_SSM_TOKEN":                 "disp-tok-awsssm",
		"WARRANT_GCP_OSCONFIG_READ_URL":         estateMock.URL,
		"WARRANT_GCP_OSCONFIG_READ_TOKEN":       "read-tok-gcp",
		"WARRANT_GCP_OSCONFIG_TOKEN":            "disp-tok-gcp",
		"WARRANT_KUBE_READ_URL":                 estateMock.URL,
		"WARRANT_KUBE_READ_TOKEN":               "read-tok-k8s",
		"WARRANT_KUBE_API_TOKEN":                "disp-tok-k8s",
		"WARRANT_ARGOCD_READ_URL":               estateMock.URL,
		"WARRANT_ARGOCD_READ_TOKEN":             "read-tok-argocd",
		"WARRANT_ARGOCD_TOKEN":                  "disp-tok-argocd",
		"WARRANT_FLUX_READ_URL":                 estateMock.URL,
		"WARRANT_FLUX_READ_TOKEN":               "read-tok-flux",
		"WARRANT_FLUX_TOKEN":                    "disp-tok-flux",
		"WARRANT_TANIUM_READ_URL":               estateMock.URL,
		"WARRANT_TANIUM_READ_TOKEN":             "read-tok-tanium",
		"WARRANT_TANIUM_TOKEN":                  "disp-tok-tanium",
		"WARRANT_IVANTI_READ_URL":               estateMock.URL,
		"WARRANT_IVANTI_READ_TOKEN":             "read-tok-ivanti",
		"WARRANT_IVANTI_TOKEN":                  "disp-tok-ivanti",
		"WARRANT_AUTOMOX_READ_URL":              estateMock.URL,
		"WARRANT_AUTOMOX_READ_TOKEN":            "read-tok-automox",
		"WARRANT_AUTOMOX_TOKEN":                 "disp-tok-automox",
		"WARRANT_JAMF_PRO_READ_URL":             estateMock.URL,
		"WARRANT_JAMF_PRO_READ_TOKEN":           "read-tok-jamf",
		"WARRANT_JAMF_PRO_TOKEN":                "disp-tok-jamf",
		"WARRANT_REDHAT_SATELLITE_READ_URL":     estateMock.URL,
		"WARRANT_REDHAT_SATELLITE_READ_TOKEN":   "read-tok-sat",
		"WARRANT_REDHAT_SATELLITE_TOKEN":        "disp-tok-sat",
		"WARRANT_ANSIBLE_AWX_READ_URL":          estateMock.URL,
		"WARRANT_ANSIBLE_AWX_READ_TOKEN":        "read-tok-awx",
		"WARRANT_ANSIBLE_AWX_TOKEN":             "disp-tok-awx",
		"WARRANT_QUALYS_READ_URL":               estateMock.URL,
		"WARRANT_QUALYS_READ_TOKEN":             "read-tok-qualys",
		"WARRANT_TENABLE_READ_URL":              estateMock.URL,
		"WARRANT_TENABLE_READ_TOKEN":            "read-tok-tenable",
		"WARRANT_RAPID7_READ_URL":               estateMock.URL,
		"WARRANT_RAPID7_READ_TOKEN":             "read-tok-rapid7",
		"WARRANT_INTAKE_TOKEN":                  "intake-tok-inv20",
	}

	reg18 := estatereader.NewRegistry()
	if err := estatereader.RegisterAllBuiltinEstateReaders(reg18, nil, nil, func(k string) string { return env18[k] }); err != nil {
		t.Fatalf("RegisterAllBuiltinEstateReaders: %v", err)
	}
	descs := reg18.ListDescriptors()
	if len(descs) != 18 {
		t.Fatalf("expected exactly 18 builtin EstateReader descriptors, got %d", len(descs))
	}

	tierCounts := map[string]int{}
	familySet := map[string]bool{}
	for _, d := range descs {
		tierCounts[d.SourceTier]++
		familySet[d.HandlerFamily] = true
		er, gErr := reg18.Get(d.SourceSystem)
		if gErr != nil {
			t.Fatalf("Get(%s): %v", d.SourceSystem, gErr)
		}
		snap, rErr := er.ReadEstateSnapshot(ctx, estatereader.EstateReadQuery{
			WarrantClass:  "KEV-TIER1-STATELESS",
			ScopeServices: []string{"payments-ledger-api"},
		})
		if rErr != nil {
			t.Fatalf("ReadEstateSnapshot(%s): %v", d.SourceSystem, rErr)
		}
		if snap.OCSFClassUID != models.OCSFInventoryInfoClassUID || snap.SnapshotSHA256 == "" || snap.ClassMembershipCount <= 0 {
			t.Fatalf("invalid snapshot for %s: %+v", d.SourceSystem, snap)
		}
		if d.SourceTier == models.EstateSourceTierCCensus {
			if len(snap.CandidateCloneSources) != 0 {
				t.Fatalf("Tier C scanner %s MUST return 0 candidate_clone_sources, got %d", d.SourceSystem, len(snap.CandidateCloneSources))
			}
		} else if len(snap.CandidateCloneSources) == 0 {
			t.Fatalf("Tier A/B system %s expected >=1 candidate_clone_sources", d.SourceSystem)
		}
	}
	if tierCounts[models.EstateSourceTierAMachine] != 12 ||
		tierCounts[models.EstateSourceTierBWorkload] != 3 ||
		tierCounts[models.EstateSourceTierCCensus] != 3 {
		t.Fatalf("expected tier split 12/3/3, got %+v", tierCounts)
	}
	if len(familySet) != 5 {
		t.Fatalf("expected strictly 5 handler families, got %d (%v)", len(familySet), familySet)
	}

	// Prove 19th proprietary REST endpoint manager via declarative JSON mapping ONLY (zero new Go handler code!)
	spec19JSON := []byte(`{
		"source_system": "bigfix-enterprise",
		"display_name": "HCL BigFix Inventory (Declarative 19th System)",
		"source_tier": "TIER_A_MACHINE",
		"read_env_prefix": "WARRANT_BIGFIX",
		"dispatch_env_prefix": "WARRANT_BIGFIX",
		"inventory_method": "GET",
		"inventory_path": "/api/bigfix/v1/computers",
		"class_query_param": "bes_group",
		"default_platform": "LINUX_RPM",
		"default_os_family": "LINUX",
		"records_array_path": "computers",
		"total_count_path": "computer_total",
		"freshness_path": "report_time",
		"record_count_field": "group_count",
		"os_family_field": "os_type",
		"os_version_field": "os_rel",
		"kernel_release_field": "kern",
		"software_name_field": "sw_name",
		"software_version_field": "sw_ver",
		"software_cpe23_field": "sw_cpe",
		"software_swid_field": "sw_swid",
		"candidates_array_path": "vm_templates",
		"candidate_id_field": "tpl_id",
		"candidate_platform_field": "plat",
		"candidate_created_field": "built_at"
	}`)
	spec19, sErr := estatereader.ParseRESTMappingSpecJSON(spec19JSON)
	if sErr != nil {
		t.Fatalf("ParseRESTMappingSpecJSON: %v", sErr)
	}
	if err := reg18.RegisterDeclarativeREST(spec19, estateMock.URL, "read-tok-bigfix", "disp-tok-bigfix", nil); err != nil {
		t.Fatalf("RegisterDeclarativeREST(bigfix-enterprise): %v", err)
	}
	er19, _ := reg18.Get("bigfix-enterprise")
	snap19, err := er19.ReadEstateSnapshot(ctx, estatereader.EstateReadQuery{WarrantClass: "KEV-TIER1-STATELESS", ScopeServices: []string{"payments-ledger-api"}})
	if err != nil || snap19.ClassMembershipCount != 95 || len(snap19.CandidateCloneSources) != 1 || snap19.CandidateCloneSources[0].ImageIdentity != "bigfix://rhel94-qa-clone" {
		t.Fatalf("19th declarative REST reader failed: err=%v snap=%+v", err, snap19)
	}

	// Prove constructor-level same-token rejection (Read == Dispatch token MUST fail)
	badReader := estatereader.NewDeclarativeRESTEstateReader(spec19, estateMock.URL, "shared-bad-tok", "shared-bad-tok", nil)
	if _, sameErr := badReader.ReadEstateSnapshot(ctx, estatereader.EstateReadQuery{WarrantClass: "KEV"}); sameErr == nil || !strings.Contains(sameErr.Error(), "CREDENTIAL_SEPARATION_VIOLATION") {
		t.Fatalf("expected CREDENTIAL_SEPARATION_VIOLATION when readToken == dispatchToken, got: %v", sameErr)
	}

	// =========================================================================
	// PART 2–4: Full PostgreSQL Orchestrator E2E Lifecycle, Drift Gate, No-Replication & Credential Separation
	// =========================================================================
	adminDSN := os.Getenv("TEST_DATABASE_URL")
	if adminDSN == "" {
		adminDSN = os.Getenv("DATABASE_URL")
	}
	if adminDSN == "" {
		adminDSN = "postgres://warrant:warrant@localhost:5432/postgres?sslmode=disable"
	}
	adminConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Skipf("PostgreSQL not reachable for Part 2–4 E2E (%v)", err)
	}
	dbName := "warrant_inv20_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
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

	for k, v := range env18 {
		t.Setenv(k, v)
	}
	// Point ms-wsus at the simulated offline endpoint to test unavailable-at-signing & MANUAL override
	t.Setenv("WARRANT_MS_WSUS_READ_URL", estateMock.URL+"/offline-wsus")
	t.Setenv("WARRANT_MS_MECM_URL", estateMock.URL)
	t.Setenv("WARRANT_ENABLE_TEST_SMARTCARDS", "false")
	t.Setenv("WARRANT_BOOTSTRAP_ADMIN_TOKEN", "g1adm_inv20_bootstrap_secret")
	t.Setenv("WARRANT_ESTATE_READ_TOKEN", "g1read_inv20_dedicated_read_only")
	t.Setenv("WARRANT_AUTOMATION_TOKEN", "g1auto_inv20_dispatch_automation")
	t.Setenv("WARRANT_VM_TWIN_DRIVER", "hyperv")
	t.Setenv("WARRANT_HYPERV_AGENT_URL", estateMock.URL)
	t.Setenv("WARRANT_HYPERV_AGENT_TOKEN", "hv-agent-inv20")
	t.Setenv("WARRANT_HYPERV_QA_PARENT_VHDX", `D:\HyperV\Golden\env-fallback.vhdx`)

	store, err := db.NewStore(ctx, replaceDBName(adminDSN, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-extractor-inv20"))
	defer extSrv.Close()
	sim := fleetsim.NewClusterSimulator()
	simSrv := httptest.NewServer(sim.Handler())
	defer simSrv.Close()

	orch, err := server.NewOrchestrator(ctx, store, extSrv.URL, simSrv.URL, "inv20-estate-loader-seed", crypto.DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	httpSrv := httptest.NewServer(orch.BuildHTTPHandler())
	defer httpSrv.Close()

	svc := models.EstateService{
		ServiceID:                  "payments-ledger-api",
		DisplayName:                "Hybrid Payments Estate Workload",
		Namespace:                  "fin-core",
		Tier:                       "TIER_1_MISSION_CRITICAL",
		WarrantClass:               "KEV-TIER1-STATELESS",
		CurrentDigest:              "sha256:a100000000000000000000000000000000000000000000000000000000000001",
		CurrentPURL:                "pkg:oci/payments-ledger-api@sha256:a100000000000000000000000000000000000000000000000000000000000001",
		Replicas:                   4,
		TestCoveragePct:            94.0,
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

	soBundle, _ := warrantsdk.GenerateEd25519SignerBundle("usr-inv20-so", "so@agency.gov", "Inv20 SO", warrantsdk.RoleServiceOwner)
	aoBundle, _ := warrantsdk.GenerateEd25519SignerBundle("usr-inv20-ao", "ao@agency.gov", "Inv20 AO", warrantsdk.RoleAuthorizingOfficial)
	adminCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithAdminToken("g1adm_inv20_bootstrap_secret"))
	_, _ = adminCli.RegisterPrincipal(ctx, soBundle.ToRegisterRequest())
	_, _ = adminCli.RegisterPrincipal(ctx, aoBundle.ToRegisterRequest())

	// -------------------------------------------------------------------------
	// Structural Assertion (b): Strict Read vs. Dispatch Credential Separation
	// -------------------------------------------------------------------------
	// 1. Dispatch credentials MUST be rejected on EstateReader routes
	for _, badDispatchTok := range []string{"disp-tok-ms-mecm", "g1auto_inv20_dispatch_automation", "intake-tok-inv20"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, httpSrv.URL+"/api/v1/estate-loader/sources", nil)
		req.Header.Set("Authorization", "Bearer "+badDispatchTok)
		resp, dErr := http.DefaultClient.Do(req)
		if dErr != nil {
			t.Fatal(dErr)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected dispatch credential %q to be rejected on /api/v1/estate-loader/sources, got HTTP %d", badDispatchTok, resp.StatusCode)
		}
	}

	// 2. EstateReader read-only credentials MUST be rejected on WN-8 dispatch & warrant signing routes
	for _, readOnlyTok := range []string{"g1read_inv20_dedicated_read_only", "read-tok-ms-mecm"} {
		for _, mutRoute := range []string{"/api/v1/distributors/dispatch", "/api/v1/warrants"} {
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, httpSrv.URL+mutRoute, bytes.NewReader([]byte(`{}`)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+readOnlyTok)
			resp, mErr := http.DefaultClient.Do(req)
			if mErr != nil {
				t.Fatal(mErr)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("expected read-only credential %q to be rejected on %s, got HTTP %d", readOnlyTok, mutRoute, resp.StatusCode)
			}
		}
	}

	readCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithEstateReadToken("g1read_inv20_dedicated_read_only"))

	// Tier C scanner rejected as primary clone-source proposer
	if _, badTierCErr := readCli.ProposeEstateClass(ctx, warrantsdk.EstateProposalRequest{
		SourceSystem:  "tenable",
		WarrantClass:  "KEV-TIER1-STATELESS",
		ScopeServices: []string{"payments-ledger-api"},
	}); badTierCErr == nil || !strings.Contains(badTierCErr.Error(), "TIER_C_SCANNER_CANNOT_PROPOSE_CLONE_SOURCES") {
		t.Fatalf("expected TIER_C_SCANNER_CANNOT_PROPOSE_CLONE_SOURCES, got: %v", badTierCErr)
	}

	// -------------------------------------------------------------------------
	// End-to-End Lifecycle 1: ms-mecm (Tier A) + tenable (Tier C Census) -> 2-of-2 Sign -> Proving Re-Read -> OSCAL 1.1.2
	// -------------------------------------------------------------------------
	propMECM, err := readCli.ProposeEstateClass(ctx, warrantsdk.EstateProposalRequest{
		SourceSystem:         "ms-mecm",
		CorroboratingScanner: "tenable",
		WarrantClass:         "MECM-WIN2022-CLASS",
		ScopeServices:        []string{"payments-ledger-api"},
		EstateDriftPolicy:    warrantsdk.EstateDriftPolicyRecordOnly,
		DriftTolerancePct:    10.0,
	})
	if err != nil {
		t.Fatalf("ProposeEstateClass(ms-mecm + tenable): %v", err)
	}
	if propMECM.PrimarySnapshot.ClassMembershipCount != 120 || len(propMECM.ProposedCloneSources) != 1 {
		t.Fatalf("unexpected ms-mecm proposal: %+v", propMECM)
	}
	if propMECM.CensusSnapshot == nil || propMECM.CensusSnapshot.ClassMembershipCount != 127 || propMECM.CensusCountDelta != 7 || len(propMECM.CensusSnapshot.CandidateCloneSources) != 0 {
		t.Fatalf("unexpected tenable Tier C census cross-check: %+v", propMECM.CensusSnapshot)
	}

	wEnvMECM, _, err := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:               "wrt-inv20-mecm",
		WarrantClass:            "MECM-WIN2022-CLASS",
		ScopeServices:           []string{"payments-ledger-api"},
		ScopeAssets:             []string{"payments-ledger-api"},
		MaxCVSS:                 10.0,
		KEVEligible:             true,
		MaxBlastRadiusReplicas:  8,
		CloneSources:            propMECM.ProposedCloneSources,
		EstateSnapshotSHA256:    propMECM.ProposedEstateSnapshotSHA256,
		EstateDriftPolicy:       warrantsdk.EstateDriftPolicyRecordOnly,
		EstateDriftTolerancePct: 10.0,
		SLABridgeMinutes:        60,
		MaxP99LatencyMs:         120.0,
		TTLDays:                 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = soBundle.SignEnvelope(1, wEnvMECM)
	_ = aoBundle.SignEnvelope(2, wEnvMECM)
	mintedMECM, err := adminCli.CreateWarrant(ctx, *wEnvMECM)
	if err != nil {
		t.Fatalf("CreateWarrant(wrt-inv20-mecm): %v", err)
	}

	// Verify snapshot_sha256 & clone_sources[] are cryptographically bound inside the signed DSSE payload
	rawSignedPayload, _ := mintedMECM.DSSEEnvelope.DecodePayload()
	if !bytes.Contains(rawSignedPayload, []byte(propMECM.ProposedEstateSnapshotSHA256)) || !bytes.Contains(rawSignedPayload, []byte("wim://mecm-win2022-qa-v1")) {
		t.Fatalf("signed DSSE WarrantPayload missing bound estate_snapshot_sha256 or clone_sources: %s", string(rawSignedPayload))
	}

	// Inject estate drift beyond 10% tolerance (120 -> 180 = 50% drift) to verify RECORD_ONLY discloses drift in Manifest + OSCAL!
	mu.Lock()
	mecmMemberCount = 180
	mu.Unlock()

	intakeCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithIntakeToken("intake-tok-inv20"))
	tenableIntake := []byte(`[{
		"state": "OPEN",
		"asset": {"asset_key": "payments-ledger-api", "service_id": "payments-ledger-api", "operating_system": ["Windows Server 2022"]},
		"plugin": {"id": 99101, "cve": ["CVE-2026-96001"], "cvss3_base_score": 9.1, "cisa_kev": true}
	}]`)
	ingested, err := intakeCli.SubmitFinderIntake(ctx, "tenable", tenableIntake, warrantsdk.FinderIntakeOptions{
		PatchProfile: "UPSTREAM_VENDOR_PENDING",
	})
	if err != nil || len(ingested) != 1 {
		t.Fatalf("SubmitFinderIntake: err=%v items=%+v", err, ingested)
	}

	soCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithSignerBundle(soBundle))
	dispOK, err := soCli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: ingested[0].RemediationID,
		DistributorID: warrantsdk.DistributorMSMECM,
		FixIdentity: &warrantsdk.FixIdentity{
			CVEID:       "CVE-2026-96001",
			KBArticleID: "KB5044281",
		},
		TargetAssets: []warrantsdk.AssetTarget{{AssetKey: "payments-ledger-api", ServiceID: "payments-ledger-api"}},
	})
	if err != nil {
		t.Fatalf("DispatchDistributorOrder (RECORD_ONLY drift): %v", err)
	}
	if dispOK.Remediation.AttestationID == "" || dispOK.Remediation.CloneTwinProving == nil {
		t.Fatalf("expected minted attestation and CloneTwinProvingManifest, got: %+v", dispOK.Remediation)
	}
	ctp := dispOK.Remediation.CloneTwinProving
	if ctp.CloneSourceResolutionPath != warrantsdk.CloneSourceResolutionSignedClass ||
		ctp.SigningSnapshotSHA256 != propMECM.ProposedEstateSnapshotSHA256 ||
		ctp.ProvingSnapshotSHA256 == "" ||
		ctp.SigningSnapshotSHA256 == ctp.ProvingSnapshotSHA256 ||
		!ctp.DriftExceeded ||
		ctp.ObservedDriftPct < 49.0 ||
		len(ctp.ResolvedCloneSources) != 1 ||
		ctp.ResolvedCloneSources[0].ImageIdentity != "wim://mecm-win2022-qa-v1" ||
		ctp.ResolvedCloneSources[0].ImageAgeSeconds <= 0 {
		t.Fatalf("unexpected CloneTwinProvingManifest estate drift/source evidence: %+v", ctp)
	}

	// Verify exported NIST OSCAL 1.1.2 POA&M carries both snapshot hashes, timestamps, clone source identity & age, and verifies offline!
	oscalRaw, err := adminCli.ExportOSCALBundle(ctx, dispOK.Remediation.AttestationID)
	if err != nil {
		t.Fatalf("ExportOSCALBundle: %v", err)
	}
	oscalStr := string(oscalRaw)
	for _, needle := range []string{
		"SIGNED_CLASS",
		ctp.SigningSnapshotSHA256,
		ctp.ProvingSnapshotSHA256,
		"wim://mecm-win2022-qa-v1",
		"clone-source-0-age-seconds",
		"observed-drift-pct",
	} {
		if !strings.Contains(oscalStr, needle) {
			t.Fatalf("minted OSCAL 1.1.2 POA&M missing expected Estate Loader evidence %q", needle)
		}
	}
	kPubB64 := base64.StdEncoding.EncodeToString(orch.N5Ledger.KernelPublicKey().PublicKeyBytes)
	if offVer, vErr := warrantsdk.VerifyOSCALBundleOffline(oscalRaw, kPubB64); vErr != nil || !offVer.Valid {
		t.Fatalf("offline OSCAL verification failed: err=%v res=%+v", vErr, offVer)
	}

	// -------------------------------------------------------------------------
	// End-to-End Lifecycle 2: FAIL_CLOSED Drift Policy Blocks Proving Run
	// -------------------------------------------------------------------------
	mu.Lock()
	mecmMemberCount = 120
	mu.Unlock()
	propStrict, err := readCli.ProposeEstateClass(ctx, warrantsdk.EstateProposalRequest{
		SourceSystem:      "ms-mecm",
		WarrantClass:      "MECM-STRICT-CLASS",
		ScopeServices:     []string{"payments-ledger-api"},
		EstateDriftPolicy: warrantsdk.EstateDriftPolicyFailClosed,
		DriftTolerancePct: 5.0,
	})
	if err != nil {
		t.Fatal(err)
	}
	wStrictEnv, _, _ := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:               "wrt-inv20-strict",
		WarrantClass:            "MECM-STRICT-CLASS",
		ScopeServices:           []string{"payments-ledger-api"},
		MaxCVSS:                 10.0,
		KEVEligible:             true,
		MaxBlastRadiusReplicas:  8,
		CloneSources:            propStrict.ProposedCloneSources,
		EstateSnapshotSHA256:    propStrict.ProposedEstateSnapshotSHA256,
		EstateDriftPolicy:       warrantsdk.EstateDriftPolicyFailClosed,
		EstateDriftTolerancePct: 5.0,
	})
	_ = soBundle.SignEnvelope(1, wStrictEnv)
	_ = aoBundle.SignEnvelope(2, wStrictEnv)
	if _, err := adminCli.CreateWarrant(ctx, *wStrictEnv); err != nil {
		t.Fatalf("CreateWarrant(strict): %v", err)
	}

	// Drift 120 -> 200 (66.7% > 5% FAIL_CLOSED)
	mu.Lock()
	mecmMemberCount = 200
	mu.Unlock()
	tenable2 := []byte(`[{
		"state": "OPEN",
		"asset": {"asset_key": "payments-ledger-api", "service_id": "payments-ledger-api"},
		"plugin": {"id": 99102, "cve": ["CVE-2026-96002"], "cvss3_base_score": 9.0, "cisa_kev": true}
	}]`)
	ing2, _ := intakeCli.SubmitFinderIntake(ctx, "tenable", tenable2, warrantsdk.FinderIntakeOptions{PatchProfile: "UPSTREAM_VENDOR_PENDING"})
	if _, fErr := soCli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: ing2[0].RemediationID,
		DistributorID: warrantsdk.DistributorMSMECM,
		FixIdentity:   &warrantsdk.FixIdentity{CVEID: "CVE-2026-96002", KBArticleID: "KB5044299"},
		TargetAssets:  []warrantsdk.AssetTarget{{AssetKey: "payments-ledger-api", ServiceID: "payments-ledger-api"}},
	}); fErr == nil || !strings.Contains(fErr.Error(), "ESTATE_DRIFT_TOLERANCE_EXCEEDED") {
		t.Fatalf("expected FAIL_CLOSED drift to abort with ESTATE_DRIFT_TOLERANCE_EXCEEDED, got: %v", fErr)
	}

	// -------------------------------------------------------------------------
	// End-to-End Lifecycle 3: Unavailable at Proving on KERNEL Class Defaults Strictly to FAIL_CLOSED
	// -------------------------------------------------------------------------
	mu.Lock()
	mecmMemberCount = 120
	mecmUnavailable = false
	mu.Unlock()
	propKern, _ := readCli.ProposeEstateClass(ctx, warrantsdk.EstateProposalRequest{
		SourceSystem:  "ms-mecm",
		WarrantClass:  "KERNEL-DEFAULT-DRIFT",
		ScopeServices: []string{"payments-ledger-api"},
	})
	// Note: EstateDriftPolicy intentionally omitted ("") to prove KERNEL defaults to FAIL_CLOSED when re-read is unavailable!
	wKernEnv, _, _ := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:              "wrt-inv20-kern-default",
		WarrantClass:           "KERNEL-DEFAULT-DRIFT",
		ScopeServices:          []string{"payments-ledger-api"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 8,
		CloneSources:           propKern.ProposedCloneSources,
		EstateSnapshotSHA256:   propKern.ProposedEstateSnapshotSHA256,
	})
	_ = soBundle.SignEnvelope(1, wKernEnv)
	_ = aoBundle.SignEnvelope(2, wKernEnv)
	if _, err := adminCli.CreateWarrant(ctx, *wKernEnv); err != nil {
		t.Fatalf("CreateWarrant(kern): %v", err)
	}

	mu.Lock()
	mecmUnavailable = true
	mu.Unlock()
	tenable3 := []byte(`[{
		"state": "OPEN",
		"asset": {"asset_key": "payments-ledger-api", "service_id": "payments-ledger-api"},
		"plugin": {"id": 99103, "cve": ["CVE-2026-96003"], "cvss3_base_score": 9.3, "cisa_kev": true}
	}]`)
	ing3, _ := intakeCli.SubmitFinderIntake(ctx, "tenable", tenable3, warrantsdk.FinderIntakeOptions{PatchProfile: "UPSTREAM_VENDOR_PENDING"})
	if _, kErr := soCli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: ing3[0].RemediationID,
		DistributorID: warrantsdk.DistributorMSMECM,
		FixIdentity:   &warrantsdk.FixIdentity{CVEID: "CVE-2026-96003", PackageNEVRA: "kernel-core-6.8.0-50.el9.x86_64"},
		TargetAssets:  []warrantsdk.AssetTarget{{AssetKey: "payments-ledger-api", ServiceID: "payments-ledger-api"}},
	}); kErr == nil || !strings.Contains(kErr.Error(), "ESTATE_REREAD_UNAVAILABLE_FAIL_CLOSED") {
		t.Fatalf("expected KERNEL proving unavailability to default FAIL_CLOSED (ESTATE_REREAD_UNAVAILABLE_FAIL_CLOSED), got: %v", kErr)
	}

	// -------------------------------------------------------------------------
	// End-to-End Lifecycle 4: Unavailable at Signing Rejects ESTATE_LOADER & Allows Explicit MANUAL; Tier B K8s Lifecycle
	// -------------------------------------------------------------------------
	if _, wsusErr := readCli.ProposeEstateClass(ctx, warrantsdk.EstateProposalRequest{
		SourceSystem:  "ms-wsus",
		WarrantClass:  "WSUS-OFFLINE-TEST",
		ScopeServices: []string{"payments-ledger-api"},
	}); wsusErr == nil || !strings.Contains(wsusErr.Error(), "ESTATE_READ_UNAVAILABLE_AT_SIGNING") {
		t.Fatalf("expected ESTATE_READ_UNAVAILABLE_AT_SIGNING for offline ms-wsus, got: %v", wsusErr)
	}

	// Forging an unrecorded ESTATE_LOADER snapshot_sha256 at signing MUST fail closed
	wForgedEnv, _, _ := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:              "wrt-inv20-forged",
		WarrantClass:           "WSUS-OFFLINE-TEST",
		ScopeServices:          []string{"payments-ledger-api"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 8,
		CloneSources: []warrantsdk.DeclaredCloneSource{{
			SourceSystem:   "ms-wsus",
			ImageIdentity:  `D:\HyperV\Golden\wsus-win2019-qa.vhdx`,
			SnapshotSHA256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			SourceMode:     warrantsdk.CloneSourceModeEstateLoader,
			DeclaredAt:     time.Now().UTC().Format(time.RFC3339),
		}},
	})
	_ = soBundle.SignEnvelope(1, wForgedEnv)
	_ = aoBundle.SignEnvelope(2, wForgedEnv)
	if _, forgeErr := adminCli.CreateWarrant(ctx, *wForgedEnv); forgeErr == nil || !strings.Contains(forgeErr.Error(), "ESTATE_READ_UNAVAILABLE_AT_SIGNING") {
		t.Fatalf("expected unrecorded ESTATE_LOADER snapshot to be rejected at signing, got: %v", forgeErr)
	}

	// Explicit MANUAL override (zero fabricated snapshot hash) succeeds and tags manifest SIGNED_CLASS_MANUAL
	wManualEnv, _, _ := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:              "wrt-inv20-manual",
		WarrantClass:           "WSUS-MANUAL-OVERRIDE",
		ScopeServices:          []string{"payments-ledger-api"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 8,
		CloneSources: []warrantsdk.DeclaredCloneSource{{
			SourceSystem:  "ms-wsus",
			ImageIdentity: `D:\HyperV\Golden\manual-override.vhdx`,
			SourceMode:    warrantsdk.CloneSourceModeManual,
			DeclaredAt:    time.Now().UTC().Format(time.RFC3339),
		}},
	})
	_ = soBundle.SignEnvelope(1, wManualEnv)
	_ = aoBundle.SignEnvelope(2, wManualEnv)
	if _, mErr := adminCli.CreateWarrant(ctx, *wManualEnv); mErr != nil {
		t.Fatalf("expected explicit MANUAL clone source override to succeed: %v", mErr)
	}
	tenable4 := []byte(`[{
		"state": "OPEN",
		"asset": {"asset_key": "payments-ledger-api", "service_id": "payments-ledger-api"},
		"plugin": {"id": 99104, "cve": ["CVE-2026-96004"], "cvss3_base_score": 8.9, "cisa_kev": true}
	}]`)
	ing4, _ := intakeCli.SubmitFinderIntake(ctx, "tenable", tenable4, warrantsdk.FinderIntakeOptions{PatchProfile: "UPSTREAM_VENDOR_PENDING"})
	dispManual, err := soCli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: ing4[0].RemediationID,
		DistributorID: warrantsdk.DistributorMSMECM,
		FixIdentity:   &warrantsdk.FixIdentity{CVEID: "CVE-2026-96004", KBArticleID: "KB5044300"},
		TargetAssets:  []warrantsdk.AssetTarget{{AssetKey: "payments-ledger-api", ServiceID: "payments-ledger-api"}},
	})
	if err != nil || dispManual.Remediation.CloneTwinProving == nil || dispManual.Remediation.CloneTwinProving.CloneSourceResolutionPath != warrantsdk.CloneSourceResolutionSignedClassManual {
		t.Fatalf("expected SIGNED_CLASS_MANUAL resolution path, err=%v ctp=%+v", err, dispManual.Remediation.CloneTwinProving)
	}

	// Tier B (k8s-cilium-native) CONTAINER_TWIN lifecycle
	propK8s, err := readCli.ProposeEstateClass(ctx, warrantsdk.EstateProposalRequest{
		SourceSystem:  "k8s-cilium-native",
		WarrantClass:  "K8S-TIERB-CLASS",
		ScopeServices: []string{"payments-ledger-api"},
	})
	if err != nil || propK8s.PrimarySnapshot.SourceTier != warrantsdk.EstateSourceTierBWorkload {
		t.Fatalf("ProposeEstateClass(k8s-cilium-native): err=%v prop=%+v", err, propK8s)
	}
	wK8sEnv, _, _ := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:              "wrt-inv20-k8s",
		WarrantClass:           "K8S-TIERB-CLASS",
		ScopeServices:          []string{"payments-ledger-api"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 8,
		CloneSources:           propK8s.ProposedCloneSources,
		EstateSnapshotSHA256:   propK8s.ProposedEstateSnapshotSHA256,
	})
	_ = soBundle.SignEnvelope(1, wK8sEnv)
	_ = aoBundle.SignEnvelope(2, wK8sEnv)
	if _, err := adminCli.CreateWarrant(ctx, *wK8sEnv); err != nil {
		t.Fatalf("CreateWarrant(k8s): %v", err)
	}
	sarifPayload := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "Trivy"}},
			"results": [{
				"ruleId": "CVE-2026-96005",
				"properties": {
					"cve_id": "CVE-2026-96005",
					"cwe_id": "CWE-787",
					"cvss_score": 9.4,
					"is_kev": true,
					"service_id": "payments-ledger-api",
					"package_purl": "pkg:golang/golang.org/x/net@0.28.0",
					"vulnerable_digest": "sha256:a100000000000000000000000000000000000000000000000000000000000001",
					"patched_digest": "sha256:b200000000000000000000000000000000000000000000000000000000000002"
				}
			}]
		}]
	}`)
	k8sItems, err := intakeCli.IngestSARIF(ctx, sarifPayload, warrantsdk.SARIFIntakeOptions{Profile: "STATELESS_CLEAN"})
	if err != nil || len(k8sItems) != 1 || k8sItems[0].CloneTwinProving == nil || k8sItems[0].CloneTwinProving.CloneSourceResolutionPath != warrantsdk.CloneSourceResolutionSignedClass {
		t.Fatalf("Tier B k8s-cilium-native proving failed: err=%v items=%+v", err, k8sItems)
	}

	// -------------------------------------------------------------------------
	// Structural Assertion (a): No-Replication Schema & Bounded Evidence Row Audit
	// -------------------------------------------------------------------------
	rows, err := store.Pool().Query(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'public' ORDER BY table_name ASC
	`)
	if err != nil {
		t.Fatal(err)
	}
	var publicTables []string
	for rows.Next() {
		var tn string
		_ = rows.Scan(&tn)
		publicTables = append(publicTables, tn)
	}
	rows.Close()

	forbiddenMirrorSubstrings := []string{
		"estate_hosts", "estate_assets", "estate_devices", "estate_machines",
		"asset_inventory", "host_inventory", "device_inventory", "software_inventory",
	}
	for _, tbl := range publicTables {
		for _, bad := range forbiddenMirrorSubstrings {
			if strings.Contains(tbl, bad) {
				t.Fatalf("NO_REPLICATION_DOCTRINE_VIOLATION: forbidden asset/host mirror table %q exists in schema", tbl)
			}
		}
	}

	evRows, err := readCli.ListEstateEvidence(ctx, "", "")
	if err != nil || len(evRows) < 6 {
		t.Fatalf("expected bounded estate_read_evidence rows recorded, err=%v count=%d", err, len(evRows))
	}
	// Verify WORM immutability trigger blocks UPDATE/DELETE on estate_read_evidence
	if _, uErr := store.Pool().Exec(ctx, `DELETE FROM estate_read_evidence`); uErr == nil || !strings.Contains(uErr.Error(), "IMMUTABLE_LEDGER_VIOLATION") {
		t.Fatalf("expected WORM trigger to reject DELETE on estate_read_evidence, got: %v", uErr)
	}

	// Verify all ledger chains (including estate_read_evidence!) pass SHA-256 verification
	ledgerRep, err := adminCli.VerifyLedgerChains(ctx)
	if err != nil || !ledgerRep.AllValid || len(ledgerRep.EstateEvidenceTables) != 1 || !ledgerRep.EstateEvidenceTables[0].Valid {
		t.Fatalf("VerifyLedgerChains failed: err=%v rep=%+v", err, ledgerRep)
	}
}
