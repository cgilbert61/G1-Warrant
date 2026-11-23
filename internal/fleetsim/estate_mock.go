package fleetsim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

type demoServerSeed struct {
	ServerID       string
	Hostname       string
	ServiceID      string
	OSFamily       string
	OSVersion      string
	KernelRelease  string
	OSCPE23        string
	PackageName    string
	PackageVersion string
	PackagePURL    string
	PlatformFamily string
	TwinImageID    string
}

func defaultDemoServices() []string {
	return []string{
		"payments-ledger-api",
		"identity-sso-gateway",
		"fulfillment-worker",
		"checkout-cart-svc",
		"ledger-audit-sink",
		"fraud-scoring-engine",
	}
}

func parseRequestedDemoServices(r *http.Request, bodyMap map[string]any) []string {
	var rawList []string
	for _, qp := range []string{"scope", "services", "search"} {
		if v := strings.TrimSpace(r.URL.Query().Get(qp)); v != "" {
			for _, part := range strings.Split(v, ",") {
				if p := strings.TrimSpace(part); p != "" && p != "*" {
					rawList = append(rawList, p)
				}
			}
		}
	}
	if len(rawList) == 0 && bodyMap != nil {
		for _, bk := range []string{"scope_services", "ScopeServices", "scope_filter"} {
			if arr, ok := bodyMap[bk].([]any); ok {
				for _, item := range arr {
					if s := strings.TrimSpace(fmt.Sprintf("%v", item)); s != "" && s != "*" {
						rawList = append(rawList, s)
					}
				}
			}
		}
	}
	if len(rawList) == 0 {
		return defaultDemoServices()[:2]
	}
	return rawList
}

func shortSvcSlug(svc string) string {
	switch svc {
	case "payments-ledger-api":
		return "pay"
	case "identity-sso-gateway":
		return "sso"
	case "fulfillment-worker":
		return "fulfill"
	case "checkout-cart-svc":
		return "cart"
	case "ledger-audit-sink":
		return "audit"
	case "fraud-scoring-engine":
		return "fraud"
	default:
		s := strings.ReplaceAll(strings.ToLower(svc), "_", "-")
		if len(s) > 10 {
			return s[:10]
		}
		return s
	}
}

func buildDemoServersForSystem(sys string, services []string, cs *ClusterSimulator) []demoServerSeed {
	var out []demoServerSeed
	for _, svc := range services {
		slug := shortSvcSlug(svc)
		switch sys {
		case "ms-intune", "ms-mecm", "ms-wsus", "azure-update-manager":
			imgPrefix := "vhdx://qa-golden/"
			if sys == "ms-mecm" {
				imgPrefix = "wim://mecm-qa/"
			} else if sys == "azure-update-manager" {
				imgPrefix = "/subscriptions/demo-qa/resourceGroups/rg-qa/providers/Microsoft.Compute/images/"
			}
			for idx := 1; idx <= 2; idx++ {
				host := fmt.Sprintf("win-%s-%02d.corp.internal", slug, idx)
				build := "10.0.20348.2655"
				if idx == 2 {
					build = "10.0.20348.2700"
				}
				out = append(out, demoServerSeed{
					ServerID:       fmt.Sprintf("%s-%s-%02d", sys, slug, idx),
					Hostname:       host,
					ServiceID:      svc,
					OSFamily:       "WINDOWS",
					OSVersion:      build,
					KernelRelease:  "NT-" + build,
					OSCPE23:        "cpe:2.3:o:microsoft:windows_server_2022:21h2:*:*:*:*:*:*:*",
					PackageName:    "Windows-Cumulative-Security-Update",
					PackageVersion: "KB5043050",
					PackagePURL:    "pkg:generic/microsoft/windows-kb@KB5043050",
					PlatformFamily: "WINDOWS_SERVER",
					TwinImageID:    fmt.Sprintf("%swin-%s-%02d-srv2022", imgPrefix, slug, idx),
				})
			}

		case "aws-ssm":
			for idx := 1; idx <= 2; idx++ {
				osVer := "Amazon Linux 2023.5"
				kern := "6.1.102-111.182.amzn2023.x86_64"
				if idx == 2 {
					osVer = "RHEL 9.4"
					kern = "5.14.0-427.31.1.el9_4.x86_64"
				}
				out = append(out, demoServerSeed{
					ServerID:       fmt.Sprintf("i-0a91f40%s%02d", slug, idx),
					Hostname:       fmt.Sprintf("ec2-%s-%02d.us-east-1.internal", slug, idx),
					ServiceID:      svc,
					OSFamily:       "LINUX",
					OSVersion:      osVer,
					KernelRelease:  kern,
					OSCPE23:        "cpe:2.3:o:amazon:amazon_linux:2023:*:*:*:*:*:*:*",
					PackageName:    "openssl",
					PackageVersion: "3.0.8-2.amzn2023",
					PackagePURL:    "pkg:rpm/amzn/openssl@3.0.8-2.amzn2023",
					PlatformFamily: "LINUX_RPM",
					TwinImageID:    fmt.Sprintf("ami-0qa8812ec2%s%02d", slug, idx),
				})
			}

		case "gcp-os-config":
			for idx := 1; idx <= 2; idx++ {
				out = append(out, demoServerSeed{
					ServerID:       fmt.Sprintf("gce-%s-%02d", slug, idx),
					Hostname:       fmt.Sprintf("gce-%s-%02d.us-central1.internal", slug, idx),
					ServiceID:      svc,
					OSFamily:       "LINUX",
					OSVersion:      "Debian 12.7 (Bookworm)",
					KernelRelease:  "6.1.0-25-cloud-amd64",
					OSCPE23:        "cpe:2.3:o:debian:debian_linux:12.7:*:*:*:*:*:*:*",
					PackageName:    "libssl3",
					PackageVersion: "3.0.14-1~deb12u2",
					PackagePURL:    "pkg:deb/debian/libssl3@3.0.14-1~deb12u2",
					PlatformFamily: "LINUX_DEB",
					TwinImageID:    fmt.Sprintf("projects/demo-qa/global/machineImages/gce-%s-%02d-deb12", slug, idx),
				})
			}

		case "k8s-cilium-native", "argocd", "flux":
			digest := fmt.Sprintf("sha256:de00%s00000000000000000000000000000000000000000000000000000001", fmt.Sprintf("%-4s", slug)[:4])
			digest = strings.ReplaceAll(digest, " ", "0")
			if cs != nil {
				cs.mu.RLock()
				if wl, ok := cs.workloads[svc]; ok && wl.BaselineDigest != "" {
					digest = wl.BaselineDigest
				}
				cs.mu.RUnlock()
			}
			for idx := 1; idx <= 2; idx++ {
				imgRef := digest
				if idx == 2 {
					imgRef = fmt.Sprintf("oci://staging.internal/%s-replica-%02d@%s", svc, idx, digest)
				}
				out = append(out, demoServerSeed{
					ServerID:       fmt.Sprintf("%s-pod-%s-%02d", sys, slug, idx),
					Hostname:       fmt.Sprintf("%s-replica-%02d.prod.svc.cluster.local", svc, idx),
					ServiceID:      svc,
					OSFamily:       "CONTAINER_LINUX",
					OSVersion:      "distroless-static-debian12",
					KernelRelease:  "6.6.32-cilium-k8s",
					OSCPE23:        "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*",
					PackageName:    svc,
					PackageVersion: digest,
					PackagePURL:    fmt.Sprintf("pkg:oci/%s@%s", svc, digest),
					PlatformFamily: "CONTAINER_LINUX",
					TwinImageID:    imgRef,
				})
			}

		case "jamf-pro":
			for idx := 1; idx <= 2; idx++ {
				out = append(out, demoServerSeed{
					ServerID:       fmt.Sprintf("jamf-mac-%s-%02d", slug, idx),
					Hostname:       fmt.Sprintf("mac-%s-%02d.corp.internal", slug, idx),
					ServiceID:      svc,
					OSFamily:       "MACOS",
					OSVersion:      "14.6.1",
					KernelRelease:  "23G93",
					OSCPE23:        "cpe:2.3:o:apple:macos:14.6.1:*:*:*:*:*:*:*",
					PackageName:    "curl-macos",
					PackageVersion: "8.7.1",
					PackagePURL:    "pkg:generic/apple/curl@8.7.1",
					PlatformFamily: "MACOS",
					TwinImageID:    fmt.Sprintf("ipsw://qa-apple/macos14-6-1-%s-%02d.ipsw", slug, idx),
				})
			}

		case "redhat-satellite", "ansible-awx":
			for idx := 1; idx <= 2; idx++ {
				out = append(out, demoServerSeed{
					ServerID:       fmt.Sprintf("%s-%s-%02d", sys, slug, idx),
					Hostname:       fmt.Sprintf("rhel-%s-%02d.corp.internal", slug, idx),
					ServiceID:      svc,
					OSFamily:       "RHEL",
					OSVersion:      "9.4",
					KernelRelease:  "5.14.0-427.31.1.el9_4.x86_64",
					OSCPE23:        "cpe:2.3:o:redhat:enterprise_linux:9.4:*:*:*:*:*:*:*",
					PackageName:    "kernel-core",
					PackageVersion: "5.14.0-427.31.1.el9_4.x86_64",
					PackagePURL:    "pkg:rpm/redhat/kernel-core@5.14.0-427.31.1.el9_4",
					PlatformFamily: "LINUX_RPM",
					TwinImageID:    fmt.Sprintf("qcow2://qa-linux/rhel94-%s-%02d-golden.qcow2", slug, idx),
				})
			}

		case "automox":
			for idx := 1; idx <= 2; idx++ {
				out = append(out, demoServerSeed{
					ServerID:       fmt.Sprintf("amx-%s-%02d", slug, idx),
					Hostname:       fmt.Sprintf("ubuntu-%s-%02d.corp.internal", slug, idx),
					ServiceID:      svc,
					OSFamily:       "LINUX",
					OSVersion:      "Ubuntu 24.04.1 LTS",
					KernelRelease:  "6.8.0-45-generic",
					OSCPE23:        "cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:*:*:*:*",
					PackageName:    "openssh-server",
					PackageVersion: "1:9.6p1-3ubuntu13.5",
					PackagePURL:    "pkg:deb/ubuntu/openssh-server@9.6p1-3ubuntu13.5",
					PlatformFamily: "LINUX_DEB",
					TwinImageID:    fmt.Sprintf("ami-0qa2404ubuntu%s%02d", slug, idx),
				})
			}

		default: // tanium-patch, ivanti-neurons, or any custom declarative REST source
			for idx := 1; idx <= 2; idx++ {
				osFam := "WINDOWS"
				osVer := "10.0.20348.2655"
				kern := "NT-10.0.20348"
				plat := "WINDOWS_SERVER"
				host := fmt.Sprintf("srv-%s-win-%02d.corp.internal", slug, idx)
				img := fmt.Sprintf("vhdx://%s-qa/srv-%s-win-%02d.vhdx", sys, slug, idx)
				if idx == 2 {
					osFam = "LINUX"
					osVer = "RHEL 9.4"
					kern = "5.14.0-427.31.1.el9_4.x86_64"
					plat = "LINUX_RPM"
					host = fmt.Sprintf("srv-%s-rhel-%02d.corp.internal", slug, idx)
					img = fmt.Sprintf("vhdx://%s-qa/srv-%s-rhel-%02d.vhdx", sys, slug, idx)
				}
				out = append(out, demoServerSeed{
					ServerID:       fmt.Sprintf("%s-ep-%s-%02d", sys, slug, idx),
					Hostname:       host,
					ServiceID:      svc,
					OSFamily:       osFam,
					OSVersion:      osVer,
					KernelRelease:  kern,
					OSCPE23:        "cpe:2.3:o:microsoft:windows_server_2022:21h2:*:*:*:*:*:*:*",
					PackageName:    "openssl-enterprise",
					PackageVersion: "3.0.14",
					PackagePURL:    "pkg:generic/openssl@3.0.14",
					PlatformFamily: plat,
					TwinImageID:    img,
				})
			}
		}
	}
	return out
}

// registerDemoEstateMockRoutes mounts wire-accurate Demo Estate mock inventory endpoints (/mock-estate/{system_id}/...)
// and Demo WN-8 Distributor endpoints (/mock-distributor/{system_id}/...) on fleet-sim for interactive demo & evaluation.
func (cs *ClusterSimulator) registerDemoEstateMockRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/mock-estate/", func(w http.ResponseWriter, r *http.Request) {
		// Enforce EstateReader read-role header & reject WN-8 dispatch tokens (Doctrine Rule 2)
		if r.Header.Get("X-Warrant-Read-Role") != models.AgentActionReadEstateSnapshot {
			writeSimJSON(w, http.StatusForbidden, map[string]string{
				"error": "CREDENTIAL_SEPARATION_VIOLATION: missing X-Warrant-Read-Role=READ_ESTATE_SNAPSHOT on mock estate read endpoint",
			})
			return
		}
		if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.Contains(strings.ToLower(auth), "demo-disp-") {
			writeSimJSON(w, http.StatusForbidden, map[string]string{
				"error": "CREDENTIAL_SEPARATION_VIOLATION: WN-8 dispatch token rejected on mock estate read endpoint",
			})
			return
		}

		trimmed := strings.TrimPrefix(r.URL.Path, "/mock-estate/")
		parts := strings.SplitN(trimmed, "/", 2)
		sys := strings.ToLower(strings.TrimSpace(parts[0]))
		if sys == "" {
			writeSimJSON(w, http.StatusBadRequest, map[string]string{"error": "missing system_id in /mock-estate/{system_id}/..."})
			return
		}

		var bodyMap map[string]any
		if r.Body != nil && r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&bodyMap)
		}

		now := time.Now().UTC()
		freshISO := now.Add(-90 * time.Second).Format(time.RFC3339)
		createdISO := now.Add(-18 * time.Hour).Format(time.RFC3339)
		services := parseRequestedDemoServices(r, bodyMap)

		// Family (e): Tier C Scanners (Qualys, Tenable, Rapid7) — census corroboration ONLY (0 clone sources)
		switch sys {
		case "qualys_vmdr", "qualys":
			var hosts []map[string]any
			for i, svc := range services {
				for h := 1; h <= 2; h++ {
					hosts = append(hosts, map[string]any{
						"id":              fmt.Sprintf("990%d%d", i+1, h),
						"dns":             fmt.Sprintf("srv-%s-%02d.corp.internal", shortSvcSlug(svc), h),
						"os":              "Windows Server 2022",
						"service_id":      svc,
						"last_scan_at":    freshISO,
						"detections": []map[string]any{
							{
								"qid":          91992,
								"severity":     5,
								"status":       "Active",
								"cves":         []string{"CVE-2026-41001"},
								"kb_article":   "KB5043050",
								"last_seen_at": freshISO,
							},
						},
					})
				}
			}
			writeSimJSON(w, http.StatusOK, map[string]any{"hosts": hosts})
			return

		case "tenable":
			var findings []map[string]any
			for i, svc := range services {
				for h := 1; h <= 2; h++ {
					findings = append(findings, map[string]any{
						"asset": map[string]any{
							"uuid":             fmt.Sprintf("00000000-0000-0000-000%d-00000000000%d", i+1, h),
							"fqdn":             fmt.Sprintf("srv-%s-%02d.corp.internal", shortSvcSlug(svc), h),
							"operating_system": []string{"Linux Kernel 6.1"},
							"tags":             map[string]string{"service_id": svc},
						},
						"plugin": map[string]any{
							"id":   195001,
							"cve":  []string{"CVE-2026-41001"},
							"cvss3_base_score": 9.1,
						},
						"state":     "OPEN",
						"last_seen": freshISO,
					})
				}
			}
			writeSimJSON(w, http.StatusOK, map[string]any{"findings": findings})
			return

		case "rapid7_insightvm", "rapid7":
			var resources []map[string]any
			for i, svc := range services {
				for h := 1; h <= 2; h++ {
					resources = append(resources, map[string]any{
						"id":        (i+1)*100 + h,
						"hostName":  fmt.Sprintf("srv-%s-%02d.corp.internal", shortSvcSlug(svc), h),
						"os":        "Red Hat Enterprise Linux 9.4",
						"serviceId": svc,
						"vulnerabilities": []map[string]any{
							{
								"id":         "rhel-cve-2026-41001",
								"cves":       []string{"CVE-2026-41001"},
								"cvssScore":  8.8,
								"status":     "vulnerable",
								"lastSeenAt": freshISO,
							},
						},
					})
				}
			}
			writeSimJSON(w, http.StatusOK, map[string]any{"resources": resources})
			return
		}

		seeds := buildDemoServersForSystem(sys, services, cs)

		// Family (a): Microsoft Estate (`ms-intune`, `azure-update-manager`, `ms-mecm`, `ms-wsus`)
		switch sys {
		case "ms-intune", "azure-update-manager", "ms-mecm", "ms-wsus":
			var valRows []map[string]any
			var images []map[string]any
			for _, s := range seeds {
				valRows = append(valRows, map[string]any{
					"id":               s.ServerID,
					"deviceName":       s.Hostname,
					"serviceId":        s.ServiceID,
					"operatingSystem":  s.OSFamily,
					"osVersion":        s.OSVersion,
					"kernelRelease":    s.KernelRelease,
					"cpe23":            s.OSCPE23,
					"softwareName":     s.PackageName,
					"softwareVersion":  s.PackageVersion,
					"purl":             s.PackagePURL,
					"qaImageId":        s.TwinImageID,
					"platformFamily":   s.PlatformFamily,
					"imageCreatedAt":   createdISO,
					"lastSyncDateTime": freshISO,
					"count":            1,
				})
				images = append(images, map[string]any{
					"image_id":        s.TwinImageID,
					"platform_family": s.PlatformFamily,
					"created_at":      createdISO,
					"tags": map[string]string{
						"server_id":  s.ServerID,
						"hostname":   s.Hostname,
						"service_id": s.ServiceID,
					},
				})
			}
			writeSimJSON(w, http.StatusOK, map[string]any{
				"total_count":      len(seeds),
				"freshness_at":     freshISO,
				"lastSyncDateTime": freshISO,
				"value":            valRows,
				"data":             valRows,
				"images":           images,
			})
			return

		// Family (b): Cloud Inventory (`aws-ssm`, `gcp-os-config`)
		case "aws-ssm", "gcp-os-config":
			var entities []map[string]any
			var candImgs []map[string]any
			for _, s := range seeds {
				entities = append(entities, map[string]any{
					"Id":              s.ServerID,
					"ComputerName":    s.Hostname,
					"ServiceId":       s.ServiceID,
					"PlatformType":    s.OSFamily,
					"PlatformVersion": s.OSVersion,
					"KernelRelease":   s.KernelRelease,
					"cpe23":           s.OSCPE23,
					"PackageName":     s.PackageName,
					"PackageVersion":  s.PackageVersion,
					"PackagePurl":     s.PackagePURL,
					"qaImageId":       s.TwinImageID,
					"imageCreatedAt":  createdISO,
					"CaptureTime":     freshISO,
					"count":           1,
				})
				candImgs = append(candImgs, map[string]any{
					"image_id":        s.TwinImageID,
					"platform_family": s.PlatformFamily,
					"created_at":      createdISO,
					"tags": map[string]string{
						"server_id":  s.ServerID,
						"hostname":   s.Hostname,
						"service_id": s.ServiceID,
					},
				})
			}
			writeSimJSON(w, http.StatusOK, map[string]any{
				"total_instances":               len(seeds),
				"capture_time":                  freshISO,
				"updateTime":                    freshISO,
				"Entities":                      entities,
				"instanceOSPoliciesCompliances": entities,
				"candidate_images":              candImgs,
			})
			return

		// Family (c): Kubernetes API (`k8s-cilium-native`, `argocd`, `flux`)
		case "k8s-cilium-native", "argocd", "flux":
			var items []map[string]any
			var staging []map[string]any
			for _, s := range seeds {
				items = append(items, map[string]any{
					"metadata": map[string]any{
						"name":              s.Hostname,
						"namespace":         "prod",
						"creationTimestamp": createdISO,
						"uid":               s.ServerID,
						"serviceId":         s.ServiceID,
					},
					"spec": map[string]any{"replicas": 1},
					"status": map[string]any{
						"readyReplicas": 1,
						"imageID":       s.PackageVersion,
						"stagingDigest": s.TwinImageID,
						"nodeKernel":    s.KernelRelease,
					},
				})
				staging = append(staging, map[string]any{
					"image_id":        s.TwinImageID,
					"platform_family": "CONTAINER_LINUX",
					"created_at":      createdISO,
					"tags": map[string]string{
						"server_id":  s.ServerID,
						"hostname":   s.Hostname,
						"service_id": s.ServiceID,
					},
				})
			}
			writeSimJSON(w, http.StatusOK, map[string]any{
				"total_pods":            len(seeds),
				"freshness_at":          freshISO,
				"items":                 items,
				"staging_clone_sources": staging,
			})
			return

		// Family (d): Declarative REST Endpoint Managers (`tanium-patch`, `ivanti-neurons`, `automox`, `jamf-pro`, `redhat-satellite`, `ansible-awx`)
		case "tanium-patch":
			var eps, imgs []map[string]any
			for _, s := range seeds {
				eps = append(eps, map[string]any{
					"server_id":           s.ServerID,
					"hostname":            s.Hostname,
					"service_id":          s.ServiceID,
					"twin_image_identity": s.TwinImageID,
					"platform_family":     s.PlatformFamily,
					"count":               1,
					"os": map[string]any{
						"platform":   s.OSFamily,
						"generation": s.OSVersion,
						"kernel":     s.KernelRelease,
						"cpe23":      s.OSCPE23,
					},
					"installed_applications": []map[string]any{
						{"name": s.PackageName, "version": s.PackageVersion, "purl": s.PackagePURL},
					},
				})
				imgs = append(imgs, map[string]any{
					"image_identity":  s.TwinImageID,
					"platform_family": s.PlatformFamily,
					"created_at":      createdISO,
				})
			}
			writeSimJSON(w, http.StatusOK, map[string]any{
				"data": map[string]any{
					"total_count":       len(seeds),
					"last_collected_at": freshISO,
					"endpoints":         eps,
					"golden_images":     imgs,
				},
			})
			return

		case "ivanti-neurons":
			var devs, tmpls []map[string]any
			for _, s := range seeds {
				devs = append(devs, map[string]any{
					"server_id":           s.ServerID,
					"hostname":            s.Hostname,
					"service_id":          s.ServiceID,
					"twin_image_identity": s.TwinImageID,
					"platform_family":     s.PlatformFamily,
					"device_count":        1,
					"os_family":           s.OSFamily,
					"os_build":            s.OSVersion,
					"kernel_version":      s.KernelRelease,
					"os_cpe23":            s.OSCPE23,
					"software": []map[string]any{
						{"product_name": s.PackageName, "product_version": s.PackageVersion},
					},
				})
				tmpls = append(tmpls, map[string]any{
					"template_image_id": s.TwinImageID,
					"platform_family":   s.PlatformFamily,
					"created_at":        createdISO,
				})
			}
			writeSimJSON(w, http.StatusOK, map[string]any{
				"total_devices":          len(seeds),
				"inventory_synced_at":    freshISO,
				"devices":                devs,
				"provisioning_templates": tmpls,
			})
			return

		case "automox":
			var res, imgs []map[string]any
			for _, s := range seeds {
				res = append(res, map[string]any{
					"server_id":           s.ServerID,
					"hostname":            s.Hostname,
					"service_id":          s.ServiceID,
					"twin_image_identity": s.TwinImageID,
					"platform_family":     s.PlatformFamily,
					"count":               1,
					"os_family":           s.OSFamily,
					"os_version":          s.OSVersion,
					"kernel_version":      s.KernelRelease,
					"cpe23":               s.OSCPE23,
					"packages": []map[string]any{
						{"display_name": s.PackageName, "version": s.PackageVersion, "purl": s.PackagePURL},
					},
				})
				imgs = append(imgs, map[string]any{
					"image_id":        s.TwinImageID,
					"platform_family": s.PlatformFamily,
					"created_at":      createdISO,
				})
			}
			writeSimJSON(w, http.StatusOK, map[string]any{
				"total_servers":     len(seeds),
				"last_refresh_time": freshISO,
				"results":           res,
				"qa_images":         imgs,
			})
			return

		case "jamf-pro":
			var res, imgs []map[string]any
			for _, s := range seeds {
				res = append(res, map[string]any{
					"server_id":           s.ServerID,
					"hostname":            s.Hostname,
					"service_id":          s.ServiceID,
					"twin_image_identity": s.TwinImageID,
					"platform_family":     s.PlatformFamily,
					"count":               1,
					"operatingSystem": map[string]any{
						"name":    s.OSFamily,
						"version": s.OSVersion,
						"build":   s.KernelRelease,
						"cpe23":   s.OSCPE23,
					},
					"applications": []map[string]any{
						{"name": s.PackageName, "version": s.PackageVersion},
					},
				})
				imgs = append(imgs, map[string]any{
					"ipswImageId":    s.TwinImageID,
					"platformFamily": s.PlatformFamily,
					"createdAt":      createdISO,
				})
			}
			writeSimJSON(w, http.StatusOK, map[string]any{
				"totalCount":              len(seeds),
				"lastInventoryUpdateDate": freshISO,
				"results":                 res,
				"macosRestoreImages":      imgs,
			})
			return

		case "redhat-satellite":
			var res, imgs []map[string]any
			for _, s := range seeds {
				res = append(res, map[string]any{
					"server_id":               s.ServerID,
					"hostname":                s.Hostname,
					"service_id":              s.ServiceID,
					"twin_image_identity":     s.TwinImageID,
					"platform_family":         s.PlatformFamily,
					"count":                   1,
					"operatingsystem_name":    s.OSFamily,
					"operatingsystem_release": s.OSVersion,
					"kernel_version":          s.KernelRelease,
					"os_cpe23":                s.OSCPE23,
					"installed_packages": []map[string]any{
						{"name": s.PackageName, "nvra": s.PackageVersion, "purl": s.PackagePURL},
					},
				})
				imgs = append(imgs, map[string]any{
					"uuid":            s.TwinImageID,
					"platform_family": s.PlatformFamily,
					"created_at":      createdISO,
				})
			}
			writeSimJSON(w, http.StatusOK, map[string]any{
				"subtotal":       len(seeds),
				"reported_at":    freshISO,
				"results":        res,
				"compute_images": imgs,
			})
			return

		case "ansible-awx":
			var res, imgs []map[string]any
			for _, s := range seeds {
				res = append(res, map[string]any{
					"server_id":           s.ServerID,
					"hostname":            s.Hostname,
					"service_id":          s.ServiceID,
					"twin_image_identity": s.TwinImageID,
					"platform_family":     s.PlatformFamily,
					"host_count":          1,
					"ansible_facts": map[string]any{
						"ansible_distribution":         s.OSFamily,
						"ansible_distribution_version": s.OSVersion,
						"ansible_kernel":               s.KernelRelease,
						"os_cpe23":                     s.OSCPE23,
						"packages": []map[string]any{
							{"name": s.PackageName, "version": s.PackageVersion, "purl": s.PackagePURL},
						},
					},
				})
				imgs = append(imgs, map[string]any{
					"image_ref":       s.TwinImageID,
					"platform_family": s.PlatformFamily,
					"created_at":      createdISO,
				})
			}
			writeSimJSON(w, http.StatusOK, map[string]any{
				"count":              len(seeds),
				"last_fact_modified": freshISO,
				"results":            res,
				"golden_templates":   imgs,
			})
			return

		default:
			var hosts, imgs []map[string]any
			for _, s := range seeds {
				hosts = append(hosts, map[string]any{
					"server_id":           s.ServerID,
					"hostname":            s.Hostname,
					"service_id":          s.ServiceID,
					"twin_image_identity": s.TwinImageID,
					"platform_family":     s.PlatformFamily,
					"platform":            s.OSFamily,
					"os_version":          s.OSVersion,
					"kernel_version":      s.KernelRelease,
					"primary_package":     s.PackageName,
					"primary_version":     s.PackageVersion,
				})
				imgs = append(imgs, map[string]any{
					"image_id":        s.TwinImageID,
					"platform_family": s.PlatformFamily,
					"created_at":      createdISO,
				})
			}
			writeSimJSON(w, http.StatusOK, map[string]any{
				"count":         len(seeds),
				"updated_at":    freshISO,
				"hosts":         hosts,
				"golden_images": imgs,
			})
		}
	})

	// Demo WN-8 Distributor Mock endpoint (/mock-distributor/{system_id}/...) — rejects read-only credentials
	mux.HandleFunc("/mock-distributor/", func(w http.ResponseWriter, r *http.Request) {
		if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.Contains(strings.ToLower(auth), "demo-read-") {
			writeSimJSON(w, http.StatusForbidden, map[string]string{
				"error": "CREDENTIAL_SEPARATION_VIOLATION: read-only EstateReader credential rejected on WN-8 distributor endpoint",
			})
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		writeSimJSON(w, http.StatusOK, map[string]any{
			"id":                    "demo-dist-order-01",
			"AssignmentUniqueID":    "demo-dist-order-01",
			"CommandId":             "demo-dist-order-01",
			"name":                  "demo-dist-order-01",
			"status":                "SUCCEEDED",
			"completed_at":          now,
			"value":                 []map[string]any{{"DeviceName": "payments-ledger-api", "EnforcementState": "1001", "LastEnforcementMessageTime": now}},
			"CommandInvocations":    []map[string]any{{"InstanceId": "payments-ledger-api", "Status": "Success", "ResponseCode": 0}},
			"instanceDetails":       []map[string]any{{"instance": "payments-ledger-api", "state": "SUCCEEDED"}},
			"endpoints":             []map[string]any{{"computer_name": "payments-ledger-api", "status": "Installed"}},
			"devices":               []map[string]any{{"device_name": "payments-ledger-api", "patch_state": "INSTALLED"}},
			"events":                []map[string]any{{"server_name": "payments-ledger-api", "status": "success"}},
			"logs":                  []map[string]any{{"computerName": "payments-ledger-api", "statusCode": "COMPLETED"}},
		})
	})
}
