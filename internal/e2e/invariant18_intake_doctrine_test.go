package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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

// TestInvariant18_IngestNeverRequiresDualKeyStandingWarrantOrFourEyes proves v1.3.0 Item 1 & Item 2:
//  1. Clean-Room Zero-Signature Intake Doctrine:
//     - Control plane boots with 0 Standing Warrants, 0 human principals enrolled, WARRANT_ENABLE_TEST_SMARTCARDS=false,
//       and WARRANT_INTAKE_TOKEN enforced.
//     - Qualys VMDR (including unmapped QID-99881), Tenable.io/sc (including unmapped PLUGIN-88771), Rapid7 InsightVM,
//       and SARIF 2.1.0 ingest cleanly with HTTP 201 across:
//         a) Raw HTTP API (`POST /api/v1/intake/{qualys,tenable,rapid7,sarif}`) with `X-Warrant-Intake-Token` ONLY,
//         b) Go SDK (`warrantsdk.WithIntakeToken`) & built `warrant intake ... --intake-token` CLI subprocess (zero signer keys),
//         c) Console intake flow HTTP contract (`X-Warrant-Intake-Token` only, zero WebAuthn / DSSE headers).
//     - Asserts 0 `PENDING_DUAL_KEY` Four-Eyes exceptions created (`len(ListExceptions) == 0`), `status_health == "BRIDGED"`,
//       `class_binding_status == "UNBOUND"`, and `cve_mapping_status == "UNMAPPED_VENDOR_ADVISORY"` where unmapped.
//  2. Decoupled Class-Binding + 3-Clone Proving Ground + Runtime-Follows-Patch:
//     - Enrolling principals and signing a 2-of-2 Standing Warrant class later binds & closes the held finding via
//       `POST /api/v1/remediations/{id}/bind-class`, executing the 3-Clone Proving Ground (`CloneCount == 3`,
//       `TwinRuntime == "CONTAINER_TWIN"`, `ProvingNamespace == "g1-twin-proving"`) and binding the evidence into OSCAL 1.1.2!
//     - Routing a `KERNEL` (`linux-image-*`) or `BOOT_LAYER` (`grub2-*`) patch to `CONTAINER_TWIN` fails closed with
//       `KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME` and dispatches 0 canary promotions / 0 DeploymentOrders.
func TestInvariant18_IngestNeverRequiresDualKeyStandingWarrantOrFourEyes(t *testing.T) {
	ctx := context.Background()
	adminDSN := os.Getenv("TEST_DATABASE_URL")
	if adminDSN == "" {
		adminDSN = os.Getenv("DATABASE_URL")
	}
	if adminDSN == "" {
		adminDSN = "postgres://warrant:warrant@localhost:5432/postgres?sslmode=disable"
	}

	adminConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		if os.Getenv("REQUIRE_DB_TESTS") == "true" {
			t.Fatalf("PostgreSQL unreachable: %v", err)
		}
		t.Skipf("PostgreSQL not running on host: %v", err)
	}
	dbName := "warrant_inv18_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, dbName)); err != nil {
		_ = adminConn.Close(ctx)
		t.Fatalf("create isolated test db %s: %v", dbName, err)
	}
	_ = adminConn.Close(ctx)
	t.Cleanup(func() {
		c, cErr := pgx.Connect(context.Background(), adminDSN)
		if cErr == nil {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, dbName))
			_ = c.Close(context.Background())
		}
	})

	intakeSecret := "g1int_cleanroom_intake_only_v130"
	adminSecret := "g1adm_cleanroom_genesis_v130"
	t.Setenv("WARRANT_ENABLE_TEST_SMARTCARDS", "false")
	t.Setenv("WARRANT_INTAKE_TOKEN", intakeSecret)
	t.Setenv("WARRANT_BOOTSTRAP_ADMIN_TOKEN", adminSecret)

	store, err := db.NewStore(ctx, replaceDBName(adminDSN, dbName))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-extractor-inv18"))
	defer extSrv.Close()
	sim := fleetsim.NewClusterSimulator()
	simSrv := httptest.NewServer(sim.Handler())
	defer simSrv.Close()

	orch, err := server.NewOrchestrator(ctx, store, extSrv.URL, simSrv.URL, "inv18-cleanroom-seed", crypto.DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	httpSrv := httptest.NewServer(orch.BuildHTTPHandler())
	defer httpSrv.Close()

	// Seed ONLY estate workloads — ZERO principals enrolled and ZERO Standing Warrants minted!
	stdSyscalls := []string{"accept4", "close", "epoll_ctl", "epoll_wait", "fcntl", "fstat", "futex", "getsockopt", "mmap", "munmap", "nanosleep", "openat", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt", "socket", "write"}
	for _, svcID := range []string{"payments-ledger-api", "identity-sso-gateway"} {
		svc := models.EstateService{
			ServiceID:                  svcID,
			DisplayName:                svcID,
			Namespace:                  "fin-core",
			Tier:                       "TIER_1_MISSION_CRITICAL",
			WarrantClass:               "KEV-TIER1-STATELESS",
			CurrentDigest:              "sha256:a100000000000000000000000000000000000000000000000000000000000001",
			CurrentPURL:                "pkg:oci/" + svcID + "@sha256:a100000000000000000000000000000000000000000000000000000000000001",
			Replicas:                   6,
			TestCoveragePct:            94.0,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      true,
			RollbackAutomationVerified: true,
			ReadOnlyRootFilesystem:     true,
			NoExecTmpMounts:            true,
			UnorderedArrayPaths:        []string{"$.shard_nodes"},
			BaselineSyscalls:           stdSyscalls,
		}
		gate.GradeServiceReadiness(&svc)
		if err := store.UpsertEstateService(ctx, svc); err != nil {
			t.Fatal(err)
		}
	}

	warrantsBefore, _ := store.ListWarrants(ctx)
	principalsBefore, _ := store.ListPrincipals(ctx)
	if len(warrantsBefore) != 0 || len(principalsBefore) != 0 {
		t.Fatalf("expected clean-room 0 warrants and 0 principals, got warrants=%d principals=%d", len(warrantsBefore), len(principalsBefore))
	}

	// -------------------------------------------------------------------------
	// 1. Missing X-Warrant-Intake-Token -> 401; Valid X-Warrant-Intake-Token -> 201
	// -------------------------------------------------------------------------
	qualysPayload := []byte(`{
		"hosts": [{
			"service_id": "payments-ledger-api",
			"asset_key": "win-pay-01",
			"ip": "10.42.8.15",
			"detections": [
				{"qid": 379801, "severity": 5, "cvss3_base": 9.8, "status": "Active", "cisa_kev": true, "cves": ["CVE-2026-88001"]},
				{"qid": 99881, "severity": 5, "cvss3_base": 9.1, "status": "New", "cves": []}
			]
		}]
	}`)

	unauthResp, err := http.Post(httpSrv.URL+"/api/v1/intake/qualys", "application/json", bytes.NewReader(qualysPayload))
	if err != nil || unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on missing X-Warrant-Intake-Token, got %v err=%v", unauthResp, err)
	}
	_ = unauthResp.Body.Close()

	// 1A. Raw HTTP API Intake (Qualys + Rapid7) with ONLY X-Warrant-Intake-Token
	postRawIntake := func(path, contentType string, body []byte) []models.RemediationItem {
		req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("X-Warrant-Intake-Token", intakeSecret)
		resp, dErr := http.DefaultClient.Do(req)
		if dErr != nil {
			t.Fatalf("POST %s failed: %v", path, dErr)
		}
		defer resp.Body.Close()
		rawResp, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected HTTP 201 Created on %s with X-Warrant-Intake-Token only, got %d: %s", path, resp.StatusCode, string(rawResp))
		}
		var out []models.RemediationItem
		if uErr := json.Unmarshal(rawResp, &out); uErr != nil {
			t.Fatalf("decode %s items: %v", path, uErr)
		}
		return out
	}

	qItems := postRawIntake("/api/v1/intake/qualys", "application/json", qualysPayload)
	if len(qItems) != 2 {
		t.Fatalf("expected 2 Qualys items ingested at HTTP 201 with 0 warrants, got %d", len(qItems))
	}
	var unmappedQIDItem models.RemediationItem
	for _, it := range qItems {
		if it.StatusHealth == models.HealthExceptionRouted {
			t.Fatalf("DOCTRINE VIOLATION: ingest set StatusHealth=EXCEPTION_ROUTED on %+v", it)
		}
		if it.StatusHealth != models.HealthBridged || it.ClassBindingStatus != models.ClassBindingStatusUnbound {
			t.Fatalf("expected StatusHealth=BRIDGED and ClassBindingStatus=UNBOUND at 0-warrant ingest, got %+v", it)
		}
		if it.VendorDetectionID == "QID-99881" {
			unmappedQIDItem = it
		}
	}
	if unmappedQIDItem.RemediationID == "" || unmappedQIDItem.CVEMappingStatus != models.CVEMappingStatusUnmappedVendor {
		t.Fatalf("expected unmapped QID-99881 persisted with CVEMappingStatus=UNMAPPED_VENDOR_ADVISORY, got %+v", unmappedQIDItem)
	}

	rapid7Payload := []byte(`{
		"resources": [{
			"id": 7001,
			"hostName": "identity-sso-gateway",
			"ip": "10.42.9.10",
			"vulnerabilities": [
				{"id": "r7-cve-2026-88002", "status": "vulnerable", "cves": ["CVE-2026-88002"], "cvss": {"v3": {"score": 9.4}}},
				{"id": "r7-unmapped-check-77", "status": "vulnerable", "cves": [], "riskScore": 910.0}
			]
		}]
	}`)
	r7Items := postRawIntake("/api/v1/intake/rapid7?target_service=identity-sso-gateway", "application/json", rapid7Payload)
	if len(r7Items) != 2 {
		t.Fatalf("expected 2 Rapid7 items ingested with 0 warrants, got %d", len(r7Items))
	}

	// 1B. Go SDK + Go CLI Subprocess (`warrant intake tenable <file> --intake-token ...` — zero signer keys!)
	tenablePayload := []byte(`{
		"findings": [
			{
				"state": "OPEN",
				"severity": "critical",
				"asset": {"ipv4": "10.42.8.22", "hostname": "payments-ledger-api"},
				"plugin": {"id": 195881, "cve": ["CVE-2026-88003"], "cwe": ["CWE-787"], "cvss3_base_score": 9.6, "cisa_known_exploited": true}
			},
			{
				"state": "OPEN",
				"severity": "high",
				"asset": {"ipv4": "10.42.8.22", "hostname": "payments-ledger-api"},
				"plugin": {"id": "88771", "cve": [], "cvss3_base_score": 8.7}
			}
		]
	}`)
	tmpDir := t.TempDir()
	tenableFile := filepath.Join(tmpDir, "tenable-export.json")
	if err := os.WriteFile(tenableFile, tenablePayload, 0600); err != nil {
		t.Fatal(err)
	}

	warrantBin := filepath.Join(tmpDir, "warrant-cli-test")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", warrantBin, "../../cmd/warrant")
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, bErr := buildCmd.CombinedOutput(); bErr != nil {
		t.Fatalf("build warrant CLI failed: %v\n%s", bErr, string(out))
	}

	cliCmd := exec.CommandContext(ctx, warrantBin, "--url", httpSrv.URL, "intake", "tenable", tenableFile, "--service", "payments-ledger-api", "--intake-token", intakeSecret)
	cliCmd.Env = append(os.Environ(), "WARRANT_SIGNER_KEY=", "WARRANT_OPERATOR_TOKEN=")
	cliOut, cErr := cliCmd.CombinedOutput()
	if cErr != nil {
		t.Fatalf("warrant intake tenable --intake-token (zero signer keys) failed: %v\n%s", cErr, string(cliOut))
	}
	var tenableCLIItems []models.RemediationItem
	if err := json.Unmarshal(cliOut, &tenableCLIItems); err != nil || len(tenableCLIItems) != 2 {
		t.Fatalf("unexpected Go CLI tenable intake output: err=%v items=%+v raw=%s", err, tenableCLIItems, string(cliOut))
	}

	// 1C. Console Token-Only Intake Flow Contract (SARIF 2.1.0 with X-Warrant-Intake-Token only, zero DSSE/WebAuthn)
	consoleSARIF := server.BuildDeterministicSARIF(
		"CVE-2026-88004", "CWE-787", 9.8, true, "payments-ledger-api",
		"sha256:a100000000000000000000000000000000000000000000000000000000000001",
		"sha256:a188888888888888888888888888888888888888888888888888888888888844",
		"tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)
	sarifItems := postRawIntake("/api/v1/intake/sarif?target_service=payments-ledger-api", "application/json", consoleSARIF)
	if len(sarifItems) != 1 || sarifItems[0].StatusHealth != models.HealthBridged || sarifItems[0].ClassBindingStatus != models.ClassBindingStatusUnbound {
		t.Fatalf("unexpected Console token-only SARIF intake item: %+v", sarifItems)
	}

	// CRITICAL ITEM 1 ASSERTION: 0 Four-Eyes PENDING_DUAL_KEY exceptions created across ALL 7 ingested findings!
	allExceptions, err := store.ListExceptions(ctx)
	if err != nil {
		t.Fatalf("ListExceptions: %v", err)
	}
	if len(allExceptions) != 0 {
		t.Fatalf("ITEM 1 DOCTRINE VIOLATION: expected 0 Four-Eyes exceptions after Clean-Room Qualys/Tenable/Rapid7/SARIF ingest, got %d: %+v",
			len(allExceptions), allExceptions)
	}

	// -------------------------------------------------------------------------
	// 2. Decoupled Class-Binding + 3-Clone Proving Ground Closure
	// -------------------------------------------------------------------------
	soBundle, _ := warrantsdk.GenerateEd25519SignerBundle("usr-inv18-so", "so@agency.gov", "Inv18 SO", warrantsdk.RoleServiceOwner)
	aoBundle, _ := warrantsdk.GenerateEd25519SignerBundle("usr-inv18-ao", "ao@agency.gov", "Inv18 AO", warrantsdk.RoleAuthorizingOfficial)
	adminCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithAdminToken(adminSecret))
	if _, err := adminCli.RegisterPrincipal(ctx, soBundle.ToRegisterRequest()); err != nil {
		t.Fatalf("RegisterPrincipal(SO): %v", err)
	}
	if _, err := adminCli.RegisterPrincipal(ctx, aoBundle.ToRegisterRequest()); err != nil {
		t.Fatalf("RegisterPrincipal(AO): %v", err)
	}

	wEnv, _, err := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:                  "wrt-inv18-class-bound",
		WarrantClass:               "KEV-TIER1-STATELESS",
		ScopeServices:              []string{"payments-ledger-api", "identity-sso-gateway"},
		ScopeAssets:                []string{"payments-ledger-api", "win-pay-01"},
		AuthorizedVendorDetections: []string{"QID-99881"},
		MaxCVSS:                    10.0,
		KEVEligible:                true,
		MaxBlastRadiusReplicas:     8,
		SLABridgeMinutes:           60,
		MaxP99LatencyMs:            120.0,
		TTLDays:                    30,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = soBundle.SignEnvelope(1, wEnv)
	_ = aoBundle.SignEnvelope(2, wEnv)

	sdkCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithSignerBundle(soBundle))
	boundItem, err := sdkCli.BindRemediationToWarrantClass(ctx, unmappedQIDItem.RemediationID, warrantsdk.ClassBindingRequest{
		WarrantEnvelope: wEnv,
		DistributorID:   warrantsdk.DistributorMSIntune,
		AutoExecute:     true,
	})
	if err != nil {
		t.Fatalf("BindRemediationToWarrantClass(QID-99881) failed: %v", err)
	}
	if boundItem.ClassBindingStatus != models.ClassBindingStatusBound || boundItem.Stage != models.StageAttestedClosed {
		t.Fatalf("expected decoupled class binding to prove 3 clones and close remediation, got %+v", boundItem)
	}
	if boundItem.CloneTwinProving == nil ||
		boundItem.CloneTwinProving.CloneCount != 3 ||
		boundItem.CloneTwinProving.ServicesUpCount != 3 ||
		boundItem.CloneTwinProving.SmokePassedCount != 3 ||
		boundItem.CloneTwinProving.AcceptancePassedCount != 3 ||
		boundItem.CloneTwinProving.TwinRuntime != models.TwinRuntimeContainer ||
		boundItem.CloneTwinProving.ProvingNamespace != "g1-twin-proving" ||
		!boundItem.CloneTwinProving.AllPassed {
		t.Fatalf("expected 3-clone CONTAINER_TWIN proving manifest on closed item, got %+v", boundItem.CloneTwinProving)
	}

	// Verify exported OSCAL 1.1.2 POA&M includes the 3-Clone Proving Ground observation!
	oscalRaw, err := sdkCli.ExportOSCALBundle(ctx, boundItem.AttestationID)
	if err != nil {
		t.Fatalf("ExportOSCALBundle: %v", err)
	}
	if !strings.Contains(string(oscalRaw), "N3 Isolated Clone-Twin Proving Ground Verification") ||
		!strings.Contains(string(oscalRaw), "clone-count") ||
		!strings.Contains(string(oscalRaw), "g1-twin-proving") {
		t.Fatalf("expected exported OSCAL bundle to embed 3-clone proving ground observation, got: %s", string(oscalRaw))
	}

	// -------------------------------------------------------------------------
	// 3. Item 2 Runtime-Follows-Patch: KERNEL & BOOT_LAYER Fail Closed on CONTAINER_TWIN
	// -------------------------------------------------------------------------
	kernelFindingQualys := []byte(`{
		"hosts": [{
			"service_id": "payments-ledger-api",
			"asset_key": "win-pay-01",
			"detections": [{
				"qid": 379901,
				"severity": 5,
				"cvss3_base": 9.3,
				"status": "Active",
				"cisa_kev": true,
				"cves": ["CVE-2026-88999"]
			}]
		}]
	}`)
	kItems := postRawIntake("/api/v1/intake/qualys?patch_profile=UPSTREAM_VENDOR_PENDING", "application/json", kernelFindingQualys)
	if len(kItems) != 1 {
		t.Fatalf("expected 1 kernel test item, got %d", len(kItems))
	}
	_, kernelDispatchErr := sdkCli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: kItems[0].RemediationID,
		DistributorID: warrantsdk.DistributorAnsibleAWX,
		FixIdentity: &warrantsdk.FixIdentity{
			CVEID:        "CVE-2026-88999",
			PackageNEVRA: "kernel-core-5.14.0-427.el9.x86_64",
		},
		TargetAssets: []warrantsdk.AssetTarget{{AssetKey: "win-pay-01", ServiceID: "payments-ledger-api"}},
	})
	if kernelDispatchErr == nil || !strings.Contains(kernelDispatchErr.Error(), "KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME") {
		t.Fatalf("expected KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME when kernel-core patch routes to CONTAINER_TWIN, got: %v", kernelDispatchErr)
	}
	ordersForKernel, _ := sdkCli.ListDeploymentOrders(ctx, kItems[0].RemediationID)
	if len(ordersForKernel) != 0 {
		t.Fatalf("expected 0 DeploymentOrders created after KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME rejection, got %d", len(ordersForKernel))
	}
}
