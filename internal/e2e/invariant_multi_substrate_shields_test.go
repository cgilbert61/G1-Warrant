package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/extractor"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/gate"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/server"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestInvariant_MultiSubstrateShieldsAndStatefulDDLExceptionCompletion(t *testing.T) {
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
	dbName := "warrant_shields_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
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

	var (
		mu             sync.Mutex
		awsEC2Calls    []string
		azureCalls     []string
		gcpCalls       []string
		linuxCalls     []string
		windowsCalls   []string
	)
	shieldWire := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		path := r.URL.Path

		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256"):
			vals, _ := url.ParseQuery(string(raw))
			act := vals.Get("Action")
			awsEC2Calls = append(awsEC2Calls, act)
			w.Header().Set("Content-Type", "text/xml")
			if act == "DescribeInstances" {
				_, _ = w.Write([]byte(`<DescribeInstancesResponse><reservationSet><item><instancesSet><item><groupSet><item><groupId>sg-orig-payments</groupId></item></groupSet></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`))
				return
			}
			_, _ = w.Write([]byte(`<ModifyResponse><return>true</return></ModifyResponse>`))
		case strings.HasPrefix(path, "/subscriptions/"):
			azureCalls = append(azureCalls, r.Method)
			_, _ = w.Write([]byte(`{"status":"Succeeded"}`))
		case strings.HasPrefix(path, "/projects/"):
			gcpCalls = append(gcpCalls, r.Method)
			_, _ = w.Write([]byte(`{"status":"DONE"}`))
		case strings.HasPrefix(path, "/v1/shields/nftables/"):
			var p map[string]any
			_ = json.Unmarshal(raw, &p)
			linuxCalls = append(linuxCalls, fmt.Sprint(p["action"]))
			_, _ = w.Write([]byte(`{"ok":true}`))
		case strings.HasPrefix(path, "/v1/shields/windows-wfp/"):
			var p map[string]any
			_ = json.Unmarshal(raw, &p)
			windowsCalls = append(windowsCalls, fmt.Sprint(p["action"]))
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer shieldWire.Close()

	intakeSecret := "g1int_multishield_tok"
	t.Setenv("WARRANT_ENABLE_TEST_SMARTCARDS", "true")
	t.Setenv("WARRANT_INTAKE_TOKEN", intakeSecret)
	t.Setenv("WARRANT_AWS_REGION", "us-east-1")
	t.Setenv("WARRANT_AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("WARRANT_AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("WARRANT_AWS_SHIELD_ENDPOINT", shieldWire.URL)
	t.Setenv("WARRANT_AWS_QUARANTINE_SG_ID", "sg-quarantine-999")
	t.Setenv("WARRANT_AZURE_SHIELD_URL", shieldWire.URL)
	t.Setenv("WARRANT_AZURE_SHIELD_TOKEN", "az-tok")
	t.Setenv("WARRANT_GCP_SHIELD_URL", shieldWire.URL)
	t.Setenv("WARRANT_GCP_SHIELD_TOKEN", "gcp-tok")
	t.Setenv("WARRANT_LINUX_SHIELD_URL", shieldWire.URL)
	t.Setenv("WARRANT_LINUX_SHIELD_TOKEN", "lnx-tok")
	t.Setenv("WARRANT_WINDOWS_SHIELD_URL", shieldWire.URL)
	t.Setenv("WARRANT_WINDOWS_SHIELD_TOKEN", "win-tok")

	store, err := db.NewStore(ctx, replaceDBName(adminDSN, dbName))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-extractor-shields"))
	defer extSrv.Close()
	sim := fleetsim.NewClusterSimulator()
	simSrv := httptest.NewServer(sim.Handler())
	defer simSrv.Close()

	orch, err := server.NewOrchestrator(ctx, store, extSrv.URL, simSrv.URL, "shields-seed", crypto.DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	httpSrv := httptest.NewServer(orch.BuildHTTPHandler())
	defer httpSrv.Close()

	// Seed services, enroll Alice (SO) + Bob (AO), and mint a Standing Warrant
	stdSyscalls := []string{"accept4", "close", "epoll_ctl", "epoll_wait", "fcntl", "fstat", "futex", "getsockopt", "mmap", "munmap", "nanosleep", "openat", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt", "socket", "write"}
	for _, svcID := range []string{"payments-ledger-api", "identity-sso-gateway"} {
		reps := 6
		if svcID == "identity-sso-gateway" {
			reps = 4
		}
		svc := models.EstateService{
			ServiceID:                  svcID,
			DisplayName:                svcID,
			Namespace:                  "fin-core",
			Tier:                       "TIER_1_MISSION_CRITICAL",
			WarrantClass:               "KEV-TIER1-STATELESS",
			CurrentDigest:              "sha256:a100000000000000000000000000000000000000000000000000000000000001",
			CurrentPURL:                "pkg:oci/" + svcID + "@sha256:a100000000000000000000000000000000000000000000000000000000000001",
			Replicas:                   reps,
			TestCoveragePct:            95.0,
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

	personas := crypto.BuiltinTestPersonas()
	alice, bob := personas[0], personas[1]
	for _, tp := range []crypto.TestSmartcardPersona{alice, bob} {
		p := models.Principal{
			PrincipalID:       tp.PrincipalID,
			Email:             tp.Email,
			DisplayName:       tp.DisplayName,
			Role:              tp.Role,
			KeyID:             tp.KeyID,
			Alg:               tp.Alg,
			PublicKeyB64:      tp.PublicKeyB64,
			KeyFingerprint:    tp.KeyFingerprint,
			AuthenticatorMode: "ED25519_ENROLLED",
			CreatedAt:         time.Now().UTC(),
		}
		if err := store.AppendPrincipalWithLineage(ctx, &p, models.LineageModeGenesisSealed, nil); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC()
	wPayload := models.WarrantPayload{
		WarrantID:              "wrt-multishield-001",
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          []string{"payments-ledger-api", "identity-sso-gateway"},
		ScopeAssets:            []string{"*"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 20,
		AllowStatefulPatches:   false,
		AllowGuardedCanary:     true,
		SLABridgeMinutes:       60,
		MaxP99LatencyMs:        120.0,
		IssuedAt:               now.Add(-1 * time.Minute).Format(time.RFC3339),
		ExpiresAt:              now.Add(24 * time.Hour).Format(time.RFC3339),
	}
	wEnv, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, wPayload)
	if err != nil {
		t.Fatal(err)
	}
	_ = wEnv.SignEd25519(1, alice.ToPrincipalKey(), alice.PrivateKey)
	_ = wEnv.SignEd25519(2, bob.ToPrincipalKey(), bob.PrivateKey)
	if _, err := orch.N1Warrant.SubmitDualSignedWarrant(ctx, *wEnv); err != nil {
		t.Fatalf("SubmitDualSignedWarrant: %v", err)
	}

	// -------------------------------------------------------------------------
	// Part 1: Ingest non-Docker findings across Windows, Linux, AWS, Azure & GCP
	//         -> verify sub-second shield arming AND symmetric Stage 04 retirement!
	// -------------------------------------------------------------------------
	postIntake := func(vendor, distID, body string) []models.RemediationItem {
		t.Helper()
		u := fmt.Sprintf("%s/api/v1/intake/%s?target_service=payments-ledger-api&distributor_id=%s", httpSrv.URL, vendor, url.QueryEscape(distID))
		req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Warrant-Intake-Token", intakeSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("intake %s/%s: %v", vendor, distID, err)
		}
		defer resp.Body.Close()
		rawResp, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201 on %s/%s, got %d: %s", vendor, distID, resp.StatusCode, string(rawResp))
		}
		var out []models.RemediationItem
		if err := json.Unmarshal(rawResp, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// 1a. Windows Host via ms-intune -> WINDOWS_WFP_NETFIREWALL armed then retired on FULL landing!
	winItems := postIntake("qualys", "ms-intune", `{"hosts":[{"service_id":"payments-ledger-api","asset_key":"win-pay-01","ip":"10.42.8.15","os":"Windows Server 2022","detections":[{"qid":379501,"severity":5,"cvss3_base":9.8,"status":"Active","cisa_kev":true,"cves":["CVE-2026-91001"]}]}]}`)
	if len(winItems) != 1 || winItems[0].Stage != models.StageAttestedClosed {
		t.Fatalf("expected Windows Intune item to close end-to-end, got %+v", winItems)
	}
	winBrg, err := store.GetBridge(ctx, winItems[0].BridgeID)
	if err != nil || winBrg.BridgeType != models.BridgeTypeWindowsNetFW || winBrg.SubstrateFamily != models.ShieldSubstrateWindowsHost || winBrg.Status != "RETIRED" {
		t.Fatalf("expected retired WINDOWS_WFP_NETFIREWALL bridge, got brg=%+v err=%v", winBrg, err)
	}

	// 1b. Linux Host via ansible-awx -> LINUX_NFTABLES_SHIELD armed then retired on FULL landing!
	lnxItems := postIntake("rapid7", "ansible-awx", `{"resources":[{"id":701,"hostName":"payments-ledger-api","os":"Red Hat Enterprise Linux 9","ip":"10.42.9.10","vulnerabilities":[{"id":"r7-cve-2026-91002","status":"vulnerable","cves":["CVE-2026-91002"],"cwe":"CWE-787","cisaKev":true,"cvss":{"v3":{"score":9.1}}}]}]}`)
	if len(lnxItems) != 1 || lnxItems[0].Stage != models.StageAttestedClosed {
		t.Fatalf("expected Linux AWX item to close end-to-end, got %+v", lnxItems)
	}
	lnxBrg, err := store.GetBridge(ctx, lnxItems[0].BridgeID)
	if err != nil || lnxBrg.BridgeType != models.BridgeTypeLinuxNftables || lnxBrg.SubstrateFamily != models.ShieldSubstrateLinuxHost || lnxBrg.Status != "RETIRED" {
		t.Fatalf("expected retired LINUX_NFTABLES_SHIELD bridge, got brg=%+v err=%v", lnxBrg, err)
	}

	// 1c. AWS EC2 via aws-ssm -> AWS_EC2_SG_IMDS armed (SigV4 + IMDSv2) then restored/retired!
	awsItems := postIntake("tenable", "aws-ssm", `{"findings":[{"state":"OPEN","severity":"critical","asset":{"ipv4":"10.42.8.22","hostname":"payments-ledger-api","aws_ec2_instance_id":"i-0abc1122334455667"},"plugin":{"id":195201,"cve":["CVE-2026-91003"],"cwe":["CWE-918"],"cvss3_base_score":9.6,"cisa_known_exploited":true}}]}`)
	if len(awsItems) != 1 || awsItems[0].Stage != models.StageAttestedClosed {
		t.Fatalf("expected AWS SSM item to close end-to-end, got %+v", awsItems)
	}
	awsBrg, err := store.GetBridge(ctx, awsItems[0].BridgeID)
	if err != nil || awsBrg.BridgeType != models.BridgeTypeAWSEC2SGIMDS || awsBrg.SubstrateFamily != models.ShieldSubstrateAWSEC2 || awsBrg.Status != "RETIRED" {
		t.Fatalf("expected retired AWS_EC2_SG_IMDS bridge, got brg=%+v err=%v", awsBrg, err)
	}

	// 1d. Azure VM via azure-update-manager & GCP GCE via gcp-os-config
	azItems := postIntake("tenable", "azure-update-manager", `{"findings":[{"state":"OPEN","severity":"critical","asset":{"ipv4":"10.42.8.23","hostname":"payments-ledger-api"},"plugin":{"id":195202,"cve":["CVE-2026-91004"],"cwe":["CWE-787"],"cvss3_base_score":9.4,"cisa_known_exploited":true}}]}`)
	gcpItems := postIntake("tenable", "gcp-os-config", `{"findings":[{"state":"OPEN","severity":"critical","asset":{"ipv4":"10.42.8.24","hostname":"payments-ledger-api"},"plugin":{"id":195203,"cve":["CVE-2026-91005"],"cwe":["CWE-787"],"cvss3_base_score":9.2,"cisa_known_exploited":true}}]}`)
	azBrg, _ := store.GetBridge(ctx, azItems[0].BridgeID)
	gcpBrg, _ := store.GetBridge(ctx, gcpItems[0].BridgeID)
	if azBrg == nil || azBrg.BridgeType != models.BridgeTypeAzureNSG || azBrg.Status != "RETIRED" {
		t.Fatalf("expected retired AZURE_NSG_QUARANTINE bridge, got %+v", azBrg)
	}
	if gcpBrg == nil || gcpBrg.BridgeType != models.BridgeTypeGCPVPCFirewall || gcpBrg.Status != "RETIRED" {
		t.Fatalf("expected retired GCP_VPC_FIREWALL bridge, got %+v", gcpBrg)
	}

	mu.Lock()
	if len(awsEC2Calls) != 4 || len(azureCalls) != 2 || len(gcpCalls) != 2 || len(linuxCalls) != 2 || len(windowsCalls) != 2 {
		t.Fatalf("unexpected wire call counts: aws=%v az=%v gcp=%v lnx=%v win=%v", awsEC2Calls, azureCalls, gcpCalls, linuxCalls, windowsCalls)
	}
	mu.Unlock()

	// -------------------------------------------------------------------------
	// Part 2: Stateful DDL Four-Eyes Exception Approval Completes 01 -> 05!
	// -------------------------------------------------------------------------
	ddlSARIF := server.BuildDeterministicSARIF(
		"CVE-2026-33912", "CWE-89", 8.8, true, "identity-sso-gateway",
		"sha256:a100000000000000000000000000000000000000000000000000000000000001",
		"sha256:b299999999999999999999999999999999999999999999999999999999999902",
		"", "HTTP_PATH_TRAVERSAL", 8080,
	)
	ddlItems, err := orch.ExecuteSARIFRemediationWithOptions(ctx, ddlSARIF, "STATEFUL_DDL", "identity-sso-gateway", "", 1)
	if err != nil || len(ddlItems) != 1 {
		t.Fatalf("ExecuteSARIFRemediationWithOptions STATEFUL_DDL: items=%+v err=%v", ddlItems, err)
	}
	if ddlItems[0].StatusHealth != models.HealthExceptionRouted {
		t.Fatalf("expected STATEFUL_DDL_MIGRATION to route to Four-Eyes Exception Cockpit, got %+v", ddlItems[0])
	}

	exList, _ := store.ListExceptions(ctx)
	if len(exList) != 1 || exList[0].Status != "PENDING_DUAL_KEY" {
		t.Fatalf("expected 1 PENDING_DUAL_KEY exception, got %+v", exList)
	}

	excPayload := models.ExceptionResolutionPayload{
		EnvelopeID:    "exc-approve-ddl-001",
		ExceptionID:   exList[0].ExceptionID,
		RemediationID: ddlItems[0].RemediationID,
		ServiceID:     "identity-sso-gateway",
		CVEID:         "CVE-2026-33912",
		Decision:      "APPROVED",
		IssuedAt:      time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:     time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339),
	}
	excEnv, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeException, excPayload)
	_ = excEnv.SignEd25519(1, alice.ToPrincipalKey(), alice.PrivateKey)
	_ = excEnv.SignEd25519(2, bob.ToPrincipalKey(), bob.PrivateKey)

	approveBody, _ := json.Marshal(map[string]any{
		"decision":      "APPROVED",
		"dsse_envelope": *excEnv,
	})
	appResp, err := http.Post(httpSrv.URL+"/api/v1/exceptions/"+exList[0].ExceptionID+"/resolve", "application/json", bytes.NewReader(approveBody))
	if err != nil {
		t.Fatalf("POST approve exception: %v", err)
	}
	defer appResp.Body.Close()
	rawApprove, _ := io.ReadAll(appResp.Body)
	if appResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 approving Stateful DDL exception, got %d: %s", appResp.StatusCode, string(rawApprove))
	}

	updatedDDL, err := store.GetRemediation(ctx, ddlItems[0].RemediationID)
	if err != nil {
		t.Fatal(err)
	}
	if updatedDDL.Stage != models.StageAttestedClosed || updatedDDL.StatusHealth != models.HealthAttested || updatedDDL.AttestationID == "" {
		t.Fatalf("expected approved Stateful DDL item to reach ATTESTED_CLOSED with OSCAL POA&M, got stage=%s health=%s att=%s blocker=%s",
			updatedDDL.Stage, updatedDDL.StatusHealth, updatedDDL.AttestationID, updatedDDL.BlockerCode)
	}
}
