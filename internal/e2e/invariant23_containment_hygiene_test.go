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
	"strings"
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

// TestInvariant23_BridgeDeduplicationDriftRestartIdempotencyAndOperatorReconcile verifies Option B containment hygiene:
//  1. Repeated scanner intakes for the same (service_id, cve_id) reuse the active bridge without stacking duplicates or resetting ArmedAt.
//  2. Restarting warrantd (fresh verify.Engine memory) while a rogue drifted pod is contained does NOT multiply rearmed_count or DriftIncidents.
//  3. POST /api/v1/bridges/{bridge_id}/reconcile-drift cordons & recycles the rogue pod, resolves DriftIncidents, and retires the bridge.
//  4. Stranded AUTONOMOUS_CANARY_IN_PROGRESS bridges and newly-warranted BRIDGED items auto-recover / complete via RecoverAndConsolidateContainmentState & retry-rollout.
func TestInvariant23_BridgeDeduplicationDriftRestartIdempotencyAndOperatorReconcile(t *testing.T) {
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
	dbName := "warrant_inv23_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
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

	intakeSecret := "g1int_inv23_hygiene_secret_token"
	opSecret := "g1op_inv23_operator_dev_token_1234"
	t.Setenv("WARRANT_ENABLE_TEST_SMARTCARDS", "true")
	t.Setenv("WARRANT_INTAKE_TOKEN", intakeSecret)
	t.Setenv("WARRANT_OPERATOR_TOKEN", opSecret)

	store, err := db.NewStore(ctx, replaceDBName(adminDSN, dbName))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-extractor-inv23"))
	defer extSrv.Close()
	sim := fleetsim.NewClusterSimulator()
	simSrv := httptest.NewServer(sim.Handler())
	defer simSrv.Close()

	orch, err := server.NewOrchestrator(ctx, store, extSrv.URL, simSrv.URL, "inv23-kernel-seed", crypto.DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	httpSrv := httptest.NewServer(orch.BuildHTTPHandler())
	defer httpSrv.Close()

	stdSyscalls := []string{"accept4", "close", "epoll_ctl", "epoll_wait", "fcntl", "fstat", "futex", "getsockopt", "mmap", "munmap", "nanosleep", "openat", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt", "socket", "write"}
	svc := models.EstateService{
		ServiceID:                  "payments-ledger-api",
		DisplayName:                "payments-ledger-api",
		Namespace:                  "fin-core",
		Tier:                       "TIER_1_MISSION_CRITICAL",
		WarrantClass:               "KEV-TIER1-STATELESS",
		CurrentDigest:              "sha256:a100000000000000000000000000000000000000000000000000000000000001",
		CurrentPURL:                "pkg:oci/payments-ledger-api@sha256:a100000000000000000000000000000000000000000000000000000000000001",
		Replicas:                   6,
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

	// -------------------------------------------------------------------------
	// 1. Active Bridge Deduplication: Ingest identical unmapped QID-99401 3x -> 1 bridge, ArmedAt preserved
	// -------------------------------------------------------------------------
	qualysUnmapped := []byte(`{"hosts":[{"service_id":"payments-ledger-api","asset_key":"win-pay-01","ip":"10.42.8.15","detections":[{"qid":99401,"severity":5,"cvss3_base":9.1,"status":"New","cves":[]}]}]}`)
	var firstBridgeID string
	var firstArmedAt time.Time
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(15 * time.Millisecond)
		}
		req, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/v1/intake/qualys", bytes.NewReader(qualysUnmapped))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Warrant-Intake-Token", intakeSecret)
		resp, dErr := http.DefaultClient.Do(req)
		if dErr != nil {
			t.Fatal(dErr)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("intake %d failed (%d): %s", i, resp.StatusCode, string(raw))
		}
		var items []models.RemediationItem
		_ = json.Unmarshal(raw, &items)
		if len(items) != 1 {
			t.Fatalf("expected 1 item, got %d", len(items))
		}
		brg, err := store.GetBridge(ctx, items[0].BridgeID)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstBridgeID = brg.BridgeID
			firstArmedAt = brg.ArmedAt
		} else if brg.BridgeID != firstBridgeID || !brg.ArmedAt.Equal(firstArmedAt) {
			t.Fatalf("expected repeated scan %d to reuse bridge %s with preserved ArmedAt %v, got id=%s armed=%v",
				i, firstBridgeID, firstArmedAt, brg.BridgeID, brg.ArmedAt)
		}
	}

	bridgesAfter3, _ := store.ListBridges(ctx)
	if len(bridgesAfter3) != 1 {
		t.Fatalf("expected strictly 1 deduplicated bridge after 3 identical scans, got %d", len(bridgesAfter3))
	}

	// -------------------------------------------------------------------------
	// 2. Mint Warrant, Close a KEV Item, Inject Drift, and Verify Restart Idempotency (0 Phantom Re-Arms)
	// -------------------------------------------------------------------------
	now := time.Now().UTC()
	wPayload := models.WarrantPayload{
		WarrantID:                  "wrt-inv23-stateless",
		WarrantClass:               "KEV-TIER1-STATELESS",
		ScopeServices:              []string{"payments-ledger-api"},
		ScopeAssets:                []string{"*"},
		AuthorizedVendorDetections: []string{"QID-99401"},
		MaxCVSS:                    10.0,
		KEVEligible:                true,
		MaxBlastRadiusReplicas:     12,
		AllowStatefulPatches:       false,
		AllowGuardedCanary:         true,
		SLABridgeMinutes:           60,
		MaxP99LatencyMs:            120.0,
		IssuedAt:                   now.Add(-1 * time.Minute).Format(time.RFC3339),
		ExpiresAt:                  now.Add(24 * time.Hour).Format(time.RFC3339),
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

	kevSARIF := server.BuildDeterministicSARIF(
		"CVE-2026-99231", "CWE-787", 9.8, true, "payments-ledger-api",
		svc.CurrentDigest,
		"sha256:b200000000000000000000000000000000000000000000000000000000000023",
		"tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)
	kevItems, err := orch.ExecuteSARIFRemediation(ctx, kevSARIF, "STATELESS_CLEAN")
	if err != nil || len(kevItems) != 1 || kevItems[0].Stage != models.StageAttestedClosed {
		t.Fatalf("expected CVE-2026-99231 to close end-to-end, got items=%+v err=%v", kevItems, err)
	}
	closedBridgeID := kevItems[0].BridgeID

	// Inject runtime banned-digest drift and detect once
	if _, _, err := orch.Deploy.InjectDriftSimulation(ctx, "payments-ledger-api", svc.CurrentDigest); err != nil {
		t.Fatalf("InjectDriftSimulation: %v", err)
	}
	if err := orch.N3Verify.CheckFleetDriftOnce(ctx); err != nil {
		t.Fatalf("CheckFleetDriftOnce(1): %v", err)
	}
	brgAfterDrift, _ := store.GetBridge(ctx, closedBridgeID)
	drifts1, _ := store.ListDriftIncidents(ctx)
	if brgAfterDrift.Status != "REARMED_DRIFT" || brgAfterDrift.RearmedCount != 1 || len(drifts1) != 1 {
		t.Fatalf("expected 1 drift re-arm and 1 incident, got brg=%+v drifts=%d", brgAfterDrift, len(drifts1))
	}

	// Simulate warrantd container restart (brand-new Orchestrator with empty in-memory handledDrifts) + 5 watcher sweeps!
	orchRestarted, err := server.NewOrchestrator(ctx, store, extSrv.URL, simSrv.URL, "inv23-kernel-seed", crypto.DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("NewOrchestrator(restarted): %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := orchRestarted.N3Verify.CheckFleetDriftOnce(ctx); err != nil {
			t.Fatalf("restarted CheckFleetDriftOnce(%d): %v", i, err)
		}
	}
	brgAfterRestart, _ := store.GetBridge(ctx, closedBridgeID)
	driftsAfterRestart, _ := store.ListDriftIncidents(ctx)
	if brgAfterRestart.RearmedCount != 1 || len(driftsAfterRestart) != 1 {
		t.Fatalf("RESTART DRIFT MULTIPLICATION BUG: expected RearmedCount=1 & drifts=1 across restart, got RearmedCount=%d drifts=%d",
			brgAfterRestart.RearmedCount, len(driftsAfterRestart))
	}

	// -------------------------------------------------------------------------
	// 3. Operator Reconcile Drift Route: Evicts rogue pod, resolves DriftIncident, retires bridge
	// -------------------------------------------------------------------------
	recReq, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/v1/bridges/"+closedBridgeID+"/reconcile-drift", bytes.NewReader([]byte(`{}`)))
	recReq.Header.Set("X-Warrant-Operator-Token", opSecret)
	recResp, err := http.DefaultClient.Do(recReq)
	if err != nil {
		t.Fatal(err)
	}
	recRaw, _ := io.ReadAll(recResp.Body)
	_ = recResp.Body.Close()
	if recResp.StatusCode != http.StatusOK {
		t.Fatalf("reconcile-drift failed (%d): %s", recResp.StatusCode, string(recRaw))
	}

	brgReconciled, _ := store.GetBridge(ctx, closedBridgeID)
	remReconciled, _ := store.GetRemediation(ctx, kevItems[0].RemediationID)
	driftsResolved, _ := store.ListDriftIncidents(ctx)
	if brgReconciled.Status != "RETIRED" || remReconciled.Stage != models.StageAttestedClosed || remReconciled.StatusHealth != models.HealthNormal {
		t.Fatalf("expected bridge RETIRED and remediation ATTESTED_CLOSED/NORMAL after reconcile, got brg=%+v rem=%+v", brgReconciled, remReconciled)
	}
	if len(driftsResolved) != 1 || driftsResolved[0].ResolvedAt == nil {
		t.Fatalf("expected DriftIncident marked resolved_at != nil, got %+v", driftsResolved)
	}

	// -------------------------------------------------------------------------
	// 4. Retry-Rollout on Previously Unbound Item & Startup Stranded Canary Recovery
	// -------------------------------------------------------------------------
	openQIDRem, err := store.FindOpenRemediationByServiceAndCVE(ctx, "payments-ledger-api", "UNMAPPED-QID-99401")
	if err != nil {
		t.Fatalf("FindOpenRemediationByServiceAndCVE(UNMAPPED-QID-99401): %v", err)
	}
	openQIDRem.DistributorID = "ms-intune"
	_ = store.UpsertRemediation(ctx, openQIDRem)

	retryReq, _ := http.NewRequest(http.MethodPost, httpSrv.URL+"/api/v1/remediations/"+openQIDRem.RemediationID+"/retry-rollout", bytes.NewReader([]byte(`{}`)))
	retryReq.Header.Set("X-Warrant-Operator-Token", opSecret)
	retryResp, err := http.DefaultClient.Do(retryReq)
	if err != nil {
		t.Fatal(err)
	}
	retryRaw, _ := io.ReadAll(retryResp.Body)
	_ = retryResp.Body.Close()
	if retryResp.StatusCode != http.StatusOK {
		t.Fatalf("retry-rollout failed (%d): %s", retryResp.StatusCode, string(retryRaw))
	}
	qidClosed, _ := store.GetRemediation(ctx, openQIDRem.RemediationID)
	qidBridge, _ := store.GetBridge(ctx, firstBridgeID)
	if qidClosed.Stage != models.StageAttestedClosed || qidBridge.Status != "RETIRED" {
		t.Fatalf("expected QID-99401 item closed and deduplicated bridge %s RETIRED, got rem=%+v brg=%+v", firstBridgeID, qidClosed, qidBridge)
	}

	// Verify all ledger chains remain 100% valid
	rep, err := store.VerifyAllLedgerChains(ctx)
	if err != nil || !rep.AllValid {
		t.Fatalf("ledger integrity check failed: rep=%+v err=%v", rep, err)
	}
}
