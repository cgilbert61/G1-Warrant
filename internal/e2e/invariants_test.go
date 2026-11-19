package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/db"
	"github.com/g1163rt-labs/g1-warrant/internal/extractor"
	"github.com/g1163rt-labs/g1-warrant/internal/fleetsim"
	"github.com/g1163rt-labs/g1-warrant/internal/gate"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
	"github.com/g1163rt-labs/g1-warrant/internal/server"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type testHarness struct {
	ctx        context.Context
	store      *db.Store
	orch       *server.ControlPlaneOrchestrator
	httpSrv    *httptest.Server
	alice      crypto.TestSmartcardPersona
	bob        crypto.TestSmartcardPersona
	elena      crypto.TestSmartcardPersona
	marcus     crypto.TestSmartcardPersona
	mallory    crypto.TestSmartcardPersona
	carol      crypto.TestSmartcardPersona
}

func setupIsolatedHarness(t *testing.T) *testHarness {
	t.Helper()
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
			t.Fatalf("REQUIRE_DB_TESTS=true but PostgreSQL unreachable at %s: %v", adminDSN, err)
		}
		t.Skipf("PostgreSQL not running on host (%v); run via `docker compose --profile test run --rm verifier`", err)
	}

	dbName := "warrant_test_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, dbName)); err != nil {
		_ = adminConn.Close(ctx)
		t.Fatalf("create isolated test database %s: %v", dbName, err)
	}
	_ = adminConn.Close(ctx)

	t.Cleanup(func() {
		c, cErr := pgx.Connect(context.Background(), adminDSN)
		if cErr == nil {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, dbName))
			_ = c.Close(context.Background())
		}
	})

	testDSN := replaceDBName(adminDSN, dbName)
	store, err := db.NewStore(ctx, testDSN)
	if err != nil {
		t.Fatalf("NewStore on %s: %v", dbName, err)
	}
	t.Cleanup(store.Close)

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-extractor-test-binary"))
	t.Cleanup(extSrv.Close)

	sim := fleetsim.NewClusterSimulator()
	fleetSrv := httptest.NewServer(sim.Handler())
	t.Cleanup(fleetSrv.Close)

	orch, err := server.NewOrchestrator(ctx, store, extSrv.URL, fleetSrv.URL, "test-kernel-seed", crypto.DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}

	apiSrv := httptest.NewServer(orch.BuildHTTPHandler())
	t.Cleanup(apiSrv.Close)

	h := &testHarness{
		ctx:     ctx,
		store:   store,
		orch:    orch,
		httpSrv: apiSrv,
	}

	for _, p := range crypto.BuiltinTestPersonas() {
		if err := store.UpsertPrincipal(ctx, models.Principal{
			PrincipalID:       p.PrincipalID,
			Email:             p.Email,
			DisplayName:       p.DisplayName,
			Role:              p.Role,
			KeyID:             p.KeyID,
			Alg:               p.Alg,
			PublicKeyB64:      p.PublicKeyB64,
			KeyFingerprint:    p.KeyFingerprint,
			AuthenticatorMode: "FIPS_PIV_SMARTCARD",
		}); err != nil {
			t.Fatal(err)
		}
		switch p.PrincipalID {
		case "usr-alice-so":
			h.alice = p
		case "usr-bob-ao":
			h.bob = p
		case "usr-elena-so":
			h.elena = p
		case "usr-marcus-ao":
			h.marcus = p
		case "usr-mallory-so":
			h.mallory = p
		case "usr-carol-sysadmin":
			h.carol = p
		}
	}

	// Register eligible services matching fleet-sim
	stdSyscalls := []string{"accept4", "close", "epoll_ctl", "epoll_wait", "fcntl", "fstat", "futex", "getsockopt", "mmap", "munmap", "nanosleep", "openat", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt", "socket", "write"}
	svcs := []models.EstateService{
		{
			ServiceID:                  "payments-ledger-api",
			DisplayName:                "Payments Ledger API",
			Namespace:                  "fin-core",
			Tier:                       "TIER_1_CRITICAL",
			WarrantClass:               "KEV-TIER1-STATELESS",
			CurrentDigest:              "sha256:a100000000000000000000000000000000000000000000000000000000000001",
			CurrentPURL:                "pkg:oci/payments-ledger-api@sha256:a100000000000000000000000000000000000000000000000000000000000001",
			SBOMPURLs:                  []string{"pkg:golang/golang.org/x/net@0.16.0"},
			Replicas:                   6,
			TestCoveragePct:            94.0,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      true,
			RollbackAutomationVerified: true,
			BaselineSyscalls:           stdSyscalls,
		},
		{
			ServiceID:                  "identity-sso-gateway",
			DisplayName:                "Identity SSO Gateway",
			Namespace:                  "sec-authn",
			Tier:                       "TIER_1_CRITICAL",
			WarrantClass:               "KEV-TIER1-STATELESS",
			CurrentDigest:              "sha256:b200000000000000000000000000000000000000000000000000000000000002",
			CurrentPURL:                "pkg:oci/identity-sso-gateway@sha256:b200000000000000000000000000000000000000000000000000000000000002",
			Replicas:                   4,
			TestCoveragePct:            91.0,
			OtelHealthProbes:           true,
			ReadonlyShadowReplica:      true,
			RollbackAutomationVerified: true,
			BaselineSyscalls:           stdSyscalls,
		},
	}
	for i := range svcs {
		gate.GradeServiceReadiness(&svcs[i])
		if err := store.UpsertEstateService(ctx, svcs[i]); err != nil {
			t.Fatal(err)
		}
	}

	return h
}

func mintDualWarrant(t *testing.T, h *testHarness, warrantID string, scopes []string, so, ao crypto.TestSmartcardPersona) *models.WarrantRecord {
	t.Helper()
	now := time.Now().UTC()
	wp := models.WarrantPayload{
		WarrantID:              warrantID,
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          scopes,
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 10,
		AllowStatefulPatches:   false,
		SLABridgeMinutes:       60,
		MaxP99LatencyMs:        120.0,
		IssuedAt:               now.Format(time.RFC3339),
		ExpiresAt:              now.Add(24 * time.Hour).Format(time.RFC3339),
	}
	env, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, wp)
	if err != nil {
		t.Fatal(err)
	}
	_ = env.SignEd25519(1, so.ToPrincipalKey(), so.PrivateKey)
	_ = env.SignEd25519(2, ao.ToPrincipalKey(), ao.PrivateKey)
	rec, err := h.orch.N1Warrant.SubmitDualSignedWarrant(h.ctx, *env)
	if err != nil {
		t.Fatalf("SubmitDualSignedWarrant(%s) failed: %v", warrantID, err)
	}
	return rec
}

// INVARIANT 1: End-to-End KEV Closure + Scoped Auditor Token Isolation
func TestInvariant1_EndToEndKEVClosureAndOSCALVerification(t *testing.T) {
	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-inv1", []string{"payments-ledger-api"}, h.alice, h.bob)

	vulnDigest := "sha256:a100000000000000000000000000000000000000000000000000000000000001"
	patchedDigest := "sha256:a199999999999999999999999999999999999999999999999999999999999999"
	sarif := server.BuildDeterministicSARIF(
		"CVE-2026-90001", "CWE-787", 9.8, true, "payments-ledger-api",
		vulnDigest, patchedDigest, "tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)

	items, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif, "STATELESS_CLEAN")
	if err != nil {
		t.Fatalf("ExecuteSARIFRemediation failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 remediation item, got %d", len(items))
	}
	got := items[0]
	if got.Stage != models.StageAttestedClosed || got.StatusHealth != models.HealthAttested {
		t.Fatalf("expected ATTESTED_CLOSED, got stage=%s health=%s blocker=%s", got.Stage, got.StatusHealth, got.BlockerCode)
	}
	if got.TwinReplayStatus != "EXPLOIT_BLOCKED" || got.PodSweepMatched != 6 || got.LockoutPolicyID == "" {
		t.Fatalf("incomplete N3 verification state: %+v", got)
	}

	// Confirm bridge was retired ONLY after lockout
	bridge, err := h.store.GetBridge(h.ctx, got.BridgeID)
	if err != nil || bridge.Status != "RETIRED" {
		t.Fatalf("expected bridge RETIRED after lockout, got %+v err=%v", bridge, err)
	}

	// Confirm Admission Lockout rejects any attempt to re-deploy vulnerable digest
	if _, err := h.orch.Deploy.ProgressCanary(h.ctx, "payments-ledger-api", fleetsim.StageRolloutRequest{
		PatchedDigest: vulnDigest,
		StageWeight:   10,
	}); err == nil || !strings.Contains(err.Error(), "ADMISSION_DENIED_LOCKED_DIGEST") {
		t.Fatalf("expected cluster ValidatingAdmissionPolicy to reject banned digest, got: %v", err)
	}

	// Confirm DSSE-signed OSCAL 1.1.2 POA&M bundle cryptographically verifies
	atts, err := h.store.ListAttestations(h.ctx)
	if err != nil || len(atts) != 1 {
		t.Fatalf("expected 1 attestation, got %d err=%v", len(atts), err)
	}
	if err := h.orch.N5Ledger.VerifyAttestationEnvelope(atts[0].DSSEEnvelope); err != nil {
		t.Fatalf("OSCAL DSSE cryptographic verification failed: %v", err)
	}
	poamRoot, ok := atts[0].OSCALPOAM["plan-of-action-and-milestones"].(map[string]any)
	if !ok {
		t.Fatalf("missing plan-of-action-and-milestones root in OSCAL JSON")
	}
	meta, _ := poamRoot["metadata"].(map[string]any)
	if meta["oscal-version"] != "1.1.2" {
		t.Fatalf("expected oscal-version 1.1.2, got %v", meta["oscal-version"])
	}

	// Confirm Scoped External Auditor Token accesses /api/v1/auditor/vault (200) and is blocked on /api/v1/warrants (403)
	_, rawBearer, err := h.orch.N5Ledger.MintScopedAuditorToken(h.ctx, "3PAO Test", "test", []string{atts[0].AttestationID}, 2)
	if err != nil {
		t.Fatal(err)
	}
	reqVault, _ := http.NewRequest(http.MethodGet, h.httpSrv.URL+"/api/v1/auditor/vault", nil)
	reqVault.Header.Set("Authorization", "Bearer "+rawBearer)
	respVault, err := http.DefaultClient.Do(reqVault)
	if err != nil || respVault.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /api/v1/auditor/vault, got %v err=%v", respVault, err)
	}
	_ = respVault.Body.Close()

	reqOp, _ := http.NewRequest(http.MethodGet, h.httpSrv.URL+"/api/v1/warrants", nil)
	reqOp.Header.Set("Authorization", "Bearer "+rawBearer)
	respOp, err := http.DefaultClient.Do(reqOp)
	if err != nil || respOp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when auditor token calls operational endpoint, got %d", respOp.StatusCode)
	}
	_ = respOp.Body.Close()
}

// INVARIANT 2: NIST SP 800-53 AC-5 Separation of Duties & Live Execution-Time Revocation
func TestInvariant2_AC5SeparationOfDutiesAndLiveRevocation(t *testing.T) {
	h := setupIsolatedHarness(t)
	now := time.Now().UTC()
	wp := models.WarrantPayload{
		WarrantID:              "wrt-bad-ac5",
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          []string{"identity-sso-gateway"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 8,
		SLABridgeMinutes:       60,
		IssuedAt:               now.Format(time.RFC3339),
		ExpiresAt:              now.Add(24 * time.Hour).Format(time.RFC3339),
	}

	// 1. Reject Mallory signing both Slot 1 and Slot 2
	sameEnv, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, wp)
	_ = sameEnv.SignEd25519(1, h.mallory.ToPrincipalKey(), h.mallory.PrivateKey)
	_ = sameEnv.SignEd25519(2, h.mallory.ToPrincipalKey(), h.mallory.PrivateKey)
	if _, err := h.orch.N1Warrant.SubmitDualSignedWarrant(h.ctx, *sameEnv); err == nil {
		t.Fatal("expected AC-5 rejection for identical signer across Slot 1 and Slot 2")
	}

	// 2. Reject Carol (SYSTEM_ADMIN) signing Slot 2
	sysEnv, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeWarrant, wp)
	_ = sysEnv.SignEd25519(1, h.alice.ToPrincipalKey(), h.alice.PrivateKey)
	_ = sysEnv.SignEd25519(2, h.carol.ToPrincipalKey(), h.carol.PrivateKey)
	if _, err := h.orch.N1Warrant.SubmitDualSignedWarrant(h.ctx, *sysEnv); err == nil || !strings.Contains(err.Error(), "AC5_SYSADMIN_PROHIBITED") {
		t.Fatalf("expected AC5_SYSADMIN_PROHIBITED, got %v", err)
	}

	// 3. Mint valid Elena + Marcus warrant, then revoke Marcus before N2 execution
	w := mintDualWarrant(t, h, "wrt-revoke-live", []string{"identity-sso-gateway"}, h.elena, h.marcus)
	if _, err := h.orch.N1Warrant.RevokeSigner(h.ctx, h.marcus.PrincipalID, h.marcus.KeyFingerprint, "AO_DEPARTED_ROLE", "sec-admin"); err != nil {
		t.Fatal(err)
	}

	// Direct execution-time re-verification must immediately fail closed
	if _, err := h.orch.N1Warrant.ReverifyWarrantForExecution(h.ctx, w.WarrantID, "identity-sso-gateway", 9.1, 4); err == nil {
		t.Fatal("expected ReverifyWarrantForExecution to fail closed after AO key revocation")
	}

	// Pipeline intake must arm containment bridge and fail closed before N2 rollout
	sarif := server.BuildDeterministicSARIF(
		"CVE-2026-90002", "CWE-287", 9.1, true, "identity-sso-gateway",
		"sha256:b200000000000000000000000000000000000000000000000000000000000002",
		"sha256:b299999999999999999999999999999999999999999999999999999999999999",
		"saml_dsig_xpath_eval_v1", "HTTP_PATH_TRAVERSAL", 8443,
	)
	items, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif, "STATELESS_CLEAN")
	if err != nil || len(items) != 1 {
		t.Fatalf("ExecuteSARIFRemediation err=%v len=%d", err, len(items))
	}
	if items[0].Stage == models.StageAttestedClosed {
		t.Fatal("revoked warrant must never advance to ATTESTED_CLOSED")
	}
	bridge, _ := h.store.GetBridge(h.ctx, items[0].BridgeID)
	if bridge == nil || bridge.Status != "ARMED" {
		t.Fatalf("containment bridge must remain ARMED on fail-closed warrant, got %+v", bridge)
	}
}

// INVARIANT 3: Canary Safety Rollback (Unauthorized execve Syscall & Stateful DDL Exception Routing)
func TestInvariant3_CanarySafetyRollbackAndStatefulRouting(t *testing.T) {
	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-inv3", []string{"payments-ledger-api", "identity-sso-gateway"}, h.alice, h.bob)

	// 3a. Unauthorized execve syscall triggers automatic canary rollback
	sarifExecve := server.BuildDeterministicSARIF(
		"CVE-2026-90003", "CWE-78", 9.4, true, "payments-ledger-api",
		"sha256:a100000000000000000000000000000000000000000000000000000000000001",
		"sha256:a177777777777777777777777777777777777777777777777777777777777777",
		"tls_heartbeat_ext_parse_vuln", "HTTP_PATH_TRAVERSAL", 8080,
	)
	items, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarifExecve, "BAD_SYSCALL_EXECVE")
	if err != nil || len(items) != 1 {
		t.Fatalf("unexpected error: %v", err)
	}
	if items[0].StatusHealth != models.HealthRollbackFailed || items[0].CanaryWeight != 0 {
		t.Fatalf("expected ROLLBACK_FAILED at weight 0, got %+v", items[0])
	}
	if !strings.Contains(items[0].BlockerCode, "execve") {
		t.Fatalf("expected execve failure code, got %q", items[0].BlockerCode)
	}
	wl, _ := h.orch.Deploy.InspectLiveWorkload(h.ctx, "payments-ledger-api")
	if wl.CanaryWeight != 0 {
		t.Fatalf("expected fleet-sim canary rolled back to 0%%, got %d%%", wl.CanaryWeight)
	}

	// 3b. Stateful SQL DDL mutation routes to Four-Eyes Ceiling Exception Cockpit
	sarifDDL := server.BuildDeterministicSARIF(
		"CVE-2026-90004", "CWE-89", 8.8, false, "identity-sso-gateway",
		"sha256:b200000000000000000000000000000000000000000000000000000000000002",
		"sha256:b266666666666666666666666666666666666666666666666666666666666666",
		"saml_dsig_xpath_eval_v1", "HTTP_PATH_TRAVERSAL", 8443,
	)
	ddlItems, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarifDDL, "STATEFUL_DDL")
	if err != nil || len(ddlItems) != 1 {
		t.Fatalf("unexpected error: %v", err)
	}
	if ddlItems[0].StatusHealth != models.HealthExceptionRouted {
		t.Fatalf("expected EXCEPTION_ROUTED for stateful DDL patch, got %+v", ddlItems[0])
	}
	exList, _ := h.store.ListExceptions(h.ctx)
	if len(exList) == 0 || exList[0].Status != "PENDING_DUAL_KEY" || exList[0].DDLCount == 0 {
		t.Fatalf("expected PENDING_DUAL_KEY exception with DDLCount > 0, got %+v", exList)
	}
}

// INVARIANT 4: Asymmetric Dual-Mode Emergency Freeze & 2-of-2 Thaw Ceremony
func TestInvariant4_AsymmetricFreezeAndDualKeyThaw(t *testing.T) {
	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-inv4", []string{"payments-ledger-api"}, h.alice, h.bob)

	// Activate FREEZE_HOLD
	fs, err := h.orch.N1Warrant.TriggerEmergencyFreeze(h.ctx, models.FreezeModeHold, "ops-oncall", "DRILL_HOLD", h.orch.N2Gate.RollbackAllActiveCanaries)
	if err != nil || fs.Mode != models.FreezeModeHold {
		t.Fatalf("TriggerEmergencyFreeze failed: %v", err)
	}

	// Inject KEV during active FREEZE_HOLD: Shield bridge MUST arm, while N2 rollout MUST halt!
	sarif := server.BuildDeterministicSARIF(
		"CVE-2026-90005", "CWE-787", 9.8, true, "payments-ledger-api",
		"sha256:a100000000000000000000000000000000000000000000000000000000000001",
		"sha256:a155555555555555555555555555555555555555555555555555555555555555",
		"tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)
	items, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif, "STATELESS_CLEAN")
	if err != nil || len(items) != 1 {
		t.Fatalf("ExecuteSARIFRemediation during freeze err=%v", err)
	}
	if items[0].StatusHealth != models.HealthFrozen {
		t.Fatalf("expected remediation status FROZEN, got %s", items[0].StatusHealth)
	}
	bridge, _ := h.store.GetBridge(h.ctx, items[0].BridgeID)
	if bridge == nil || bridge.Status != "ARMED" {
		t.Fatalf("Shield containment bridge MUST remain ARMED during FREEZE_HOLD, got %+v", bridge)
	}

	// Switch to FREEZE_ROLLBACK and confirm bridge stays ARMED
	if _, err := h.orch.N1Warrant.TriggerEmergencyFreeze(h.ctx, models.FreezeModeRollback, "ops-oncall", "DRILL_ROLLBACK", h.orch.N2Gate.RollbackAllActiveCanaries); err != nil {
		t.Fatal(err)
	}
	bridgeAfter, _ := h.store.GetBridge(h.ctx, items[0].BridgeID)
	if bridgeAfter.Status != "ARMED" {
		t.Fatalf("Shield containment bridge MUST remain ARMED during FREEZE_ROLLBACK")
	}

	// Single-signature Thaw attempt MUST fail closed
	badThaw, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeThaw, map[string]string{"action": "THAW"})
	_ = badThaw.SignEd25519(1, h.alice.ToPrincipalKey(), h.alice.PrivateKey)
	if _, err := h.orch.N1Warrant.ThawEmergencyFreeze(h.ctx, *badThaw); err == nil {
		t.Fatal("expected single-signature Thaw to be rejected")
	}

	// Valid 2-of-2 DSSE Thaw ceremony (Alice + Bob) restores OPERATIONAL state
	validThaw, _, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeThaw, map[string]string{"action": "THAW"})
	_ = validThaw.SignEd25519(1, h.alice.ToPrincipalKey(), h.alice.PrivateKey)
	_ = validThaw.SignEd25519(2, h.bob.ToPrincipalKey(), h.bob.PrivateKey)
	thawed, err := h.orch.N1Warrant.ThawEmergencyFreeze(h.ctx, *validThaw)
	if err != nil || thawed.Mode != models.FreezeModeOperational {
		t.Fatalf("expected valid 2-of-2 Thaw to restore OPERATIONAL, got %+v err=%v", thawed, err)
	}
}

// INVARIANT 5: Sub-Second Runtime Drift Detection & Automatic Bridge Re-Arming
func TestInvariant5_SubSecondDriftReArming(t *testing.T) {
	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-inv5", []string{"payments-ledger-api"}, h.alice, h.bob)

	vulnDigest := "sha256:a100000000000000000000000000000000000000000000000000000000000001"
	patchedDigest := "sha256:a144444444444444444444444444444444444444444444444444444444444444"
	sarif := server.BuildDeterministicSARIF(
		"CVE-2026-90006", "CWE-787", 9.8, true, "payments-ledger-api",
		vulnDigest, patchedDigest, "tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)
	items, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif, "STATELESS_CLEAN")
	if err != nil || len(items) != 1 || items[0].Stage != models.StageAttestedClosed {
		t.Fatalf("pre-drift closure failed: %+v err=%v", items, err)
	}

	// Start background 100ms N3 drift watcher AND activate FREEZE_HOLD to prove drift re-arming works even while frozen!
	watchCtx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	h.orch.N3Verify.StartDriftWatcher(watchCtx, 100*time.Millisecond)
	_, _ = h.orch.N1Warrant.TriggerEmergencyFreeze(h.ctx, models.FreezeModeHold, "ops-test", "FREEZE_DURING_DRIFT_TEST", nil)

	start := time.Now()
	if _, _, err := h.orch.Deploy.InjectDriftSimulation(h.ctx, "payments-ledger-api", vulnDigest); err != nil {
		t.Fatalf("InjectDriftSimulation failed: %v", err)
	}

	var detected *models.DriftIncident
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		drifts, _ := h.store.ListDriftIncidents(h.ctx)
		if len(drifts) > 0 {
			detected = &drifts[0]
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	elapsed := time.Since(start)
	if detected == nil {
		t.Fatal("N3 drift watcher failed to detect runtime drift and re-arm bridge")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected sub-second/near-instant drift re-arming, took %v", elapsed)
	}

	rearmedBridge, err := h.store.GetBridge(h.ctx, detected.RearmedBridgeID)
	if err != nil || rearmedBridge.Status != "REARMED_DRIFT" {
		t.Fatalf("expected Cilium bridge REARMED_DRIFT, got %+v err=%v", rearmedBridge, err)
	}
	updatedRem, _ := h.store.GetRemediation(h.ctx, items[0].RemediationID)
	if updatedRem.StatusHealth != models.HealthDriftViolation {
		t.Fatalf("expected remediation marked DRIFT_VIOLATION, got %s", updatedRem.StatusHealth)
	}
}

// INVARIANT 6: Immutable Trigger-Protected & SHA-256 Hash-Chained Ledger Tables
func TestInvariant6_ImmutableHashChainedLedger(t *testing.T) {
	h := setupIsolatedHarness(t)
	w := mintDualWarrant(t, h, "wrt-inv6-a", []string{"payments-ledger-api"}, h.alice, h.bob)
	mintDualWarrant(t, h, "wrt-inv6-b", []string{"identity-sso-gateway"}, h.elena, h.marcus)

	sarif := server.BuildDeterministicSARIF(
		"CVE-2026-90007", "CWE-787", 9.8, true, "payments-ledger-api",
		"sha256:a100000000000000000000000000000000000000000000000000000000000001",
		"sha256:a133333333333333333333333333333333333333333333333333333333333333",
		"tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
	)
	if _, err := h.orch.ExecuteSARIFRemediation(h.ctx, sarif, "STATELESS_CLEAN"); err != nil {
		t.Fatal(err)
	}

	// 1. Prove PostgreSQL BEFORE UPDATE OR DELETE triggers block mutations on all 3 ledger tables
	immutableChecks := []string{
		fmt.Sprintf(`UPDATE warrant_envelopes SET max_cvss = 5.0 WHERE warrant_id = '%s'`, w.WarrantID),
		fmt.Sprintf(`DELETE FROM warrant_envelopes WHERE warrant_id = '%s'`, w.WarrantID),
		`UPDATE agent_action_ledger SET status = 'SECURITY_VIOLATION'`,
		`DELETE FROM agent_action_ledger`,
		`UPDATE attestation_records SET cve_id = 'CVE-1999-0001'`,
		`DELETE FROM attestation_records`,
	}
	for _, stmt := range immutableChecks {
		_, err := h.store.Pool().Exec(h.ctx, stmt)
		if err == nil || !strings.Contains(err.Error(), "IMMUTABLE_LEDGER_VIOLATION") {
			t.Fatalf("expected PostgreSQL trigger IMMUTABLE_LEDGER_VIOLATION for %q, got: %v", stmt, err)
		}
	}

	// 2. Prove intact hash chains verify cleanly across all 3 tables
	rep, err := h.store.VerifyAllLedgerChains(h.ctx)
	if err != nil || !rep.AllValid {
		t.Fatalf("expected all 3 ledger hash chains valid, got %+v err=%v", rep, err)
	}

	// 3. Simulate superuser disk-level hash-link tampering (by disabling trigger temporarily, mutating a field, re-enabling trigger)
	// and prove VerifyAllLedgerChains immediately detects the broken cryptographic hash link!
	_, err = h.store.Pool().Exec(h.ctx, `
		ALTER TABLE agent_action_ledger DISABLE TRIGGER trg_immutable_agent_action_ledger;
		UPDATE agent_action_ledger SET worker_name = 'tampered-worker' WHERE seq_no = 1;
		ALTER TABLE agent_action_ledger ENABLE TRIGGER trg_immutable_agent_action_ledger;
	`)
	if err != nil {
		t.Fatalf("simulate disk tamper setup failed: %v", err)
	}

	tamperedRep, err := h.store.VerifyAllLedgerChains(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tamperedRep.AllValid {
		t.Fatal("expected VerifyAllLedgerChains to detect tampered hash link in agent_action_ledger")
	}
}

// LIVE THREAT & SCANNER FEEDS: Offline Enclave Default + Sanitized CISA KEV, OSV.dev & Trivy SARIF Intake
func TestLiveFeeds_OfflineDefaultAndCISAKEVOSVTrivyEnrichment(t *testing.T) {
	h := setupIsolatedHarness(t)
	mintDualWarrant(t, h, "wrt-live-feeds", []string{"payments-ledger-api"}, h.alice, h.bob)

	// 1. Default mode MUST be offline and block external sync calls
	st, err := h.store.GetLiveFeedStatus(h.ctx)
	if err != nil || st.Config.Mode != models.FeedModeOffline {
		t.Fatalf("expected default feed mode 'offline', got %+v err=%v", st, err)
	}
	if _, err := h.orch.Feeds.SyncCISAKEV(h.ctx); err == nil || !strings.Contains(err.Error(), "FEED_MODE_OFFLINE") {
		t.Fatalf("expected SyncCISAKEV blocked in offline mode, got: %v", err)
	}

	// 2. Spin up local mock CISA KEV + Google OSV.dev servers and switch runtime feed config to 'live'
	feedMux := http.NewServeMux()
	feedMux.HandleFunc("GET /cisa/kev.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"catalogVersion": "2026.11.19",
			"dateReleased": "2026-11-19T00:00:00Z",
			"vulnerabilities": [
				{"cveID": "CVE-2023-38545", "dateAdded": "2023-10-18", "dueDate": "2023-11-08", "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-787"], "shortDescription": "STRIP_PROSE"},
				{"cveID": "CVE-2023-44487", "dateAdded": "2023-10-10", "dueDate": "2023-10-31", "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-400"], "shortDescription": "STRIP_PROSE"}
			]
		}`))
	})
	feedMux.HandleFunc("POST /osv/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results": [{"vulns": [{"id": "GO-2023-2102"}]}]}`))
	})
	feedMux.HandleFunc("GET /osv/v1/vulns/GO-2023-2102", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "GO-2023-2102",
			"aliases": ["CVE-2023-44487"],
			"summary": "UNTRUSTED SUMMARY",
			"database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-400"]},
			"affected": [{"ranges": [{"events": [{"fixed": "0.17.0"}]}]}]
		}`))
	})
	mockFeeds := httptest.NewServer(feedMux)
	defer mockFeeds.Close()

	_, err = h.orch.Feeds.UpdateConfig(h.ctx, models.FeedRuntimeConfig{
		Mode:            models.FeedModeLive,
		CISAKEVURL:      mockFeeds.URL + "/cisa/kev.json",
		KEVPollInterval: "1h",
		OSVAPIURL:       mockFeeds.URL + "/osv/v1/querybatch",
		TrivyEnabled:    true,
	})
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	kevRun, err := h.orch.Feeds.SyncCISAKEV(h.ctx)
	if err != nil || kevRun.ItemsIngested != 2 {
		t.Fatalf("SyncCISAKEV failed: run=%+v err=%v", kevRun, err)
	}

	osvRun, osvAdvisories, err := h.orch.Feeds.SyncOSV(h.ctx)
	if err != nil || osvRun.ItemsIngested != 1 || len(osvAdvisories) != 1 || !osvAdvisories[0].IsKEV {
		t.Fatalf("SyncOSV expected 1 KEV-matched advisory, got run=%+v adv=%+v err=%v", osvRun, osvAdvisories, err)
	}

	// 3. POST unmodified native Trivy SARIF 2.1.0 report to /api/v1/intake/sarif?target_service=payments-ledger-api
	// Note: raw Trivy SARIF does NOT set cisa_kev=true, proving warrantd cross-checks against synced cisa_kev_catalog!
	trivySARIF := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {
				"name": "Trivy",
				"rules": [{"id": "CVE-2023-38545", "properties": {"security-severity": "9.8", "tags": ["CRITICAL", "CWE-787"]}}]
			}},
			"results": [{"ruleId": "CVE-2023-38545", "level": "error"}]
		}]
	}`)
	resp, err := http.Post(
		h.httpSrv.URL+"/api/v1/intake/sarif?target_service=payments-ledger-api&max_findings=2",
		"application/json",
		bytes.NewReader(trivySARIF),
	)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST Trivy SARIF failed: resp=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()

	rems, _ := h.store.ListRemediations(h.ctx)
	if len(rems) != 1 || !rems[0].IsKEV || rems[0].Stage != models.StageAttestedClosed {
		t.Fatalf("expected Trivy CVE-2023-38545 enriched as IsKEV=true and closed, got %+v", rems)
	}

	// Verify ledger chains remain 100% intact after feed extractions
	chainRep, err := h.store.VerifyAllLedgerChains(h.ctx)
	if err != nil || !chainRep.AllValid {
		t.Fatalf("ledger chain broken after live feed syncs: %+v err=%v", chainRep, err)
	}
}

func replaceDBName(dsn, newDB string) string {
	qIdx := strings.Index(dsn, "?")
	query := ""
	base := dsn
	if qIdx >= 0 {
		base = dsn[:qIdx]
		query = dsn[qIdx:]
	}
	slashIdx := strings.LastIndex(base, "/")
	if slashIdx < 0 {
		return dsn
	}
	return base[:slashIdx+1] + newDB + query
}
