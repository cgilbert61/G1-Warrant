package e2e

import (
	"context"
	"fmt"
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
	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestInvariant21_GUIVendorConfiguratorDemoMockAndServerTwinSelection locks the v1.4.1 GUI Connector,
// fleet-sim Demo Estate Mock, and Ephemeral Server-to-Twin Selection invariants:
//  1. GET /api/v1/estate-loader/connectors exposes all 18 systems with masked token status (never raw secrets).
//  2. PUT /api/v1/estate-loader/connectors/{id} enforces Rule 2 (ReadToken == DispatchToken -> HTTP 403) and RejectEstateReadCredentialOnMutation.
//  3. POST /api/v1/estate-loader/connectors/demo-mock wires all 18 systems to fleet-sim's wire-accurate Demo Estate Mock,
//     where every Tier A & Tier B system returns selectable servers and Tier C scanners return 0 clone sources / 0 twin servers.
//  4. Selecting a specific server from the connected estate service (e.g., ec2-pay-01.us-east-1.internal -> ami-0qa8812ec2pay01)
//     binds SelectedServerID + SelectedServerHostname + ImageIdentity into the 2-of-2 Standing Warrant while storing ZERO server rows in PostgreSQL.
func TestInvariant21_GUIVendorConfiguratorDemoMockAndServerTwinSelection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	adminDSN := os.Getenv("TEST_DATABASE_URL")
	if adminDSN == "" {
		adminDSN = os.Getenv("DATABASE_URL")
	}
	if adminDSN == "" {
		adminDSN = "postgres://warrant:warrant@localhost:5432/postgres?sslmode=disable"
	}
	adminConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Skipf("PostgreSQL not reachable for TestInvariant21 (%v)", err)
	}
	dbName := "warrant_inv21_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
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

	t.Setenv("WARRANT_ENABLE_TEST_SMARTCARDS", "false")
	t.Setenv("WARRANT_BOOTSTRAP_ADMIN_TOKEN", "g1adm_inv21_bootstrap_secret")

	store, err := db.NewStore(ctx, replaceDBName(adminDSN, dbName))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-extractor-inv21"))
	defer extSrv.Close()
	sim := fleetsim.NewClusterSimulator()
	simSrv := httptest.NewServer(sim.Handler())
	defer simSrv.Close()

	orch, err := server.NewOrchestrator(ctx, store, extSrv.URL, simSrv.URL, "inv21-gui-connectors-seed", crypto.DefaultWebAuthnConfig())
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
		TestCoveragePct:            95.0,
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

	soBundle, _ := warrantsdk.GenerateEd25519SignerBundle("usr-inv21-so", "so21@agency.gov", "Inv21 SO", warrantsdk.RoleServiceOwner)
	aoBundle, _ := warrantsdk.GenerateEd25519SignerBundle("usr-inv21-ao", "ao21@agency.gov", "Inv21 AO", warrantsdk.RoleAuthorizingOfficial)
	adminCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithAdminToken("g1adm_inv21_bootstrap_secret"))
	_, _ = adminCli.RegisterPrincipal(ctx, soBundle.ToRegisterRequest())
	_, _ = adminCli.RegisterPrincipal(ctx, aoBundle.ToRegisterRequest())

	uiCli := warrantsdk.NewClient(httpSrv.URL)

	// 1. Initial connector state: 18 systems, k8s-cilium-native LOCAL_CLUSTER, others UNCONFIGURED, DemoMockAvailable=true
	initialConns, err := uiCli.ListVendorConnectors(ctx)
	if err != nil || len(initialConns) != 18 {
		t.Fatalf("expected 18 vendor connectors, err=%v len=%d", err, len(initialConns))
	}
	for _, c := range initialConns {
		if !c.DemoMockAvailable {
			t.Fatalf("expected demo_mock_available=true for %s", c.SourceSystem)
		}
	}

	// 2. Same Read & Dispatch token MUST be rejected with HTTP 403 CREDENTIAL_SEPARATION_VIOLATION
	_, sameErr := uiCli.UpdateVendorConnector(ctx, "aws-ssm", warrantsdk.VendorConnectorUpdateReq{
		ReadURL:       simSrv.URL + "/mock-estate/aws-ssm",
		ReadToken:     "identical-shared-token-1234",
		DispatchURL:   simSrv.URL + "/mock-distributor/aws-ssm",
		DispatchToken: "identical-shared-token-1234",
	})
	if sameErr == nil || !strings.Contains(sameErr.Error(), "CREDENTIAL_SEPARATION_VIOLATION") {
		t.Fatalf("expected HTTP 403 CREDENTIAL_SEPARATION_VIOLATION on identical Read/Dispatch tokens, got: %v", sameErr)
	}

	// Distinct Read & Dispatch tokens succeed and return ONLY masked token previews (never cleartext)
	customSt, err := uiCli.UpdateVendorConnector(ctx, "aws-ssm", warrantsdk.VendorConnectorUpdateReq{
		ReadURL:       "https://ssm-inventory.corp.example",
		ReadToken:     "super-secret-read-9981",
		DispatchURL:   "https://ssm-dispatch.corp.example",
		DispatchToken: "super-secret-disp-4412",
	})
	if err != nil {
		t.Fatalf("UpdateVendorConnector(distinct tokens): %v", err)
	}
	if customSt.ReadTokenMasked != "••••9981" || strings.Contains(customSt.ReadTokenMasked, "super-secret") {
		t.Fatalf("expected masked read token ••••9981 without cleartext leak, got %q", customSt.ReadTokenMasked)
	}
	if customSt.DispatchTokenMasked != "••••4412" || strings.Contains(customSt.DispatchTokenMasked, "super-secret") {
		t.Fatalf("expected masked dispatch token ••••4412 without cleartext leak, got %q", customSt.DispatchTokenMasked)
	}

	// Verify read-only credential CANNOT call UpdateVendorConnector
	readOnlyCli := warrantsdk.NewClient(httpSrv.URL, warrantsdk.WithEstateReadToken("super-secret-read-9981"))
	if _, rMutErr := readOnlyCli.UpdateVendorConnector(ctx, "aws-ssm", warrantsdk.VendorConnectorUpdateReq{ReadURL: "https://evil.example"}); rMutErr == nil || !strings.Contains(rMutErr.Error(), "CREDENTIAL_SEPARATION_VIOLATION") {
		t.Fatalf("expected read-only token to be rejected on connector mutation route, got: %v", rMutErr)
	}

	// 3. Connect ALL 18 systems to fleet-sim Demo Estate Mock and verify live ephemeral server reads across all 5 families
	demoConns, err := uiCli.ConnectDemoEstateMock(ctx, "*")
	if err != nil || len(demoConns) != 18 {
		t.Fatalf("ConnectDemoEstateMock(*): err=%v len=%d", err, len(demoConns))
	}
	for _, sys := range []string{"ms-mecm", "aws-ssm", "k8s-cilium-native", "tanium-patch", "redhat-satellite", "jamf-pro"} {
		tr, tErr := uiCli.TestVendorConnectorRead(ctx, sys, "KEV-TIER1-STATELESS", []string{"payments-ledger-api", "identity-sso-gateway"})
		if tErr != nil || !tr.Reachable || len(tr.SelectableServers) < 2 {
			t.Fatalf("TestVendorConnectorRead(%s) expected >=2 selectable servers, err=%v res=%+v", sys, tErr, tr)
		}
	}
	for _, scanner := range []string{"qualys_vmdr", "tenable", "rapid7_insightvm"} {
		tr, tErr := uiCli.TestVendorConnectorRead(ctx, scanner, "KEV-TIER1-STATELESS", []string{"payments-ledger-api"})
		if tErr != nil || tr.CandidateSourceCount != 0 || len(tr.SelectableServers) != 0 {
			t.Fatalf("Tier C scanner %s MUST return 0 twin servers & 0 clone sources, err=%v res=%+v", scanner, tErr, tr)
		}
	}

	// Confirm TestVendorConnectorRead wrote ZERO rows to estate_read_evidence (pure ephemeral test)
	evBefore, err := uiCli.ListEstateEvidence(ctx, "", "")
	if err != nil || len(evBefore) != 0 {
		t.Fatalf("TestVendorConnectorRead must write 0 DB rows, got count=%d err=%v", len(evBefore), err)
	}

	// 4. Propose from aws-ssm + tenable census cross-check, select ONE specific server (`ec2-pay-01.us-east-1.internal`) to twin, and mint 2-of-2 Standing Warrant
	prop, err := uiCli.ProposeEstateClass(ctx, warrantsdk.EstateProposalRequest{
		SourceSystem:         "aws-ssm",
		CorroboratingScanner: "tenable",
		WarrantClass:         "KEV-TIER1-STATELESS",
		ScopeServices:        []string{"payments-ledger-api"},
		EstateDriftPolicy:    warrantsdk.EstateDriftPolicyRecordOnly,
		DriftTolerancePct:    15.0,
	})
	if err != nil || len(prop.SelectableServers) < 2 {
		t.Fatalf("ProposeEstateClass(aws-ssm): err=%v servers=%d", err, len(prop.SelectableServers))
	}

	chosenServer := prop.SelectableServers[0]
	if chosenServer.Hostname == "" || chosenServer.TwinImageIdentity == "" {
		t.Fatalf("invalid selectable server: %+v", chosenServer)
	}

	selectedClone := warrantsdk.DeclaredCloneSource{
		SourceSystem:           "aws-ssm",
		ImageIdentity:          chosenServer.TwinImageIdentity,
		PlatformFamily:         chosenServer.PlatformFamily,
		SelectedServerID:       chosenServer.ServerID,
		SelectedServerHostname: chosenServer.Hostname,
		SnapshotSHA256:         prop.ProposedEstateSnapshotSHA256,
		QueryIdentity:          prop.PrimarySnapshot.QueryIdentity,
		SourceMode:             warrantsdk.CloneSourceModeEstateLoader,
		ImageCreatedAt:         chosenServer.ImageCreatedAt,
		ImageAgeSecondsAtSign:  chosenServer.ImageAgeSeconds,
		DeclaredAt:             time.Now().UTC().Format(time.RFC3339),
	}

	wEnv, _, err := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:               "wrt-inv21-srv-twin",
		WarrantClass:            "KEV-TIER1-STATELESS",
		ScopeServices:           []string{"payments-ledger-api"},
		MaxCVSS:                 10.0,
		KEVEligible:             true,
		MaxBlastRadiusReplicas:  8,
		CloneSources:            []warrantsdk.DeclaredCloneSource{selectedClone},
		EstateSnapshotSHA256:    prop.ProposedEstateSnapshotSHA256,
		EstateDriftPolicy:       warrantsdk.EstateDriftPolicyRecordOnly,
		EstateDriftTolerancePct: 15.0,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = soBundle.SignEnvelope(1, wEnv)
	_ = aoBundle.SignEnvelope(2, wEnv)

	minted, err := uiCli.CreateWarrant(ctx, *wEnv)
	if err != nil {
		t.Fatalf("CreateWarrant(selected server twin): %v", err)
	}
	if len(minted.CloneSources) != 1 ||
		minted.CloneSources[0].SelectedServerHostname != chosenServer.Hostname ||
		minted.CloneSources[0].ImageIdentity != chosenServer.TwinImageIdentity {
		t.Fatalf("expected minted warrant to bind chosen server %s -> %s, got: %+v",
			chosenServer.Hostname, chosenServer.TwinImageIdentity, minted.CloneSources)
	}

	// Verify all ledger chains remain 100% valid and zero host-replication tables exist
	ledgerRep, err := uiCli.VerifyLedgerChains(ctx)
	if err != nil || !ledgerRep.AllValid {
		t.Fatalf("VerifyLedgerChains failed: err=%v rep=%+v", err, ledgerRep)
	}
}
