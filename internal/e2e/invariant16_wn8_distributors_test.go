package e2e

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters/distributors"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/extractor"
	"github.com/cgilbert61/G1-Warrant/internal/gate"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
)

// TestInvariant16_WN8DistributorContractsWaveSequencingRollbackAndPartialClosure proves the WN-8 Distributor Contract:
//  1. All 15 canonical enterprise patch distributors across 6 families are registered behind a single
//     DistributorTranslator interface (DeploymentOrder out / DeploymentResult in).
//  2. Immovable Preconditions:
//     - Out-of-scope target assets fail closed (TARGET_ASSET_OUTSIDE_WARRANT_SCOPE) with zero orders created.
//     - Missing N3 twin/provenance proof fails closed (NO_PROOF_NO_DEPLOYMENT_ORDER) with zero orders created.
//  3. Every outbound distributor HTTP call carries verifiable N4 wire X-Warrant-Task-DSSE + X-Warrant-Agent-PoP
//     bound to agt-distributor-gateway and action DEPLOY_GOVERNED_PATCH.
//  4. Native-ring distributors (ms-intune) pass progressive ring waves directly, and partial fleet convergence
//     (4/6 LANDED, 2/6 REBOOT_WAITING) mints an honest PARTIAL OSCAL attestation while REFUSING to retire the
//     active containment bridge (Zero Overclaim).
//  5. Fire-and-forget distributors (flux / DISPATCH_ACK_ONLY) receive ASSURANCE_TIER_0_DISTRIBUTOR_DISPATCH_ONLY
//     and refuse to retire containment bridges.
//  6. Non-ring batch distributors (ansible-awx) are deterministically wave-sliced (5% -> 25% -> 100%) by N2:
//     - Pre-recorded NativeRollbackSpec is persisted immutably in WORM deployment_orders BEFORE Wave 1 fires.
//     - On full landing (6/6), FULL OSCAL is minted and the containment bridge is retired.
//     - On Wave-2 failure threshold breach, Wave 3 never fires, symmetric ExecuteRollback invokes the pre-recorded
//       native downgrade instruction, remediation enters QUARANTINED_ROLLBACK, and containment stays ARMED.
func TestInvariant16_WN8DistributorContractsWaveSequencingRollbackAndPartialClosure(t *testing.T) {
	h := setupIsolatedHarness(t)
	ctx := h.ctx

	aliceBundle := personaToSignerBundle(h.alice)
	bobBundle := personaToSignerBundle(h.bob)
	cli := warrantsdk.NewClient(h.httpSrv.URL, warrantsdk.WithSignerBundle(aliceBundle))

	// -------------------------------------------------------------------------
	// 1. Verify All 15 Canonical Distributor Translators Are Registered
	// -------------------------------------------------------------------------
	distList, err := cli.ListDistributors(ctx)
	if err != nil {
		t.Fatalf("ListDistributors: %v", err)
	}
	if len(distList) != 15 {
		t.Fatalf("expected all 15 built-in WN-8 DistributorTranslators registered, got %d", len(distList))
	}

	// Mint a 2-of-2 Standing Warrant scoping explicit Windows + Linux fleet assets
	allowedWinAssets := []string{"win-pay-01", "win-pay-02", "win-pay-03", "win-pay-04", "win-pay-05", "win-pay-06"}
	allowedRhelAssets := []string{"rhel-pay-01", "rhel-pay-02", "rhel-pay-03", "rhel-pay-04", "rhel-pay-05", "rhel-pay-06"}
	scopeAssets := append([]string{"payments-ledger-api", "identity-sso-gateway"}, allowedWinAssets...)
	scopeAssets = append(scopeAssets, allowedRhelAssets...)

	wEnv, _, err := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantID:              "wrt-inv16-fleet",
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          []string{"payments-ledger-api", "identity-sso-gateway"},
		ScopeAssets:            scopeAssets,
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 8,
		SLABridgeMinutes:       60,
		MaxP99LatencyMs:        120.0,
		TTLDays:                30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceBundle.SignEnvelope(1, wEnv); err != nil {
		t.Fatal(err)
	}
	if err := bobBundle.SignEnvelope(2, wEnv); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.CreateWarrant(ctx, *wEnv); err != nil {
		t.Fatalf("CreateWarrant: %v", err)
	}

	// Helper to verify wire-level N4 PoP headers on mock vendor HTTP endpoints
	kernelPub := ed25519.PublicKey(h.orch.N5Ledger.KernelPublicKey().PublicKeyBytes)
	verifyDistributorWirePoP := func(r *http.Request, body []byte) error {
		if _, vErr := extractor.VerifyWireTaskAndAgentPoP(
			r,
			body,
			"DISPATCH_DEPLOYMENT_ORDER",
			[]ed25519.PublicKey{kernelPub},
			true,
		); vErr != nil {
			return vErr
		}
		envRaw, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Warrant-Task-DSSE"))
		var taskEnv crypto.Envelope
		if err := json.Unmarshal(envRaw, &taskEnv); err != nil {
			return err
		}
		pBytes, err := taskEnv.DecodePayload()
		if err != nil {
			return err
		}
		var tp models.EphemeralTaskWarrantPayload
		if err := json.Unmarshal(pBytes, &tp); err != nil {
			return err
		}
		if tp.Sub != "agt-distributor-gateway" {
			t.Errorf("expected governed distributor sub=agt-distributor-gateway, got %s", tp.Sub)
		}
		return nil
	}

	// Create a contained remediation item ready for distributor dispatch (using UPSTREAM_VENDOR_PENDING so intake stops at Stage 2 Bridged)
	createContainedRemediation := func(cveID string) models.RemediationItem {
		qualysDoc := []byte(`{"hosts":[{"service_id":"payments-ledger-api","asset_key":"win-pay-01","ip":"10.50.1.1","detections":[{"qid":380001,"severity":5,"cvss3_base":9.8,"status":"Active","cisa_kev":true,"cves":["` + cveID + `"]}]}]}`)
		items, fErr := cli.SubmitFinderIntake(ctx, "qualys", qualysDoc, warrantsdk.FinderIntakeOptions{
			PatchProfile:  "UPSTREAM_VENDOR_PENDING",
			TargetService: "payments-ledger-api",
		})
		if fErr != nil || len(items) != 1 {
			t.Fatalf("seed contained remediation (%s): %+v err=%v", cveID, items, fErr)
		}
		return items[0]
	}

	// -------------------------------------------------------------------------
	// 2. Immovable Precondition Gates: Out-of-Scope Asset & Missing N3 Proof
	// -------------------------------------------------------------------------
	remGuard := createContainedRemediation("CVE-2026-61001")

	// 2A. Out-of-scope target asset ("rogue-unscoped-host-99") MUST fail closed with zero orders persisted
	_, scopeErr := cli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: remGuard.RemediationID,
		DistributorID: warrantsdk.DistributorMSIntune,
		TargetAssets: []warrantsdk.AssetTarget{
			{AssetKey: "win-pay-01", ServiceID: "payments-ledger-api"},
			{AssetKey: "rogue-unscoped-host-99", ServiceID: "payments-ledger-api"},
		},
		RollbackInstruction: warrantsdk.NativeRollbackSpec{
			Strategy:    "INTUNE_UNINSTALL_KB",
			UninstallKB: "KB5040001",
		},
	})
	if scopeErr == nil || !strings.Contains(scopeErr.Error(), "TARGET_ASSET_OUTSIDE_WARRANT_SCOPE") {
		t.Fatalf("expected TARGET_ASSET_OUTSIDE_WARRANT_SCOPE rejection, got: %v", scopeErr)
	}
	ordersAfterScopeBlock, _ := cli.ListDeploymentOrders(ctx, remGuard.RemediationID)
	if len(ordersAfterScopeBlock) != 0 {
		t.Fatalf("expected 0 DeploymentOrders created after out-of-scope block, got %d", len(ordersAfterScopeBlock))
	}

	// 2B. Calling N2Gate.ExecuteDistributorRollout without N3 proof (ProofVerified=false) MUST fail closed
	svcPay, _ := h.store.GetEstateService(ctx, "payments-ledger-api")
	remGuardDB, _ := h.store.GetRemediation(ctx, remGuard.RemediationID)
	_, noProofErr := h.orch.N2Gate.ExecuteDistributorRollout(ctx, h.orch.Distributors, gate.DistributorExecutionRequest{
		Remediation:   remGuardDB,
		Service:       svcPay,
		DistributorID: models.DistributorMSIntune,
		FixIdentity:   models.FixIdentity{CVEID: remGuardDB.CVEID, KBArticleID: "KB5040001"},
		TargetAssets:  []models.AssetTarget{{AssetKey: "win-pay-01", ServiceID: "payments-ledger-api"}},
		RollbackInstruction: models.NativeRollbackSpec{
			Strategy:    "INTUNE_UNINSTALL_KB",
			UninstallKB: "KB5040001",
		},
		ProofVerified:    false,
		TwinReplayStatus: "PENDING",
	})
	if noProofErr == nil || !strings.Contains(noProofErr.Error(), "NO_PROOF_NO_DEPLOYMENT_ORDER") {
		t.Fatalf("expected NO_PROOF_NO_DEPLOYMENT_ORDER fail-closed rejection, got: %v", noProofErr)
	}
	ordersAfterNoProof, _ := cli.ListDeploymentOrders(ctx, remGuard.RemediationID)
	if len(ordersAfterNoProof) != 0 {
		t.Fatalf("expected 0 DeploymentOrders created when N3 proof is absent, got %d", len(ordersAfterNoProof))
	}

	// -------------------------------------------------------------------------
	// 3. Native-Ring Distributor (ms-intune) + Honest PARTIAL Closure (4/6 Landed, 2/6 Reboot-Waiting)
	// -------------------------------------------------------------------------
	var intuneDispatchCalls int
	var intuneRingsCount int
	mockIntune := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := verifyDistributorWirePoP(r, body); err != nil {
			http.Error(w, "WIRE_POP_INVALID: "+err.Error(), http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/beta/deviceManagement/windowsQualityUpdateProfiles":
			intuneDispatchCalls++
			var reqMap map[string]any
			_ = json.Unmarshal(body, &reqMap)
			if rings, ok := reqMap["deploymentRings"].([]any); ok {
				intuneRingsCount = len(rings)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "intune-prof-partial-01"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/deviceUpdateStates"):
			// Report 4 succeeded + 2 pendingReboot across the 6 Windows hosts
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"deviceId": "dev-1", "deviceDisplayName": "win-pay-01", "status": "succeeded"},
					{"deviceId": "dev-2", "deviceDisplayName": "win-pay-02", "status": "succeeded"},
					{"deviceId": "dev-3", "deviceDisplayName": "win-pay-03", "status": "succeeded"},
					{"deviceId": "dev-4", "deviceDisplayName": "win-pay-04", "status": "succeeded"},
					{"deviceId": "dev-5", "deviceDisplayName": "win-pay-05", "status": "pendingReboot"},
					{"deviceId": "dev-6", "deviceDisplayName": "win-pay-06", "status": "pendingReboot"},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockIntune.Close()
	h.orch.Distributors.Register(distributors.NewMSIntuneTranslator(mockIntune.URL, "intune-graph-tok", nil))

	remPartial := createContainedRemediation("CVE-2026-61002")
	winTargets := make([]warrantsdk.AssetTarget, 0, len(allowedWinAssets))
	for _, ak := range allowedWinAssets {
		winTargets = append(winTargets, warrantsdk.AssetTarget{
			AssetKey:       ak,
			ServiceID:      "payments-ledger-api",
			Hostname:       ak + ".corp.internal",
			PlatformFamily: "WINDOWS",
		})
	}

	partialOut, err := cli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: remPartial.RemediationID,
		DistributorID: warrantsdk.DistributorMSIntune,
		FixIdentity: &warrantsdk.FixIdentity{
			CVEID:       "CVE-2026-61002",
			KBArticleID: "KB5041111",
		},
		TargetAssets: winTargets,
		RollbackInstruction: warrantsdk.NativeRollbackSpec{
			Strategy:    "INTUNE_UNINSTALL_KB",
			UninstallKB: "KB5041111",
		},
	})
	if err != nil {
		t.Fatalf("DispatchDistributorOrder(ms-intune partial): %v", err)
	}
	if intuneDispatchCalls != 1 || intuneRingsCount != 3 {
		t.Fatalf("expected ms-intune (SupportsNativeRings=true) to dispatch 1 native ring profile with 3 rings, got calls=%d rings=%d",
			intuneDispatchCalls, intuneRingsCount)
	}
	if partialOut.Attestation == nil {
		t.Fatalf("expected honest PARTIAL OSCAL attestation minted for 4/6 landed + 2/6 reboot-waiting")
	}
	if partialOut.Attestation.ClosureCompleteness != models.ClosureCompletenessPartial ||
		partialOut.Attestation.LandedAssetCount != 4 ||
		partialOut.Attestation.TargetedAssetCount != 6 ||
		partialOut.Attestation.RebootWaitingCount != 2 {
		t.Fatalf("unexpected PARTIAL attestation counts: %+v", partialOut.Attestation)
	}
	// Crucial WN-8 invariant: Containment Bridge MUST NOT be retired while 2/6 hosts await reboot!
	partialBridge, err := h.store.GetBridge(ctx, remPartial.BridgeID)
	if err != nil || partialBridge == nil || partialBridge.Status != "ARMED" {
		t.Fatalf("OVERCLAIM VIOLATION: containment bridge %s must remain ARMED during PARTIAL closure (4/6 landed), got %+v",
			remPartial.BridgeID, partialBridge)
	}
	if partialOut.Remediation.Stage == models.StageAttestedClosed || partialOut.Remediation.ClosureCompleteness != models.ClosureCompletenessPartial {
		t.Fatalf("expected remediation NOT to enter ATTESTED_CLOSED while bridge holds unpatched hosts (got stage=%s completeness=%s)",
			partialOut.Remediation.Stage, partialOut.Remediation.ClosureCompleteness)
	}

	// Verify exported OSCAL JSON explicitly records PARTIAL closure & reboot-waiting-count=2
	oscalBytes, err := cli.ExportOSCALBundle(ctx, partialOut.Attestation.AttestationID)
	if err != nil {
		t.Fatalf("ExportOSCALBundle(partial): %v", err)
	}
	oscalStr := string(oscalBytes)
	if !strings.Contains(oscalStr, `"value":"PARTIAL"`) && !strings.Contains(oscalStr, `"value": "PARTIAL"`) {
		t.Fatalf("expected exported OSCAL POA&M bundle to declare closure-completeness=PARTIAL")
	}

	// -------------------------------------------------------------------------
	// 4. Fire-and-Forget Distributor (flux -> DISPATCH_ACK_ONLY / Tier 0)
	// -------------------------------------------------------------------------
	remFlux := createContainedRemediation("CVE-2026-61003")
	fluxOut, err := cli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: remFlux.RemediationID,
		DistributorID: warrantsdk.DistributorFlux,
		TargetAssets:  []warrantsdk.AssetTarget{{AssetKey: "payments-ledger-api", ServiceID: "payments-ledger-api"}},
		RollbackInstruction: warrantsdk.NativeRollbackSpec{
			Strategy:        "GIT_REVERT_COMMIT",
			GitRevertCommit: "a1b2c3d4e5f6",
		},
	})
	if err != nil {
		t.Fatalf("DispatchDistributorOrder(flux): %v", err)
	}
	if fluxOut.Remediation.AssuranceTier != models.AssuranceTier0DistributorDispatchOnly ||
		fluxOut.Remediation.ClosureCompleteness != models.ClosureCompletenessDispatchOnly {
		t.Fatalf("expected flux DISPATCH_ACK_ONLY to receive ASSURANCE_TIER_0_DISTRIBUTOR_DISPATCH_ONLY, got tier=%s completeness=%s",
			fluxOut.Remediation.AssuranceTier, fluxOut.Remediation.ClosureCompleteness)
	}
	fluxBridge, _ := h.store.GetBridge(ctx, remFlux.BridgeID)
	if fluxBridge == nil || fluxBridge.Status != "ARMED" {
		t.Fatalf("expected containment bridge to remain ARMED for fire-and-forget DISPATCH_ACK_ONLY distributor, got %+v", fluxBridge)
	}

	// -------------------------------------------------------------------------
	// 5. Warrant-Sequenced Waves (ansible-awx: SupportsNativeRings=false)
	//    5A: Clean 3-Wave Full Closure + WORM Pre-Wave Rollback Persistence Proof
	//    5B: Wave-2 Failure -> Wave 3 Aborted + Automatic Native Rollback
	// -------------------------------------------------------------------------
	var awxMu sync.Mutex
	var awxLaunchedWaves []int
	var awxWaveHosts [][]string
	var firstWaveReceivedAt time.Time
	failOnWave2 := false
	var rollbackInvocations int
	var lastRollbackPrevNEVRA string

	mockAWX := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := verifyDistributorWirePoP(r, body); err != nil {
			http.Error(w, "WIRE_POP_INVALID: "+err.Error(), http.StatusUnauthorized)
			return
		}
		awxMu.Lock()
		defer awxMu.Unlock()

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/job_templates/patch/launch/":
			if firstWaveReceivedAt.IsZero() {
				firstWaveReceivedAt = time.Now().UTC()
			}
			var payload struct {
				ExtraVars struct {
					WaveNumber  int      `json:"wave_number"`
					TargetHosts []string `json:"target_hosts"`
				} `json:"extra_vars"`
			}
			_ = json.Unmarshal(body, &payload)
			awxLaunchedWaves = append(awxLaunchedWaves, payload.ExtraVars.WaveNumber)
			awxWaveHosts = append(awxWaveHosts, payload.ExtraVars.TargetHosts)
			jobID := "awx-job-" + strings.Join(payload.ExtraVars.TargetHosts, "_")
			_ = json.NewEncoder(w).Encode(map[string]any{"job": jobID})

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/job_events/"):
			waveIdx := len(awxWaveHosts) - 1
			hosts := awxWaveHosts[waveIdx]
			var events []map[string]any
			for _, host := range hosts {
				evType := "runner_on_ok"
				rc := 0
				if failOnWave2 && len(awxLaunchedWaves) == 2 {
					evType = "runner_on_failed"
					rc = 2
				}
				events = append(events, map[string]any{
					"host":     host,
					"event":    evType,
					"changed":  true,
					"modified": time.Now().UTC().Format(time.RFC3339),
					"event_data": map[string]any{
						"res": map[string]any{"rc": rc, "reboot_required": false},
					},
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": events})

		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/job_templates/rollback_package_downgrade/launch/":
			rollbackInvocations++
			var rbReq struct {
				ExtraVars struct {
					PreviousPackageNEVRA string   `json:"previous_package_nevra"`
					TargetHosts          []string `json:"target_hosts"`
				} `json:"extra_vars"`
			}
			_ = json.Unmarshal(body, &rbReq)
			lastRollbackPrevNEVRA = rbReq.ExtraVars.PreviousPackageNEVRA
			var items []models.AssetDeploymentStatus
			for _, host := range rbReq.ExtraVars.TargetHosts {
				items = append(items, models.AssetDeploymentStatus{
					AssetKey:   host,
					State:      models.AssetDeployRolledBack,
					ReportedAt: time.Now().UTC(),
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": items})

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockAWX.Close()
	h.orch.Distributors.Register(distributors.NewAnsibleAWXTranslator(mockAWX.URL, "awx-tok", nil))

	rhelTargets := make([]warrantsdk.AssetTarget, 0, len(allowedRhelAssets))
	for _, ak := range allowedRhelAssets {
		rhelTargets = append(rhelTargets, warrantsdk.AssetTarget{
			AssetKey:       ak,
			ServiceID:      "payments-ledger-api",
			Hostname:       ak,
			PlatformFamily: "LINUX_RPM",
		})
	}

	// 5A. Clean 3-Wave Full Closure (5% -> 25% -> 100% across 6 RHEL hosts -> [1 host, 1 host, 4 hosts])
	remAWXFull := createContainedRemediation("CVE-2026-61004")
	fullOut, err := cli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: remAWXFull.RemediationID,
		DistributorID: warrantsdk.DistributorAnsibleAWX,
		FixIdentity: &warrantsdk.FixIdentity{
			CVEID:        "CVE-2026-61004",
			PackageNEVRA: "openssl-3.0.7-28.el9_4.x86_64",
		},
		TargetAssets:    rhelTargets,
		WavePercentages: []int{5, 25, 100},
		RollbackInstruction: warrantsdk.NativeRollbackSpec{
			Strategy:             "ANSIBLE_PLAYBOOK_DOWNGRADE_NEVRA",
			RollbackPlaybookID:   "rollback_package_downgrade",
			PreviousPackageNEVRA: "openssl-3.0.7-24.el9.x86_64",
		},
	})
	if err != nil {
		t.Fatalf("DispatchDistributorOrder(ansible-awx full): %v", err)
	}
	if len(awxLaunchedWaves) != 3 || awxLaunchedWaves[0] != 1 || awxLaunchedWaves[1] != 2 || awxLaunchedWaves[2] != 3 {
		t.Fatalf("expected Warrant wave_sequencer to slice non-ring ansible-awx into 3 sequential waves [1,2,3], got %v", awxLaunchedWaves)
	}
	if len(awxWaveHosts[0])+len(awxWaveHosts[1])+len(awxWaveHosts[2]) != 6 {
		t.Fatalf("expected disjoint 6 hosts across 3 waves, got %v", awxWaveHosts)
	}

	// Prove Primary DeploymentOrder + RollbackInstruction was persisted in PostgreSQL BEFORE Wave 1 reached AWX
	persistedOrders, err := cli.ListDeploymentOrders(ctx, remAWXFull.RemediationID)
	if err != nil || len(persistedOrders) < 1 {
		t.Fatalf("ListDeploymentOrders(ansible-awx): %+v err=%v", persistedOrders, err)
	}
	primaryOrd := fullOut.Rollout.PrimaryOrder
	if primaryOrd.CreatedAt.After(firstWaveReceivedAt) {
		t.Fatalf("PRE-WAVE PERSISTENCE VIOLATION: primary order created_at (%s) was after Wave 1 HTTP launch (%s)!",
			primaryOrd.CreatedAt.Format(time.RFC3339Nano), firstWaveReceivedAt.Format(time.RFC3339Nano))
	}
	if primaryOrd.RollbackInstruction.PreviousPackageNEVRA != "openssl-3.0.7-24.el9.x86_64" {
		t.Fatalf("missing pre-recorded RollbackInstruction in DeploymentOrder: %+v", primaryOrd.RollbackInstruction)
	}

	// Prove WORM immutability trigger on deployment_orders rejects SQL UPDATE!
	if _, uErr := h.store.Pool().Exec(ctx, `UPDATE deployment_orders SET warrant_id = 'tampered' WHERE order_id = $1`, primaryOrd.OrderID); uErr == nil {
		t.Fatalf("WORM VIOLATION: SQL UPDATE on deployment_orders succeeded instead of failing closed via trigger!")
	}

	// Verify 6/6 FULL closure retired the containment bridge and minted FULL OSCAL
	if fullOut.Attestation == nil || fullOut.Attestation.ClosureCompleteness != models.ClosureCompletenessFull || fullOut.Attestation.LandedAssetCount != 6 {
		t.Fatalf("expected FULL OSCAL closure with 6/6 landed, got %+v", fullOut.Attestation)
	}
	retiredBridge, _ := h.store.GetBridge(ctx, remAWXFull.BridgeID)
	if retiredBridge == nil || retiredBridge.Status != "RETIRED" {
		t.Fatalf("expected containment bridge to RETIRE after 6/6 FULL verified landing, got %+v", retiredBridge)
	}

	// 5B. Inject Wave-2 Failure on ansible-awx -> Prove Wave 3 Never Fires & Automatic Native Rollback Executes!
	awxMu.Lock()
	awxLaunchedWaves = nil
	awxWaveHosts = nil
	failOnWave2 = true
	rollbackInvocations = 0
	lastRollbackPrevNEVRA = ""
	awxMu.Unlock()

	remAWXFail := createContainedRemediation("CVE-2026-61005")
	failOut, err := cli.DispatchDistributorOrder(ctx, warrantsdk.DistributorDispatchRequest{
		RemediationID: remAWXFail.RemediationID,
		DistributorID: warrantsdk.DistributorAnsibleAWX,
		FixIdentity: &warrantsdk.FixIdentity{
			CVEID:        "CVE-2026-61005",
			PackageNEVRA: "glibc-2.34-105.el9_4.x86_64",
		},
		TargetAssets:      rhelTargets,
		WavePercentages:   []int{5, 25, 100},
		MaxFailureRatePct: 0.0,
		RollbackInstruction: warrantsdk.NativeRollbackSpec{
			Strategy:             "ANSIBLE_PLAYBOOK_DOWNGRADE_NEVRA",
			RollbackPlaybookID:   "rollback_package_downgrade",
			PreviousPackageNEVRA: "glibc-2.34-100.el9.x86_64",
		},
	})
	if err != nil {
		t.Fatalf("DispatchDistributorOrder(ansible-awx wave-2 failure): %v", err)
	}
	if len(awxLaunchedWaves) != 2 {
		t.Fatalf("expected Wave 3 to NEVER fire after Wave 2 failure! Launched waves=%v", awxLaunchedWaves)
	}
	if !failOut.Rollout.RolledBack || rollbackInvocations == 0 || lastRollbackPrevNEVRA != "glibc-2.34-100.el9.x86_64" {
		t.Fatalf("expected automatic symmetric ExecuteRollback with pre-recorded glibc-2.34-100.el9.x86_64, got rolledBack=%t invocations=%d prev=%s",
			failOut.Rollout.RolledBack, rollbackInvocations, lastRollbackPrevNEVRA)
	}
	if failOut.Remediation.StatusHealth != models.HealthQuarantinedRollback || failOut.Remediation.Stage != models.StageBridgedContained {
		t.Fatalf("expected remediation to transition to QUARANTINED_ROLLBACK / BRIDGED_CONTAINED, got %+v", failOut.Remediation)
	}
	rearmedBridge, _ := h.store.GetBridge(ctx, remAWXFail.BridgeID)
	if rearmedBridge == nil || rearmedBridge.Status != "ARMED" {
		t.Fatalf("expected containment bridge to stay/re-arm ARMED after Wave 2 rollback, got %+v", rearmedBridge)
	}

	// Verify all cryptographic hash chains remain 100% valid
	chainRep, err := cli.VerifyLedgerChains(ctx)
	if err != nil || !chainRep.AllValid {
		t.Fatalf("VerifyLedgerChains failed after WN-7/WN-8 operations: %+v err=%v", chainRep, err)
	}
}
