package warrantsdk_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
)

func TestDualKeyCeremonyAndOfflineOSCALVerification(t *testing.T) {
	soBundle, err := warrantsdk.GenerateEd25519SignerBundle("usr-so-1", "so@agency.gov", "Service Owner", warrantsdk.RoleServiceOwner)
	if err != nil {
		t.Fatalf("generate SO key: %v", err)
	}
	aoBundle, err := warrantsdk.GenerateEd25519SignerBundle("usr-ao-1", "ao@agency.gov", "Authorizing Official", warrantsdk.RoleAuthorizingOfficial)
	if err != nil {
		t.Fatalf("generate AO key: %v", err)
	}

	env, payload, err := warrantsdk.DraftWarrantEnvelope(warrantsdk.WarrantDraftOptions{
		WarrantClass:           "KEV-TIER1-STATELESS",
		ScopeServices:          []string{"payments-ledger-api"},
		MaxCVSS:                10.0,
		KEVEligible:            true,
		MaxBlastRadiusReplicas: 6,
		SLABridgeMinutes:       45,
		MaxP99LatencyMs:        100.0,
		TTLDays:                14,
	})
	if err != nil {
		t.Fatalf("draft warrant: %v", err)
	}
	if payload.WarrantID == "" || len(env.Signatures) != 0 {
		t.Fatalf("unexpected initial draft state")
	}

	if err := soBundle.SignEnvelope(1, env); err != nil {
		t.Fatalf("slot 1 sign: %v", err)
	}
	if err := aoBundle.SignEnvelope(2, env); err != nil {
		t.Fatalf("slot 2 sign: %v", err)
	}
	if len(env.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(env.Signatures))
	}

	// Verify offline OSCAL bundle verification primitive
	kernelPub, kernelPriv, _ := ed25519.GenerateKey(rand.Reader)
	kernelPK := crypto.PrincipalKey{
		PrincipalID:    "sys-warrantd-kernel",
		Email:          "kernel@g1163rt.sec",
		Role:           crypto.RoleAttestationKernel,
		KeyID:          "kernel-seal-v1",
		Alg:            crypto.AlgEd25519,
		PublicKeyBytes: kernelPub,
		KeyFingerprint: crypto.SHA256Hex(kernelPub),
	}
	attEnv, _, err := crypto.NewUnsignedEnvelope(warrantsdk.PayloadTypeAttestation, map[string]any{
		"attestation_id": "att-test-001",
		"cve_id":         "CVE-2026-41001",
		"service_id":     "payments-ledger-api",
		"warrant_id":     payload.WarrantID,
		"ttvr_seconds":   12,
	})
	if err != nil {
		t.Fatalf("new attestation env: %v", err)
	}
	if err := attEnv.SignEd25519(1, kernelPK, kernelPriv); err != nil {
		t.Fatalf("sign attestation env: %v", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(kernelPub)
	bundleBytes, _ := json.Marshal(map[string]any{
		"attestation_id": "att-test-001",
		"cve_id":         "CVE-2026-41001",
		"service_id":     "payments-ledger-api",
		"warrant_id":     payload.WarrantID,
		"dsse_envelope":  attEnv,
		"entry_hash":     strings.Repeat("a", 64),
		"kernel_public_key_ring": []warrantsdk.KernelPublicKeyRecord{
			{
				KeyID:          kernelPK.KeyID,
				Alg:            "Ed25519",
				PublicKeyB64:   pubB64,
				KeyFingerprint: kernelPK.KeyFingerprint,
			},
		},
	})

	res, err := warrantsdk.VerifyOSCALBundleOffline(bundleBytes, pubB64)
	if err != nil || !res.Valid || !res.JCSCanonicalMatch {
		t.Fatalf("expected valid offline OSCAL verification, got res=%+v err=%v", res, err)
	}
	if res.TrustBasis != warrantsdk.TrustBasisExternalPinnedPubKey {
		t.Fatalf("expected TrustBasis=%s, got %s", warrantsdk.TrustBasisExternalPinnedPubKey, res.TrustBasis)
	}
	if res.AttestationID != "att-test-001" || res.CVEID != "CVE-2026-41001" || res.ServiceID != "payments-ledger-api" || res.WarrantID != payload.WarrantID {
		t.Fatalf("expected identity fields extracted from signed payload, got %+v", res)
	}

	// WN-3a: Stripping unsigned outer wrapper fields still populates identity from signed DSSE payload
	strippedWrapperBytes, _ := json.Marshal(map[string]any{
		"dsse_envelope": attEnv,
		"entry_hash":    strings.Repeat("a", 64),
	})
	strippedRes, err := warrantsdk.VerifyOSCALBundleOffline(strippedWrapperBytes, pubB64)
	if err != nil || strippedRes.CVEID != "CVE-2026-41001" || strippedRes.ServiceID != "payments-ledger-api" || strippedRes.WarrantID != payload.WarrantID {
		t.Fatalf("expected stripped wrapper to derive identity from signed payload, got %+v err=%v", strippedRes, err)
	}

	// WN-3b: Tampering with unsigned outer wrapper field MUST fail closed with UNSIGNED_WRAPPER_MISMATCH
	tamperedWrapperBytes, _ := json.Marshal(map[string]any{
		"attestation_id": "att-test-001",
		"cve_id":         "CVE-2099-99999",
		"service_id":     "payments-ledger-api",
		"warrant_id":     payload.WarrantID,
		"dsse_envelope":  attEnv,
	})
	if _, err := warrantsdk.VerifyOSCALBundleOffline(tamperedWrapperBytes, pubB64); err == nil || !strings.Contains(err.Error(), "UNSIGNED_WRAPPER_MISMATCH") {
		t.Fatalf("expected UNSIGNED_WRAPPER_MISMATCH when outer wrapper cve_id is spoofed, got: %v", err)
	}

	// WN-4a: VerifyOSCALBundleWithKeyRing with nil/empty keyring MUST fail closed even when embedded ring exists!
	if _, err := warrantsdk.VerifyOSCALBundleWithKeyRing(bundleBytes, nil); err == nil || !strings.Contains(err.Error(), "UNTRUSTED_KEYRING_EMPTY") {
		t.Fatalf("expected UNTRUSTED_KEYRING_EMPTY when external keyring is empty, got: %v", err)
	}

	// WN-4b: External keyring verification reports TrustBasisExternalKeyRing
	extRes, err := warrantsdk.VerifyOSCALBundleWithKeyRing(bundleBytes, []warrantsdk.KernelPublicKeyRecord{
		{KeyID: kernelPK.KeyID, Alg: "Ed25519", PublicKeyB64: pubB64, KeyFingerprint: kernelPK.KeyFingerprint},
	})
	if err != nil || extRes.TrustBasis != warrantsdk.TrustBasisExternalKeyRing {
		t.Fatalf("expected TrustBasisExternalKeyRing, got res=%+v err=%v", extRes, err)
	}

	// WN-4c: Explicit opt-in embedded keyring succeeds and names EMBEDDED_BUNDLE_KEYRING_UNTRUSTED_OPT_IN
	optInRes, err := warrantsdk.VerifyOSCALBundleWithKeyRingOpts(bundleBytes, nil, warrantsdk.KeyRingVerificationOptions{
		AllowEmbeddedKeyRingOptIn: true,
	})
	if err != nil || optInRes.TrustBasis != warrantsdk.TrustBasisEmbeddedKeyRingOptIn {
		t.Fatalf("expected TrustBasisEmbeddedKeyRingOptIn, got res=%+v err=%v", optInRes, err)
	}

	// Tamper with kernel key -> must fail closed
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := warrantsdk.VerifyOSCALBundleOffline(bundleBytes, base64.StdEncoding.EncodeToString(wrongPub)); err == nil {
		t.Fatalf("expected signature verification error with wrong public key")
	}
}

func TestClientEndpointsAndAuditorScopeIsolation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer g1aud_") {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "AUDITOR_TOKEN_SCOPE_VIOLATION"})
			return
		}
		_ = json.NewEncoder(w).Encode(warrantsdk.HealthStatus{
			Status:       "OK",
			Service:      "warrantd",
			Organization: "G1163RT Security Labs, Inc.",
			FreezeMode:   "OPERATIONAL",
		})
	})
	mux.HandleFunc("GET /api/v1/scoreboard", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(warrantsdk.GlobalScoreboard{
			ActiveWarrantsCount:      3,
			AutonomousEligibilityPct: 66.7,
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx := context.Background()
	cli := warrantsdk.NewClient(ts.URL)
	h, err := cli.Health(ctx)
	if err != nil || h.Status != "OK" {
		t.Fatalf("Health failed: %+v %v", h, err)
	}

	sb, err := cli.Scoreboard(ctx)
	if err != nil || sb.ActiveWarrantsCount != 3 {
		t.Fatalf("Scoreboard failed: %+v %v", sb, err)
	}

	audCli := warrantsdk.NewClient(ts.URL, warrantsdk.WithAuditorToken("g1aud_scopedtoken1234567890"))
	_, err = audCli.Health(ctx)
	apiErr, ok := err.(*warrantsdk.APIError)
	if !ok || !apiErr.IsAuditorScopeViolation() {
		t.Fatalf("expected APIError with IsAuditorScopeViolation=true, got %T: %v", err, err)
	}
}

func TestSplitKeygenHygieneAndPrivateKeyClientRejection(t *testing.T) {
	so, err := warrantsdk.GenerateEd25519SignerBundle("usr-split-so", "split-so@agency.gov", "Split SO", warrantsdk.RoleServiceOwner)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privPath, pubPath, err := warrantsdk.WriteSplitKeyPairFiles(filepath.Join(dir, "so-key"), so)
	if err != nil {
		t.Fatalf("WriteSplitKeyPairFiles failed: %v", err)
	}
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pubRaw), "private_key") {
		t.Fatalf("public identity file %s leaked private_key field: %s", pubPath, string(pubRaw))
	}
	pubIdent, err := warrantsdk.LoadPublicIdentityFile(pubRaw)
	if err != nil || pubIdent.PrincipalID != "usr-split-so" {
		t.Fatalf("LoadPublicIdentityFile(.pub.json) failed: %+v err=%v", pubIdent, err)
	}

	// Passing .priv.json to LoadPublicIdentityFile MUST fail closed client-side!
	privRaw, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := warrantsdk.LoadPublicIdentityFile(privRaw); err == nil || !strings.Contains(err.Error(), "PRIVATE_KEY_REJECTED_CLIENT_SIDE") {
		t.Fatalf("expected LoadPublicIdentityFile(.priv.json) to fail with PRIVATE_KEY_REJECTED_CLIENT_SIDE, got: %v", err)
	}
}

func TestRequestScopedGovernanceHeadersAndEpochThawDrafts(t *testing.T) {
	if warrantsdk.Version != "1.3.0" {
		t.Fatalf("expected warrantsdk.Version == 1.3.0, got %s", warrantsdk.Version)
	}
	so, err := warrantsdk.GenerateEd25519SignerBundle("usr-so-scope", "so-scope@agency.gov", "Scope SO", warrantsdk.RoleServiceOwner)
	if err != nil {
		t.Fatal(err)
	}

	var gotHeader string
	var gotBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/freeze", func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Warrant-Governance-DSSE")
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotBody = append([]byte(nil), buf[:n]...)
		_ = json.NewEncoder(w).Encode(warrantsdk.FreezeState{
			Mode:        warrantsdk.FreezeModeHold,
			Actor:       "usr-so-scope",
			ReasonCode:  "UNIT_TEST_HOLD",
			FreezeEpoch: 7,
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli := warrantsdk.NewClient(ts.URL, warrantsdk.WithSignerBundle(so))
	fs, err := cli.TriggerFreeze(context.Background(), warrantsdk.FreezeModeHold, "usr-so-scope", "UNIT_TEST_HOLD")
	if err != nil || fs.FreezeEpoch != 7 {
		t.Fatalf("TriggerFreeze failed: %+v err=%v", fs, err)
	}
	if gotHeader == "" {
		t.Fatalf("expected X-Warrant-Governance-DSSE header")
	}
	envRaw, err := base64.StdEncoding.DecodeString(gotHeader)
	if err != nil {
		t.Fatal(err)
	}
	var env warrantsdk.Envelope
	if err := json.Unmarshal(envRaw, &env); err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := env.DecodePayload()
	if err != nil {
		t.Fatal(err)
	}
	var gp warrantsdk.PrincipalGovernancePayload
	if err := json.Unmarshal(payloadBytes, &gp); err != nil {
		t.Fatal(err)
	}
	if gp.HTTPMethod != "POST" || gp.CanonicalPath != "/api/v1/freeze" || gp.RequestBodySHA256 != crypto.SHA256Hex(gotBody) {
		t.Fatalf("request-scope binding mismatch: %+v vs body sha %s", gp, crypto.SHA256Hex(gotBody))
	}

	thawEnv, err := warrantsdk.DraftThawEnvelopeForEpoch(7)
	if err != nil {
		t.Fatal(err)
	}
	thawBytes, _ := thawEnv.DecodePayload()
	var tp warrantsdk.ThawPayload
	_ = json.Unmarshal(thawBytes, &tp)
	if tp.FreezeEpoch != 7 || tp.EnvelopeID == "" || tp.ExpiresAt == "" {
		t.Fatalf("unexpected ThawPayload: %+v", tp)
	}
}

func TestAgentProvenanceTokenExchangeAndWirePoPHeaders(t *testing.T) {
	if warrantsdk.Version != "1.3.0" {
		t.Fatalf("expected Go SDK Version 1.3.0, got %s", warrantsdk.Version)
	}
	builder, err := warrantsdk.GenerateAgentKeyBundle("bld-test", "Builder")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := warrantsdk.GenerateAgentKeyBundle("agt-test", "Agent")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	sig, err := warrantsdk.SignBuilderProvenance(agent.AgentID, digest, agent.PublicKeyB64, builder.PrivateKeyB64)
	if err != nil || sig == "" {
		t.Fatalf("SignBuilderProvenance failed: %v", err)
	}
	bPubBytes, _ := crypto.DecodeBase64Any(builder.PublicKeyB64)
	if err := crypto.VerifyAgentBuilderProvenance(agent.AgentID, digest, agent.PublicKeyB64, sig, ed25519.PublicKey(bPubBytes)); err != nil {
		t.Fatalf("VerifyAgentBuilderProvenance failed: %v", err)
	}

	xchEnv, err := warrantsdk.SignTokenExchangeRequest(agent, warrantsdk.AgentTokenExchangePayload{
		AuthorityMode:       warrantsdk.AuthorityModeAutonomousSponsored,
		TargetAsset:         "payments-ledger-api",
		RequestedAction:     "EXTRACT_SARIF_2_1_0",
		RequestedTTLSeconds: 60,
	}, nil)
	if err != nil || len(xchEnv.Signatures) != 1 {
		t.Fatalf("SignTokenExchangeRequest failed: %v", err)
	}
}

func TestV120FinderIntakeAndDistributorSDKContracts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/intake/qualys", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("distributor_id") != warrantsdk.DistributorAnsibleAWX {
			t.Fatalf("expected distributor_id=%s, got %s", warrantsdk.DistributorAnsibleAWX, r.URL.Query().Get("distributor_id"))
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode([]warrantsdk.RemediationItem{
			{
				RemediationID:     "rem-q-1",
				CVEID:             "UNMAPPED-QID-99101",
				FinderVendor:      warrantsdk.FinderVendorQualys,
				VendorDetectionID: "QID-99101",
				CVEMappingStatus:  warrantsdk.CVEMappingStatusUnmappedVendor,
			},
		})
	})
	mux.HandleFunc("GET /api/v1/distributors", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]warrantsdk.DistributorDescriptor{
			{DistributorID: warrantsdk.DistributorMSIntune, DisplayName: "Microsoft Intune"},
			{DistributorID: warrantsdk.DistributorAnsibleAWX, DisplayName: "Ansible AWX"},
		})
	})
	mux.HandleFunc("GET /api/v1/distributors/orders", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]warrantsdk.DeploymentOrder{
			{OrderID: "ord-123", DistributorID: warrantsdk.DistributorAnsibleAWX, WarrantID: "wrt-1"},
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli := warrantsdk.NewClient(ts.URL, warrantsdk.WithIntakeToken("g1int_test"))
	ctx := context.Background()

	items, err := cli.SubmitFinderIntake(ctx, "qualys", []byte(`<HOST_LIST_VM_DETECTION_OUTPUT/>`), warrantsdk.FinderIntakeOptions{
		TargetService: "payments-ledger-api",
		DistributorID: warrantsdk.DistributorAnsibleAWX,
	})
	if err != nil || len(items) != 1 || items[0].CVEMappingStatus != warrantsdk.CVEMappingStatusUnmappedVendor {
		t.Fatalf("SubmitFinderIntake failed: %+v err=%v", items, err)
	}
	dists, err := cli.ListDistributors(ctx)
	if err != nil || len(dists) != 2 {
		t.Fatalf("ListDistributors failed: %+v err=%v", dists, err)
	}
	orders, err := cli.ListDeploymentOrders(ctx, "rem-q-1")
	if err != nil || len(orders) != 1 || orders[0].OrderID != "ord-123" {
		t.Fatalf("ListDeploymentOrders failed: %+v err=%v", orders, err)
	}
}
