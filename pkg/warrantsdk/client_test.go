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
		"ttvr_seconds":   12,
	})
	if err != nil {
		t.Fatalf("new attestation env: %v", err)
	}
	if err := attEnv.SignEd25519(1, kernelPK, kernelPriv); err != nil {
		t.Fatalf("sign attestation env: %v", err)
	}

	bundleBytes, _ := json.Marshal(map[string]any{
		"attestation_id": "att-test-001",
		"cve_id":         "CVE-2026-41001",
		"service_id":     "payments-ledger-api",
		"warrant_id":     payload.WarrantID,
		"dsse_envelope":  attEnv,
		"entry_hash":     strings.Repeat("a", 64),
	})

	pubB64 := base64.StdEncoding.EncodeToString(kernelPub)
	res, err := warrantsdk.VerifyOSCALBundleOffline(bundleBytes, pubB64)
	if err != nil || !res.Valid || !res.JCSCanonicalMatch {
		t.Fatalf("expected valid offline OSCAL verification, got res=%+v err=%v", res, err)
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
	if warrantsdk.Version != "1.0.3" {
		t.Fatalf("expected warrantsdk.Version == 1.0.3, got %s", warrantsdk.Version)
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
