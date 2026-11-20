package adapters

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
)

func TestCiliumShield_DeniesKubeAPIServerByDefaultUnlessExplicitlyDeclared(t *testing.T) {
	mockFleet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ARMED"}`))
	}))
	defer mockFleet.Close()

	shield := NewCiliumShieldAdapter(mockFleet.URL)

	// 1. Default ZERO_PROSE_EGRESS_MESH_QUARANTINE MUST deny both world and kube-apiserver
	brDefault, err := shield.CompileAndApplyBridge(context.Background(), BridgeApplyRequest{
		BridgeID:      "brg-test-default",
		RemediationID: "rem-1",
		ServiceID:     "payments-ledger-api",
		Namespace:     "fin-core",
		CVEID:         "CVE-2026-99001",
		CWEID:         "CWE-000",
	})
	if err != nil {
		t.Fatalf("CompileAndApplyBridge default failed: %v", err)
	}
	if !strings.Contains(brDefault.CiliumManifestYAML, "kube-apiserver") || !strings.Contains(brDefault.CiliumManifestYAML, "world") {
		t.Fatalf("expected default bridge to deny both world and kube-apiserver in CiliumManifestYAML:\n%s", brDefault.CiliumManifestYAML)
	}

	// 2. Explicit AllowKubeAPIServerEgress opt-in omits kube-apiserver from egressDeny while still blocking world & IMDS
	brOptIn, err := shield.CompileAndApplyBridge(context.Background(), BridgeApplyRequest{
		BridgeID:                 "brg-test-k8s-optin",
		RemediationID:            "rem-2",
		ServiceID:                "cluster-controller",
		Namespace:                "kube-system",
		CVEID:                    "CVE-2026-99002",
		CWEID:                    "CWE-000",
		AllowKubeAPIServerEgress: true,
	})
	if err != nil {
		t.Fatalf("CompileAndApplyBridge opt-in failed: %v", err)
	}
	if strings.Contains(brOptIn.CiliumManifestYAML, "kube-apiserver") {
		t.Fatalf("expected explicit AllowKubeAPIServerEgress=true to omit kube-apiserver from egressDeny:\n%s", brOptIn.CiliumManifestYAML)
	}
	if !strings.Contains(brOptIn.CiliumManifestYAML, "169.254.169.254/32") {
		t.Fatalf("expected 169.254.169.254/32 still blocked even when kube-apiserver is allowed:\n%s", brOptIn.CiliumManifestYAML)
	}
}

func TestLiveKubernetesAdapter_WatchHandles410GoneExpiredAndIdleTimeoutViaListResync(t *testing.T) {
	var listCalls int32
	var watchCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "true" {
			n := atomic.AddInt32(&listCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"metadata": {"resourceVersion": "rv-list-%d"},
				"items": [{
					"metadata": {"name": "pod-from-list-%d", "labels": {"app.kubernetes.io/name": "payments-ledger-api"}},
					"status": {"containerStatuses": [{"imageID": "docker-pullable://repo@sha256:111111111111111111111111111111111111111111111111111111111111111%d"}]}
				}]
			}`, n, n, n)
			return
		}

		wn := atomic.AddInt32(&watchCalls, 1)
		switch wn {
		case 1:
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"kind":"Status","code":410,"reason":"Expired"}`))
		case 2:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired"}}` + "\n"))
		case 3:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			<-r.Context().Done()
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			<-r.Context().Done()
		}
	}))
	defer srv.Close()

	k8s := NewLiveKubernetesAdapter(srv.URL, "test-sa-token", "fin-core", 120*time.Millisecond, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var mu sync.Mutex
	seenPods := map[string]bool{}
	doneCh := make(chan struct{})
	var once sync.Once

	go func() {
		_ = k8s.WatchPodDriftEvents(ctx, func(serviceID, podName, _ string) {
			mu.Lock()
			seenPods[podName] = true
			count := len(seenPods)
			mu.Unlock()
			if count >= 4 {
				once.Do(func() {
					close(doneCh)
					cancel()
				})
			}
		})
	}()

	select {
	case <-doneCh:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for WATCH 410 Gone + Expired + idle timeout LIST re-syncs; listCalls=%d watchCalls=%d seenPods=%v",
			atomic.LoadInt32(&listCalls), atomic.LoadInt32(&watchCalls), seenPods)
	}

	if atomic.LoadInt32(&listCalls) < 4 {
		t.Fatalf("expected at least 4 full LIST syncs (boot + 410 HTTP + 410 in-stream + idle timeout), got %d", atomic.LoadInt32(&listCalls))
	}
}

type mockTwinBehavior struct {
	neverComplete bool
	exitCode      int
	termReason    string
	logOutput     string
}

type mockTwinAPIServer struct {
	mu          sync.Mutex
	jobsCreated map[string]string // jobName -> targetDigest
	jobsDeleted map[string]bool
	pollCounts  map[string]int
	byDigest    map[string]mockTwinBehavior
}

func newMockTwinAPIServer(t *testing.T, byDigest map[string]mockTwinBehavior) (*mockTwinAPIServer, *httptest.Server) {
	t.Helper()
	state := &mockTwinAPIServer{
		jobsCreated: make(map[string]string),
		jobsDeleted: make(map[string]bool),
		pollCounts:  make(map[string]int),
		byDigest:    byDigest,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()

		// 1. Create Job: POST /apis/batch/v1/namespaces/g1-twin-isolated/jobs
		if r.Method == http.MethodPost && r.URL.Path == "/apis/batch/v1/namespaces/g1-twin-isolated/jobs" {
			raw, _ := io.ReadAll(r.Body)
			var doc struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Spec struct {
					Template struct {
						Spec struct {
							Containers []struct {
								Name  string `json:"name"`
								Image string `json:"image"`
							} `json:"containers"`
						} `json:"spec"`
					} `json:"template"`
				} `json:"spec"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			digest := ""
			for _, c := range doc.Spec.Template.Spec.Containers {
				if c.Name == "workload-twin" {
					digest = c.Image
				}
			}
			state.jobsCreated[doc.Metadata.Name] = digest
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"metadata":{"name":%q,"namespace":"g1-twin-isolated"}}`, doc.Metadata.Name)
			return
		}

		// 2. Poll or Delete Job: /apis/batch/v1/namespaces/g1-twin-isolated/jobs/{name}
		if strings.HasPrefix(r.URL.Path, "/apis/batch/v1/namespaces/g1-twin-isolated/jobs/") {
			jobName := strings.TrimPrefix(r.URL.Path, "/apis/batch/v1/namespaces/g1-twin-isolated/jobs/")
			if r.Method == http.MethodDelete {
				state.jobsDeleted[jobName] = true
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"Success"}`))
				return
			}
			digest, exists := state.jobsCreated[jobName]
			if !exists {
				http.Error(w, "job not found", http.StatusNotFound)
				return
			}
			beh := state.byDigest[digest]
			state.pollCounts[jobName]++
			w.Header().Set("Content-Type", "application/json")
			if beh.neverComplete || state.pollCounts[jobName] < 2 {
				// First poll simulates running job so wait loop exercises real polling
				_, _ = w.Write([]byte(`{"status":{"active":1,"succeeded":0,"failed":0}}`))
				return
			}
			if beh.exitCode == 0 {
				_, _ = w.Write([]byte(`{"status":{"succeeded":1,"conditions":[{"type":"Complete","status":"True"}]}}`))
			} else {
				_, _ = w.Write([]byte(`{"status":{"failed":1,"conditions":[{"type":"Failed","status":"True","reason":"BackoffLimitExceeded"}]}}`))
			}
			return
		}

		// 3. List Pods for Job: GET /api/v1/namespaces/g1-twin-isolated/pods?labelSelector=job-name=...
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/g1-twin-isolated/pods" {
			sel := r.URL.Query().Get("labelSelector")
			jobName := strings.TrimPrefix(sel, "job-name=")
			digest, exists := state.jobsCreated[jobName]
			if !exists {
				http.Error(w, "unknown job selector", http.StatusNotFound)
				return
			}
			beh := state.byDigest[digest]
			podName := jobName + "-pod-0"
			reason := beh.termReason
			if reason == "" {
				if beh.exitCode == 0 {
					reason = "Completed"
				} else {
					reason = "Error"
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"items": [{
					"metadata": {"name": %q},
					"status": {
						"phase": "Succeeded",
						"containerStatuses": [{
							"name": "exploit-probe",
							"state": {"terminated": {"exitCode": %d, "reason": %q}}
						}]
					}
				}]
			}`, podName, beh.exitCode, reason)
			return
		}

		// 4. Pod Logs: GET /api/v1/namespaces/g1-twin-isolated/pods/{pod}/log
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/g1-twin-isolated/pods/") && strings.HasSuffix(r.URL.Path, "/log") {
			trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/g1-twin-isolated/pods/")
			podName := strings.TrimSuffix(trimmed, "/log")
			jobName := strings.TrimSuffix(podName, "-pod-0")
			digest := state.jobsCreated[jobName]
			beh := state.byDigest[digest]
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(beh.logOutput))
			return
		}

		http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
	}))
	return state, srv
}

// F3(a): Clean differential block — unpatched fails probe (EXPLOIT_SUCCEEDED), patched resists probe (EXPLOIT_BLOCKED),
// and TranscriptSHA256 equals the exact SHA-256 of the combined raw pod execution transcripts.
func TestLiveKubernetesAdapter_TwinReplay_CleanDifferentialBlock(t *testing.T) {
	vulnDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	patchedDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	unpatchedLog := "[probe] sending heartbeat payload len=65535\n[probe] leaked 64KB heap memory!\nG1_TWIN_VERDICT=EXPLOIT_SUCCEEDED"
	patchedLog := "[probe] sending heartbeat payload len=65535\n[probe] frame rejected with ErrOversizedExploitFrame\nG1_TWIN_VERDICT=EXPLOIT_BLOCKED"

	mockState, srv := newMockTwinAPIServer(t, map[string]mockTwinBehavior{
		vulnDigest:    {exitCode: 42, logOutput: unpatchedLog},
		patchedDigest: {exitCode: 0, logOutput: patchedLog},
	})
	defer srv.Close()

	k8s := NewLiveKubernetesAdapter(srv.URL, "test-token", "fin-core", time.Second, nil, nil)
	k8s.SetTwinTiming(5*time.Millisecond, 500*time.Millisecond)

	resp, err := k8s.RunExploitReplay(context.Background(), fleetsim.TwinReplayRequest{
		ServiceID:        "payments-ledger-api",
		CVEID:            "CVE-2026-41001",
		VulnerableDigest: vulnDigest,
		PatchedDigest:    patchedDigest,
		ExploitVector:    "TLS_HEARTBEAT",
		VulnerableSymbol: "tls_heartbeat_ext_parse_vuln",
		HasSignedProbe:   true,
	})
	if err != nil {
		t.Fatalf("expected clean differential twin block, got error: %v", err)
	}
	if resp.UnpatchedStatus != "EXPLOIT_SUCCEEDED" || resp.Status != "EXPLOIT_BLOCKED" {
		t.Fatalf("unexpected differential verdicts: %+v", resp)
	}
	if resp.IsolatedNamespace != "g1-twin-isolated" || !resp.ProductionUntouched || resp.ExitCode != 0 {
		t.Fatalf("unexpected twin metadata: %+v", resp)
	}

	mockState.mu.Lock()
	defer mockState.mu.Unlock()
	if len(mockState.jobsCreated) != 2 || len(mockState.jobsDeleted) != 2 {
		t.Fatalf("expected 2 isolated twin jobs created and cleaned up, got created=%d deleted=%d", len(mockState.jobsCreated), len(mockState.jobsDeleted))
	}

	var unpatchedJob, patchedJob string
	for jName, dig := range mockState.jobsCreated {
		if dig == vulnDigest {
			unpatchedJob = jName
		} else if dig == patchedDigest {
			patchedJob = jName
		}
	}
	expectedTranscript := fmt.Sprintf(
		"=== UNPATCHED_BASELINE (%s | job=%s | pod=%s-pod-0 | exit=42) ===\n%s\n=== PATCHED_CANDIDATE (%s | job=%s | pod=%s-pod-0 | exit=0) ===\n%s\n",
		vulnDigest, unpatchedJob, unpatchedJob, unpatchedLog,
		patchedDigest, patchedJob, patchedJob, patchedLog,
	)
	expectedSHA := crypto.SHA256Hex([]byte(expectedTranscript))
	if resp.TranscriptSHA256 != expectedSHA {
		t.Fatalf("TranscriptSHA256 mismatch: got %s want %s", resp.TranscriptSHA256, expectedSHA)
	}
}

// F3(b): Fail closed on Job execution timeout, pod crash, unparseable logs, or broken positive control.
func TestLiveKubernetesAdapter_TwinReplay_FailsClosedOnTimeoutCrashOrUnparseableLogs(t *testing.T) {
	vulnDigest := "sha256:aaaa111111111111111111111111111111111111111111111111111111111111"
	patchedDigest := "sha256:bbbb222222222222222222222222222222222222222222222222222222222222"

	cases := []struct {
		name        string
		behaviors   map[string]mockTwinBehavior
		wantErrCode string
	}{
		{
			name: "job_timeout",
			behaviors: map[string]mockTwinBehavior{
				vulnDigest:    {neverComplete: true},
				patchedDigest: {exitCode: 0, logOutput: "VERDICT=EXPLOIT_BLOCKED"},
			},
			wantErrCode: "TWIN_JOB_TIMEOUT",
		},
		{
			name: "pod_oom_crash",
			behaviors: map[string]mockTwinBehavior{
				vulnDigest:    {exitCode: 137, termReason: "OOMKilled", logOutput: "VERDICT=EXPLOIT_SUCCEEDED"},
				patchedDigest: {exitCode: 0, logOutput: "VERDICT=EXPLOIT_BLOCKED"},
			},
			wantErrCode: "TWIN_POD_CRASHED",
		},
		{
			name: "unparseable_logs",
			behaviors: map[string]mockTwinBehavior{
				vulnDigest:    {exitCode: 1, logOutput: "syntax error near unexpected token"},
				patchedDigest: {exitCode: 0, logOutput: "VERDICT=EXPLOIT_BLOCKED"},
			},
			wantErrCode: "TWIN_UNPARSEABLE_LOGS",
		},
		{
			name: "broken_positive_control",
			behaviors: map[string]mockTwinBehavior{
				vulnDigest:    {exitCode: 0, logOutput: "VERDICT=EXPLOIT_BLOCKED"},
				patchedDigest: {exitCode: 0, logOutput: "VERDICT=EXPLOIT_BLOCKED"},
			},
			wantErrCode: "TWIN_POSITIVE_CONTROL_FAILED",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, srv := newMockTwinAPIServer(t, tc.behaviors)
			defer srv.Close()

			k8s := NewLiveKubernetesAdapter(srv.URL, "test-token", "fin-core", time.Second, nil, nil)
			k8s.SetTwinTiming(5*time.Millisecond, 60*time.Millisecond)

			_, err := k8s.RunExploitReplay(context.Background(), fleetsim.TwinReplayRequest{
				ServiceID:        "payments-ledger-api",
				CVEID:            "CVE-2026-41002",
				VulnerableDigest: vulnDigest,
				PatchedDigest:    patchedDigest,
				ExploitVector:    "TLS_HEARTBEAT",
				HasSignedProbe:   true,
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErrCode) {
				t.Fatalf("expected fail-closed error containing %q, got %v", tc.wantErrCode, err)
			}
		})
	}
}

// F3(c): Regression detection — patched candidate image remains exploitable -> fail closed.
func TestLiveKubernetesAdapter_TwinReplay_DetectsPatchedImageRegression(t *testing.T) {
	vulnDigest := "sha256:cccc111111111111111111111111111111111111111111111111111111111111"
	patchedDigest := "sha256:dddd222222222222222222222222222222222222222222222222222222222222"

	_, srv := newMockTwinAPIServer(t, map[string]mockTwinBehavior{
		vulnDigest:    {exitCode: 42, logOutput: "[probe] vulnerable baseline exploited\nG1_TWIN_VERDICT=EXPLOIT_SUCCEEDED"},
		patchedDigest: {exitCode: 42, logOutput: "[probe] candidate STILL leaked 64KB memory!\nG1_TWIN_VERDICT=EXPLOIT_SUCCEEDED"},
	})
	defer srv.Close()

	k8s := NewLiveKubernetesAdapter(srv.URL, "test-token", "fin-core", time.Second, nil, nil)
	k8s.SetTwinTiming(5*time.Millisecond, 300*time.Millisecond)

	_, err := k8s.RunExploitReplay(context.Background(), fleetsim.TwinReplayRequest{
		ServiceID:        "payments-ledger-api",
		CVEID:            "CVE-2026-41003",
		VulnerableDigest: vulnDigest,
		PatchedDigest:    patchedDigest,
		ExploitVector:    "TLS_HEARTBEAT",
		HasSignedProbe:   true,
	})
	if err == nil || !strings.Contains(err.Error(), "TWIN_REGRESSION_DETECTED") {
		t.Fatalf("expected TWIN_REGRESSION_DETECTED when patched image remains exploitable, got %v", err)
	}
}

// F1: Verify rejection of legacy public-string-derived signatures and fail-closed live posture startup.
func TestAuthorityCustody_RejectsLegacyPublicSeedsAndFailsClosedInLivePosture(t *testing.T) {
	// Reconstruct the exact historical compromised keys from the banned public string literals
	deriveBanned := func(domain string) (ed25519.PublicKey, ed25519.PrivateKey, string) {
		seed := sha256.Sum256([]byte("g1163rt-g1-warrant-v1:" + domain))
		priv := ed25519.NewKeyFromSeed(seed[:])
		return priv.Public().(ed25519.PublicKey), priv, hex.EncodeToString(seed[:])
	}

	bannedPubKey, bannedPubPriv, bannedPubSeedHex := deriveBanned("publisher:g1163rt-trusted-build-pipeline-v1")
	bannedRuleKey, bannedRulePriv, bannedRuleSeedHex := deriveBanned("publisher:g1163rt-signed-rulepack-authority-v1")

	// 1. Custody constructors must reject banned seeds and public keys
	if _, err := crypto.NewEd25519SignerFromSeedHex(bannedPubSeedHex, "p", "p@x", "p", crypto.RoleArtifactPublisher, "pub"); err == nil {
		t.Fatal("expected NewEd25519SignerFromSeedHex to reject legacy publisher public-string seed")
	}
	if _, err := crypto.NewEd25519SignerFromSeedHex(bannedRuleSeedHex, "r", "r@x", "r", crypto.RoleRulepackAuthority, "rpk"); err == nil {
		t.Fatal("expected NewEd25519SignerFromSeedHex to reject legacy rulepack public-string seed")
	}
	if _, err := NewRulepackRegistry(bannedRuleKey, "rulepack-authority-ed25519-v1"); err == nil {
		t.Fatal("expected NewRulepackRegistry to reject legacy public-string-derived public key")
	}

	// 2. Live/Kubernetes posture must fail closed when no authoritative publisher public key is configured
	liveEnv := func(k string) string {
		if k == "WARRANT_POSTURE" {
			return "live"
		}
		return ""
	}
	if _, err := NewFixProviderFromEnv(liveEnv); err == nil || !strings.Contains(err.Error(), "FATAL_SECURITY_GUARD") {
		t.Fatalf("expected NewFixProviderFromEnv to fail closed in WARRANT_POSTURE=live without key, got %v", err)
	}
	if _, err := NewRulepackRegistryFromEnv(liveEnv); err == nil || !strings.Contains(err.Error(), "FATAL_SECURITY_GUARD") {
		t.Fatalf("expected NewRulepackRegistryFromEnv to fail closed in WARRANT_POSTURE=live without key, got %v", err)
	}

	// 3. Legitimate operator seed works cleanly AND rejects rulepacks/artifacts signed by the legacy string keys
	validSeed := strings.Repeat("a7", 32)
	validRuleSigner, err := crypto.NewEd25519SignerFromSeedHex(validSeed, "rpk", "rpk@g1", "Rulepack Auth", crypto.RoleRulepackAuthority, "rpk")
	if err != nil {
		t.Fatalf("unexpected error creating valid operator seed signer: %v", err)
	}
	reg, err := NewRulepackRegistry(ed25519.PublicKey(validRuleSigner.PublicKey().PublicKeyBytes), validRuleSigner.PublicKey().KeyID)
	if err != nil {
		t.Fatalf("NewRulepackRegistry failed: %v", err)
	}

	legacyRP := SignedVirtualPatchRulepack{
		RulepackID:     "rpk-legacy-forged",
		CWEID:          "CWE-22",
		ExploitVector:  "HTTP_PATH_TRAVERSAL",
		BlockedPaths:   []string{"/.."},
		HasSignedProbe: true,
		PublisherKeyID: "rulepack-authority-ed25519-v1",
	}
	legacyRP.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(bannedRulePriv, canonicalRulepackSignBytes(legacyRP)))
	if err := reg.Register(legacyRP); err == nil {
		t.Fatal("expected RulepackRegistry.Register to reject rulepack signed with legacy public-string seed")
	}

	validPubSeed := strings.Repeat("b8", 32)
	validPubSigner, err := crypto.NewEd25519SignerFromSeedHex(validPubSeed, "pub", "pub@g1", "Publisher Auth", crypto.RoleArtifactPublisher, "pub")
	if err != nil {
		t.Fatal(err)
	}
	fixProv, err := NewFixProviderVerifyOnly(validPubSigner.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	diff := "diff --git a/x.go b/x.go\n+// fix\n"
	forgedArt := SignedPatchArtifact{
		ServiceID:        "payments-ledger-api",
		CVEID:            "CVE-2026-11111",
		PatchedDigest:    "sha256:" + strings.Repeat("f", 64),
		PublisherID:      "pub-g1163rt-ci",
		PublisherKeyID:   "pub-provenance-ed25519-01",
		UnifiedDiff:      diff,
		ProvenanceSigB64: base64.StdEncoding.EncodeToString(ed25519.Sign(bannedPubPriv, ProvenanceSigningBytes("payments-ledger-api", "CVE-2026-11111", "sha256:"+strings.Repeat("f", 64), diff))),
	}
	if err := fixProv.VerifyProvenance(forgedArt); err == nil {
		t.Fatal("expected VerifyProvenance to reject patch artifact signed with legacy public-string seed")
	}

	// 4. Verify DSSE VerifySingleSignature also rejects legacy public-string keys fail-closed
	env, rawPayload, _ := crypto.NewUnsignedEnvelope(crypto.PayloadTypeAttestation, map[string]string{"test": "legacy"})
	bannedPK := crypto.PrincipalKey{
		PrincipalID:    "pub-g1163rt-ci",
		KeyID:          "pub-provenance-ed25519-01",
		Alg:            crypto.AlgEd25519,
		PublicKeyBytes: bannedPubKey,
		KeyFingerprint: crypto.SHA256Hex(bannedPubKey),
	}
	_ = env.SignEd25519(1, bannedPK, bannedPubPriv)
	if err := crypto.VerifySingleSignature(env.PayloadType, rawPayload, env.Signatures[0], &bannedPK, crypto.DefaultWebAuthnConfig()); err == nil || !strings.Contains(err.Error(), "FORBIDDEN_LEGACY_PUBLIC_SEED_KEY") {
		t.Fatalf("expected DSSE VerifySingleSignature to reject legacy public-string key, got %v", err)
	}
}
