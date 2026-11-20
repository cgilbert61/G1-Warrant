package adapters

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
			// First WATCH: return HTTP 410 Gone -> must trigger immediate LIST #2
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"kind":"Status","code":410,"reason":"Expired"}`))
		case 2:
			// Second WATCH: stream an in-band Kubernetes 410 Expired Status event -> must trigger LIST #3
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired"}}` + "\n"))
		case 3:
			// Third WATCH: stall silently longer than watchIdleTimeout -> must time out & trigger LIST #4
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
