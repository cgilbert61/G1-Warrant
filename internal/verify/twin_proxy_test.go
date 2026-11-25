package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTwinRecordingProxyCapturesContentAddressedWireReceipt(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(gzipBytes(t, []byte("EXPLOIT_BLOCKED: patched twin rejected payload")))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("NORMAL_CONTROL_OK: service healthy"))
	}))
	defer target.Close()

	proxy, err := StartTwinRecordingProxy(target.URL, WireReceiptMaxDecodeBytes)
	if err != nil {
		t.Fatalf("StartTwinRecordingProxy: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = proxy.Close(ctx)
	}()

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(proxy.URL() + "/gzip")
	if err != nil {
		t.Fatalf("proxy GET /gzip: %v", err)
	}
	_ = resp.Body.Close()

	exs := proxy.Exchanges()
	if len(exs) != 1 || exs[0].StatusCode != http.StatusForbidden {
		t.Fatalf("expected 1 recorded 403 exchange, got %+v", exs)
	}
	if _, ok := proxy.LookupBlob(exs[0].ResponseBlob.BlobSHA256); !ok {
		t.Fatalf("expected content-addressed blob lookup to succeed")
	}

	ver := proxy.VerifyLatestReceipt([]string{"EXPLOIT_BLOCKED: patched twin"})
	if ver.Status != WireReceiptStatusVerified {
		t.Fatalf("expected S1 VERIFIED receipt from gzipped proxy capture, got %+v", ver)
	}
}
