package netguard

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassifyDisallowedIP(t *testing.T) {
	tests := []struct {
		ip        string
		strict    bool
		wantBlock bool
	}{
		{"169.254.169.254", false, true},       // AWS/GCP metadata ALWAYS blocked
		{"169.254.170.2", false, true},         // ECS metadata ALWAYS blocked
		{"168.63.129.16", false, true},         // Azure WireServer ALWAYS blocked
		{"100.100.100.200", false, true},       // Alibaba metadata ALWAYS blocked
		{"fd00:ec2::254", false, true},         // AWS IPv6 metadata ALWAYS blocked
		{"::ffff:169.254.169.254", false, true},// IPv4-mapped IPv6 metadata ALWAYS blocked
		{"127.0.0.1", false, false},            // Loopback allowed in non-strict/simulator mode
		{"127.0.0.1", true, true},              // Loopback blocked in strict mode
		{"10.0.0.5", true, true},               // RFC1918 blocked in strict mode
		{"172.16.1.1", true, true},             // RFC1918 blocked in strict mode
		{"192.168.1.1", true, true},            // RFC1918 blocked in strict mode
		{"100.64.0.1", true, true},             // CGNAT blocked in strict mode
		{"64:ff9b::1.2.3.4", true, true},       // NAT64 blocked in strict mode
		{"2002:c000:0204::1", true, true},      // 6to4 blocked in strict mode
		{"fc00::1", true, true},                // ULA blocked in strict mode
		{"8.8.8.8", true, false},               // Public IPv4 allowed
		{"2606:4700:4700::1111", true, false},  // Public IPv6 allowed
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("failed to parse test IP %q", tc.ip)
		}
		reason, blocked := ClassifyDisallowedIP(ip, tc.strict)
		if blocked != tc.wantBlock {
			t.Errorf("ClassifyDisallowedIP(%s, strict=%v) = (%q, %v), want blocked=%v", tc.ip, tc.strict, reason, blocked, tc.wantBlock)
		}
	}
}

func TestPinnedDialerBlocksMetadataAndStrictPrivate(t *testing.T) {
	dialStrict := NewPinnedDialContext(Options{EnforceStrict: true})
	if _, err := dialStrict(context.Background(), "tcp", "127.0.0.1:80"); err == nil || !strings.Contains(err.Error(), "SSRF_GUARD_BLOCKED") {
		t.Fatalf("expected strict dialer to block 127.0.0.1, got: %v", err)
	}
	if _, err := dialStrict(context.Background(), "tcp", "metadata.google.internal:80"); err == nil || !strings.Contains(err.Error(), "SSRF_GUARD_BLOCKED") {
		t.Fatalf("expected dialer to block metadata.google.internal, got: %v", err)
	}
	// Even if metadata IP is placed in AllowedPrivateHosts, it MUST remain blocked.
	dialAllowMeta := NewPinnedDialContext(Options{
		EnforceStrict:       true,
		AllowedPrivateHosts: []string{"169.254.169.254:80", "169.254.169.254"},
	})
	if _, err := dialAllowMeta(context.Background(), "tcp", "169.254.169.254:80"); err == nil || !strings.Contains(err.Error(), "CLOUD_METADATA_IP_BLOCKED") {
		t.Fatalf("expected cloud metadata IP to remain blocked even when allowlisted, got: %v", err)
	}
}

func TestSafeHTTPClientBlocksMetadataRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	client := NewSafeHTTPClient(5*time.Second, nil, Options{EnforceStrict: false})
	resp, err := client.Get(srv.URL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "CLOUD_METADATA_IP_BLOCKED") {
		t.Fatalf("expected redirect to cloud metadata to fail closed, got: %v", err)
	}
}

func TestGovernedRoundTripperRetry429AndCoalesceGET(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/retry" {
			n := hits.Add(1)
			if n < 3 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("recovered"))
			return
		}
		if r.URL.Path == "/coalesce" {
			hits.Add(1)
			time.Sleep(60 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("shared-body"))
		}
	}))
	defer srv.Close()

	cfg := DefaultGovernorConfig()
	cfg.BaseBackoff = 5 * time.Millisecond
	cfg.MaxBackoff = 20 * time.Millisecond
	cfg.RequestsPerSecond = 100
	cfg.Burst = 100
	rt := NewGovernedRoundTripper(srv.Client().Transport, cfg)
	client := &http.Client{Transport: rt, Timeout: 5 * time.Second}

	// 1. Verify 429 retry recovery
	resp, err := client.Get(srv.URL + "/retry")
	if err != nil {
		t.Fatalf("expected 429 recovery, got error: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() != 3 {
		t.Fatalf("expected 200 after 3 attempts, got status=%d hits=%d", resp.StatusCode, hits.Load())
	}

	// 2. Verify concurrent GET coalescing
	hits.Store(0)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, gErr := client.Get(srv.URL + "/coalesce")
			if gErr != nil {
				t.Errorf("coalesced GET failed: %v", gErr)
				return
			}
			_ = r.Body.Close()
		}()
	}
	wg.Wait()
	if hits.Load() != 1 {
		t.Fatalf("expected 6 concurrent identical GETs to coalesce into 1 upstream hit, got %d", hits.Load())
	}
}
