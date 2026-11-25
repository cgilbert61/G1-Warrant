package verify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
)

// RecordedTwinExchange captures one deterministic HTTP wire exchange observed inside g1-twin-proving.
type RecordedTwinExchange struct {
	ExchangeID       string          `json:"exchange_id"`
	CapturedAt       time.Time       `json:"captured_at"`
	Method           string          `json:"method"`
	TargetURL        string          `json:"target_url"`
	StatusCode       int             `json:"status_code"`
	ContentEncoding  string          `json:"content_encoding,omitempty"`
	RequestBodySHA   string          `json:"request_body_sha256,omitempty"`
	ResponseBlob     WireReceiptBlob `json:"response_blob"`
}

// TwinRecordingProxy is an opt-in, ephemeral HTTP reverse/recording proxy intended strictly for
// isolated g1-twin-proving namespaces. It captures wire-level HTTP transcripts as content-addressed
// SHA-256 WireReceiptBlobs so N3 can run S1 verbatim receipt verification on real twin traffic.
type TwinRecordingProxy struct {
	mu        sync.RWMutex
	target    *url.URL
	server    *http.Server
	listener  net.Listener
	maxBytes  int
	exchanges []RecordedTwinExchange
	blobs     map[string]WireReceiptBlob
}

// StartTwinRecordingProxy launches an ephemeral loopback recording proxy forwarding to targetURL.
func StartTwinRecordingProxy(targetURL string, maxCaptureBytes int) (*TwinRecordingProxy, error) {
	u, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid twin proxy target URL %q", targetURL)
	}
	if maxCaptureBytes <= 0 {
		maxCaptureBytes = WireReceiptMaxDecodeBytes
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen twin recording proxy: %w", err)
	}

	p := &TwinRecordingProxy{
		target:   u,
		listener: ln,
		maxBytes: maxCaptureBytes,
		blobs:    make(map[string]WireReceiptBlob),
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = u.Host
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		if resp == nil || resp.Body == nil {
			return nil
		}
		raw, rErr := io.ReadAll(io.LimitReader(resp.Body, int64(p.maxBytes)+1))
		_ = resp.Body.Close()
		if rErr != nil {
			return rErr
		}
		truncated := false
		if len(raw) > p.maxBytes {
			truncated = true
			raw = raw[:p.maxBytes]
		}
		resp.Body = io.NopCloser(bytes.NewReader(raw))

		enc := resp.Header.Get("Content-Encoding")
		blob := NewContentAddressedBlob("twin_recording_proxy", enc, raw, truncated)

		var reqURL string
		var method string
		if resp.Request != nil {
			method = resp.Request.Method
			reqURL = resp.Request.URL.String()
		}
		p.record(RecordedTwinExchange{
			CapturedAt:      time.Now().UTC(),
			Method:          method,
			TargetURL:       reqURL,
			StatusCode:      resp.StatusCode,
			ContentEncoding: enc,
			ResponseBlob:    blob,
		})
		return nil
	}

	p.server = &http.Server{
		Handler:           rp,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = p.server.Serve(ln)
	}()
	return p, nil
}

// URL returns the loopback base URL of the running twin recording proxy.
func (p *TwinRecordingProxy) URL() string {
	if p == nil || p.listener == nil {
		return ""
	}
	return "http://" + p.listener.Addr().String()
}

// Close gracefully shuts down the ephemeral twin recording proxy.
func (p *TwinRecordingProxy) Close(ctx context.Context) error {
	if p == nil || p.server == nil {
		return nil
	}
	return p.server.Shutdown(ctx)
}

func (p *TwinRecordingProxy) record(ex RecordedTwinExchange) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ex.ExchangeID = fmt.Sprintf("twx-%04d-%s", len(p.exchanges)+1, crypto.SHA256Hex([]byte(ex.ResponseBlob.BlobSHA256))[:8])
	p.exchanges = append(p.exchanges, ex)
	p.blobs[ex.ResponseBlob.BlobSHA256] = ex.ResponseBlob
}

// Exchanges returns a snapshot copy of all recorded wire exchanges.
func (p *TwinRecordingProxy) Exchanges() []RecordedTwinExchange {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]RecordedTwinExchange, len(p.exchanges))
	copy(out, p.exchanges)
	return out
}

// LookupBlob retrieves a content-addressed WireReceiptBlob by its SHA-256 digest.
func (p *TwinRecordingProxy) LookupBlob(sha256Hex string) (WireReceiptBlob, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	b, ok := p.blobs[strings.ToLower(strings.TrimSpace(sha256Hex))]
	return b, ok
}

// VerifyLatestReceipt runs S1 deterministic verbatim receipt verification against the latest captured exchange.
func (p *TwinRecordingProxy) VerifyLatestReceipt(assertions []string) WireReceiptResult {
	exs := p.Exchanges()
	if len(exs) == 0 {
		return WireReceiptResult{
			Status:        WireReceiptStatusNotAssessed,
			FailureReason: "NO_CAPTURED_EXCHANGES",
		}
	}
	return VerifyWireReceipt(exs[len(exs)-1].ResponseBlob, assertions)
}
