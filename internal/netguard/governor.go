package netguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GovernorConfig configures outbound per-host rate limiting, concurrency caps,
// 429/503 Retry-After backoff, and in-flight GET coalescing for vendor API clients.
type GovernorConfig struct {
	// RequestsPerSecond sets the sustained per-host token refill rate. <= 0 disables rate pacing.
	RequestsPerSecond float64
	// Burst sets the per-host token bucket burst capacity. Defaults to max(1, int(RPS*2)).
	Burst int
	// MaxInFlightPerHost caps concurrent requests to a single host. Defaults to 4.
	MaxInFlightPerHost int
	// MaxInFlightGlobal caps total concurrent requests across all hosts. Defaults to 32.
	MaxInFlightGlobal int
	// MaxRetries caps automatic retries on HTTP 429 and 503. Defaults to 3.
	MaxRetries int
	// BaseBackoff is the initial backoff delay when Retry-After is absent. Defaults to 250ms.
	BaseBackoff time.Duration
	// MaxBackoff caps retry delay. Defaults to 5s.
	MaxBackoff time.Duration
	// CoalesceGET deduplicates concurrent identical GET requests (method + URL + auth hash).
	CoalesceGET bool
}

// DefaultGovernorConfig returns production-safe defaults for G1-Warrant's 18 vendor API integrations.
func DefaultGovernorConfig() GovernorConfig {
	return GovernorConfig{
		RequestsPerSecond:  10.0,
		Burst:              20,
		MaxInFlightPerHost: 4,
		MaxInFlightGlobal:  32,
		MaxRetries:         3,
		BaseBackoff:        250 * time.Millisecond,
		MaxBackoff:         5 * time.Second,
		CoalesceGET:        true,
	}
}

type hostLimiter struct {
	mu       sync.Mutex
	tokens   float64
	lastTime time.Time
	sem      chan struct{}
}

type bufferedResp struct {
	statusCode int
	status     string
	proto      string
	protoMajor int
	protoMinor int
	header     http.Header
	body       []byte
}

func (b *bufferedResp) toHTTPResponse(req *http.Request) *http.Response {
	return &http.Response{
		Status:        b.status,
		StatusCode:    b.statusCode,
		Proto:         b.proto,
		ProtoMajor:    b.protoMajor,
		ProtoMinor:    b.protoMinor,
		Header:        b.header.Clone(),
		Body:          io.NopCloser(bytes.NewReader(b.body)),
		ContentLength: int64(len(b.body)),
		Request:       req,
	}
}

type inflightCall struct {
	done chan struct{}
	resp *bufferedResp
	err  error
}

// GovernedRoundTripper wraps an http.RoundTripper with per-host pacing, concurrency caps,
// 429/503 Retry-After exponential backoff, and optional in-flight GET coalescing.
type GovernedRoundTripper struct {
	base      http.RoundTripper
	cfg       GovernorConfig
	globalSem chan struct{}

	mu       sync.Mutex
	hosts    map[string]*hostLimiter
	inflight map[string]*inflightCall
}

// NewGovernedRoundTripper wraps base (defaulting to a PinnedTransport) with outbound governance.
func NewGovernedRoundTripper(base http.RoundTripper, cfg ...GovernorConfig) *GovernedRoundTripper {
	c := DefaultGovernorConfig()
	if len(cfg) > 0 {
		c = cfg[0]
	}
	if c.MaxInFlightPerHost <= 0 {
		c.MaxInFlightPerHost = 4
	}
	if c.MaxInFlightGlobal <= 0 {
		c.MaxInFlightGlobal = 32
	}
	if c.Burst <= 0 {
		if c.RequestsPerSecond > 0 {
			c.Burst = int(c.RequestsPerSecond * 2)
		}
		if c.Burst < 1 {
			c.Burst = 1
		}
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = 250 * time.Millisecond
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 5 * time.Second
	}
	if base == nil {
		base = NewPinnedTransport(DefaultOptionsFromEnv())
	}
	return &GovernedRoundTripper{
		base:      base,
		cfg:       c,
		globalSem: make(chan struct{}, c.MaxInFlightGlobal),
		hosts:     make(map[string]*hostLimiter),
		inflight:  make(map[string]*inflightCall),
	}
}

func (g *GovernedRoundTripper) getHostLimiter(host string) *hostLimiter {
	h := strings.ToLower(strings.TrimSpace(host))
	g.mu.Lock()
	defer g.mu.Unlock()
	hl, ok := g.hosts[h]
	if !ok {
		hl = &hostLimiter{
			tokens:   float64(g.cfg.Burst),
			lastTime: time.Now(),
			sem:      make(chan struct{}, g.cfg.MaxInFlightPerHost),
		}
		g.hosts[h] = hl
	}
	return hl
}

func (g *GovernedRoundTripper) waitToken(ctx context.Context, hl *hostLimiter) error {
	if g.cfg.RequestsPerSecond <= 0 {
		return nil
	}
	for {
		hl.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(hl.lastTime).Seconds()
		hl.tokens += elapsed * g.cfg.RequestsPerSecond
		if hl.tokens > float64(g.cfg.Burst) {
			hl.tokens = float64(g.cfg.Burst)
		}
		hl.lastTime = now
		if hl.tokens >= 1.0 {
			hl.tokens -= 1.0
			hl.mu.Unlock()
			return nil
		}
		waitSec := (1.0 - hl.tokens) / g.cfg.RequestsPerSecond
		hl.mu.Unlock()

		timer := time.NewTimer(time.Duration(waitSec * float64(time.Second)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func coalesceKey(req *http.Request) string {
	authSum := sha256.Sum256([]byte(req.Header.Get("Authorization") + "|" + req.Header.Get("X-Warrant-Task-DSSE")))
	return req.Method + "|" + req.URL.String() + "|" + hex.EncodeToString(authSum[:8])
}

// RoundTrip executes req under concurrency limits, rate pacing, GET coalescing, and 429/503 retries.
func (g *GovernedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if g.cfg.CoalesceGET && req.Method == http.MethodGet && req.Body == nil {
		return g.roundTripCoalescedGET(req)
	}
	return g.executeWithRetry(req)
}

func (g *GovernedRoundTripper) roundTripCoalescedGET(req *http.Request) (*http.Response, error) {
	key := coalesceKey(req)
	g.mu.Lock()
	if call, ok := g.inflight[key]; ok {
		g.mu.Unlock()
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-call.done:
			if call.err != nil {
				return nil, call.err
			}
			return call.resp.toHTTPResponse(req), nil
		}
	}
	call := &inflightCall{done: make(chan struct{})}
	g.inflight[key] = call
	g.mu.Unlock()

	resp, err := g.executeWithRetry(req)
	if err == nil && resp != nil {
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			err = readErr
		} else {
			call.resp = &bufferedResp{
				statusCode: resp.StatusCode,
				status:     resp.Status,
				proto:      resp.Proto,
				protoMajor: resp.ProtoMajor,
				protoMinor: resp.ProtoMinor,
				header:     resp.Header.Clone(),
				body:       raw,
			}
		}
	}
	call.err = err
	close(call.done)

	g.mu.Lock()
	delete(g.inflight, key)
	g.mu.Unlock()

	if call.err != nil {
		return nil, call.err
	}
	return call.resp.toHTTPResponse(req), nil
}

func (g *GovernedRoundTripper) executeWithRetry(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	host := req.URL.Host
	hl := g.getHostLimiter(host)

	// Buffer small request bodies so retries can replay them cleanly when GetBody is absent.
	var bodyCopy []byte
	canReplayBody := req.Body == nil || req.GetBody != nil
	if req.Body != nil && req.GetBody == nil && g.cfg.MaxRetries > 0 {
		raw, err := io.ReadAll(io.LimitReader(req.Body, 4<<20))
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		bodyCopy = raw
		canReplayBody = true
	}

	attempts := g.cfg.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	for attempt := 0; attempt < attempts; attempt++ {
		if err := g.waitToken(ctx, hl); err != nil {
			return nil, err
		}

		// Acquire global and per-host concurrency slots
		select {
		case g.globalSem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case hl.sem <- struct{}{}:
		case <-ctx.Done():
			<-g.globalSem
			return nil, ctx.Err()
		}

		attemptReq := req.Clone(ctx)
		if bodyCopy != nil {
			attemptReq.Body = io.NopCloser(bytes.NewReader(bodyCopy))
			attemptReq.ContentLength = int64(len(bodyCopy))
		} else if attempt > 0 && req.GetBody != nil {
			b, gErr := req.GetBody()
			if gErr != nil {
				<-hl.sem
				<-g.globalSem
				return nil, gErr
			}
			attemptReq.Body = b
		}

		resp, err := g.base.RoundTrip(attemptReq)
		<-hl.sem
		<-g.globalSem

		if err != nil {
			return nil, err
		}

		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable) &&
			attempt < attempts-1 && canReplayBody {
			delay := g.retryDelay(resp.Header.Get("Retry-After"), attempt)
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()

			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		return resp, nil
	}
	return g.base.RoundTrip(req)
}

func (g *GovernedRoundTripper) retryDelay(retryAfter string, attempt int) time.Duration {
	if ra := strings.TrimSpace(retryAfter); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
			d := time.Duration(secs) * time.Second
			if d > g.cfg.MaxBackoff {
				return g.cfg.MaxBackoff
			}
			return d
		}
		if t, err := http.ParseTime(ra); err == nil {
			d := time.Until(t)
			if d > 0 {
				if d > g.cfg.MaxBackoff {
					return g.cfg.MaxBackoff
				}
				return d
			}
		}
	}
	d := g.cfg.BaseBackoff << attempt
	if d > g.cfg.MaxBackoff {
		d = g.cfg.MaxBackoff
	}
	// Add up to 25% random jitter to prevent synchronized retry storms
	if d > 0 {
		jitter := time.Duration(rand.Int63n(int64(d/4) + 1))
		d += jitter
	}
	return d
}
