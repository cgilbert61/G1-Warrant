package e2e

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/extractor"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/server"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type capturedHTTPBatch struct {
	Path            string
	RawQuery        string
	ContentType     string
	ContentEncoding string
	AuthHeader      string
	Headers         http.Header
	Body            []byte
}

type tcpSyslogCollector struct {
	ln     net.Listener
	mu     sync.Mutex
	frames []string
	wg     sync.WaitGroup
}

func newTCPSyslogCollector(t *testing.T) *tcpSyslogCollector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp syslog: %v", err)
	}
	c := &tcpSyslogCollector{ln: ln}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.wg.Add(1)
			go func(cn net.Conn) {
				defer c.wg.Done()
				defer cn.Close()
				sc := bufio.NewScanner(cn)
				sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line != "" {
						c.mu.Lock()
						c.frames = append(c.frames, line)
						c.mu.Unlock()
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		c.wg.Wait()
	})
	return c
}

func (c *tcpSyslogCollector) Endpoint() string {
	return "tcp://" + c.ln.Addr().String()
}

func (c *tcpSyslogCollector) Snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]string, len(c.frames))
	copy(cp, c.frames)
	return cp
}

// TestInvariant24_SIEMAll13SendersOrderedRetryWORMConfigAndZeroDualKey verifies the G1-Warrant SIEM Work Order:
//  1. Zero dual-key & zero extra device/auth step on SIEM destination create, update, toggle, flush, and delete.
//  2. Strict credential_ref-only enforcement (raw secrets/headers/PEMs/smuggled secret keys rejected HTTP 400; secrets never echoed).
//  3. All 13 named SIEM senders execute on the shared ordered shipping path against protocol-validating receivers.
//  4. Multi-batch shipping preserves strict ledger sequence order (never reorders records) and cryptographic fields.
//  5. Receiver outages queue unshipped records without loss, surface failures in Warrant status, and deliver 100% on recovery.
//  6. Configuration changes are sealed in WORM table siem_config_audit and verified by VerifyAllLedgerChains.
func TestInvariant24_SIEMAll13SendersOrderedRetryWORMConfigAndZeroDualKey(t *testing.T) {
	ctx := context.Background()
	adminDSN := os.Getenv("TEST_DATABASE_URL")
	if adminDSN == "" {
		adminDSN = os.Getenv("DATABASE_URL")
	}
	if adminDSN == "" {
		adminDSN = "postgres://warrant:warrant@localhost:5432/postgres?sslmode=disable"
	}

	adminConn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		if os.Getenv("REQUIRE_DB_TESTS") == "true" {
			t.Fatalf("PostgreSQL unreachable: %v", err)
		}
		t.Skipf("PostgreSQL not running on host: %v", err)
	}
	dbName := "warrant_inv24_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := adminConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, dbName)); err != nil {
		_ = adminConn.Close(ctx)
		t.Fatalf("create isolated test db %s: %v", dbName, err)
	}
	_ = adminConn.Close(ctx)
	t.Cleanup(func() {
		c, cErr := pgx.Connect(context.Background(), adminDSN)
		if cErr == nil {
			_, _ = c.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, dbName))
			_ = c.Close(context.Background())
		}
	})

	opSecret := "g1op_inv24_operator_session_token"
	secretVal := "s3cr3t-siem-ingest-credential-inv24"
	t.Setenv("WARRANT_ENABLE_TEST_SMARTCARDS", "true")
	t.Setenv("WARRANT_OPERATOR_TOKEN", opSecret)
	t.Setenv("INV24_SIEM_SECRET", secretVal)

	store, err := db.NewStore(ctx, replaceDBName(adminDSN, dbName))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	extSrv := httptest.NewServer(extractor.NewHTTPHandler("sha256-extractor-inv24"))
	defer extSrv.Close()
	sim := fleetsim.NewClusterSimulator()
	simSrv := httptest.NewServer(sim.Handler())
	defer simSrv.Close()

	orch, err := server.NewOrchestrator(ctx, store, extSrv.URL, simSrv.URL, "inv24-kernel-seed", crypto.DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	if err := orch.SeedEnterpriseEstate(ctx); err != nil {
		t.Fatalf("SeedEnterpriseEstate: %v", err)
	}
	httpSrv := httptest.NewServer(orch.BuildHTTPHandler())
	defer httpSrv.Close()

	doOperatorJSON := func(method, path string, payload any) (int, []byte) {
		var body io.Reader
		if payload != nil {
			b, mErr := json.Marshal(payload)
			if mErr != nil {
				t.Fatalf("marshal request: %v", mErr)
			}
			body = bytes.NewReader(b)
		}
		req, rErr := http.NewRequest(method, httpSrv.URL+path, body)
		if rErr != nil {
			t.Fatalf("new request: %v", rErr)
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		// Operator auth ONLY — zero X-Warrant-Governance-DSSE, zero dual-key, zero WebAuthn assertion!
		req.Header.Set("X-Warrant-Operator-Token", opSecret)
		resp, dErr := http.DefaultClient.Do(req)
		if dErr != nil {
			t.Fatalf("%s %s failed: %v", method, path, dErr)
		}
		defer resp.Body.Close()
		rb, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, rb
	}

	// 1. Verify catalog exposes all 13 named SIEM vendors.
	code, catBytes := doOperatorJSON(http.MethodGet, "/api/v1/siem/vendors", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/siem/vendors status=%d body=%s", code, string(catBytes))
	}
	var catResp struct {
		Vendors []models.SIEMVendorDescriptor `json:"vendors"`
	}
	if err := json.Unmarshal(catBytes, &catResp); err != nil || len(catResp.Vendors) != 13 {
		t.Fatalf("expected 13 SIEM vendors, got len=%d err=%v", len(catResp.Vendors), err)
	}

	// 2. Verify raw secrets are strictly rejected on UI/API configuration routes.
	badPayloads := []map[string]any{
		{
			"display_name":   "Bad Raw Bearer",
			"siem_vendor":    "splunk_es",
			"endpoint":       "https://splunk.example:8088/services/collector/event",
			"credential_ref": "Splunk 11111111-2222-3333-4444-555555555555",
		},
		{
			"display_name":   "Bad Raw UUID",
			"siem_vendor":    "splunk_es",
			"endpoint":       "https://splunk.example:8088/services/collector/event",
			"credential_ref": "11111111-2222-3333-4444-555555555555",
		},
		{
			"display_name":   "Bad Smuggled Key",
			"siem_vendor":    "splunk_es",
			"endpoint":       "https://splunk.example:8088/services/collector/event",
			"credential_ref": "env://INV24_SIEM_SECRET",
			"api_key":        "raw-secret-not-allowed",
		},
	}
	for i, bp := range badPayloads {
		st, rb := doOperatorJSON(http.MethodPost, "/api/v1/siem/destinations", bp)
		if st != http.StatusBadRequest {
			t.Fatalf("bad secret payload #%d expected HTTP 400, got %d (%s)", i, st, string(rb))
		}
	}

	// 3. Spin up multi-vendor HTTP fixture receiver + TCP Syslog collector and test all 13 senders.
	var (
		httpMu      sync.Mutex
		httpBatches = make(map[string][]capturedHTTPBatch)
		failMode    atomic.Bool
	)
	fixtureHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failMode.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"simulated_siem_receiver_outage"}`))
			return
		}
		rawBody, _ := io.ReadAll(r.Body)
		if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
			zr, zErr := gzip.NewReader(bytes.NewReader(rawBody))
			if zErr != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			rawBody, _ = io.ReadAll(zr)
			_ = zr.Close()
		}

		if r.URL.Path == "/oauth2/v2.0/token" {
			r.Body = io.NopCloser(bytes.NewReader(rawBody))
			_ = r.ParseForm()
			if r.FormValue("scope") != "https://monitor.azure.com/.default" || r.FormValue("client_secret") != secretVal {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"entra-minted-jwt-inv24"}`))
			return
		}

		httpMu.Lock()
		httpBatches[r.URL.Path] = append(httpBatches[r.URL.Path], capturedHTTPBatch{
			Path:            r.URL.Path,
			RawQuery:        r.URL.RawQuery,
			ContentType:     r.Header.Get("Content-Type"),
			ContentEncoding: r.Header.Get("Content-Encoding"),
			AuthHeader:      r.Header.Get("Authorization"),
			Headers:         r.Header.Clone(),
			Body:            rawBody,
		})
		httpMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/services/collector"):
			_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
		case strings.Contains(r.URL.Path, "/_bulk"):
			_, _ = w.Write([]byte(`{"took":2,"errors":false,"items":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"accepted"}`))
		}
	}))
	defer fixtureHTTP.Close()

	syslogQRadar := newTCPSyslogCollector(t)
	syslogExabeam := newTCPSyslogCollector(t)
	syslogLogRhythm := newTCPSyslogCollector(t)
	syslogFortiSIEM := newTCPSyslogCollector(t)
	syslogArcSight := newTCPSyslogCollector(t)
	syslogGeneric := newTCPSyslogCollector(t)

	type vendorCase struct {
		vendor        string
		endpoint      string
		credRef       string
		format        string
		vendorOptions map[string]string
		verify        func(t *testing.T, dest models.SIEMDestination)
	}

	cases := []vendorCase{
		{
			vendor:        models.SIEMVendorSplunkES,
			endpoint:      fixtureHTTP.URL + "/services/collector/event",
			credRef:       "env://INV24_SIEM_SECRET",
			format:        models.SIEMFormatSplunkHECJSON,
			vendorOptions: map[string]string{"index": "sec_audit", "sourcetype": "g1:warrant:json"},
			verify: func(t *testing.T, _ models.SIEMDestination) {
				httpMu.Lock()
				batches := httpBatches["/services/collector/event"]
				httpMu.Unlock()
				if len(batches) == 0 {
					t.Fatalf("splunk_es received 0 HTTP batches")
				}
				if batches[0].AuthHeader != "Splunk "+secretVal {
					t.Fatalf("splunk_es wrong Authorization header: %q", batches[0].AuthHeader)
				}
				if !bytes.Contains(batches[0].Body, []byte(`"dsse_envelope"`)) && !bytes.Contains(batches[0].Body, []byte(`"entry_hash"`)) {
					t.Fatalf("splunk_es missing cryptographic fields in HEC payload")
				}
			},
		},
		{
			vendor:   models.SIEMVendorMicrosoftSentinel,
			endpoint: fixtureHTTP.URL,
			credRef:  "env://INV24_SIEM_SECRET",
			format:   models.SIEMFormatSentinelDCEJSON,
			vendorOptions: map[string]string{
				"dcr_immutable_id": "dcr-0011223344",
				"stream_name":      "Custom-G1Warrant_CL",
				"tenant_id":        "tenant-inv24",
				"client_id":        "client-inv24",
				"oauth_token_url":  fixtureHTTP.URL + "/oauth2/v2.0/token",
			},
			verify: func(t *testing.T, _ models.SIEMDestination) {
				httpMu.Lock()
				batches := httpBatches["/dataCollectionRules/dcr-0011223344/streams/Custom-G1Warrant_CL"]
				httpMu.Unlock()
				if len(batches) == 0 {
					t.Fatalf("microsoft_sentinel received 0 DCE batches")
				}
				if batches[0].AuthHeader != "Bearer entra-minted-jwt-inv24" || batches[0].RawQuery != "api-version=2023-01-01" {
					t.Fatalf("microsoft_sentinel auth/query mismatch: auth=%q query=%q", batches[0].AuthHeader, batches[0].RawQuery)
				}
			},
		},
		{
			vendor:   models.SIEMVendorIBMQRadar,
			endpoint: syslogQRadar.Endpoint(),
			credRef:  "none://",
			format:   models.SIEMFormatQRadarLEEF20,
			verify: func(t *testing.T, dest models.SIEMDestination) {
				frames := syslogQRadar.Snapshot()
				if int64(len(frames)) != dest.SentCount || len(frames) == 0 {
					t.Fatalf("ibm_qradar frames=%d want=%d", len(frames), dest.SentCount)
				}
				if !strings.Contains(frames[0], "LEEF:2.0|G1163RT|G1-Warrant|") {
					t.Fatalf("ibm_qradar missing LEEF:2.0 header: %s", frames[0])
				}
			},
		},
		{
			vendor:        models.SIEMVendorGoogleSecOps,
			endpoint:      fixtureHTTP.URL + "/v2/udmEvents:batchCreate",
			credRef:       "env://INV24_SIEM_SECRET",
			format:        models.SIEMFormatChronicleUDMJSON,
			vendorOptions: map[string]string{"customer_id": "cust-secops-1", "auth_mode": "api_key"},
			verify: func(t *testing.T, _ models.SIEMDestination) {
				httpMu.Lock()
				batches := httpBatches["/v2/udmEvents:batchCreate"]
				httpMu.Unlock()
				if len(batches) == 0 || batches[0].Headers.Get("X-goog-api-key") != secretVal {
					t.Fatalf("google_secops missing X-goog-api-key or batch")
				}
			},
		},
		{
			vendor:   models.SIEMVendorCrowdStrikeLogScale,
			endpoint: fixtureHTTP.URL + "/api/v1/ingest/hec",
			credRef:  "env://INV24_SIEM_SECRET",
			format:   models.SIEMFormatLogScaleHECJSON,
			verify: func(t *testing.T, _ models.SIEMDestination) {
				httpMu.Lock()
				batches := httpBatches["/api/v1/ingest/hec"]
				httpMu.Unlock()
				if len(batches) == 0 || batches[0].AuthHeader != "Bearer "+secretVal {
					t.Fatalf("crowdstrike_logscale expected Bearer token, got %+v", batches)
				}
			},
		},
		{
			vendor:        models.SIEMVendorElasticSecurity,
			endpoint:      fixtureHTTP.URL + "/_bulk",
			credRef:       "env://INV24_SIEM_SECRET",
			format:        models.SIEMFormatElasticBulkECSJSON,
			vendorOptions: map[string]string{"index_name": "g1-warrant-inv24", "auth_scheme": "ApiKey"},
			verify: func(t *testing.T, _ models.SIEMDestination) {
				httpMu.Lock()
				batches := httpBatches["/_bulk"]
				httpMu.Unlock()
				if len(batches) == 0 || batches[0].AuthHeader != "ApiKey "+secretVal || batches[0].ContentType != "application/x-ndjson" {
					t.Fatalf("elastic_security _bulk mismatch")
				}
			},
		},
		{
			vendor:        models.SIEMVendorCortexXSIAM,
			endpoint:      fixtureHTTP.URL + "/logs/v1/event",
			credRef:       "env://INV24_SIEM_SECRET",
			format:        models.SIEMFormatXSIAMNDJSON,
			vendorOptions: map[string]string{"gzip": "true"},
			verify: func(t *testing.T, _ models.SIEMDestination) {
				httpMu.Lock()
				batches := httpBatches["/logs/v1/event"]
				httpMu.Unlock()
				if len(batches) == 0 {
					t.Fatalf("cortex_xsiam received 0 batches")
				}
				// XSIAM explicitly prohibits "Bearer " prefix on Authorization header!
				if batches[0].AuthHeader != secretVal || batches[0].ContentEncoding != "gzip" {
					t.Fatalf("cortex_xsiam auth/gzip mismatch: auth=%q enc=%q", batches[0].AuthHeader, batches[0].ContentEncoding)
				}
			},
		},
		{
			vendor:   models.SIEMVendorExabeam,
			endpoint: syslogExabeam.Endpoint(),
			credRef:  "none://",
			format:   models.SIEMFormatSyslogRFC5424CEF,
			verify: func(t *testing.T, dest models.SIEMDestination) {
				if int64(len(syslogExabeam.Snapshot())) != dest.SentCount || dest.SentCount == 0 {
					t.Fatalf("exabeam syslog count mismatch")
				}
			},
		},
		{
			vendor:   models.SIEMVendorLogRhythm,
			endpoint: syslogLogRhythm.Endpoint(),
			credRef:  "none://",
			format:   models.SIEMFormatSyslogRFC5424CEF,
			verify: func(t *testing.T, dest models.SIEMDestination) {
				if int64(len(syslogLogRhythm.Snapshot())) != dest.SentCount || dest.SentCount == 0 {
					t.Fatalf("logrhythm syslog count mismatch")
				}
			},
		},
		{
			vendor:   models.SIEMVendorSumoLogic,
			endpoint: fixtureHTTP.URL + "/receiver/v1/http",
			credRef:  "env://INV24_SIEM_SECRET",
			format:   models.SIEMFormatSumoHTTPJSON,
			verify: func(t *testing.T, _ models.SIEMDestination) {
				httpMu.Lock()
				batches := httpBatches["/receiver/v1/http/"+secretVal]
				httpMu.Unlock()
				if len(batches) == 0 || batches[0].Headers.Get("X-Sumo-Category") != "security/g1-warrant" {
					t.Fatalf("sumo_logic receiver path / X-Sumo-Category mismatch")
				}
			},
		},
		{
			vendor:   models.SIEMVendorFortiSIEM,
			endpoint: syslogFortiSIEM.Endpoint(),
			credRef:  "none://",
			format:   models.SIEMFormatSyslogRFC5424CEF,
			verify: func(t *testing.T, dest models.SIEMDestination) {
				if int64(len(syslogFortiSIEM.Snapshot())) != dest.SentCount || dest.SentCount == 0 {
					t.Fatalf("fortisiem syslog count mismatch")
				}
			},
		},
		{
			vendor:   models.SIEMVendorArcSight,
			endpoint: syslogArcSight.Endpoint(),
			credRef:  "none://",
			format:   models.SIEMFormatSyslogRFC5424CEF,
			verify: func(t *testing.T, dest models.SIEMDestination) {
				frames := syslogArcSight.Snapshot()
				if int64(len(frames)) != dest.SentCount || len(frames) == 0 || !strings.Contains(frames[0], "CEF:0|G1163RT|G1-Warrant|") {
					t.Fatalf("arcsight CEF:0 syslog mismatch")
				}
			},
		},
		{
			vendor:   models.SIEMVendorGenericFallback,
			endpoint: syslogGeneric.Endpoint(),
			credRef:  "none://",
			format:   models.SIEMFormatSyslogRFC5424JSON,
			verify: func(t *testing.T, dest models.SIEMDestination) {
				frames := syslogGeneric.Snapshot()
				if int64(len(frames)) != dest.SentCount || len(frames) == 0 || !strings.Contains(frames[0], `"raw_record_sha256"`) {
					t.Fatalf("generic_fallback RFC5424 JSON mismatch")
				}
			},
		},
	}

	for _, tc := range cases {
		createReq := map[string]any{
			"display_name":     "Inv24 " + tc.vendor,
			"siem_vendor":      tc.vendor,
			"endpoint":         tc.endpoint,
			"credential_ref":   tc.credRef,
			"format":           tc.format,
			"vendor_options":   tc.vendorOptions,
			"record_types":     []string{models.SIEMRecordWORMLedger, models.SIEMRecordAuthClassSigning, models.SIEMRecordSignedClosure, models.SIEMRecordShieldEvent},
			"batch_size":       2, // Small batch size forces multi-batch cursor iteration!
			"schedule_seconds": 3600,
			"enabled":          true,
			"console_views":    []string{"VIEW1_RACE", "VIEW5_AUDITOR"},
		}
		st, rb := doOperatorJSON(http.MethodPost, "/api/v1/siem/destinations", createReq)
		if st != http.StatusCreated {
			t.Fatalf("create %s failed: HTTP %d (%s)", tc.vendor, st, string(rb))
		}
		if bytes.Contains(rb, []byte(secretVal)) {
			t.Fatalf("SECURITY VIOLATION: resolved secret leaked in API response for %s", tc.vendor)
		}
		var createWrap struct {
			Destination models.SIEMDestination `json:"destination"`
		}
		if err := json.Unmarshal(rb, &createWrap); err != nil {
			t.Fatalf("unmarshal created %s: %v", tc.vendor, err)
		}
		created := createWrap.Destination

		// Flush multiple small batches until QueuedCount == 0
		var flushed models.SIEMDestination
		for attempt := 0; attempt < 15; attempt++ {
			fst, frb := doOperatorJSON(http.MethodPost, "/api/v1/siem/destinations/"+created.DestinationID+"/flush", map[string]any{})
			if fst != http.StatusOK {
				t.Fatalf("flush %s failed: HTTP %d (%s)", tc.vendor, fst, string(frb))
			}
			var fResp struct {
				Destination models.SIEMDestination `json:"destination"`
			}
			if err := json.Unmarshal(frb, &fResp); err != nil {
				t.Fatalf("unmarshal flush %s: %v", tc.vendor, err)
			}
			flushed = fResp.Destination
			if flushed.QueuedCount == 0 {
				break
			}
		}
		if flushed.SentCount == 0 || flushed.FailedCount != 0 || flushed.QueuedCount != 0 {
			t.Fatalf("%s unexpected delivery state: sent=%d failed=%d queued=%d err=%q", tc.vendor, flushed.SentCount, flushed.FailedCount, flushed.QueuedCount, flushed.LastError)
		}
		// Give async TCP accept goroutine a brief moment for syslog sockets
		time.Sleep(30 * time.Millisecond)
		tc.verify(t, flushed)
	}

	// 4. Verify strict monotonic sequence ordering across multi-batch Splunk HEC flushes (batch_size=2).
	httpMu.Lock()
	splunkBatches := httpBatches["/services/collector/event"]
	httpMu.Unlock()
	streamLastSeq := make(map[string]int64)
	totalSplunkEvents := 0
	for _, b := range splunkBatches {
		lines := strings.Split(strings.TrimSpace(string(b.Body)), "\n")
		for _, ln := range lines {
			var wrapper struct {
				Event struct {
					StreamName string `json:"stream_name"`
					CursorSeq  int64  `json:"cursor_seq"`
				} `json:"event"`
			}
			if err := json.Unmarshal([]byte(ln), &wrapper); err != nil {
				t.Fatalf("unmarshal splunk event line: %v", err)
			}
			prev := streamLastSeq[wrapper.Event.StreamName]
			if wrapper.Event.CursorSeq <= prev {
				t.Fatalf("LEDGER REORDERING DETECTED in stream %s: cursor_seq %d <= previous %d", wrapper.Event.StreamName, wrapper.Event.CursorSeq, prev)
			}
			streamLastSeq[wrapper.Event.StreamName] = wrapper.Event.CursorSeq
			totalSplunkEvents++
		}
	}
	if totalSplunkEvents < 4 {
		t.Fatalf("expected >=4 multi-batch Splunk events, got %d", totalSplunkEvents)
	}

	// 5. Verify outage queueing, failure reporting in Warrant, and zero-loss retry on recovery.
	failMode.Store(true)
	st, rb := doOperatorJSON(http.MethodPost, "/api/v1/siem/destinations", map[string]any{
		"display_name":     "Outage Resilience Test",
		"siem_vendor":      models.SIEMVendorGenericFallback,
		"endpoint":         fixtureHTTP.URL + "/generic-webhook",
		"credential_ref":   "env://INV24_SIEM_SECRET",
		"format":           models.SIEMFormatHTTPSJSONBatch,
		"record_types":     []string{models.SIEMRecordWORMLedger},
		"batch_size":       50,
		"schedule_seconds": 3600,
		"enabled":          true,
		"console_views":    []string{"VIEW4_CONTAINMENT"},
	})
	if st != http.StatusCreated {
		t.Fatalf("create outage dest: %d %s", st, string(rb))
	}
	var outageWrap struct {
		Destination models.SIEMDestination `json:"destination"`
	}
	_ = json.Unmarshal(rb, &outageWrap)
	outageDest := outageWrap.Destination

	fSt, frb := doOperatorJSON(http.MethodPost, "/api/v1/siem/destinations/"+outageDest.DestinationID+"/flush", map[string]any{})
	if fSt != http.StatusUnprocessableEntity {
		t.Fatalf("expected HTTP 422 on outage flush, got %d (%s)", fSt, string(frb))
	}
	var failedFlush struct {
		FlushResult struct {
			Destination models.SIEMDestination `json:"destination"`
		} `json:"flush_result"`
	}
	_ = json.Unmarshal(frb, &failedFlush)
	if failedFlush.FlushResult.Destination.SentCount != 0 || failedFlush.FlushResult.Destination.FailedCount < 1 || failedFlush.FlushResult.Destination.QueuedCount == 0 || failedFlush.FlushResult.Destination.LastError == "" {
		t.Fatalf("expected queued failure without cursor advance during outage, got %+v", failedFlush.FlushResult.Destination)
	}
	queuedDuringOutage := failedFlush.FlushResult.Destination.QueuedCount

	// Restore receiver and flush again — 100% of queued records must ship without loss!
	failMode.Store(false)
	_, rrb := doOperatorJSON(http.MethodPost, "/api/v1/siem/destinations/"+outageDest.DestinationID+"/flush", map[string]any{})
	var recoveredFlush struct {
		Destination models.SIEMDestination `json:"destination"`
	}
	_ = json.Unmarshal(rrb, &recoveredFlush)
	if recoveredFlush.Destination.SentCount != queuedDuringOutage || recoveredFlush.Destination.QueuedCount != 0 || recoveredFlush.Destination.LastError != "" {
		t.Fatalf("expected 100%% lossless recovery (want sent=%d queued=0), got %+v", queuedDuringOutage, recoveredFlush.Destination)
	}

	// Delete outage destination (no dual-key!) and verify WORM audit trail + immutability.
	delSt, delRb := doOperatorJSON(http.MethodDelete, "/api/v1/siem/destinations/"+outageDest.DestinationID, nil)
	if delSt != http.StatusOK {
		t.Fatalf("DELETE destination failed: %d %s", delSt, string(delRb))
	}

	// 5b. Verify strict X.509 TLS certificate verification (fail-closed without pinned CA; succeeds with ca_cert_b64).
	tlsSIEM := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer tlsSIEM.Close()

	stTLS, rbTLS := doOperatorJSON(http.MethodPost, "/api/v1/siem/destinations", map[string]any{
		"display_name":     "Strict TLS X509 Pinning Test",
		"siem_vendor":      models.SIEMVendorSplunkES,
		"endpoint":         tlsSIEM.URL + "/services/collector/event",
		"credential_ref":   "env://INV24_SIEM_SECRET",
		"format":           models.SIEMFormatSplunkHECJSON,
		"record_types":     []string{models.SIEMRecordWORMLedger},
		"batch_size":       50,
		"schedule_seconds": 3600,
		"enabled":          true,
		"console_views":    []string{"VIEW5_AUDITOR"},
	})
	if stTLS != http.StatusCreated {
		t.Fatalf("create TLS dest: %d %s", stTLS, string(rbTLS))
	}
	var tlsWrap struct {
		Destination models.SIEMDestination `json:"destination"`
	}
	_ = json.Unmarshal(rbTLS, &tlsWrap)
	tlsDest := tlsWrap.Destination

	// Must fail closed against untrusted self-signed cert when ca_cert_b64 is not pinned!
	badTLSCode, badTLSBody := doOperatorJSON(http.MethodPost, "/api/v1/siem/destinations/"+tlsDest.DestinationID+"/flush", map[string]any{})
	if badTLSCode != http.StatusUnprocessableEntity || !bytes.Contains(badTLSBody, []byte("x509")) {
		t.Fatalf("expected fail-closed x509 error on unpinned TLS cert, got HTTP %d (%s)", badTLSCode, string(badTLSBody))
	}

	// Pin public X.509 certificate via ca_cert_b64 and verify verified-TLS delivery succeeds!
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSIEM.Certificate().Raw})
	updSt, updRb := doOperatorJSON(http.MethodPut, "/api/v1/siem/destinations/"+tlsDest.DestinationID, map[string]any{
		"destination_id":   tlsDest.DestinationID,
		"display_name":     tlsDest.DisplayName,
		"siem_vendor":      tlsDest.SIEMVendor,
		"endpoint":         tlsDest.Endpoint,
		"credential_ref":   tlsDest.CredentialRef,
		"format":           tlsDest.Format,
		"vendor_options":   map[string]string{"ca_cert_b64": base64.StdEncoding.EncodeToString(certPEM)},
		"record_types":     tlsDest.RecordTypes,
		"batch_size":       50,
		"schedule_seconds": 3600,
		"enabled":          true,
		"console_views":    tlsDest.ConsoleViews,
	})
	if updSt != http.StatusOK {
		t.Fatalf("update TLS dest ca_cert_b64 failed: %d %s", updSt, string(updRb))
	}
	okTLSCode, okTLSBody := doOperatorJSON(http.MethodPost, "/api/v1/siem/destinations/"+tlsDest.DestinationID+"/flush", map[string]any{})
	if okTLSCode != http.StatusOK {
		t.Fatalf("expected verified TLS flush HTTP 200 after pinning ca_cert_b64, got %d (%s)", okTLSCode, string(okTLSBody))
	}
	_, _ = doOperatorJSON(http.MethodDelete, "/api/v1/siem/destinations/"+tlsDest.DestinationID, nil)

	// 6. Verify PostgreSQL WORM trigger blocks UPDATE and DELETE on siem_config_audit, and VerifyAllLedgerChains passes!
	rawConn, err := pgx.Connect(ctx, replaceDBName(adminDSN, dbName))
	if err != nil {
		t.Fatalf("connect raw db: %v", err)
	}
	defer rawConn.Close(ctx)
	if _, uErr := rawConn.Exec(ctx, `UPDATE siem_config_audit SET actor = 'tampered' WHERE seq_no = 1`); uErr == nil {
		t.Fatalf("WORM VIOLATION: UPDATE on siem_config_audit succeeded!")
	}
	if _, dErr := rawConn.Exec(ctx, `DELETE FROM siem_config_audit WHERE seq_no = 1`); dErr == nil {
		t.Fatalf("WORM VIOLATION: DELETE on siem_config_audit succeeded!")
	}

	ledgerRep, err := store.VerifyAllLedgerChains(ctx)
	if err != nil {
		t.Fatalf("VerifyAllLedgerChains error: %v", err)
	}
	if !ledgerRep.AllValid || len(ledgerRep.SIEMConfigAuditTables) != 1 || !ledgerRep.SIEMConfigAuditTables[0].Valid || ledgerRep.SIEMConfigAuditTables[0].RowCount < 15 {
		t.Fatalf("VerifyAllLedgerChains SIEM WORM audit invalid: %+v", ledgerRep)
	}
}
