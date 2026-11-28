package siem

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// SIEMSender delivers an ordered batch of Warrant export envelopes to a target SIEM in its native wire format.
type SIEMSender interface {
	VendorID() string
	Descriptor() models.SIEMVendorDescriptor
	SendBatch(ctx context.Context, dest models.SIEMDestination, resolvedSecret string, batch []models.SIEMExportEnvelope) (transportStatus string, err error)
}

// Registry holds the 13 SIEM senders registered on the single shared shipping path.
type Registry struct {
	senders map[string]SIEMSender
	order   []string
}

// NewRegistry constructs the built-in registry of all 13 SIEM senders.
func NewRegistry() *Registry {
	r := &Registry{senders: make(map[string]SIEMSender)}
	all := []SIEMSender{
		&splunkHECSender{},
		&microsoftSentinelSender{},
		&ibmQRadarSender{},
		&googleSecOpsSender{},
		&crowdStrikeLogScaleSender{},
		&elasticSecuritySender{},
		&cortexXSIAMSender{},
		&exabeamSender{},
		&logRhythmSender{},
		&sumoLogicSender{},
		&fortiSIEMSender{},
		&arcSightSender{},
		&genericFallbackSender{},
	}
	for _, s := range all {
		r.senders[s.VendorID()] = s
		r.order = append(r.order, s.VendorID())
	}
	return r
}

// Get retrieves a registered SIEMSender by vendor ID.
func (r *Registry) Get(vendorID string) (SIEMSender, error) {
	s, ok := r.senders[strings.ToLower(strings.TrimSpace(vendorID))]
	if !ok {
		return nil, fmt.Errorf("UNSUPPORTED_SIEM_VENDOR: %q", vendorID)
	}
	return s, nil
}

// Catalog returns descriptors for all 13 SIEM targets in canonical order.
func (r *Registry) Catalog() []models.SIEMVendorDescriptor {
	out := make([]models.SIEMVendorDescriptor, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.senders[id].Descriptor())
	}
	return out
}

func httpClientForDest(dest models.SIEMDestination) *http.Client {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   8 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 8 * time.Second,
	}
	if strings.EqualFold(dest.VendorOptions["tls_skip_verify"], "true") {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // explicit opt-in for local self-signed dev SIEMs
	} else {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
	}
}

func doHTTPPost(
	ctx context.Context,
	dest models.SIEMDestination,
	fullURL string,
	contentType string,
	headers map[string]string,
	body []byte,
	useGzip bool,
) (int, []byte, error) {
	payload := body
	if useGzip {
		var gz bytes.Buffer
		w := gzip.NewWriter(&gz)
		if _, err := w.Write(body); err != nil {
			return 0, nil, err
		}
		if err := w.Close(); err != nil {
			return 0, nil, err
		}
		payload = gz.Bytes()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if useGzip {
		req.Header.Set("Content-Encoding", "gzip")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClientForDest(dest).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, respBytes, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, dest.SIEMVendor, truncatePreview(respBytes, 240))
	}
	return resp.StatusCode, respBytes, nil
}

func sendSyslogFrames(ctx context.Context, dest models.SIEMDestination, frames []string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(dest.Endpoint))
	if err != nil || u.Host == "" {
		return "INVALID_ENDPOINT", fmt.Errorf("invalid syslog endpoint %q (expected tcp://host:port, tls://host:port, or udp://host:port)", dest.Endpoint)
	}
	scheme := strings.ToLower(u.Scheme)
	framing := strings.ToLower(strings.TrimSpace(dest.VendorOptions["framing"]))

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	var conn net.Conn
	switch scheme {
	case "tcp":
		conn, err = dialer.DialContext(ctx, "tcp", u.Host)
	case "udp":
		conn, err = dialer.DialContext(ctx, "udp", u.Host)
	case "tls", "tcp+tls":
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if strings.EqualFold(dest.VendorOptions["tls_skip_verify"], "true") {
			tlsCfg.InsecureSkipVerify = true //nolint:gosec
		}
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: tlsCfg}
		conn, err = tlsDialer.DialContext(ctx, "tcp", u.Host)
	default:
		return "UNSUPPORTED_SCHEME", fmt.Errorf("unsupported syslog transport scheme %q", scheme)
	}
	if err != nil {
		return "DIAL_ERROR", err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	}

	for _, f := range frames {
		var wire []byte
		if scheme == "udp" {
			wire = []byte(f)
		} else if framing == "octet-counted" {
			wire = []byte(fmt.Sprintf("%d %s", len(f), f))
		} else {
			wire = []byte(f + "\n")
		}
		if _, wErr := conn.Write(wire); wErr != nil {
			return "WRITE_ERROR", wErr
		}
	}
	return fmt.Sprintf("SYSLOG_%s_OK(%d)", strings.ToUpper(scheme), len(frames)), nil
}

func truncatePreview(b []byte, max int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func normalizeURLWithDefaultPath(rawEndpoint, defaultPath string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawEndpoint))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("invalid HTTP(S) endpoint %q", rawEndpoint)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = defaultPath
	}
	return u.String(), nil
}

// =============================================================================
// 1. Splunk Enterprise Security — HTTP Event Collector (HEC JSON)
// =============================================================================

type splunkHECSender struct{}

func (s *splunkHECSender) VendorID() string { return models.SIEMVendorSplunkES }
func (s *splunkHECSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorSplunkES,
		DisplayName:      "Splunk Enterprise Security",
		DefaultFormat:    models.SIEMFormatSplunkHECJSON,
		SupportedFormats: []string{models.SIEMFormatSplunkHECJSON},
		EndpointHint:     "https://splunk.corp.example:8088/services/collector/event",
		AuthDescription:  "Authorization: Splunk <HEC-Token> via credential_ref (e.g. env://SPLUNK_HEC_TOKEN)",
		OptionKeys:       []string{"index", "sourcetype", "tls_skip_verify"},
		ProofStatus:      "LIVE_TESTED",
	}
}
func (s *splunkHECSender) SendBatch(ctx context.Context, dest models.SIEMDestination, secret string, batch []models.SIEMExportEnvelope) (string, error) {
	if secret == "" {
		return "MISSING_SECRET", fmt.Errorf("Splunk HEC requires a resolved token via credential_ref")
	}
	targetURL, err := normalizeURLWithDefaultPath(dest.Endpoint, "/services/collector/event")
	if err != nil {
		return "INVALID_ENDPOINT", err
	}
	body := FormatSplunkHECBatch(batch, dest.VendorOptions["index"], dest.VendorOptions["sourcetype"])
	code, respBytes, err := doHTTPPost(ctx, dest, targetURL, "application/json", map[string]string{
		"Authorization": "Splunk " + secret,
	}, body, strings.EqualFold(dest.VendorOptions["gzip"], "true"))
	if err != nil {
		return fmt.Sprintf("HTTP_%d", code), err
	}
	var ack struct {
		Code int    `json:"code"`
		Text string `json:"text"`
	}
	if json.Unmarshal(respBytes, &ack) == nil && ack.Code != 0 {
		return fmt.Sprintf("HEC_CODE_%d", ack.Code), fmt.Errorf("Splunk HEC error code=%d text=%s", ack.Code, ack.Text)
	}
	return fmt.Sprintf("HTTP_%d_HEC_OK", code), nil
}

// =============================================================================
// 2. Microsoft Sentinel — Azure Monitor Logs Ingestion API (DCE / DCR)
// =============================================================================

type microsoftSentinelSender struct{}

func (s *microsoftSentinelSender) VendorID() string { return models.SIEMVendorMicrosoftSentinel }
func (s *microsoftSentinelSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorMicrosoftSentinel,
		DisplayName:      "Microsoft Sentinel",
		DefaultFormat:    models.SIEMFormatSentinelDCEJSON,
		SupportedFormats: []string{models.SIEMFormatSentinelDCEJSON},
		EndpointHint:     "https://<dce>.<region>.ingest.monitor.azure.com",
		AuthDescription:  "OAuth2 Bearer (https://monitor.azure.com/.default) via Entra client secret or Bearer token ref",
		OptionKeys:       []string{"dcr_immutable_id", "stream_name", "tenant_id", "client_id", "oauth_token_url"},
		ProofStatus:      "FIXTURE_TESTED",
	}
}
func (s *microsoftSentinelSender) SendBatch(ctx context.Context, dest models.SIEMDestination, secret string, batch []models.SIEMExportEnvelope) (string, error) {
	if secret == "" {
		return "MISSING_SECRET", fmt.Errorf("Microsoft Sentinel Logs Ingestion API requires a resolved token or client_secret via credential_ref")
	}
	bearer := secret
	tenantID := strings.TrimSpace(dest.VendorOptions["tenant_id"])
	clientID := strings.TrimSpace(dest.VendorOptions["client_id"])
	if tenantID != "" && clientID != "" {
		tokURL := strings.TrimSpace(dest.VendorOptions["oauth_token_url"])
		if tokURL == "" {
			tokURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenantID))
		}
		form := url.Values{
			"client_id":     {clientID},
			"client_secret": {secret},
			"scope":         {"https://monitor.azure.com/.default"},
			"grant_type":    {"client_credentials"},
		}
		_, tokBytes, tErr := doHTTPPost(ctx, dest, tokURL, "application/x-www-form-urlencoded", nil, []byte(form.Encode()), false)
		if tErr != nil {
			return "OAUTH_ERROR", fmt.Errorf("Sentinel Entra OAuth2 token exchange failed: %w", tErr)
		}
		var tr struct {
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(tokBytes, &tr) != nil || tr.AccessToken == "" {
			return "OAUTH_PARSE_ERROR", fmt.Errorf("Sentinel OAuth2 response missing access_token")
		}
		bearer = tr.AccessToken
	}

	targetURL := strings.TrimRight(strings.TrimSpace(dest.Endpoint), "/")
	dcrID := strings.TrimSpace(dest.VendorOptions["dcr_immutable_id"])
	stream := strings.TrimSpace(dest.VendorOptions["stream_name"])
	if stream == "" {
		stream = "Custom-G1Warrant_CL"
	}
	if !strings.Contains(targetURL, "/dataCollectionRules/") && dcrID != "" {
		targetURL = fmt.Sprintf("%s/dataCollectionRules/%s/streams/%s?api-version=2023-01-01", targetURL, url.PathEscape(dcrID), url.PathEscape(stream))
	} else if !strings.Contains(targetURL, "api-version=") {
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		targetURL = targetURL + sep + "api-version=2023-01-01"
	}

	body := FormatSentinelDCEBatch(batch)
	code, _, err := doHTTPPost(ctx, dest, targetURL, "application/json", map[string]string{
		"Authorization": "Bearer " + bearer,
	}, body, strings.EqualFold(dest.VendorOptions["gzip"], "true"))
	if err != nil {
		return fmt.Sprintf("HTTP_%d", code), err
	}
	return fmt.Sprintf("HTTP_%d_SENTINEL_DCE_OK", code), nil
}

// =============================================================================
// 3. IBM QRadar — Syslog RFC 5424 + LEEF 2.0 or CEF
// =============================================================================

type ibmQRadarSender struct{}

func (s *ibmQRadarSender) VendorID() string { return models.SIEMVendorIBMQRadar }
func (s *ibmQRadarSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorIBMQRadar,
		DisplayName:      "IBM QRadar",
		DefaultFormat:    models.SIEMFormatQRadarLEEF20,
		SupportedFormats: []string{models.SIEMFormatQRadarLEEF20, models.SIEMFormatQRadarCEF},
		EndpointHint:     "tcp://qradar-collector.corp.example:514",
		AuthDescription:  "Syslog TCP/TLS/UDP (none:// or TLS client/receiver config)",
		OptionKeys:       []string{"framing", "hostname", "tls_skip_verify"},
		ProofStatus:      "FIXTURE_TESTED",
	}
}
func (s *ibmQRadarSender) SendBatch(ctx context.Context, dest models.SIEMDestination, _ string, batch []models.SIEMExportEnvelope) (string, error) {
	host := dest.VendorOptions["hostname"]
	frames := make([]string, 0, len(batch))
	for _, r := range batch {
		if dest.Format == models.SIEMFormatQRadarCEF {
			frames = append(frames, FormatRFC5424CEF(r, host))
		} else {
			frames = append(frames, FormatRFC5424LEEF20(r, host))
		}
	}
	return sendSyslogFrames(ctx, dest, frames)
}

// =============================================================================
// 4. Google Chronicle Security Operations (Google SecOps) — UDM / Unstructured v2
// =============================================================================

type googleSecOpsSender struct{}

func (s *googleSecOpsSender) VendorID() string { return models.SIEMVendorGoogleSecOps }
func (s *googleSecOpsSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorGoogleSecOps,
		DisplayName:      "Google Chronicle Security Operations",
		DefaultFormat:    models.SIEMFormatChronicleUDMJSON,
		SupportedFormats: []string{models.SIEMFormatChronicleUDMJSON, models.SIEMFormatChronicleRawJSON},
		EndpointHint:     "https://malachiteingestion-pa.googleapis.com/v2/udmEvents:batchCreate",
		AuthDescription:  "Authorization: Bearer <OAuth-Token> or X-goog-api-key via credential_ref",
		OptionKeys:       []string{"customer_id", "log_type", "auth_mode"},
		ProofStatus:      "FIXTURE_TESTED",
	}
}
func (s *googleSecOpsSender) SendBatch(ctx context.Context, dest models.SIEMDestination, secret string, batch []models.SIEMExportEnvelope) (string, error) {
	if secret == "" {
		return "MISSING_SECRET", fmt.Errorf("Google SecOps requires an API key or OAuth2 Bearer token via credential_ref")
	}
	defaultPath := "/v2/udmEvents:batchCreate"
	if dest.Format == models.SIEMFormatChronicleRawJSON {
		defaultPath = "/v2/unstructuredlogentries:batchCreate"
	}
	targetURL, err := normalizeURLWithDefaultPath(dest.Endpoint, defaultPath)
	if err != nil {
		return "INVALID_ENDPOINT", err
	}

	var body []byte
	custID := strings.TrimSpace(dest.VendorOptions["customer_id"])
	if dest.Format == models.SIEMFormatChronicleRawJSON {
		entries := make([]map[string]any, 0, len(batch))
		for _, r := range batch {
			rawLine, _ := json.Marshal(BuildLosslessSIEMObject(r))
			entries = append(entries, map[string]any{
				"log_text":   string(rawLine),
				"ts_rfc3339": r.OccurredAt.UTC().Format(time.RFC3339Nano),
			})
		}
		logType := strings.TrimSpace(dest.VendorOptions["log_type"])
		if logType == "" {
			logType = "G1_WARRANT"
		}
		p := map[string]any{"log_type": logType, "entries": entries}
		if custID != "" {
			p["customer_id"] = custID
		}
		body, _ = json.Marshal(p)
	} else {
		body = FormatChronicleUDMBatch(batch, custID)
	}

	hdrs := map[string]string{}
	if strings.EqualFold(dest.VendorOptions["auth_mode"], "api_key") {
		hdrs["X-goog-api-key"] = secret
	} else {
		hdrs["Authorization"] = "Bearer " + secret
	}
	code, _, err := doHTTPPost(ctx, dest, targetURL, "application/json", hdrs, body, false)
	if err != nil {
		return fmt.Sprintf("HTTP_%d", code), err
	}
	return fmt.Sprintf("HTTP_%d_CHRONICLE_OK", code), nil
}

// =============================================================================
// 5. CrowdStrike Falcon LogScale / Next-Gen SIEM — HEC Ingest (Bearer Token)
// =============================================================================

type crowdStrikeLogScaleSender struct{}

func (s *crowdStrikeLogScaleSender) VendorID() string { return models.SIEMVendorCrowdStrikeLogScale }
func (s *crowdStrikeLogScaleSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorCrowdStrikeLogScale,
		DisplayName:      "CrowdStrike Falcon LogScale / Next-Gen SIEM",
		DefaultFormat:    models.SIEMFormatLogScaleHECJSON,
		SupportedFormats: []string{models.SIEMFormatLogScaleHECJSON},
		EndpointHint:     "https://cloud.community.humio.com/api/v1/ingest/hec",
		AuthDescription:  "Authorization: Bearer <Ingest-Token> via credential_ref",
		OptionKeys:       []string{"sourcetype", "tls_skip_verify"},
		ProofStatus:      "FIXTURE_TESTED",
	}
}
func (s *crowdStrikeLogScaleSender) SendBatch(ctx context.Context, dest models.SIEMDestination, secret string, batch []models.SIEMExportEnvelope) (string, error) {
	if secret == "" {
		return "MISSING_SECRET", fmt.Errorf("CrowdStrike Falcon LogScale requires an Ingest Token via credential_ref")
	}
	targetURL, err := normalizeURLWithDefaultPath(dest.Endpoint, "/api/v1/ingest/hec")
	if err != nil {
		return "INVALID_ENDPOINT", err
	}
	body := FormatSplunkHECBatch(batch, "", dest.VendorOptions["sourcetype"])
	code, _, err := doHTTPPost(ctx, dest, targetURL, "application/json", map[string]string{
		"Authorization": "Bearer " + secret,
	}, body, strings.EqualFold(dest.VendorOptions["gzip"], "true"))
	if err != nil {
		return fmt.Sprintf("HTTP_%d", code), err
	}
	return fmt.Sprintf("HTTP_%d_LOGSCALE_HEC_OK", code), nil
}

// =============================================================================
// 6. Elastic Security — Elasticsearch _bulk NDJSON with ECS 8.11 Mapping
// =============================================================================

type elasticSecuritySender struct{}

func (s *elasticSecuritySender) VendorID() string { return models.SIEMVendorElasticSecurity }
func (s *elasticSecuritySender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorElasticSecurity,
		DisplayName:      "Elastic Security",
		DefaultFormat:    models.SIEMFormatElasticBulkECSJSON,
		SupportedFormats: []string{models.SIEMFormatElasticBulkECSJSON},
		EndpointHint:     "http://elasticsearch:9200/_bulk",
		AuthDescription:  "Authorization: ApiKey / Bearer / Basic via credential_ref (or none:// on local dev cluster)",
		OptionKeys:       []string{"index_name", "auth_scheme", "tls_skip_verify"},
		ProofStatus:      "LIVE_TESTED",
	}
}
func (s *elasticSecuritySender) SendBatch(ctx context.Context, dest models.SIEMDestination, secret string, batch []models.SIEMExportEnvelope) (string, error) {
	targetURL, err := normalizeURLWithDefaultPath(dest.Endpoint, "/_bulk")
	if err != nil {
		return "INVALID_ENDPOINT", err
	}
	hdrs := map[string]string{}
	if secret != "" {
		scheme := strings.TrimSpace(dest.VendorOptions["auth_scheme"])
		if scheme == "" {
			scheme = "ApiKey"
		}
		hdrs["Authorization"] = scheme + " " + secret
	}
	body := FormatElasticBulkECS(batch, dest.VendorOptions["index_name"])
	code, respBytes, err := doHTTPPost(ctx, dest, targetURL, "application/x-ndjson", hdrs, body, false)
	if err != nil {
		return fmt.Sprintf("HTTP_%d", code), err
	}
	var bulkResp struct {
		Errors bool `json:"errors"`
	}
	if json.Unmarshal(respBytes, &bulkResp) == nil && bulkResp.Errors {
		return "ELASTIC_BULK_ITEM_ERROR", fmt.Errorf("Elasticsearch _bulk reported item errors: %s", truncatePreview(respBytes, 240))
	}
	return fmt.Sprintf("HTTP_%d_ELASTIC_BULK_OK", code), nil
}

// =============================================================================
// 7. Palo Alto Cortex XSIAM — HTTP Log Collector (/logs/v1/event NDJSON)
// =============================================================================

type cortexXSIAMSender struct{}

func (s *cortexXSIAMSender) VendorID() string { return models.SIEMVendorCortexXSIAM }
func (s *cortexXSIAMSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorCortexXSIAM,
		DisplayName:      "Palo Alto Cortex XSIAM",
		DefaultFormat:    models.SIEMFormatXSIAMNDJSON,
		SupportedFormats: []string{models.SIEMFormatXSIAMNDJSON},
		EndpointHint:     "https://api-<tenant>.xdr.us.paloaltonetworks.com/logs/v1/event",
		AuthDescription:  "Authorization: <API_KEY> (no Bearer prefix) via credential_ref; NDJSON (+ optional gzip)",
		OptionKeys:       []string{"gzip", "tls_skip_verify"},
		ProofStatus:      "FIXTURE_TESTED",
	}
}
func (s *cortexXSIAMSender) SendBatch(ctx context.Context, dest models.SIEMDestination, secret string, batch []models.SIEMExportEnvelope) (string, error) {
	if secret == "" {
		return "MISSING_SECRET", fmt.Errorf("Cortex XSIAM HTTP Collector requires an API key via credential_ref")
	}
	targetURL, err := normalizeURLWithDefaultPath(dest.Endpoint, "/logs/v1/event")
	if err != nil {
		return "INVALID_ENDPOINT", err
	}
	body := FormatNDJSONLossless(batch)
	code, _, err := doHTTPPost(ctx, dest, targetURL, "application/json", map[string]string{
		"Authorization": secret, // XSIAM explicitly prohibits a "Bearer " prefix
	}, body, strings.EqualFold(dest.VendorOptions["gzip"], "true"))
	if err != nil {
		return fmt.Sprintf("HTTP_%d", code), err
	}
	return fmt.Sprintf("HTTP_%d_XSIAM_OK", code), nil
}

// =============================================================================
// 8. Exabeam (New-Scale SIEM) — Site Collector Syslog CEF or Cloud Webhook API
// =============================================================================

type exabeamSender struct{}

func (s *exabeamSender) VendorID() string { return models.SIEMVendorExabeam }
func (s *exabeamSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorExabeam,
		DisplayName:      "Exabeam",
		DefaultFormat:    models.SIEMFormatSyslogRFC5424CEF,
		SupportedFormats: []string{models.SIEMFormatSyslogRFC5424CEF, models.SIEMFormatHTTPSJSONBatch},
		EndpointHint:     "tcp://exabeam-site-collector.corp.example:514 (or https://api.us-west.exabeam.cloud/ingest)",
		AuthDescription:  "Syslog TCP/TLS CEF to Site Collector or Authorization: Bearer <key> to Cloud Webhook",
		OptionKeys:       []string{"framing", "hostname", "tls_skip_verify"},
		ProofStatus:      "FIXTURE_TESTED",
	}
}
func (s *exabeamSender) SendBatch(ctx context.Context, dest models.SIEMDestination, secret string, batch []models.SIEMExportEnvelope) (string, error) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(dest.Endpoint)), "http") {
		hdrs := map[string]string{}
		if secret != "" {
			hdrs["Authorization"] = "Bearer " + secret
		}
		objs := make([]map[string]any, 0, len(batch))
		for _, r := range batch {
			objs = append(objs, BuildLosslessSIEMObject(r))
		}
		body, _ := json.Marshal(objs)
		code, _, err := doHTTPPost(ctx, dest, strings.TrimSpace(dest.Endpoint), "application/json", hdrs, body, false)
		if err != nil {
			return fmt.Sprintf("HTTP_%d", code), err
		}
		return fmt.Sprintf("HTTP_%d_EXABEAM_OK", code), nil
	}
	frames := make([]string, 0, len(batch))
	for _, r := range batch {
		frames = append(frames, FormatRFC5424CEF(r, dest.VendorOptions["hostname"]))
	}
	return sendSyslogFrames(ctx, dest, frames)
}

// =============================================================================
// 9. LogRhythm — Self-Hosted SIEM Syslog / CEF
// =============================================================================

type logRhythmSender struct{}

func (s *logRhythmSender) VendorID() string { return models.SIEMVendorLogRhythm }
func (s *logRhythmSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorLogRhythm,
		DisplayName:      "LogRhythm",
		DefaultFormat:    models.SIEMFormatSyslogRFC5424CEF,
		SupportedFormats: []string{models.SIEMFormatSyslogRFC5424CEF},
		EndpointHint:     "tcp://logrhythm-agent.corp.example:514",
		AuthDescription:  "Syslog TCP/TLS/UDP CEF to LogRhythm System Monitor",
		OptionKeys:       []string{"framing", "hostname", "tls_skip_verify"},
		ProofStatus:      "FIXTURE_TESTED",
	}
}
func (s *logRhythmSender) SendBatch(ctx context.Context, dest models.SIEMDestination, _ string, batch []models.SIEMExportEnvelope) (string, error) {
	frames := make([]string, 0, len(batch))
	for _, r := range batch {
		frames = append(frames, FormatRFC5424CEF(r, dest.VendorOptions["hostname"]))
	}
	return sendSyslogFrames(ctx, dest, frames)
}

// =============================================================================
// 10. Sumo Logic — Hosted HTTP Collector (JSON + X-Sumo-* Headers)
// =============================================================================

type sumoLogicSender struct{}

func (s *sumoLogicSender) VendorID() string { return models.SIEMVendorSumoLogic }
func (s *sumoLogicSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorSumoLogic,
		DisplayName:      "Sumo Logic",
		DefaultFormat:    models.SIEMFormatSumoHTTPJSON,
		SupportedFormats: []string{models.SIEMFormatSumoHTTPJSON},
		EndpointHint:     "https://collectors.sumologic.com/receiver/v1/http",
		AuthDescription:  "Sumo HTTP Source receiver token via credential_ref (appended to receiver path or Bearer)",
		OptionKeys:       []string{"source_category", "source_name", "gzip"},
		ProofStatus:      "FIXTURE_TESTED",
	}
}
func (s *sumoLogicSender) SendBatch(ctx context.Context, dest models.SIEMDestination, secret string, batch []models.SIEMExportEnvelope) (string, error) {
	targetURL := strings.TrimRight(strings.TrimSpace(dest.Endpoint), "/")
	if !strings.HasPrefix(strings.ToLower(targetURL), "http") {
		return "INVALID_ENDPOINT", fmt.Errorf("invalid Sumo Logic HTTP endpoint %q", dest.Endpoint)
	}
	if secret != "" && strings.HasSuffix(targetURL, "/receiver/v1/http") {
		targetURL = targetURL + "/" + url.PathEscape(secret)
	}
	cat := strings.TrimSpace(dest.VendorOptions["source_category"])
	if cat == "" {
		cat = "security/g1-warrant"
	}
	name := strings.TrimSpace(dest.VendorOptions["source_name"])
	if name == "" {
		name = "g1-warrant"
	}
	hdrs := map[string]string{
		"X-Sumo-Category": cat,
		"X-Sumo-Name":     name,
		"X-Sumo-Host":     "g1-warrant",
	}
	if secret != "" && !strings.Contains(targetURL, url.PathEscape(secret)) {
		hdrs["Authorization"] = "Bearer " + secret
	}
	body := FormatNDJSONLossless(batch)
	code, _, err := doHTTPPost(ctx, dest, targetURL, "application/json", hdrs, body, strings.EqualFold(dest.VendorOptions["gzip"], "true"))
	if err != nil {
		return fmt.Sprintf("HTTP_%d", code), err
	}
	return fmt.Sprintf("HTTP_%d_SUMO_OK", code), nil
}

// =============================================================================
// 11. Fortinet FortiSIEM — Syslog RFC 5424 + CEF
// =============================================================================

type fortiSIEMSender struct{}

func (s *fortiSIEMSender) VendorID() string { return models.SIEMVendorFortiSIEM }
func (s *fortiSIEMSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorFortiSIEM,
		DisplayName:      "Fortinet FortiSIEM",
		DefaultFormat:    models.SIEMFormatSyslogRFC5424CEF,
		SupportedFormats: []string{models.SIEMFormatSyslogRFC5424CEF},
		EndpointHint:     "tcp://fortisiem-collector.corp.example:514",
		AuthDescription:  "Syslog TCP/TLS/UDP CEF to FortiSIEM Collector",
		OptionKeys:       []string{"framing", "hostname", "tls_skip_verify"},
		ProofStatus:      "FIXTURE_TESTED",
	}
}
func (s *fortiSIEMSender) SendBatch(ctx context.Context, dest models.SIEMDestination, _ string, batch []models.SIEMExportEnvelope) (string, error) {
	frames := make([]string, 0, len(batch))
	for _, r := range batch {
		frames = append(frames, FormatRFC5424CEF(r, dest.VendorOptions["hostname"]))
	}
	return sendSyslogFrames(ctx, dest, frames)
}

// =============================================================================
// 12. OpenText ArcSight — Native CEF over Syslog RFC 5424
// =============================================================================

type arcSightSender struct{}

func (s *arcSightSender) VendorID() string { return models.SIEMVendorArcSight }
func (s *arcSightSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:         models.SIEMVendorArcSight,
		DisplayName:      "OpenText ArcSight",
		DefaultFormat:    models.SIEMFormatSyslogRFC5424CEF,
		SupportedFormats: []string{models.SIEMFormatSyslogRFC5424CEF},
		EndpointHint:     "tcp://arcsight-smartconnector.corp.example:514",
		AuthDescription:  "Native CEF:0 over Syslog TCP/TLS/UDP to ArcSight SmartConnector",
		OptionKeys:       []string{"framing", "hostname", "tls_skip_verify"},
		ProofStatus:      "FIXTURE_TESTED",
	}
}
func (s *arcSightSender) SendBatch(ctx context.Context, dest models.SIEMDestination, _ string, batch []models.SIEMExportEnvelope) (string, error) {
	frames := make([]string, 0, len(batch))
	for _, r := range batch {
		frames = append(frames, FormatRFC5424CEF(r, dest.VendorOptions["hostname"]))
	}
	return sendSyslogFrames(ctx, dest, frames)
}

// =============================================================================
// 13. Generic Fallback — Syslog / CEF / JSON over Syslog (TCP/TLS/UDP) or HTTPS
// =============================================================================

type genericFallbackSender struct{}

func (s *genericFallbackSender) VendorID() string { return models.SIEMVendorGenericFallback }
func (s *genericFallbackSender) Descriptor() models.SIEMVendorDescriptor {
	return models.SIEMVendorDescriptor{
		VendorID:    models.SIEMVendorGenericFallback,
		DisplayName: "Generic Fallback (Syslog / CEF / JSON)",
		DefaultFormat: models.SIEMFormatSyslogRFC5424CEF,
		SupportedFormats: []string{
			models.SIEMFormatSyslogRFC5424CEF,
			models.SIEMFormatSyslogRFC5424JSON,
			models.SIEMFormatHTTPSJSONBatch,
		},
		EndpointHint:    "tcp://syslog-receiver:5514 (or https://siem-webhook.example/ingest)",
		AuthDescription: "Syslog TCP/TLS/UDP (none://) or HTTPS Bearer token via credential_ref",
		OptionKeys:      []string{"framing", "hostname", "tls_skip_verify"},
		ProofStatus:     "LIVE_TESTED",
	}
}
func (s *genericFallbackSender) SendBatch(ctx context.Context, dest models.SIEMDestination, secret string, batch []models.SIEMExportEnvelope) (string, error) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(dest.Endpoint)), "http") || dest.Format == models.SIEMFormatHTTPSJSONBatch {
		hdrs := map[string]string{}
		if secret != "" {
			hdrs["Authorization"] = "Bearer " + secret
		}
		objs := make([]map[string]any, 0, len(batch))
		for _, r := range batch {
			objs = append(objs, BuildLosslessSIEMObject(r))
		}
		body, _ := json.Marshal(objs)
		code, _, err := doHTTPPost(ctx, dest, strings.TrimSpace(dest.Endpoint), "application/json", hdrs, body, false)
		if err != nil {
			return fmt.Sprintf("HTTP_%d", code), err
		}
		return fmt.Sprintf("HTTP_%d_GENERIC_OK", code), nil
	}
	frames := make([]string, 0, len(batch))
	host := dest.VendorOptions["hostname"]
	for _, r := range batch {
		if dest.Format == models.SIEMFormatSyslogRFC5424JSON {
			frames = append(frames, FormatRFC5424JSON(r, host))
		} else {
			frames = append(frames, FormatRFC5424CEF(r, host))
		}
	}
	return sendSyslogFrames(ctx, dest, frames)
}
