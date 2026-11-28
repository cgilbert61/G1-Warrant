package siem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// FuzzParseCredentialRef fuzzes the credential_ref URI parser & validator to guarantee:
// 1. Zero panics on arbitrary adversarial UTF-8/binary inputs.
// 2. No accepted CredentialRef ever contains whitespace, NUL/control bytes, path traversal (".."),
//    or an unapproved URI scheme (raw tokens, Bearer strings, PEM blocks, etc. are always rejected).
func FuzzParseCredentialRef(f *testing.F) {
	seeds := []string{
		"",
		"none://",
		"env://SPLUNK_HEC_TOKEN",
		"file:///run/secrets/siem_hec_token",
		"file:///var/run/secrets/sentinel_client_secret",
		"k8s-secret://security/warrant-siem#hec_token",
		"aws-sm://prod/g1-warrant/xsiam-api-key",
		"azure-kv://warrant-kv/sentinel-dce-secret",
		"gcp-sm://projects/12345/secrets/chronicle-key/versions/1",
		"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		"Splunk 11111111-2222-3333-4444-555555555555",
		"file:///etc/passwd",
		"file:///run/secrets/../../etc/shadow",
		"env://lowercase_bad",
		"env://BAD SPACE",
		"https://not-a-cred-ref.example.com",
		"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		parsed, err := ParseAndValidateCredentialRef(raw)
		if err != nil {
			return
		}
		if strings.ContainsAny(parsed.RawURI, " \t\r\n\x00") {
			t.Fatalf("accepted CredentialRef contains whitespace/control char: %q", parsed.RawURI)
		}
		if strings.Contains(parsed.Target, "..") {
			t.Fatalf("accepted CredentialRef contains path traversal: %q", parsed.Target)
		}
		switch parsed.Scheme {
		case "none", "env", "file", "k8s-secret", "aws-sm", "azure-kv", "gcp-sm":
		default:
			t.Fatalf("accepted CredentialRef with unapproved scheme %q", parsed.Scheme)
		}
		if parsed.Scheme == "file" {
			if !strings.HasPrefix(parsed.RawURI, "file:///run/secrets/") &&
				!strings.HasPrefix(parsed.RawURI, "file:///var/run/secrets/") &&
				!strings.HasPrefix(parsed.RawURI, "file:///var/lib/warrant-secrets/") {
				t.Fatalf("accepted file:// CredentialRef outside secret directories: %q", parsed.RawURI)
			}
		}
	})
}

// FuzzSIEMFormattersNoInjection fuzzes all SIEM wire formatters (CEF:0, LEEF:2.0, RFC5424 JSON,
// Splunk HEC, Elastic Bulk ECS, Sentinel DCE, Chronicle UDM, and NDJSON) to guarantee:
// 1. Zero panics across arbitrary adversarial strings, delimiters ('|', '=', '^', '\\'), and CRLF injection payloads.
// 2. Single-frame syslog outputs (CEF:0, LEEF:2.0, RFC5424 JSON) NEVER contain raw '\r' or '\n' frame-splitting characters.
// 3. Multi-line NDJSON / Elastic _bulk / JSON outputs parse cleanly as valid JSON without injected extra lines or broken syntax.
func FuzzSIEMFormattersNoInjection(f *testing.F) {
	f.Add([]byte("SIGNED_CLOSURE\x1fatt-001|CEF:0|Evil|Injected\r\n<134>1 fake\x1fsvc-payments=1^malicious\nline2\x1fCVE-2026-31090\x1fwarrant-123\\pipe|eq=caret^tab\there\x1fSummary with \r\n newline, | pipe, = equals, ^ caret, and \x00 nul\x1fprevhash0000\x1fentryhash9999"))
	f.Add([]byte("WORM_LEDGER\x1fwrt-99\x1fidentity-sso\x1fCVE-2026-99999\x1fwrt-99\x1fNormal summary\x1faaaa\x1fbbbb"))
	f.Add([]byte("\r\n|\r\n=\r\n^\x00\\\"'{}[]"))

	f.Fuzz(func(t *testing.T, data []byte) {
		parts := strings.Split(string(data), "\x1f")
		getPart := func(idx int) string {
			if idx < len(parts) {
				return parts[idx]
			}
			return string(data)
		}
		recordType := getPart(0)
		recordID := getPart(1)
		serviceID := getPart(2)
		cveID := getPart(3)
		warrantID := getPart(4)
		summary := getPart(5)
		prevHash := getPart(6)
		entryHash := getPart(7)
		seqNo := int64(len(data))
		severity := len(data)%12 - 1
		env := models.SIEMExportEnvelope{
			StreamName:       "attestations",
			CursorSeq:        seqNo,
			RecordType:       recordType,
			RecordID:         recordID,
			OccurredAt:       time.Unix(1764288000, 123456000).UTC(),
			ServiceID:        serviceID,
			CVEID:            cveID,
			WarrantID:        warrantID,
			RemediationID:    "rem-fuzz-1",
			Severity:         severity,
			Summary:          summary,
			LedgerSeqNo:      seqNo,
			PrevHash:         prevHash,
			EntryHash:        entryHash,
			SignatureSummary: summary,
			RawRecord: map[string]any{
				"record_id":     recordID,
				"summary":       summary,
				"prev_hash":     prevHash,
				"entry_hash":    entryHash,
				"dsse_envelope": map[string]any{"payload": summary, "signatures": []string{recordID}},
			},
		}

		cef := FormatRFC5424CEF(env, "fuzz-host\r\ninjected")
		if strings.ContainsAny(cef, "\r\n") {
			t.Fatalf("CEF syslog frame contains raw CR/LF frame injection: %q", cef)
		}
		if !strings.Contains(cef, "CEF:0|") {
			t.Fatalf("CEF syslog frame missing CEF:0 header: %q", cef)
		}

		leef := FormatRFC5424LEEF20(env, "fuzz-host\n2")
		if strings.ContainsAny(leef, "\r\n") {
			t.Fatalf("LEEF 2.0 syslog frame contains raw CR/LF frame injection: %q", leef)
		}
		if !strings.Contains(leef, "LEEF:2.0|") {
			t.Fatalf("LEEF 2.0 syslog frame missing LEEF:2.0 header: %q", leef)
		}

		rfcJSON := FormatRFC5424JSON(env, "fuzz-host")
		if strings.ContainsAny(rfcJSON, "\r\n") {
			t.Fatalf("RFC5424 JSON syslog frame contains raw CR/LF frame injection: %q", rfcJSON)
		}

		batch := []models.SIEMExportEnvelope{env}

		hecBytes := FormatSplunkHECBatch(batch, "main", "g1:warrant:json")
		hecLines := strings.Split(strings.TrimSuffix(string(hecBytes), "\n"), "\n")
		if len(hecLines) != 1 {
			t.Fatalf("expected 1 HEC JSON line, got %d", len(hecLines))
		}
		var hecObj map[string]any
		if err := json.Unmarshal([]byte(hecLines[0]), &hecObj); err != nil {
			t.Fatalf("invalid Splunk HEC JSON: %v", err)
		}

		bulkBytes := FormatElasticBulkECS(batch, "g1-warrant-events")
		bulkLines := strings.Split(strings.TrimSuffix(string(bulkBytes), "\n"), "\n")
		if len(bulkLines) != 2 {
			t.Fatalf("expected 2 Elastic _bulk lines for 1 event, got %d", len(bulkLines))
		}
		for i, ln := range bulkLines {
			var obj map[string]any
			if err := json.Unmarshal([]byte(ln), &obj); err != nil {
				t.Fatalf("invalid Elastic _bulk JSON on line %d: %v", i, err)
			}
		}

		sentinelBytes := FormatSentinelDCEBatch(batch)
		var sentinelArr []map[string]any
		if err := json.Unmarshal(sentinelBytes, &sentinelArr); err != nil || len(sentinelArr) != 1 {
			t.Fatalf("invalid Sentinel DCE JSON array: err=%v len=%d", err, len(sentinelArr))
		}

		chronicleBytes := FormatChronicleUDMBatch(batch, "cust-fuzz")
		var chronicleObj map[string]any
		if err := json.Unmarshal(chronicleBytes, &chronicleObj); err != nil {
			t.Fatalf("invalid Chronicle UDM JSON: %v", err)
		}

		ndjsonBytes := FormatNDJSONLossless(batch)
		ndLines := strings.Split(strings.TrimSuffix(string(ndjsonBytes), "\n"), "\n")
		if len(ndLines) != 1 {
			t.Fatalf("expected 1 NDJSON line, got %d", len(ndLines))
		}
	})
}
