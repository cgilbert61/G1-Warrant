package siem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// EscapeCEFHeader escapes '\', '|', '\r', and '\n' per ArcSight / Fortinet / LogRhythm CEF 0.1 specification.
func EscapeCEFHeader(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '|':
			b.WriteString(`\|`)
		case '\r', '\n':
			b.WriteByte(' ')
		default:
			if r < 0x20 {
				b.WriteByte(' ')
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// EscapeCEFExtensionValue escapes '\', '=', '\r', and '\n' in CEF extension values.
func EscapeCEFExtensionValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '=':
			b.WriteString(`\=`)
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		default:
			if r < 0x20 {
				b.WriteByte(' ')
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// EscapeLEEFValue strips/escapes delimiter ('^' or '\t'), '=', '\r', '\n', and control characters for IBM QRadar LEEF 2.0.
func EscapeLEEFValue(s string, delim rune) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == delim:
			b.WriteByte(' ')
		case r == '\r' || r == '\n' || r == '\t' || r < 0x20:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func canonicalRawRecordJSON(env models.SIEMExportEnvelope) (string, string) {
	rawBytes, err := json.Marshal(env.RawRecord)
	if err != nil {
		return "{}", crypto.SHA256Hex([]byte("{}"))
	}
	if canon, cErr := crypto.CanonicalizeJSON(rawBytes); cErr == nil {
		return string(canon), crypto.SHA256Hex(canon)
	}
	return string(rawBytes), crypto.SHA256Hex(rawBytes)
}

// FormatRFC5424CEF formats a Warrant record as an RFC 5424 Syslog frame carrying CEF:0 (ArcSight, FortiSIEM, LogRhythm, Exabeam, QRadar CEF, Generic).
func FormatRFC5424CEF(env models.SIEMExportEnvelope, hostname string) string {
	if hostname == "" {
		hostname = "g1-warrant"
	}
	ts := env.OccurredAt.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	sev := env.Severity
	if sev < 0 {
		sev = 0
	} else if sev > 10 {
		sev = 10
	}
	_, rawSHA := canonicalRawRecordJSON(env)

	var ext strings.Builder
	writeKV := func(k, v string) {
		if v == "" {
			return
		}
		if ext.Len() > 0 {
			ext.WriteByte(' ')
		}
		ext.WriteString(k)
		ext.WriteByte('=')
		ext.WriteString(EscapeCEFExtensionValue(v))
	}

	writeKV("rt", strconv.FormatInt(ts.UnixMilli(), 10))
	writeKV("externalId", env.RecordID)
	writeKV("cat", env.StreamName)
	writeKV("app", env.ServiceID)
	writeKV("cn1Label", "ledgerSeqNo")
	writeKV("cn1", strconv.FormatInt(env.LedgerSeqNo, 10))
	writeKV("cn2Label", "cursorSeq")
	writeKV("cn2", strconv.FormatInt(env.CursorSeq, 10))
	writeKV("cs1Label", "warrantId")
	writeKV("cs1", env.WarrantID)
	writeKV("cs2Label", "cveId")
	writeKV("cs2", env.CVEID)
	writeKV("cs3Label", "prevHash")
	writeKV("cs3", env.PrevHash)
	writeKV("cs4Label", "entryHash")
	writeKV("cs4", env.EntryHash)
	writeKV("cs5Label", "signatureSummary")
	writeKV("cs5", env.SignatureSummary)
	writeKV("cs6Label", "rawRecordSha256")
	writeKV("cs6", rawSHA)
	writeKV("msg", env.Summary)

	cef := fmt.Sprintf(
		"CEF:0|G1163RT|G1-Warrant|1.5.0|%s|%s|%d|%s",
		EscapeCEFHeader(env.RecordType),
		EscapeCEFHeader(env.Summary),
		sev,
		ext.String(),
	)
	return fmt.Sprintf("<134>1 %s %s G1Warrant - - - %s", ts.Format("2006-01-02T15:04:05.000Z"), EscapeCEFHeader(hostname), cef)
}

// FormatRFC5424LEEF20 formats a Warrant record per IBM QRadar LEEF 2.0 over RFC 5424 Syslog with caret ('^') attribute delimiter.
func FormatRFC5424LEEF20(env models.SIEMExportEnvelope, hostname string) string {
	if hostname == "" {
		hostname = "g1-warrant"
	}
	ts := env.OccurredAt.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	sev := env.Severity
	if sev < 1 {
		sev = 1
	} else if sev > 10 {
		sev = 10
	}
	_, rawSHA := canonicalRawRecordJSON(env)

	const delim = '^'
	var attrs []string
	addKV := func(k, v string) {
		if v == "" {
			return
		}
		attrs = append(attrs, k+"="+EscapeLEEFValue(v, delim))
	}
	addKV("devTime", strconv.FormatInt(ts.UnixMilli(), 10))
	addKV("sev", strconv.Itoa(sev))
	addKV("cat", env.StreamName)
	addKV("recordId", env.RecordID)
	addKV("serviceId", env.ServiceID)
	addKV("cveId", env.CVEID)
	addKV("warrantId", env.WarrantID)
	addKV("remediationId", env.RemediationID)
	addKV("ledgerSeqNo", strconv.FormatInt(env.LedgerSeqNo, 10))
	addKV("cursorSeq", strconv.FormatInt(env.CursorSeq, 10))
	addKV("prevHash", env.PrevHash)
	addKV("entryHash", env.EntryHash)
	addKV("signatureSummary", env.SignatureSummary)
	addKV("rawRecordSha256", rawSHA)

	leef := fmt.Sprintf(
		"LEEF:2.0|G1163RT|G1-Warrant|1.5.0|%s|^|%s",
		EscapeCEFHeader(env.RecordType),
		strings.Join(attrs, "^"),
	)
	return fmt.Sprintf("<134>1 %s %s %s", ts.Format("2006-01-02T15:04:05.000Z"), EscapeCEFHeader(hostname), leef)
}

// FormatRFC5424JSON formats a lossless RFC 5424 Syslog frame carrying the full Warrant JSON payload in MSG.
func FormatRFC5424JSON(env models.SIEMExportEnvelope, hostname string) string {
	if hostname == "" {
		hostname = "g1-warrant"
	}
	ts := env.OccurredAt.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	b, _ := json.Marshal(BuildLosslessSIEMObject(env))
	cleanJSON := strings.NewReplacer("\r", "", "\n", "").Replace(string(b))
	return fmt.Sprintf("<134>1 %s %s G1Warrant - %s - %s", ts.Format("2006-01-02T15:04:05.000Z"), EscapeCEFHeader(hostname), EscapeCEFHeader(env.RecordType), cleanJSON)
}

// BuildLosslessSIEMObject constructs a flat+nested JSON map preserving 100% of Warrant's record, signature, seal, seq_no, and hash fields.
func BuildLosslessSIEMObject(env models.SIEMExportEnvelope) map[string]any {
	ts := env.OccurredAt.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	canonStr, rawSHA := canonicalRawRecordJSON(env)
	return map[string]any{
		"timestamp":         ts.Format(time.RFC3339Nano),
		"vendor":            "G1163RT Security Labs",
		"product":           "G1-Warrant",
		"record_type":       env.RecordType,
		"stream_name":       env.StreamName,
		"record_id":         env.RecordID,
		"cursor_seq":        env.CursorSeq,
		"ledger_seq_no":     env.LedgerSeqNo,
		"prev_hash":         env.PrevHash,
		"entry_hash":        env.EntryHash,
		"signature_summary": env.SignatureSummary,
		"service_id":        env.ServiceID,
		"cve_id":            env.CVEID,
		"warrant_id":        env.WarrantID,
		"remediation_id":    env.RemediationID,
		"severity":          env.Severity,
		"summary":           env.Summary,
		"raw_record_sha256": rawSHA,
		"raw_record":        env.RawRecord,
		"raw_canonical":     canonStr,
	}
}

// FormatSplunkHECBatch formats an ordered slice of records for Splunk HEC (/services/collector/event).
func FormatSplunkHECBatch(records []models.SIEMExportEnvelope, index, sourcetype string) []byte {
	if sourcetype == "" {
		sourcetype = "g1:warrant:json"
	}
	var buf bytes.Buffer
	for _, r := range records {
		ts := r.OccurredAt.UTC()
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		item := map[string]any{
			"time":       float64(ts.UnixNano()) / 1e9,
			"host":       "g1-warrant",
			"source":     "g1:warrant:" + r.StreamName,
			"sourcetype": sourcetype,
			"event":      BuildLosslessSIEMObject(r),
		}
		if index != "" {
			item["index"] = index
		}
		line, _ := json.Marshal(item)
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// FormatElasticBulkECS formats an ordered slice of records as Elasticsearch _bulk NDJSON with ECS 8.11 fields + lossless g1_warrant payload.
func FormatElasticBulkECS(records []models.SIEMExportEnvelope, indexName string) []byte {
	if indexName == "" {
		indexName = "g1-warrant-events"
	}
	var buf bytes.Buffer
	for _, r := range records {
		ts := r.OccurredAt.UTC()
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		actLine, _ := json.Marshal(map[string]any{
			"index": map[string]any{
				"_index": indexName,
				"_id":    fmt.Sprintf("%s-%d-%s", r.StreamName, r.CursorSeq, r.RecordID),
			},
		})
		warrantObj := BuildLosslessSIEMObject(r)
		// Store the full nested record as canonical JSON string (raw_canonical / raw_record_json) rather than an
		// untyped dynamic map so Elasticsearch date_detection never collides on heterogeneous OSCAL props[].value arrays.
		warrantObj["raw_record_json"] = warrantObj["raw_canonical"]
		delete(warrantObj, "raw_record")
		doc := map[string]any{
			"@timestamp": ts.Format(time.RFC3339Nano),
			"ecs":        map[string]string{"version": "8.11.0"},
			"message":    r.Summary,
			"event": map[string]any{
				"kind":     "event",
				"category": []string{"configuration", "intrusion_detection"},
				"dataset":  "g1_warrant." + r.StreamName,
				"action":   r.RecordType,
				"id":       r.RecordID,
				"sequence": r.CursorSeq,
				"severity": r.Severity,
				"hash":     r.EntryHash,
			},
			"observer": map[string]string{
				"vendor":  "G1163RT Security Labs",
				"product": "G1-Warrant",
			},
			"service":       map[string]string{"name": r.ServiceID},
			"vulnerability": map[string]string{"id": r.CVEID},
			"g1_warrant":    warrantObj,
		}
		docLine, _ := json.Marshal(doc)
		buf.Write(actLine)
		buf.WriteByte('\n')
		buf.Write(docLine)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// FormatSentinelDCEBatch formats an ordered slice of records for Microsoft Sentinel Logs Ingestion API (JSON array).
func FormatSentinelDCEBatch(records []models.SIEMExportEnvelope) []byte {
	arr := make([]map[string]any, 0, len(records))
	for _, r := range records {
		ts := r.OccurredAt.UTC()
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		canonStr, rawSHA := canonicalRawRecordJSON(r)
		arr = append(arr, map[string]any{
			"TimeGenerated":     ts.Format(time.RFC3339Nano),
			"Vendor":            "G1163RT Security Labs",
			"Product":           "G1-Warrant",
			"RecordType":        r.RecordType,
			"StreamName":        r.StreamName,
			"RecordId":          r.RecordID,
			"CursorSeq":         r.CursorSeq,
			"LedgerSeqNo":       r.LedgerSeqNo,
			"PrevHash":          r.PrevHash,
			"EntryHash":         r.EntryHash,
			"SignatureSummary":  r.SignatureSummary,
			"ServiceId":         r.ServiceID,
			"CveId":             r.CVEID,
			"WarrantId":         r.WarrantID,
			"RemediationId":     r.RemediationID,
			"Severity":          r.Severity,
			"Summary":           r.Summary,
			"RawRecordSha256":   rawSHA,
			"RawRecordDynamic":  r.RawRecord,
			"RawRecordCanonical": canonStr,
		})
	}
	b, _ := json.Marshal(arr)
	return b
}

// FormatChronicleUDMBatch formats an ordered slice of records for Google SecOps / Chronicle /v2/udmEvents:batchCreate.
func FormatChronicleUDMBatch(records []models.SIEMExportEnvelope, customerID string) []byte {
	events := make([]map[string]any, 0, len(records))
	for _, r := range records {
		ts := r.OccurredAt.UTC()
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		canonStr, rawSHA := canonicalRawRecordJSON(r)
		udm := map[string]any{
			"metadata": map[string]any{
				"event_timestamp":    ts.Format(time.RFC3339Nano),
				"event_type":         "GENERIC_EVENT",
				"vendor_name":        "G1163RT Security Labs",
				"product_name":       "G1-Warrant",
				"product_event_type": r.RecordType,
				"product_log_id":     r.RecordID,
				"description":        r.Summary,
			},
			"target": map[string]any{
				"application": r.ServiceID,
			},
			"additional": map[string]any{
				"fields": map[string]any{
					"stream_name":       map[string]any{"string_value": r.StreamName},
					"cursor_seq":        map[string]any{"string_value": strconv.FormatInt(r.CursorSeq, 10)},
					"ledger_seq_no":     map[string]any{"string_value": strconv.FormatInt(r.LedgerSeqNo, 10)},
					"prev_hash":         map[string]any{"string_value": r.PrevHash},
					"entry_hash":        map[string]any{"string_value": r.EntryHash},
					"warrant_id":        map[string]any{"string_value": r.WarrantID},
					"cve_id":            map[string]any{"string_value": r.CVEID},
					"signature_summary": map[string]any{"string_value": r.SignatureSummary},
					"raw_record_sha256": map[string]any{"string_value": rawSHA},
					"raw_record_json":   map[string]any{"string_value": canonStr},
				},
			},
		}
		events = append(events, udm)
	}
	payload := map[string]any{"events": events}
	if customerID != "" {
		payload["customer_id"] = customerID
	}
	b, _ := json.Marshal(payload)
	return b
}

// FormatNDJSONLossless formats an ordered slice of records as newline-delimited JSON (Cortex XSIAM, Sumo Logic, HTTPS NDJSON).
func FormatNDJSONLossless(records []models.SIEMExportEnvelope) []byte {
	var buf bytes.Buffer
	for _, r := range records {
		line, _ := json.Marshal(BuildLosslessSIEMObject(r))
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}
