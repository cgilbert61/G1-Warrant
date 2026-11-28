package models

import "time"

// Canonical SIEM vendor identifiers (13 targets per SIEM Work Order Page 2).
const (
	SIEMVendorSplunkES            = "splunk_es"
	SIEMVendorMicrosoftSentinel   = "microsoft_sentinel"
	SIEMVendorIBMQRadar           = "ibm_qradar"
	SIEMVendorGoogleSecOps        = "google_secops"
	SIEMVendorCrowdStrikeLogScale = "crowdstrike_logscale"
	SIEMVendorElasticSecurity     = "elastic_security"
	SIEMVendorCortexXSIAM         = "cortex_xsiam"
	SIEMVendorExabeam             = "exabeam"
	SIEMVendorLogRhythm           = "logrhythm"
	SIEMVendorSumoLogic           = "sumo_logic"
	SIEMVendorFortiSIEM           = "fortisiem"
	SIEMVendorArcSight            = "arcsight"
	SIEMVendorGenericFallback     = "generic_fallback"
)

// Canonical Warrant SIEM record families (Part A categories + SIEM config audit).
const (
	SIEMRecordSignedClosure    = "SIGNED_CLOSURE"
	SIEMRecordWORMLedger       = "WORM_LEDGER"
	SIEMRecordAuthClassSigning = "AUTH_CLASS_SIGNING"
	SIEMRecordDispatchResult   = "DISPATCH_RESULT"
	SIEMRecordShieldEvent      = "SHIELD_EVENT"
	SIEMRecordTwinProofVerdict = "TWIN_PROOF_VERDICT"
	SIEMRecordIngestEvent      = "INGEST_EVENT"
	SIEMRecordSIEMConfigAudit  = "SIEM_CONFIG_AUDIT"
)

// Supported wire formats across the 13 SIEM senders.
const (
	SIEMFormatSplunkHECJSON        = "SPLUNK_HEC_JSON"
	SIEMFormatSentinelDCEJSON      = "SENTINEL_DCE_JSON"
	SIEMFormatQRadarLEEF20         = "QRADAR_LEEF_2_0"
	SIEMFormatQRadarCEF            = "QRADAR_CEF"
	SIEMFormatChronicleUDMJSON     = "CHRONICLE_UDM_JSON"
	SIEMFormatChronicleRawJSON     = "CHRONICLE_UNSTRUCTURED_JSON"
	SIEMFormatLogScaleHECJSON      = "LOGSCALE_HEC_JSON"
	SIEMFormatElasticBulkECSJSON   = "ELASTIC_BULK_ECS_JSON"
	SIEMFormatXSIAMNDJSON          = "XSIAM_NDJSON"
	SIEMFormatSyslogRFC5424CEF     = "SYSLOG_RFC5424_CEF"
	SIEMFormatSyslogRFC5424JSON    = "SYSLOG_RFC5424_JSON"
	SIEMFormatSumoHTTPJSON         = "SUMO_HTTP_JSON"
	SIEMFormatHTTPSJSONBatch       = "HTTPS_JSON_BATCH"
)

// SIEMDestination represents a UI-configured SIEM shipping destination.
// CredentialRef holds ONLY an external secret reference URI (e.g. env://SPLUNK_HEC_TOKEN,
// file:///run/secrets/hec_token, none://) — raw secrets are never accepted, stored, or echoed.
type SIEMDestination struct {
	DestinationID       string            `json:"destination_id"`
	DisplayName         string            `json:"display_name"`
	SIEMVendor          string            `json:"siem_vendor"`
	Endpoint            string            `json:"endpoint"`
	CredentialRef       string            `json:"credential_ref"`
	Format              string            `json:"format"`
	VendorOptions       map[string]string `json:"vendor_options,omitempty"`
	RecordTypes         []string          `json:"record_types"`
	BatchSize           int               `json:"batch_size"`
	ScheduleSeconds     int               `json:"schedule_seconds"`
	Enabled             bool              `json:"enabled"`
	ConsoleViews        []string          `json:"console_views"`
	SentCount           int64             `json:"sent_count"`
	QueuedCount         int64             `json:"queued_count"`
	FailedCount         int64             `json:"failed_count"`
	RetryCount          int64             `json:"retry_count"`
	LastSentAt          *time.Time        `json:"last_sent_at,omitempty"`
	LastError           string            `json:"last_error,omitempty"`
	LastErrorAt         *time.Time        `json:"last_error_at,omitempty"`
	LastTransportStatus string            `json:"last_transport_status,omitempty"`
	NextAttemptAt       *time.Time        `json:"next_attempt_at,omitempty"`
	CreatedBy           string            `json:"created_by,omitempty"`
	UpdatedBy           string            `json:"updated_by,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

// SIEMVendorDescriptor exposes metadata and valid formats for each of the 13 SIEM targets to the Console UI.
type SIEMVendorDescriptor struct {
	VendorID         string   `json:"vendor_id"`
	DisplayName      string   `json:"display_name"`
	DefaultFormat    string   `json:"default_format"`
	SupportedFormats []string `json:"supported_formats"`
	EndpointHint     string   `json:"endpoint_hint"`
	AuthDescription  string   `json:"auth_description"`
	OptionKeys       []string `json:"option_keys,omitempty"`
	ProofStatus      string   `json:"proof_status"` // "LIVE_TESTED" | "FIXTURE_TESTED"
}

// SIEMConfigAuditRecord represents an immutable WORM hash-chained audit record of a SIEM UI config mutation.
type SIEMConfigAuditRecord struct {
	SeqNo          int64           `json:"seq_no"`
	AuditID        string          `json:"audit_id"`
	DestinationID  string          `json:"destination_id"`
	SIEMVendor     string          `json:"siem_vendor"`
	Action         string          `json:"action"`
	Actor          string          `json:"actor"`
	ConfigSnapshot SIEMDestination `json:"config_snapshot"`
	ConfigSHA256   string          `json:"config_sha256"`
	PrevHash       string          `json:"prev_hash"`
	EntryHash      string          `json:"entry_hash"`
	OccurredAt     time.Time       `json:"occurred_at"`
}

// SIEMExportEnvelope is the canonical internal representation of a Warrant record before a vendor sender bends it
// into the target SIEM's native ingestion format, preserving every cryptographic signature, seal, seq_no, and hash.
type SIEMExportEnvelope struct {
	StreamName     string         `json:"stream_name"`
	CursorSeq      int64          `json:"cursor_seq"`
	RecordType     string         `json:"record_type"`
	RecordID       string         `json:"record_id"`
	OccurredAt     time.Time      `json:"occurred_at"`
	ServiceID      string         `json:"service_id,omitempty"`
	CVEID          string         `json:"cve_id,omitempty"`
	WarrantID      string         `json:"warrant_id,omitempty"`
	RemediationID  string         `json:"remediation_id,omitempty"`
	Severity       int            `json:"severity"` // 1..10 CEF/LEEF normalized severity
	Summary        string         `json:"summary"`
	LedgerSeqNo    int64          `json:"ledger_seq_no,omitempty"`
	PrevHash       string         `json:"prev_hash,omitempty"`
	EntryHash      string         `json:"entry_hash,omitempty"`
	SignatureSummary string       `json:"signature_summary,omitempty"`
	RawRecord      map[string]any `json:"raw_record"`
}
