package verify

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
)

const (
	// WireReceiptMaxDecodeBytes caps single-layer gzip/deflate decompression at 4 MiB (S1 fail-closed bound).
	WireReceiptMaxDecodeBytes = 4 * 1024 * 1024

	WireReceiptStatusVerified     = "VERIFIED"
	WireReceiptStatusUnverified   = "UNVERIFIED"
	WireReceiptStatusNotAssessed  = "NOT_ASSESSED"
	WireReceiptStatusFailedClosed = "FAILED_CLOSED"
)

// WireReceiptBlob holds a content-addressed raw HTTP or transcript payload captured during N3 twin proving.
type WireReceiptBlob struct {
	BlobSHA256      string `json:"blob_sha256"`
	ContentEncoding string `json:"content_encoding,omitempty"`
	RawBytes        []byte `json:"-"`
	Truncated       bool   `json:"truncated,omitempty"`
	Source          string `json:"source,omitempty"`
}

// WireReceiptResult records the deterministic S1 verbatim receipt verification outcome for a bound wire blob.
type WireReceiptResult struct {
	Status            string   `json:"status"`
	BlobSHA256        string   `json:"blob_sha256"`
	DecodedBytes      int      `json:"decoded_bytes"`
	ContentEncoding   string   `json:"content_encoding,omitempty"`
	MatchedAssertions []string `json:"matched_assertions,omitempty"`
	MissingAssertions []string `json:"missing_assertions,omitempty"`
	FailureReason     string   `json:"failure_reason,omitempty"`
}

// CoverageLedgerSummary captures honest-gap untested surfaces and evidence-version staleness
// for N3 verification bundles and N5 OSCAL 1.1.2 POA&M exports.
type CoverageLedgerSummary struct {
	TestedSurfaces        []string `json:"tested_surfaces,omitempty"`
	UntestedSurface       []string `json:"untested_surface,omitempty"`
	EvidenceVersion       int      `json:"evidence_version"`
	ReportEvidenceVersion int      `json:"report_evidence_version"`
	StaleEvidence         bool     `json:"stale_evidence"`
	StaleReason           string   `json:"stale_reason,omitempty"`
}

// NewContentAddressedBlob wraps raw wire bytes with their deterministic SHA-256 content digest.
func NewContentAddressedBlob(source, contentEncoding string, raw []byte, truncated bool) WireReceiptBlob {
	cp := make([]byte, len(raw))
	copy(cp, raw)
	return WireReceiptBlob{
		BlobSHA256:      crypto.SHA256Hex(cp),
		ContentEncoding: strings.TrimSpace(contentEncoding),
		RawBytes:        cp,
		Truncated:       truncated,
		Source:          strings.TrimSpace(source),
	}
}

// DecodeWireBodySingleLayer decodes raw wire bytes under a strict maxBytes cap.
// Supports identity, single-layer gzip, and single-layer deflate (RFC 9110 zlib or raw deflate).
// Fails closed on stacked encodings, unsupported encodings, decode errors, cap overflow, or non-UTF-8 binary bodies.
func DecodeWireBodySingleLayer(raw []byte, contentEncoding string, maxBytes int) ([]byte, string, error) {
	if maxBytes <= 0 {
		maxBytes = WireReceiptMaxDecodeBytes
	}
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if strings.Contains(enc, ",") {
		return nil, "STACKED_CONTENT_ENCODING", fmt.Errorf("stacked content-encoding %q rejected (fail-closed)", contentEncoding)
	}

	var decoded []byte
	switch enc {
	case "", "identity":
		if len(raw) > maxBytes {
			return nil, "DECODE_SIZE_CAP_EXCEEDED", fmt.Errorf("wire body exceeds %d byte cap", maxBytes)
		}
		decoded = raw
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, "DECODE_ERROR", fmt.Errorf("gzip header error: %w", err)
		}
		defer func() { _ = gr.Close() }()
		b, err := io.ReadAll(io.LimitReader(gr, int64(maxBytes)+1))
		if err != nil {
			return nil, "DECODE_ERROR", fmt.Errorf("gzip decode error: %w", err)
		}
		if len(b) > maxBytes {
			return nil, "DECODE_SIZE_CAP_EXCEEDED", fmt.Errorf("gzip decoded body exceeds %d byte cap", maxBytes)
		}
		decoded = b
	case "deflate":
		if zr, zErr := zlib.NewReader(bytes.NewReader(raw)); zErr == nil {
			defer func() { _ = zr.Close() }()
			b, err := io.ReadAll(io.LimitReader(zr, int64(maxBytes)+1))
			if err != nil {
				return nil, "DECODE_ERROR", fmt.Errorf("zlib deflate decode error: %w", err)
			}
			if len(b) > maxBytes {
				return nil, "DECODE_SIZE_CAP_EXCEEDED", fmt.Errorf("deflate decoded body exceeds %d byte cap", maxBytes)
			}
			decoded = b
		} else {
			fr := flate.NewReader(bytes.NewReader(raw))
			defer func() { _ = fr.Close() }()
			b, err := io.ReadAll(io.LimitReader(fr, int64(maxBytes)+1))
			if err != nil {
				return nil, "DECODE_ERROR", fmt.Errorf("raw deflate decode error: %w", err)
			}
			if len(b) > maxBytes {
				return nil, "DECODE_SIZE_CAP_EXCEEDED", fmt.Errorf("raw deflate decoded body exceeds %d byte cap", maxBytes)
			}
			decoded = b
		}
	default:
		return nil, "UNSUPPORTED_CONTENT_ENCODING", fmt.Errorf("unsupported content-encoding %q", contentEncoding)
	}

	if !utf8.Valid(decoded) {
		return nil, "NON_UTF8_BINARY_BODY", fmt.Errorf("decoded wire body is non-UTF-8 binary")
	}
	return decoded, "", nil
}

// VerifyWireReceipt performs S1 deterministic machine receipt verification on a content-addressed wire blob.
// Every supplied assertion must appear verbatim (case-preserved after whitespace normalization) in the decoded body.
func VerifyWireReceipt(blob WireReceiptBlob, assertions []string) WireReceiptResult {
	computed := crypto.SHA256Hex(blob.RawBytes)
	res := WireReceiptResult{
		BlobSHA256:      computed,
		ContentEncoding: strings.TrimSpace(blob.ContentEncoding),
	}

	if blob.BlobSHA256 != "" && !strings.EqualFold(strings.TrimSpace(blob.BlobSHA256), computed) {
		res.Status = WireReceiptStatusFailedClosed
		res.FailureReason = "BLOB_DIGEST_MISMATCH"
		return res
	}
	if blob.Truncated {
		res.Status = WireReceiptStatusFailedClosed
		res.FailureReason = "BLOB_TRUNCATED"
		return res
	}
	if len(blob.RawBytes) == 0 {
		res.Status = WireReceiptStatusNotAssessed
		res.FailureReason = "EMPTY_WIRE_BLOB"
		return res
	}

	cleanAssertions := make([]string, 0, len(assertions))
	for _, a := range assertions {
		norm := collapseWhitespacePreserveCase(a)
		if norm != "" {
			cleanAssertions = append(cleanAssertions, norm)
		}
	}
	if len(cleanAssertions) == 0 {
		res.Status = WireReceiptStatusNotAssessed
		res.FailureReason = "NO_ASSERTIONS_SUPPLIED"
		return res
	}

	decoded, reasonCode, err := DecodeWireBodySingleLayer(blob.RawBytes, blob.ContentEncoding, WireReceiptMaxDecodeBytes)
	if err != nil {
		res.Status = WireReceiptStatusFailedClosed
		res.FailureReason = reasonCode
		return res
	}
	res.DecodedBytes = len(decoded)

	normBody := collapseWhitespacePreserveCase(string(decoded))
	for _, want := range cleanAssertions {
		if strings.Contains(normBody, want) {
			res.MatchedAssertions = append(res.MatchedAssertions, want)
		} else {
			res.MissingAssertions = append(res.MissingAssertions, want)
		}
	}

	if len(res.MissingAssertions) > 0 {
		res.Status = WireReceiptStatusUnverified
		res.FailureReason = "ASSERTION_MISMATCH"
		return res
	}
	res.Status = WireReceiptStatusVerified
	return res
}

// EvaluateCoverageAndStaleness computes explicit untested_surface entries and detects evidence staleness
// (EvidenceVersion != ReportEvidenceVersion) so untested controls are never silently reported as clean.
func EvaluateCoverageAndStaleness(expectedSurfaces, testedSurfaces []string, evidenceVersion, reportEvidenceVersion int) CoverageLedgerSummary {
	testedSet := make(map[string]bool, len(testedSurfaces))
	testedOut := make([]string, 0, len(testedSurfaces))
	for _, s := range testedSurfaces {
		n := strings.TrimSpace(s)
		if n != "" && !testedSet[n] {
			testedSet[n] = true
			testedOut = append(testedOut, n)
		}
	}
	sort.Strings(testedOut)

	untestedSet := make(map[string]bool)
	untestedOut := make([]string, 0)
	for _, exp := range expectedSurfaces {
		n := strings.TrimSpace(exp)
		if n != "" && !testedSet[n] && !untestedSet[n] {
			untestedSet[n] = true
			untestedOut = append(untestedOut, n)
		}
	}
	sort.Strings(untestedOut)

	stale := evidenceVersion != reportEvidenceVersion
	staleReason := ""
	if stale {
		staleReason = fmt.Sprintf("EVIDENCE_VERSION_DRIFT: evidence_version=%d != report_evidence_version=%d", evidenceVersion, reportEvidenceVersion)
	}
	return CoverageLedgerSummary{
		TestedSurfaces:        testedOut,
		UntestedSurface:       untestedOut,
		EvidenceVersion:       evidenceVersion,
		ReportEvidenceVersion: reportEvidenceVersion,
		StaleEvidence:         stale,
		StaleReason:           staleReason,
	}
}

func collapseWhitespacePreserveCase(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
