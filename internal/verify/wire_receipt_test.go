package verify

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"testing"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func rawDeflateBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

func TestVerifyWireReceiptPlainGzipAndDeflate(t *testing.T) {
	body := []byte("HTTP/1.1 403 Forbidden\r\nX-G1-Shield: blocked\r\n\r\nEXPLOIT_BLOCKED: CVE-2026-12345 neutralized")
	assertions := []string{"403 Forbidden", "EXPLOIT_BLOCKED: CVE-2026-12345"}

	resPlain := VerifyWireReceipt(NewContentAddressedBlob("patched_twin", "", body, false), assertions)
	if resPlain.Status != WireReceiptStatusVerified || len(resPlain.MatchedAssertions) != 2 {
		t.Fatalf("expected VERIFIED for identity, got %+v", resPlain)
	}

	resGzip := VerifyWireReceipt(NewContentAddressedBlob("patched_twin", "gzip", gzipBytes(t, body), false), assertions)
	if resGzip.Status != WireReceiptStatusVerified {
		t.Fatalf("expected VERIFIED for gzip, got %+v", resGzip)
	}

	resZlib := VerifyWireReceipt(NewContentAddressedBlob("patched_twin", "deflate", zlibBytes(t, body), false), assertions)
	if resZlib.Status != WireReceiptStatusVerified {
		t.Fatalf("expected VERIFIED for zlib deflate, got %+v", resZlib)
	}

	resFlate := VerifyWireReceipt(NewContentAddressedBlob("patched_twin", "deflate", rawDeflateBytes(t, body), false), assertions)
	if resFlate.Status != WireReceiptStatusVerified {
		t.Fatalf("expected VERIFIED for raw deflate, got %+v", resFlate)
	}

	resMismatch := VerifyWireReceipt(NewContentAddressedBlob("patched_twin", "", body, false), []string{"exploit_blocked: cve-2026-12345"})
	if resMismatch.Status != WireReceiptStatusUnverified || resMismatch.FailureReason != "ASSERTION_MISMATCH" {
		t.Fatalf("expected case-sensitive UNVERIFIED mismatch, got %+v", resMismatch)
	}
}

func TestVerifyWireReceiptFailClosedCases(t *testing.T) {
	body := []byte("EXPLOIT_BLOCKED ok")

	stacked := VerifyWireReceipt(NewContentAddressedBlob("twin", "gzip, deflate", gzipBytes(t, body), false), []string{"EXPLOIT_BLOCKED"})
	if stacked.Status != WireReceiptStatusFailedClosed || stacked.FailureReason != "STACKED_CONTENT_ENCODING" {
		t.Fatalf("expected STACKED_CONTENT_ENCODING fail-closed, got %+v", stacked)
	}

	trunc := VerifyWireReceipt(NewContentAddressedBlob("twin", "", body, true), []string{"EXPLOIT_BLOCKED"})
	if trunc.Status != WireReceiptStatusFailedClosed || trunc.FailureReason != "BLOB_TRUNCATED" {
		t.Fatalf("expected BLOB_TRUNCATED fail-closed, got %+v", trunc)
	}

	tampered := NewContentAddressedBlob("twin", "", body, false)
	tampered.BlobSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	resTamper := VerifyWireReceipt(tampered, []string{"EXPLOIT_BLOCKED"})
	if resTamper.Status != WireReceiptStatusFailedClosed || resTamper.FailureReason != "BLOB_DIGEST_MISMATCH" {
		t.Fatalf("expected BLOB_DIGEST_MISMATCH fail-closed, got %+v", resTamper)
	}

	oversized := bytes.Repeat([]byte("A"), WireReceiptMaxDecodeBytes+1024)
	resBomb := VerifyWireReceipt(NewContentAddressedBlob("twin", "gzip", gzipBytes(t, oversized), false), []string{"AAAA"})
	if resBomb.Status != WireReceiptStatusFailedClosed || resBomb.FailureReason != "DECODE_SIZE_CAP_EXCEEDED" {
		t.Fatalf("expected DECODE_SIZE_CAP_EXCEEDED fail-closed, got %+v", resBomb)
	}

	binBody := []byte{0xff, 0xfe, 0xfd, 0x00, 0x80}
	resBin := VerifyWireReceipt(NewContentAddressedBlob("twin", "", binBody, false), []string{"test"})
	if resBin.Status != WireReceiptStatusFailedClosed || resBin.FailureReason != "NON_UTF8_BINARY_BODY" {
		t.Fatalf("expected NON_UTF8_BINARY_BODY fail-closed, got %+v", resBin)
	}
}

func TestEvaluateCoverageAndStaleness(t *testing.T) {
	cov := EvaluateCoverageAndStaleness(
		[]string{"l7_http_replay", "sbom_digest_sweep", "admission_lockout", "egress_metadata_block"},
		[]string{"sbom_digest_sweep", "admission_lockout"},
		3,
		2,
	)
	if !cov.StaleEvidence {
		t.Fatalf("expected StaleEvidence=true when evidenceVersion=3 != reportEvidenceVersion=2")
	}
	if len(cov.UntestedSurface) != 2 || cov.UntestedSurface[0] != "egress_metadata_block" || cov.UntestedSurface[1] != "l7_http_replay" {
		t.Fatalf("unexpected UntestedSurface: %v", cov.UntestedSurface)
	}

	fresh := EvaluateCoverageAndStaleness([]string{"sbom_digest_sweep"}, []string{"sbom_digest_sweep"}, 2, 2)
	if fresh.StaleEvidence || len(fresh.UntestedSurface) != 0 {
		t.Fatalf("expected fresh full coverage, got %+v", fresh)
	}
}
