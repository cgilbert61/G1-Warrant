package fleetsim

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloneProvingRejectsExcessiveCloneCount(t *testing.T) {
	srv := httptest.NewServer(NewClusterSimulator().Handler())
	defer srv.Close()

	// 1. Excessive clone_count (CWE-789 DoS attempt) MUST be rejected with HTTP 400
	badBody := []byte(`{"service_id":"payments-ledger-api","cve_id":"CVE-2026-9901","candidate_digest":"sha256:abc","clone_count":1000000000}`)
	respBad, err := http.Post(srv.URL+"/v1/twins/clone-proving", "application/json", bytes.NewReader(badBody))
	if err != nil {
		t.Fatalf("POST clone-proving oversized: %v", err)
	}
	defer respBad.Body.Close()
	if respBad.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for oversized clone_count, got %d", respBad.StatusCode)
	}

	// 2. Bounded clone_count=3 succeeds cleanly
	okBody := []byte(`{"service_id":"payments-ledger-api","cve_id":"CVE-2026-9901","candidate_digest":"sha256:abc","clone_count":3}`)
	respOK, err := http.Post(srv.URL+"/v1/twins/clone-proving", "application/json", bytes.NewReader(okBody))
	if err != nil {
		t.Fatalf("POST clone-proving valid: %v", err)
	}
	defer respOK.Body.Close()
	if respOK.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 for clone_count=3, got %d", respOK.StatusCode)
	}
}
