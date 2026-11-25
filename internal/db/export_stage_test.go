package db

import "testing"

func TestComputeStagedExportDigestDeterministic(t *testing.T) {
	d1, err := ComputeStagedExportDigest("att-1", "hash-a", []string{"t1", "t2"})
	if err != nil {
		t.Fatalf("ComputeStagedExportDigest: %v", err)
	}
	d2, err := ComputeStagedExportDigest("att-1", "hash-a", []string{"t1", "t2"})
	if err != nil {
		t.Fatalf("ComputeStagedExportDigest (2): %v", err)
	}
	if d1 != d2 || len(d1) != 64 {
		t.Fatalf("expected identical 64-hex SHA-256 digests, got %q vs %q", d1, d2)
	}
	d3, _ := ComputeStagedExportDigest("att-1", "hash-a", []string{"t1", "t3"})
	if d1 == d3 {
		t.Fatalf("expected different digest when trace hashes change")
	}
}
