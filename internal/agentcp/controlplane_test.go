package agentcp

import (
	"testing"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
)

func TestMintTaskWarrant_EnforcesTTLCeilingAndAttribution(t *testing.T) {
	signer := crypto.NewSeededDevEd25519Signer("test-seed")
	cp := NewControlPlane(nil, signer, "http://extractor:8090", nil)

	// Reject TTL > 300s
	if _, _, err := cp.MintTaskWarrant("wrt-1", "rem-1", "worker", "svc-a", "ROLLOUT", "s1", "s2", 301); err == nil {
		t.Fatal("expected TTL > 300s to be rejected")
	}
	// Reject unattributed task
	if _, _, err := cp.MintTaskWarrant("", "rem-1", "worker", "svc-a", "ROLLOUT", "s1", "s2", 60); err == nil {
		t.Fatal("expected missing warrant_id to be rejected")
	}
	// Valid 60s task token
	env, payload, err := cp.MintTaskWarrant("wrt-1", "rem-1", "worker", "svc-a", "ROLLOUT", "s1", "s2", 60)
	if err != nil || env == nil || payload.TTLSeconds != 60 {
		t.Fatalf("expected valid task warrant, got err=%v", err)
	}
}
