package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func FuzzCanonicalizeJSON(f *testing.F) {
	f.Add([]byte(`{"b":1,"a":2}`))
	f.Add([]byte(`{"nested":[true,false,null,-0.0,1e20,"hello\u0020world"]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{invalid`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		canon, err := CanonicalizeJSON(raw)
		if err != nil {
			return
		}
		canon2, err := CanonicalizeJSON(canon)
		if err != nil {
			t.Fatalf("CanonicalizeJSON output failed re-canonicalization: %v", err)
		}
		if !bytes.Equal(canon, canon2) {
			t.Fatalf("CanonicalizeJSON not idempotent: %q != %q", canon, canon2)
		}
	})
}

func FuzzDSSEVerifyDualHuman(f *testing.F) {
	f.Add([]byte(`{"payloadType":"application/vnd.g1163rt.warrant.v1+json","payload":"e30=","signatures":[]}`))
	f.Add([]byte(`{"payloadType":"bad","payload":"!!!","signatures":[{"keyid":"k1","alg":"Ed25519","sig":"AAAA"}]}`))

	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	resolver := MapKeyResolver{
		"so-key": {
			PrincipalID: "so-1", Role: RoleServiceOwner, KeyID: "so-key",
			Alg: AlgEd25519, PublicKeyBytes: pub1,
		},
		"ao-key": {
			PrincipalID: "ao-1", Role: RoleAuthorizingOfficial, KeyID: "ao-key",
			Alg: AlgEd25519, PublicKeyBytes: pub2,
		},
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		var env Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return
		}
		if _, err := VerifyDualHumanCeremony(&env, PayloadTypeWarrant, resolver, WebAuthnConfig{}); err == nil {
			t.Fatalf("forged fuzzed envelope unexpectedly passed VerifyDualHumanCeremony")
		}
	})
}

func FuzzSecretBoxOpenColumn(f *testing.F) {
	f.Add("secrets", "api_key", "plaintext-value")
	f.Add("integrations", "token", "enc:v1:not-valid-base64")
	f.Add("", "", "")

	box, err := NewEphemeralSecretBox()
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, table, column, input string) {
		if strings.TrimSpace(table) != "" && strings.TrimSpace(column) != "" {
			sealed, err := box.SealColumn(table, column, input)
			if err != nil {
				t.Fatalf("SealColumn failed: %v", err)
			}
			opened, err := box.OpenColumn(table, column, sealed)
			if err != nil {
				t.Fatalf("OpenColumn failed on valid sealed value: %v", err)
			}
			if opened != input {
				t.Fatalf("roundtrip mismatch: got %q want %q", opened, input)
			}
		}
		// Arbitrary tampered strings must never panic
		_, _ = box.OpenColumn(table, column, input)
	})
}
