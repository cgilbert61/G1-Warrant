package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

func TestCanonicalizeJSON_RFC8785(t *testing.T) {
	input := []byte(`{
		"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001, -0.0],
		"a_str": "line1\nline2\t\"quoted\"",
		"z": true,
		"b": {"2": "two", "10": "ten", "1": "one"}
	}`)
	canon, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatalf("CanonicalizeJSON failed: %v", err)
	}
	want := `{"a_str":"line1\nline2\t\"quoted\"","b":{"1":"one","10":"ten","2":"two"},"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27,0],"z":true}`
	if string(canon) != want {
		t.Fatalf("JCS mismatch:\ngot:  %s\nwant: %s", string(canon), want)
	}
}

func TestDualHumanCeremony_Ed25519AndAC5(t *testing.T) {
	personas := BuiltinTestPersonas()
	resolver := make(MapKeyResolver)
	var alice, bob, mallory, carol TestSmartcardPersona
	for _, p := range personas {
		pk := p.ToPrincipalKey()
		resolver[p.KeyID] = &pk
		switch p.PrincipalID {
		case "usr-alice-so":
			alice = p
		case "usr-bob-ao":
			bob = p
		case "usr-mallory-so":
			mallory = p
		case "usr-carol-sysadmin":
			carol = p
		}
	}

	payload := map[string]any{
		"warrant_id":    "wrt-prod-001",
		"warrant_class": "KEV-TIER1-STATELESS",
		"max_cvss":      10.0,
	}

	// 1. Valid 2-of-2 ceremony (Alice + Bob)
	env, _, err := NewUnsignedEnvelope(PayloadTypeWarrant, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEnvelope: %v", err)
	}
	if err := env.SignEd25519(1, alice.ToPrincipalKey(), alice.PrivateKey); err != nil {
		t.Fatalf("Alice sign: %v", err)
	}
	if err := env.SignEd25519(2, bob.ToPrincipalKey(), bob.PrivateKey); err != nil {
		t.Fatalf("Bob sign: %v", err)
	}
	res, err := VerifyDualHumanCeremony(env, PayloadTypeWarrant, resolver, DefaultWebAuthnConfig())
	if err != nil {
		t.Fatalf("expected valid 2-of-2 ceremony, got: %v", err)
	}
	if res.Slot1.PrincipalID != "usr-alice-so" || res.Slot2.PrincipalID != "usr-bob-ao" {
		t.Fatalf("unexpected verified slots: %+v", res)
	}

	// 2. AC-5 Rejection: Mallory signing both Slot 1 and Slot 2
	sameKeyEnv, _, _ := NewUnsignedEnvelope(PayloadTypeWarrant, payload)
	_ = sameKeyEnv.SignEd25519(1, mallory.ToPrincipalKey(), mallory.PrivateKey)
	_ = sameKeyEnv.SignEd25519(2, mallory.ToPrincipalKey(), mallory.PrivateKey)
	if _, err := VerifyDualHumanCeremony(sameKeyEnv, PayloadTypeWarrant, resolver, DefaultWebAuthnConfig()); err == nil {
		t.Fatal("expected AC-5 rejection when Mallory signs both slots")
	}

	// 3. AC-5 Rejection: SYSTEM_ADMIN (Carol) attempting to sign Slot 2
	sysAdminEnv, _, _ := NewUnsignedEnvelope(PayloadTypeWarrant, payload)
	_ = sysAdminEnv.SignEd25519(1, alice.ToPrincipalKey(), alice.PrivateKey)
	_ = sysAdminEnv.SignEd25519(2, carol.ToPrincipalKey(), carol.PrivateKey)
	_, err = VerifyDualHumanCeremony(sysAdminEnv, PayloadTypeWarrant, resolver, DefaultWebAuthnConfig())
	if err == nil || !strings.Contains(err.Error(), "AC5_SYSADMIN_PROHIBITED") {
		t.Fatalf("expected AC5_SYSADMIN_PROHIBITED, got: %v", err)
	}

	// 4. Principal Revocation check
	revokedResolver := make(MapKeyResolver)
	for k, v := range resolver {
		cp := *v
		if cp.PrincipalID == "usr-bob-ao" {
			cp.Revoked = true
			cp.RevokeReason = "PIV_CARD_REVOKED"
		}
		revokedResolver[k] = &cp
	}
	_, err = VerifyDualHumanCeremony(env, PayloadTypeWarrant, revokedResolver, DefaultWebAuthnConfig())
	if err == nil || !strings.Contains(err.Error(), "REVOKED_PRINCIPAL_OR_KEY") {
		t.Fatalf("expected REVOKED_PRINCIPAL_OR_KEY error, got: %v", err)
	}
}

func TestDualHumanCeremony_WebAuthnES256HardwareAssertion(t *testing.T) {
	p256PrivSO, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256DerSO, _ := x509.MarshalPKIXPublicKey(&p256PrivSO.PublicKey)

	p256PrivAO, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256DerAO, _ := x509.MarshalPKIXPublicKey(&p256PrivAO.PublicKey)

	pkSO := &PrincipalKey{
		PrincipalID:    "usr-hw-so",
		Email:          "hw-so@g1163rt.sec",
		Role:           RoleServiceOwner,
		KeyID:          "webauthn-yubikey-so",
		Alg:            AlgWebAuthnES256,
		PublicKeyBytes: p256DerSO,
		KeyFingerprint: SHA256Hex(p256DerSO),
	}
	pkAO := &PrincipalKey{
		PrincipalID:    "usr-hw-ao",
		Email:          "hw-ao@g1163rt.sec",
		Role:           RoleAuthorizingOfficial,
		KeyID:          "webauthn-yubikey-ao",
		Alg:            AlgWebAuthnES256,
		PublicKeyBytes: p256DerAO,
		KeyFingerprint: SHA256Hex(p256DerAO),
	}
	resolver := MapKeyResolver{
		pkSO.KeyID: pkSO,
		pkAO.KeyID: pkAO,
	}

	env, rawPayload, err := NewUnsignedEnvelope(PayloadTypeWarrant, map[string]any{"warrant_id": "wrt-hw-01"})
	if err != nil {
		t.Fatal(err)
	}
	pae := PAE(env.PayloadType, rawPayload)

	sigSO, metaSO, err := CreateWebAuthnP256Assertion(p256PrivSO, "cred-so", "localhost", "http://localhost:8080", pae)
	if err != nil {
		t.Fatal(err)
	}
	sigAO, metaAO, err := CreateWebAuthnP256Assertion(p256PrivAO, "cred-ao", "localhost", "http://localhost:8080", pae)
	if err != nil {
		t.Fatal(err)
	}

	env.Signatures = append(env.Signatures,
		Signature{
			Slot:             1,
			KeyID:            pkSO.KeyID,
			Alg:              AlgWebAuthnES256,
			Role:             pkSO.Role,
			PrincipalID:      pkSO.PrincipalID,
			PrincipalEmail:   pkSO.Email,
			KeyFingerprint:   pkSO.KeyFingerprint,
			Sig:              base64.StdEncoding.EncodeToString(sigSO),
			WebAuthnMetadata: metaSO,
		},
		Signature{
			Slot:             2,
			KeyID:            pkAO.KeyID,
			Alg:              AlgWebAuthnES256,
			Role:             pkAO.Role,
			PrincipalID:      pkAO.PrincipalID,
			PrincipalEmail:   pkAO.Email,
			KeyFingerprint:   pkAO.KeyFingerprint,
			Sig:              base64.StdEncoding.EncodeToString(sigAO),
			WebAuthnMetadata: metaAO,
		},
	)

	if _, err := VerifyDualHumanCeremony(env, PayloadTypeWarrant, resolver, DefaultWebAuthnConfig()); err != nil {
		t.Fatalf("WebAuthn ES256 ceremony verification failed: %v", err)
	}
}
