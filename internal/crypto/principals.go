package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// TestSmartcardPersona represents a deterministic PIV/Ed25519 smartcard identity
// available for out-of-the-box console ceremony testing and automated test suites.
type TestSmartcardPersona struct {
	PrincipalID    string             `json:"principal_id"`
	Email          string             `json:"email"`
	DisplayName    string             `json:"display_name"`
	Role           string             `json:"role"`
	KeyID          string             `json:"key_id"`
	Alg            string             `json:"alg"`
	PublicKeyB64   string             `json:"public_key_b64"`
	KeyFingerprint string             `json:"key_fingerprint"`
	SeedHex        string             `json:"seed_hex"`
	BadgeLabel     string             `json:"badge_label"`
	PrivateKey     ed25519.PrivateKey `json:"-"`
	PublicKey      ed25519.PublicKey  `json:"-"`
}

func deriveEd25519FromDomainSeed(domain string) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	seed := sha256.Sum256([]byte("g1163rt-g1-warrant-v1:" + domain))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, hex.EncodeToString(seed[:])
}

// BuiltinTestPersonas returns the canonical FIPS/Ed25519 test smartcard personas.
func BuiltinTestPersonas() []TestSmartcardPersona {
	specs := []struct {
		id     string
		email  string
		name   string
		role   string
		keyID  string
		domain string
		badge  string
	}{
		{
			id:     "usr-alice-so",
			email:  "alice.vance@g1163rt.sec",
			name:   "Alice Vance",
			role:   RoleServiceOwner,
			keyID:  "piv-alice-ed25519-01",
			domain: "persona:alice-service-owner-v1",
			badge:  "Alice: Service Owner (Slot 1)",
		},
		{
			id:     "usr-bob-ao",
			email:  "bob.sterling@g1163rt.sec",
			name:   "Bob Sterling",
			role:   RoleAuthorizingOfficial,
			keyID:  "piv-bob-ed25519-01",
			domain: "persona:bob-authorizing-official-v1",
			badge:  "Bob: Authorizing Official (Slot 2)",
		},
		{
			id:     "usr-elena-so",
			email:  "elena.rostova@g1163rt.sec",
			name:   "Elena Rostova",
			role:   RoleServiceOwner,
			keyID:  "piv-elena-ed25519-01",
			domain: "persona:elena-service-owner-v1",
			badge:  "Elena: Backup Service Owner",
		},
		{
			id:     "usr-marcus-ao",
			email:  "marcus.thorne@g1163rt.sec",
			name:   "Marcus Thorne",
			role:   RoleAuthorizingOfficial,
			keyID:  "piv-marcus-ed25519-01",
			domain: "persona:marcus-authorizing-official-v1",
			badge:  "Marcus: Backup AO",
		},
		{
			id:     "usr-mallory-so",
			email:  "mallory.colluder@g1163rt.sec",
			name:   "Mallory Colluder",
			role:   RoleServiceOwner,
			keyID:  "piv-mallory-ed25519-01",
			domain: "persona:mallory-ac5-test-v1",
			badge:  "Mallory: AC-5 Same-Key Rejection Test",
		},
		{
			id:     "usr-carol-sysadmin",
			email:  "carol.root@g1163rt.sec",
			name:   "Carol Root",
			role:   RoleSystemAdmin,
			keyID:  "piv-carol-ed25519-01",
			domain: "persona:carol-sysadmin-prohibited-v1",
			badge:  "Carol: SYSTEM_ADMIN Prohibition Test",
		},
	}

	out := make([]TestSmartcardPersona, 0, len(specs))
	for _, s := range specs {
		pub, priv, seedHex := deriveEd25519FromDomainSeed(s.domain)
		out = append(out, TestSmartcardPersona{
			PrincipalID:    s.id,
			Email:          s.email,
			DisplayName:    s.name,
			Role:           s.role,
			KeyID:          s.keyID,
			Alg:            AlgEd25519,
			PublicKeyB64:   base64.StdEncoding.EncodeToString(pub),
			KeyFingerprint: SHA256Hex(pub),
			SeedHex:        seedHex,
			BadgeLabel:     s.badge,
			PrivateKey:     priv,
			PublicKey:      pub,
		})
	}
	return out
}

// ToPrincipalKey converts a TestSmartcardPersona to a PrincipalKey.
func (p TestSmartcardPersona) ToPrincipalKey() PrincipalKey {
	return PrincipalKey{
		PrincipalID:    p.PrincipalID,
		Email:          p.Email,
		DisplayName:    p.DisplayName,
		Role:           p.Role,
		KeyID:          p.KeyID,
		Alg:            p.Alg,
		PublicKeyBytes: append([]byte{}, p.PublicKey...),
		KeyFingerprint: p.KeyFingerprint,
	}
}

// KernelKeypair returns the deterministic or seed-derived Ed25519 keypair used by warrantd
// solely to mint N4 ephemeral task tokens and co-seal N5 OSCAL attestations.
func KernelKeypair(secretSeed string) (PrincipalKey, ed25519.PrivateKey) {
	if secretSeed == "" {
		secretSeed = "kernel:warrantd-attestation-seal-v1"
	}
	pub, priv, _ := deriveEd25519FromDomainSeed(secretSeed)
	return PrincipalKey{
		PrincipalID:    "sys-warrantd-kernel",
		Email:          "kernel-attestor@g1163rt.sec",
		DisplayName:    "G1-Warrant Deterministic Kernel Seal",
		Role:           RoleAttestationKernel,
		KeyID:          "kernel-ed25519-01",
		Alg:            AlgEd25519,
		PublicKeyBytes: append([]byte{}, pub...),
		KeyFingerprint: SHA256Hex(pub),
	}, priv
}

// PublisherKeypair returns the trusted upstream OCI/patch artifact publisher keypair.
func PublisherKeypair() (PrincipalKey, ed25519.PrivateKey) {
	pub, priv, _ := deriveEd25519FromDomainSeed("publisher:g1163rt-trusted-build-pipeline-v1")
	return PrincipalKey{
		PrincipalID:    "pub-g1163rt-ci",
		Email:          "provenance@g1163rt.sec",
		DisplayName:    "G1163RT Trusted Build Provenance Signer",
		Role:           "ARTIFACT_PUBLISHER",
		KeyID:          "pub-provenance-ed25519-01",
		Alg:            AlgEd25519,
		PublicKeyBytes: append([]byte{}, pub...),
		KeyFingerprint: SHA256Hex(pub),
	}, priv
}
