package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

const (
	RoleArtifactPublisher = "ARTIFACT_PUBLISHER"
	RoleRulepackAuthority = "RULEPACK_AUTHORITY"

	// Legacy revoked public string literals from pre-remediation builds.
	// Any key, seed, envelope, patch artifact, or rulepack derived from these strings is permanently rejected fail-closed.
	legacyPublisherDomainSeed = "publisher:g1163rt-trusted-build-pipeline-v1"
	legacyRulepackDomainSeed  = "publisher:g1163rt-signed-rulepack-authority-v1"
)

// TestSmartcardPersona represents a deterministic PIV/Ed25519 smartcard identity
// available strictly for in-process Go test suites. Private seed and key material
// are permanently excluded from JSON serialization (json:"-") across all postures.
type TestSmartcardPersona struct {
	PrincipalID    string             `json:"principal_id"`
	Email          string             `json:"email"`
	DisplayName    string             `json:"display_name"`
	Role           string             `json:"role"`
	KeyID          string             `json:"key_id"`
	Alg            string             `json:"alg"`
	PublicKeyB64   string             `json:"public_key_b64"`
	KeyFingerprint string             `json:"key_fingerprint"`
	SeedHex        string             `json:"-"`
	BadgeLabel     string             `json:"badge_label"`
	PrivateKey     ed25519.PrivateKey `json:"-"`
	PublicKey      ed25519.PublicKey  `json:"-"`
}

// PublicSmartcardPersona contains strictly public identity metadata (public key, KeyID, SHA-256 fingerprint)
// safe for HTTP serialization without any private key or seed fields on the struct.
type PublicSmartcardPersona struct {
	PrincipalID    string `json:"principal_id"`
	Email          string `json:"email"`
	DisplayName    string `json:"display_name"`
	Role           string `json:"role"`
	KeyID          string `json:"key_id"`
	Alg            string `json:"alg"`
	PublicKeyB64   string `json:"public_key_b64"`
	KeyFingerprint string `json:"key_fingerprint"`
	BadgeLabel     string `json:"badge_label"`
}

// PublicView projects a TestSmartcardPersona onto its strictly public HTTP representation.
func (p TestSmartcardPersona) PublicView() PublicSmartcardPersona {
	return PublicSmartcardPersona{
		PrincipalID:    p.PrincipalID,
		Email:          p.Email,
		DisplayName:    p.DisplayName,
		Role:           p.Role,
		KeyID:          p.KeyID,
		Alg:            p.Alg,
		PublicKeyB64:   p.PublicKeyB64,
		KeyFingerprint: p.KeyFingerprint,
		BadgeLabel:     p.BadgeLabel,
	}
}

// BuiltinPublicTestPersonas returns strictly public metadata for built-in test smartcard personas.
func BuiltinPublicTestPersonas() []PublicSmartcardPersona {
	personas := BuiltinTestPersonas()
	out := make([]PublicSmartcardPersona, 0, len(personas))
	for _, p := range personas {
		out = append(out, p.PublicView())
	}
	return out
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
// in explicitly seeded local test environments solely to mint N4 ephemeral task tokens and co-seal N5 OSCAL attestations.
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

func legacyForbiddenKeyTable() ([]ed25519.PublicKey, []string) {
	domains := []string{
		legacyPublisherDomainSeed,
		legacyRulepackDomainSeed,
	}
	pubs := make([]ed25519.PublicKey, 0, len(domains))
	seeds := make([]string, 0, len(domains))
	for _, d := range domains {
		pub, _, seedHex := deriveEd25519FromDomainSeed(d)
		pubs = append(pubs, pub)
		seeds = append(seeds, strings.ToLower(seedHex))
		// Also block raw SHA-256 of the bare domain string itself in case an attacker hashes without prefix
		rawHash := sha256.Sum256([]byte(d))
		rawPriv := ed25519.NewKeyFromSeed(rawHash[:])
		rawPub := rawPriv.Public().(ed25519.PublicKey)
		pubs = append(pubs, rawPub)
		seeds = append(seeds, strings.ToLower(hex.EncodeToString(rawHash[:])))
	}
	return pubs, seeds
}

// IsForbiddenLegacyPublicSeedKey returns true if pubBytes matches any revoked public-string-derived
// publisher or rulepack authority Ed25519 public key.
func IsForbiddenLegacyPublicSeedKey(pubBytes []byte) bool {
	if len(pubBytes) == 0 {
		return false
	}
	pubs, _ := legacyForbiddenKeyTable()
	for _, banned := range pubs {
		if bytes.Equal(pubBytes, banned) {
			return true
		}
	}
	return false
}

// IsForbiddenLegacySeedHex returns true if seedHex matches any revoked public-string-derived seed.
func IsForbiddenLegacySeedHex(seedHex string) bool {
	clean := strings.ToLower(strings.TrimSpace(seedHex))
	if clean == "" {
		return false
	}
	if clean == strings.ToLower(legacyPublisherDomainSeed) || clean == strings.ToLower(legacyRulepackDomainSeed) {
		return true
	}
	_, seeds := legacyForbiddenKeyTable()
	for _, banned := range seeds {
		if clean == banned {
			return true
		}
	}
	return false
}
