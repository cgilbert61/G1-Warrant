package adapters

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
)

// SignedVirtualPatchRulepack is a publisher-signed L7 containment rulepack binding a known
// CWE/CVE exploit class to explicit HTTP routes/headers so N3 never guesses L7 paths from stripped prose.
type SignedVirtualPatchRulepack struct {
	RulepackID     string   `json:"rulepack_id"`
	CVEID          string   `json:"cve_id,omitempty"`
	CWEID          string   `json:"cwe_id,omitempty"`
	ExploitVector  string   `json:"exploit_vector"`
	BlockedPaths   []string `json:"blocked_paths"`
	BlockedHeaders []string `json:"blocked_headers,omitempty"`
	HasSignedProbe bool     `json:"has_signed_probe"`
	PublisherKeyID string   `json:"publisher_key_id"`
	SignatureB64   string   `json:"signature_b64"`
}

// RulepackRegistry strictly verifies and resolves publisher-signed L7 virtual-patch rulepacks
// against an authoritative Ed25519 public key. It NEVER derives or holds a private signing key.
type RulepackRegistry struct {
	mu        sync.RWMutex
	pubKey    ed25519.PublicKey
	keyID     string
	rulepacks []SignedVirtualPatchRulepack
}

// NewRulepackRegistry constructs a verification-only RulepackRegistry bound to an authoritative Ed25519 public key.
// Rejects nil, malformed, or legacy public-string-derived keys fail-closed.
func NewRulepackRegistry(pubKey ed25519.PublicKey, keyID string) (*RulepackRegistry, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("INVALID_RULEPACK_PUBLIC_KEY: expected %d-byte Ed25519 public key, got %d", ed25519.PublicKeySize, len(pubKey))
	}
	if crypto.IsForbiddenLegacyPublicSeedKey(pubKey) {
		return nil, errors.New("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: rulepack registry refuses revoked public-string-derived authority key")
	}
	pubCopy := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pubCopy, pubKey)
	if strings.TrimSpace(keyID) == "" {
		keyID = "rulepack-authority-ed25519-" + crypto.SHA256Hex(pubCopy)[:12]
	}
	return &RulepackRegistry{
		pubKey: pubCopy,
		keyID:  keyID,
	}, nil
}

// PublicKey returns a copy of the configured verification public key.
func (r *RulepackRegistry) PublicKey() ed25519.PublicKey {
	if r == nil || len(r.pubKey) == 0 {
		return nil
	}
	cp := make(ed25519.PublicKey, len(r.pubKey))
	copy(cp, r.pubKey)
	return cp
}

// KeyID returns the configured verification key identifier.
func (r *RulepackRegistry) KeyID() string {
	if r == nil {
		return ""
	}
	return r.keyID
}

// DefaultUnsignedRulepackTemplates returns the canonical L7 containment rule templates prior to offline publisher signing.
func DefaultUnsignedRulepackTemplates() []SignedVirtualPatchRulepack {
	return []SignedVirtualPatchRulepack{
		{
			RulepackID:     "rpk-cwe22-path-traversal-v1",
			CWEID:          "CWE-22",
			ExploitVector:  "HTTP_PATH_TRAVERSAL",
			BlockedPaths:   []string{"/..", "/%2e%2e", "/api/v1/debug/pprof"},
			HasSignedProbe: true,
		},
		{
			RulepackID:     "rpk-cwe78-cmdi-headers-v1",
			CWEID:          "CWE-78",
			ExploitVector:  "HTTP_PATH_TRAVERSAL",
			BlockedPaths:   []string{"/cgi-bin/", "/actuator/env"},
			BlockedHeaders: []string{"X-Api-Version: ${jndi:"},
			HasSignedProbe: true,
		},
		{
			RulepackID:     "rpk-cwe787-tls-heartbeat-v1",
			CWEID:          "CWE-787",
			ExploitVector:  "TLS_HEARTBEAT",
			BlockedPaths:   []string{"/tls-heartbeat-ext"},
			HasSignedProbe: true,
		},
		{
			RulepackID:     "rpk-cwe502-jndi-lookup-v1",
			CWEID:          "CWE-502",
			ExploitVector:  "JNDI_LOOKUP",
			BlockedHeaders: []string{"${jndi:ldap://", "${jndi:rmi://"},
			BlockedPaths:   []string{"/jndi-lookup"},
			HasSignedProbe: true,
		},
		{
			RulepackID:     "rpk-cwe209-error-stack-suppression-v1",
			CWEID:          "CWE-209",
			ExploitVector:  "ERROR_STACK_TRACE",
			BlockedPaths:   []string{"/debug/vars", "/actuator/trace", "/_profiler"},
			BlockedHeaders: []string{"X-Debug-Stacktrace: true"},
			HasSignedProbe: true,
		},
		{
			RulepackID:     "rpk-cwe918-ssrf-metadata-shield-v1",
			CWEID:          "CWE-918",
			ExploitVector:  "SSRF_METADATA",
			BlockedPaths:   []string{"/proxy/fetch", "/webhook/test"},
			BlockedHeaders: []string{"X-Forwarded-Host: 169.254.169.254"},
			HasSignedProbe: true,
		},
		{
			RulepackID:     "rpk-cwe434-webshell-upload-deny-v1",
			CWEID:          "CWE-434",
			ExploitVector:  "UNRESTRICTED_UPLOAD",
			BlockedPaths:   []string{"/upload/*.jsp", "/upload/*.jspx", "/upload/*.php"},
			HasSignedProbe: true,
		},
	}
}

// SignRulepackWithAuthority signs a rulepack externally using an AuthoritySigner (KMS, hex seed, 0600 key file, or sandbox ephemeral).
func SignRulepackWithAuthority(ctx context.Context, signer crypto.AuthoritySigner, rp SignedVirtualPatchRulepack) (SignedVirtualPatchRulepack, error) {
	if signer == nil {
		return SignedVirtualPatchRulepack{}, errors.New("nil rulepack authority signer")
	}
	pk := signer.PublicKey()
	if crypto.IsForbiddenLegacyPublicSeedKey(pk.PublicKeyBytes) {
		return SignedVirtualPatchRulepack{}, errors.New("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: refusing to sign rulepack with revoked public-string seed")
	}
	rp.PublisherKeyID = pk.KeyID
	sig, err := signer.SignBytes(ctx, canonicalRulepackSignBytes(rp))
	if err != nil {
		return SignedVirtualPatchRulepack{}, err
	}
	rp.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	return rp, nil
}

// NewRulepackRegistryFromEnv initializes RulepackRegistry following the authority custody ladder:
//   - In live/Kubernetes posture, requires an authoritative public key (or KMS/seed/keyfile) and NEVER self-signs rulepacks on the fly;
//     loads pre-signed rulepacks from WARRANT_RULEPACKS_FILE when provided.
//   - In sandbox/demo posture, signs default sandbox rulepacks externally using the resolved non-production signer and passes ONLY
//     the verification public key into RulepackRegistry.
func NewRulepackRegistryFromEnv(getenv func(string) string) (*RulepackRegistry, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	isLive := crypto.IsLiveOrKubernetesPosture(getenv)
	signer, pubKey, err := crypto.ResolveAuthorityCustody(crypto.DefaultRulepackCustodyConfig(), getenv)
	if err != nil {
		return nil, err
	}
	reg, err := NewRulepackRegistry(ed25519.PublicKey(pubKey.PublicKeyBytes), pubKey.KeyID)
	if err != nil {
		return nil, err
	}

	if bundlePath := strings.TrimSpace(getenv("WARRANT_RULEPACKS_FILE")); bundlePath != "" {
		raw, readErr := os.ReadFile(bundlePath)
		if readErr != nil {
			return nil, fmt.Errorf("read WARRANT_RULEPACKS_FILE %s: %w", bundlePath, readErr)
		}
		var signedList []SignedVirtualPatchRulepack
		if uErr := json.Unmarshal(raw, &signedList); uErr != nil {
			return nil, fmt.Errorf("parse WARRANT_RULEPACKS_FILE %s: %w", bundlePath, uErr)
		}
		for _, rp := range signedList {
			if rErr := reg.Register(rp); rErr != nil {
				return nil, fmt.Errorf("verify rulepack %s from %s: %w", rp.RulepackID, bundlePath, rErr)
			}
		}
		return reg, nil
	}

	// Never self-sign rulepacks on the fly in live/Kubernetes posture.
	if isLive {
		return reg, nil
	}

	// Sandbox/demo/test posture ONLY: sign default rulepacks outside RulepackRegistry; RulepackRegistry retains only pubKey.
	if signer != nil {
		ctx := context.Background()
		for _, tmpl := range DefaultUnsignedRulepackTemplates() {
			signed, sErr := SignRulepackWithAuthority(ctx, signer, tmpl)
			if sErr != nil {
				return nil, sErr
			}
			if rErr := reg.Register(signed); rErr != nil {
				return nil, rErr
			}
		}
	}
	return reg, nil
}

// NewDefaultRulepackRegistry initializes a RulepackRegistry for sandbox/test callers using NewRulepackRegistryFromEnv.
// In live/Kubernetes posture without configured keys, returns an empty registry with no public key so all Verify calls fail closed.
func NewDefaultRulepackRegistry() *RulepackRegistry {
	reg, err := NewRulepackRegistryFromEnv(os.Getenv)
	if err != nil {
		return &RulepackRegistry{}
	}
	return reg
}

func canonicalRulepackSignBytes(rp SignedVirtualPatchRulepack) []byte {
	material := strings.Join([]string{
		"G1_RULEPACK_V1",
		rp.RulepackID,
		strings.ToUpper(rp.CVEID),
		strings.ToUpper(rp.CWEID),
		rp.ExploitVector,
		strings.Join(rp.BlockedPaths, ","),
		strings.Join(rp.BlockedHeaders, ","),
		fmt.Sprintf("%t", rp.HasSignedProbe),
	}, "|")
	return []byte(material)
}

// Verify cryptographically verifies the publisher Ed25519 signature on a SignedVirtualPatchRulepack,
// failing closed if the registry has no authoritative key or if a legacy public-string-derived key is presented.
func (r *RulepackRegistry) Verify(rp SignedVirtualPatchRulepack) error {
	if r == nil || len(r.pubKey) != ed25519.PublicKeySize {
		return errors.New("RULEPACK_AUTHORITY_UNCONFIGURED: missing authoritative rulepack public key")
	}
	if crypto.IsForbiddenLegacyPublicSeedKey(r.pubKey) {
		return errors.New("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: rulepack registry configured with revoked public-string key")
	}
	if strings.EqualFold(strings.TrimSpace(rp.PublisherKeyID), "rulepack-authority-ed25519-v1") {
		return fmt.Errorf("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: rulepack %s carries revoked legacy authority key_id", rp.RulepackID)
	}
	sigBytes, err := crypto.DecodeBase64Any(rp.SignatureB64)
	if err != nil {
		return fmt.Errorf("decode rulepack signature: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize || !ed25519.Verify(r.pubKey, canonicalRulepackSignBytes(rp), sigBytes) {
		return fmt.Errorf("INVALID_RULEPACK_SIGNATURE for %s", rp.RulepackID)
	}
	return nil
}

// Register verifies and stores a SignedVirtualPatchRulepack.
func (r *RulepackRegistry) Register(rp SignedVirtualPatchRulepack) error {
	if err := r.Verify(rp); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rulepacks = append(r.rulepacks, rp)
	return nil
}

// Lookup finds a verified publisher-signed rulepack matching CVEID or CWEID.
// Returns nil if no signed L7 rulepack exists (triggering safe Zero-Prose L3/L4 Egress Quarantine instead).
func (r *RulepackRegistry) Lookup(cveID, cweID, exploitVector string) *SignedVirtualPatchRulepack {
	if r == nil || len(r.pubKey) != ed25519.PublicKeySize {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	upperCVE := strings.ToUpper(strings.TrimSpace(cveID))
	upperCWE := strings.ToUpper(strings.TrimSpace(cweID))

	// Exact CVE match takes precedence
	for _, rp := range r.rulepacks {
		if rp.CVEID != "" && strings.ToUpper(rp.CVEID) == upperCVE {
			if r.Verify(rp) == nil {
				cp := rp
				return &cp
			}
		}
	}
	// Secondary match on specific CWE (excluding generic/unknown CWE-000 / CWE-Other)
	if upperCWE != "" && upperCWE != "CWE-000" && upperCWE != "CWE-OTHER" && upperCWE != "NVD-CWE-NOINFO" {
		for _, rp := range r.rulepacks {
			if rp.CWEID != "" && strings.ToUpper(rp.CWEID) == upperCWE {
				if r.Verify(rp) == nil {
					cp := rp
					return &cp
				}
			}
		}
	}
	// Fallback match on explicit non-default exploit vector
	if exploitVector == "TLS_HEARTBEAT" || exploitVector == "JNDI_LOOKUP" {
		for _, rp := range r.rulepacks {
			if rp.ExploitVector == exploitVector && r.Verify(rp) == nil {
				cp := rp
				return &cp
			}
		}
	}
	return nil
}
