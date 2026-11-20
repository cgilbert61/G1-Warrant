package adapters

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
)

// SignedVirtualPatchRulepack is a publisher-signed L7 containment rulepack binding a known
// CWE/CVE exploit class to explicit HTTP routes/headers so N3 never guesses L7 paths from stripped prose.
type SignedVirtualPatchRulepack struct {
	RulepackID      string   `json:"rulepack_id"`
	CVEID           string   `json:"cve_id,omitempty"`
	CWEID           string   `json:"cwe_id,omitempty"`
	ExploitVector   string   `json:"exploit_vector"`
	BlockedPaths    []string `json:"blocked_paths"`
	BlockedHeaders  []string `json:"blocked_headers,omitempty"`
	HasSignedProbe  bool     `json:"has_signed_probe"`
	PublisherKeyID  string   `json:"publisher_key_id"`
	SignatureB64    string   `json:"signature_b64"`
}

// RulepackRegistry verifies and resolves publisher-signed L7 virtual-patch rulepacks.
type RulepackRegistry struct {
	mu        sync.RWMutex
	pubKey    ed25519.PublicKey
	keyID     string
	rulepacks []SignedVirtualPatchRulepack
}

// NewDefaultRulepackRegistry initializes the verified CWE/CVE rulepack registry with publisher-signed entries.
func NewDefaultRulepackRegistry() *RulepackRegistry {
	pk, priv := crypto.KernelKeypair("publisher:g1163rt-signed-rulepack-authority-v1")
	reg := &RulepackRegistry{
		pubKey: ed25519.PublicKey(pk.PublicKeyBytes),
		keyID:  "rulepack-authority-ed25519-v1",
	}

	defaults := []SignedVirtualPatchRulepack{
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

	for _, rp := range defaults {
		rp.PublisherKeyID = reg.keyID
		msg := canonicalRulepackSignBytes(rp)
		sig := ed25519.Sign(priv, msg)
		rp.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
		_ = reg.Register(rp)
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

// Verify cryptographically verifies the publisher Ed25519 signature on a SignedVirtualPatchRulepack.
func (r *RulepackRegistry) Verify(rp SignedVirtualPatchRulepack) error {
	sigBytes, err := crypto.DecodeBase64Any(rp.SignatureB64)
	if err != nil {
		return fmt.Errorf("decode rulepack signature: %w", err)
	}
	if !ed25519.Verify(r.pubKey, canonicalRulepackSignBytes(rp), sigBytes) {
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
	if r == nil {
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
