package warrantsdk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/google/uuid"
)

// SignerKeyBundle holds a portable Ed25519 keypair and principal identity metadata
// for CLI and air-gapped 2-of-2 DSSE signing ceremonies.
type SignerKeyBundle struct {
	PrincipalID    string `json:"principal_id"`
	Email          string `json:"email"`
	DisplayName    string `json:"display_name"`
	Role           string `json:"role"`
	KeyID          string `json:"key_id"`
	Alg            string `json:"alg"`
	PublicKeyB64   string `json:"public_key_b64"`
	PrivateKeyB64  string `json:"private_key_b64"`
	KeyFingerprint string `json:"key_fingerprint"`
	CreatedAt      string `json:"created_at"`
}

// GenerateEd25519SignerBundle generates a fresh Ed25519 signing identity for Slot 1 (SERVICE_OWNER)
// or Slot 2 (AUTHORIZING_OFFICIAL).
func GenerateEd25519SignerBundle(principalID, email, displayName, role string) (*SignerKeyBundle, error) {
	if role != RoleServiceOwner && role != RoleAuthorizingOfficial {
		return nil, fmt.Errorf("invalid AC-5 signing role %q: must be SERVICE_OWNER or AUTHORIZING_OFFICIAL", role)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	fp := crypto.SHA256Hex(pub)
	short := fp[:10]
	return &SignerKeyBundle{
		PrincipalID:    principalID,
		Email:          email,
		DisplayName:    displayName,
		Role:           role,
		KeyID:          fmt.Sprintf("ed25519-%s-%s", principalID, short),
		Alg:            crypto.AlgEd25519,
		PublicKeyB64:   base64.StdEncoding.EncodeToString(pub),
		PrivateKeyB64:  base64.StdEncoding.EncodeToString(priv),
		KeyFingerprint: fp,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// LoadSignerBundleFile loads a SignerKeyBundle JSON file from disk.
// Production SDKs and CLIs strictly prohibit hardcoded/built-in demo signers.
func LoadSignerBundleFile(rawJSON []byte) (*SignerKeyBundle, error) {
	var b SignerKeyBundle
	if err := json.Unmarshal(rawJSON, &b); err != nil {
		return nil, fmt.Errorf("decode SignerKeyBundle JSON: %w", err)
	}
	if b.PrincipalID == "" || b.PrivateKeyB64 == "" || b.PublicKeyB64 == "" {
		return nil, errors.New("incomplete SignerKeyBundle: principal_id, public_key_b64, and private_key_b64 are required")
	}
	return &b, nil
}

// ToPrincipalKey extracts the public verification identity from the bundle.
func (b *SignerKeyBundle) ToPrincipalKey() (PrincipalKey, error) {
	pub, err := base64.StdEncoding.DecodeString(b.PublicKeyB64)
	if err != nil {
		return PrincipalKey{}, fmt.Errorf("decode public_key_b64: %w", err)
	}
	return PrincipalKey{
		PrincipalID:    b.PrincipalID,
		Email:          b.Email,
		DisplayName:    b.DisplayName,
		Role:           b.Role,
		KeyID:          b.KeyID,
		Alg:            b.Alg,
		PublicKeyBytes: pub,
		KeyFingerprint: b.KeyFingerprint,
	}, nil
}

// SignEnvelope appends a slot-bound Ed25519 signature over DSSEv1 PAE bytes to env.
func (b *SignerKeyBundle) SignEnvelope(slot int, env *Envelope) error {
	if slot != 1 && slot != 2 {
		return fmt.Errorf("invalid AC-5 slot %d: must be 1 (SERVICE_OWNER) or 2 (AUTHORIZING_OFFICIAL)", slot)
	}
	pk, err := b.ToPrincipalKey()
	if err != nil {
		return err
	}
	privBytes, err := base64.StdEncoding.DecodeString(b.PrivateKeyB64)
	if err != nil {
		return fmt.Errorf("decode private_key_b64: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("expected %d-byte Ed25519 private key, got %d", ed25519.PrivateKeySize, len(privBytes))
	}
	return env.SignEd25519(slot, pk, ed25519.PrivateKey(privBytes))
}

// WarrantDraftOptions defines ergonomic parameters for creating an unsigned Standing Warrant envelope.
type WarrantDraftOptions struct {
	WarrantID              string
	WarrantClass           string
	ScopeServices          []string
	MaxCVSS                float64
	KEVEligible            bool
	MaxBlastRadiusReplicas int
	AllowStatefulPatches   bool
	AllowGuardedCanary     bool
	MinCanarySamples       int
	StageDwellSeconds      int
	SLABridgeMinutes       int
	MaxP99LatencyMs        float64
	TTLDays                int
}

// DraftWarrantEnvelope builds an unsigned RFC 8785 JCS canonicalized DSSEv1 Standing Warrant envelope.
func DraftWarrantEnvelope(opts WarrantDraftOptions) (*Envelope, WarrantPayload, error) {
	if opts.WarrantID == "" {
		opts.WarrantID = "wrt-" + uuid.NewString()[:8]
	}
	if opts.WarrantClass == "" {
		opts.WarrantClass = "KEV-TIER1-STATELESS"
	}
	if len(opts.ScopeServices) == 0 {
		return nil, WarrantPayload{}, errors.New("at least one scope service (or '*') is required")
	}
	if opts.MaxCVSS <= 0 {
		opts.MaxCVSS = 10.0
	}
	if opts.MaxBlastRadiusReplicas <= 0 {
		opts.MaxBlastRadiusReplicas = 8
	}
	if opts.SLABridgeMinutes <= 0 {
		opts.SLABridgeMinutes = 60
	}
	if opts.MaxP99LatencyMs <= 0 {
		opts.MaxP99LatencyMs = 120.0
	}
	if opts.TTLDays <= 0 {
		opts.TTLDays = 30
	}
	if opts.MinCanarySamples <= 0 {
		opts.MinCanarySamples = 500
	}
	if opts.StageDwellSeconds <= 0 {
		opts.StageDwellSeconds = 300
	}
	now := time.Now().UTC()
	payload := WarrantPayload{
		WarrantID:              opts.WarrantID,
		WarrantClass:           opts.WarrantClass,
		ScopeServices:          opts.ScopeServices,
		MaxCVSS:                opts.MaxCVSS,
		KEVEligible:            opts.KEVEligible,
		MaxBlastRadiusReplicas: opts.MaxBlastRadiusReplicas,
		AllowStatefulPatches:   opts.AllowStatefulPatches,
		AllowGuardedCanary:     opts.AllowGuardedCanary,
		MinCanarySamples:       opts.MinCanarySamples,
		StageDwellSeconds:      opts.StageDwellSeconds,
		SLABridgeMinutes:       opts.SLABridgeMinutes,
		MaxP99LatencyMs:        opts.MaxP99LatencyMs,
		IssuedAt:               now.Format(time.RFC3339),
		ExpiresAt:              now.Add(time.Duration(opts.TTLDays) * 24 * time.Hour).Format(time.RFC3339),
	}
	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypeWarrant, payload)
	if err != nil {
		return nil, WarrantPayload{}, err
	}
	return env, payload, nil
}

// DraftThawEnvelope creates an unsigned DSSEv1 emergency fleet-thaw envelope ready for 2-of-2 co-signing.
func DraftThawEnvelope() (*Envelope, error) {
	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypeThaw, map[string]any{
		"action":       "THAW_FLEET",
		"requested_at": time.Now().UTC().Format(time.RFC3339),
	})
	return env, err
}

// DraftExceptionResolutionEnvelope creates an unsigned DSSEv1 envelope to approve or reject a ceiling exception.
func DraftExceptionResolutionEnvelope(ex CeilingException) (*Envelope, error) {
	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypeException, map[string]any{
		"exception_id":   ex.ExceptionID,
		"remediation_id": ex.RemediationID,
		"service_id":     ex.ServiceID,
		"cve_id":         ex.CVEID,
		"evaluated_at":   time.Now().UTC().Format(time.RFC3339),
	})
	return env, err
}

// OfflineVerificationResult summarizes standalone air-gapped verification of a signed OSCAL POA&M bundle.
type OfflineVerificationResult struct {
	Valid             bool   `json:"valid"`
	AttestationID     string `json:"attestation_id"`
	CVEID             string `json:"cve_id"`
	ServiceID         string `json:"service_id"`
	WarrantID         string `json:"warrant_id"`
	JCSCanonicalMatch bool   `json:"jcs_canonical_match"`
	PayloadSHA256     string `json:"payload_sha256"`
	PAESHA256         string `json:"pae_sha256"`
	SignerKeyID       string `json:"signer_key_id"`
	EntryHash         string `json:"entry_hash"`
}

// VerifyOSCALBundleOffline cryptographically verifies an exported NIST OSCAL 1.1.2 POA&M bundle
// against the G1-Warrant Kernel Ed25519 public key with zero network calls.
func VerifyOSCALBundleOffline(bundleJSON []byte, kernelPublicKeyB64 string) (*OfflineVerificationResult, error) {
	var bundle struct {
		AttestationID string   `json:"attestation_id"`
		CVEID         string   `json:"cve_id"`
		ServiceID     string   `json:"service_id"`
		WarrantID     string   `json:"warrant_id"`
		DSSEEnvelope  Envelope `json:"dsse_envelope"`
		EntryHash     string   `json:"entry_hash"`
	}
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return nil, fmt.Errorf("decode OSCAL bundle JSON: %w", err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(kernelPublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode kernel public key base64: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: got %d, want %d", len(pubBytes), ed25519.PublicKeySize)
	}

	rawPayload, err := bundle.DSSEEnvelope.DecodePayload()
	if err != nil {
		return nil, fmt.Errorf("decode DSSE payload: %w", err)
	}
	recanon, err := crypto.CanonicalizeJSON(rawPayload)
	if err != nil {
		return nil, fmt.Errorf("JCS canonicalize payload: %w", err)
	}
	jcsMatch := string(rawPayload) == string(recanon)
	if !jcsMatch {
		return nil, errors.New("RFC 8785 JCS canonicalization mismatch: payload bytes were modified")
	}
	if len(bundle.DSSEEnvelope.Signatures) == 0 {
		return nil, errors.New("DSSE envelope contains zero signatures")
	}

	pae := crypto.PAE(bundle.DSSEEnvelope.PayloadType, rawPayload)
	sigEntry := bundle.DSSEEnvelope.Signatures[0]
	sigBytes, err := crypto.DecodeBase64Any(sigEntry.Sig)
	if err != nil {
		return nil, fmt.Errorf("decode DSSE signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), pae, sigBytes) {
		return nil, errors.New("Ed25519 signature verification FAILED over DSSEv1 PAE")
	}

	return &OfflineVerificationResult{
		Valid:             true,
		AttestationID:     bundle.AttestationID,
		CVEID:             bundle.CVEID,
		ServiceID:         bundle.ServiceID,
		WarrantID:         bundle.WarrantID,
		JCSCanonicalMatch: true,
		PayloadSHA256:     crypto.SHA256Hex(rawPayload),
		PAESHA256:         crypto.SHA256Hex(pae),
		SignerKeyID:       sigEntry.KeyID,
		EntryHash:         bundle.EntryHash,
	}, nil
}
