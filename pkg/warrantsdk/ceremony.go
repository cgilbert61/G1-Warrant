package warrantsdk

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
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

// ToRegisterRequest extracts strictly the public verification identity (stripping PrivateKeyB64)
// for authenticated enrollment via POST /api/v1/principals/register.
func (b *SignerKeyBundle) ToRegisterRequest() RegisterPrincipalRequest {
	return RegisterPrincipalRequest{
		PrincipalID:  b.PrincipalID,
		Email:        b.Email,
		DisplayName:  b.DisplayName,
		Role:         b.Role,
		KeyID:        b.KeyID,
		Alg:          b.Alg,
		PublicKeyB64: b.PublicKeyB64,
	}
}

// PublicIdentityBundle contains strictly the non-secret public verification identity
// written to <name>.pub.json so operators never pass a private-key path to network enrollment commands.
type PublicIdentityBundle struct {
	PrincipalID    string `json:"principal_id"`
	Email          string `json:"email"`
	DisplayName    string `json:"display_name"`
	Role           string `json:"role"`
	KeyID          string `json:"key_id"`
	Alg            string `json:"alg"`
	PublicKeyB64   string `json:"public_key_b64"`
	KeyFingerprint string `json:"key_fingerprint"`
	CreatedAt      string `json:"created_at"`
}

// ToPublicIdentity extracts a PublicIdentityBundle with zero private key material.
func (b *SignerKeyBundle) ToPublicIdentity() PublicIdentityBundle {
	return PublicIdentityBundle{
		PrincipalID:    b.PrincipalID,
		Email:          b.Email,
		DisplayName:    b.DisplayName,
		Role:           b.Role,
		KeyID:          b.KeyID,
		Alg:            b.Alg,
		PublicKeyB64:   b.PublicKeyB64,
		KeyFingerprint: b.KeyFingerprint,
		CreatedAt:      b.CreatedAt,
	}
}

// ToRegisterRequest converts a PublicIdentityBundle into a RegisterPrincipalRequest.
func (p *PublicIdentityBundle) ToRegisterRequest() RegisterPrincipalRequest {
	return RegisterPrincipalRequest{
		PrincipalID:  p.PrincipalID,
		Email:        p.Email,
		DisplayName:  p.DisplayName,
		Role:         p.Role,
		KeyID:        p.KeyID,
		Alg:          p.Alg,
		PublicKeyB64: p.PublicKeyB64,
	}
}

// ResolveSplitKeyPaths normalizes a key prefix or path into <base>.priv.json and <base>.pub.json.
func ResolveSplitKeyPaths(outPrefix string) (privPath string, pubPath string) {
	base := strings.TrimSpace(outPrefix)
	for _, suf := range []string{".priv.json", ".pub.json", ".json"} {
		if strings.HasSuffix(strings.ToLower(base), suf) {
			base = base[:len(base)-len(suf)]
			break
		}
	}
	if base == "" {
		base = "signer"
	}
	return base + ".priv.json", base + ".pub.json"
}

// WriteSplitKeyPairFiles writes <name>.priv.json (0600 permissions) and <name>.pub.json (0644, public-only).
// On POSIX platforms (runtime.GOOS != "windows"), verifies the written private key file permissions are strictly 0600.
func WriteSplitKeyPairFiles(outPrefix string, bundle *SignerKeyBundle) (string, string, error) {
	if bundle == nil {
		return "", "", errors.New("nil SignerKeyBundle")
	}
	privPath, pubPath := ResolveSplitKeyPaths(outPrefix)
	privRaw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(privPath, privRaw, 0600); err != nil {
		return "", "", fmt.Errorf("write %s: %w", privPath, err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(privPath, 0600)
		st, stErr := os.Stat(privPath)
		if stErr != nil {
			return "", "", stErr
		}
		if st.Mode().Perm() != 0600 {
			return "", "", fmt.Errorf("private key file %s permissions %04o != 0600", privPath, st.Mode().Perm())
		}
	}

	pubObj := bundle.ToPublicIdentity()
	pubRaw, err := json.MarshalIndent(pubObj, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(pubPath, pubRaw, 0644); err != nil {
		return "", "", fmt.Errorf("write %s: %w", pubPath, err)
	}
	return privPath, pubPath, nil
}

// LoadPublicIdentityFile loads a <name>.pub.json file and strictly rejects any JSON containing private_key* fields.
func LoadPublicIdentityFile(rawJSON []byte) (*PublicIdentityBundle, error) {
	var rawMap map[string]any
	if err := json.Unmarshal(rawJSON, &rawMap); err != nil {
		return nil, fmt.Errorf("decode public identity JSON: %w", err)
	}
	for k := range rawMap {
		lk := strings.ToLower(strings.TrimSpace(k))
		if strings.Contains(lk, "private_key") || strings.Contains(lk, "priv_key") || lk == "seed_hex" || strings.Contains(lk, "secret_key") {
			return nil, fmt.Errorf("PRIVATE_KEY_REJECTED_CLIENT_SIDE: file contains secret field %q; pass <name>.pub.json instead of <name>.priv.json", k)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(rawJSON))
	dec.DisallowUnknownFields()
	var pub PublicIdentityBundle
	if err := dec.Decode(&pub); err != nil {
		return nil, fmt.Errorf("decode PublicIdentityBundle: %w", err)
	}
	if pub.PrincipalID == "" || pub.Email == "" || pub.Role == "" || pub.PublicKeyB64 == "" {
		return nil, errors.New("incomplete PublicIdentityBundle: principal_id, email, role, and public_key_b64 are required")
	}
	return &pub, nil
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
	AllowSecretRotation    bool
	AutoRemediateCWEs      []string
	MinCanarySamples       int
	StageDwellSeconds      int
	SLABridgeMinutes           int
	MaxP99LatencyMs            float64
	TTLDays                    int
	ScopeAssets                []string
	AuthorizedVendorDetections []string
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
	if opts.WarrantClass == WarrantClassSecretRotation {
		opts.AllowSecretRotation = true
	}
	now := time.Now().UTC()
	payload := WarrantPayload{
		WarrantID:                  opts.WarrantID,
		WarrantClass:               opts.WarrantClass,
		ScopeServices:              opts.ScopeServices,
		ScopeAssets:                opts.ScopeAssets,
		AuthorizedVendorDetections: opts.AuthorizedVendorDetections,
		MaxCVSS:                    opts.MaxCVSS,
		KEVEligible:                opts.KEVEligible,
		MaxBlastRadiusReplicas:     opts.MaxBlastRadiusReplicas,
		AllowStatefulPatches:       opts.AllowStatefulPatches,
		AllowGuardedCanary:         opts.AllowGuardedCanary,
		AllowSecretRotation:        opts.AllowSecretRotation,
		AutoRemediateCWEs:          opts.AutoRemediateCWEs,
		MinCanarySamples:           opts.MinCanarySamples,
		StageDwellSeconds:          opts.StageDwellSeconds,
		SLABridgeMinutes:           opts.SLABridgeMinutes,
		MaxP99LatencyMs:            opts.MaxP99LatencyMs,
		IssuedAt:                   now.Format(time.RFC3339),
		ExpiresAt:                  now.Add(time.Duration(opts.TTLDays) * 24 * time.Hour).Format(time.RFC3339),
	}
	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypeWarrant, payload)
	if err != nil {
		return nil, WarrantPayload{}, err
	}
	return env, payload, nil
}

// DraftThawEnvelope creates an unsigned DSSEv1 emergency fleet-thaw envelope (for default initial freeze epoch 2).
// Prefer DraftThawEnvelopeForEpoch with the live FreezeState.FreezeEpoch from Client.Scoreboard.
func DraftThawEnvelope() (*Envelope, error) {
	return DraftThawEnvelopeForEpoch(2)
}

// DraftThawEnvelopeForEpoch creates an unsigned DSSEv1 emergency fleet-thaw envelope bound to a specific monotonic freeze_epoch
// and single-use envelope_id (preventing cross-epoch THAW replay).
func DraftThawEnvelopeForEpoch(freezeEpoch int64) (*Envelope, error) {
	now := time.Now().UTC()
	payload := ThawPayload{
		EnvelopeID:  "thaw-" + uuid.NewString(),
		Action:      "THAW",
		FreezeEpoch: freezeEpoch,
		IssuedAt:    now.Format(time.RFC3339),
		ExpiresAt:   now.Add(15 * time.Minute).Format(time.RFC3339),
	}
	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypeThaw, payload)
	return env, err
}

// DraftExceptionResolutionEnvelope creates an unsigned DSSEv1 envelope bound to ex.ExceptionID and a single-use envelope_id.
func DraftExceptionResolutionEnvelope(ex CeilingException) (*Envelope, error) {
	now := time.Now().UTC()
	payload := ExceptionResolutionPayload{
		EnvelopeID:    "exc-" + uuid.NewString(),
		ExceptionID:   ex.ExceptionID,
		RemediationID: ex.RemediationID,
		ServiceID:     ex.ServiceID,
		CVEID:         ex.CVEID,
		IssuedAt:      now.Format(time.RFC3339),
		ExpiresAt:     now.Add(15 * time.Minute).Format(time.RFC3339),
	}
	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypeException, payload)
	return env, err
}

// DraftGovernanceEnvelope constructs an unsigned RFC 8785 JCS Principal Governance DSSEv1 envelope
// with a fresh single-use envelope_id and bounded short TTL (default 5m, max 15m).
func DraftGovernanceEnvelope(action string, payload PrincipalGovernancePayload, ttl time.Duration) (*Envelope, PrincipalGovernancePayload, error) {
	if ttl <= 0 || ttl > 15*time.Minute {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	if payload.EnvelopeID == "" {
		payload.EnvelopeID = "gov-" + uuid.NewString()
	}
	payload.Action = action
	payload.IssuedAt = now.Format(time.RFC3339)
	payload.ExpiresAt = now.Add(ttl).Format(time.RFC3339)

	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypePrincipalGovernance, payload)
	if err != nil {
		return nil, PrincipalGovernancePayload{}, err
	}
	return env, payload, nil
}

// DraftPrincipalEnrollEnvelope builds an unsigned 2-of-2 DSSE Principal Governance envelope (ENROLL_PRINCIPAL)
// for enrolling a new or rotated public key after genesis bootstrap has been sealed.
func DraftPrincipalEnrollEnvelope(req RegisterPrincipalRequest, ttl time.Duration) (*Envelope, PrincipalGovernancePayload, error) {
	alg := req.Alg
	if alg == "" {
		alg = crypto.AlgEd25519
	}
	return DraftGovernanceEnvelope(GovActionEnrollPrincipal, PrincipalGovernancePayload{
		PrincipalID:  req.PrincipalID,
		Email:        req.Email,
		DisplayName:  req.DisplayName,
		Role:         req.Role,
		KeyID:        req.KeyID,
		Alg:          alg,
		PublicKeyB64: req.PublicKeyB64,
	}, ttl)
}

// DraftPrincipalRevokeEnvelope builds an unsigned 1-of-2 DSSE Principal Governance envelope (REVOKE_PRINCIPAL)
// so any single active enrolled principal can immediately revoke itself or a same-role peer while preserving survivor floor.
func DraftPrincipalRevokeEnvelope(targetPrincipalID, targetKeyFingerprint, reasonCode string, ttl time.Duration) (*Envelope, PrincipalGovernancePayload, error) {
	if reasonCode == "" {
		reasonCode = "SDK_KEY_REVOCATION"
	}
	if ttl <= 0 || ttl > 5*time.Minute {
		ttl = 5 * time.Minute
	}
	return DraftGovernanceEnvelope(GovActionRevokePrincipal, PrincipalGovernancePayload{
		HTTPMethod:           "POST",
		CanonicalPath:        "/api/v1/principals/revoke",
		TargetPrincipalID:    targetPrincipalID,
		TargetKeyFingerprint: targetKeyFingerprint,
		ReasonCode:           reasonCode,
	}, ttl)
}

// DraftPrincipalRotateAndRevokeEnvelope builds an unsigned atomic 2-of-2 DSSE Principal Governance envelope
// (ROTATE_AND_REVOKE_PRINCIPAL) enrolling replacement and revoking target in a single serialized transaction.
func DraftPrincipalRotateAndRevokeEnvelope(
	replacement RegisterPrincipalRequest,
	targetPrincipalID string,
	targetKeyFingerprint string,
	reasonCode string,
	ttl time.Duration,
) (*Envelope, PrincipalGovernancePayload, error) {
	alg := replacement.Alg
	if alg == "" {
		alg = crypto.AlgEd25519
	}
	if reasonCode == "" {
		reasonCode = "ATOMIC_DUAL_KEY_ROTATION_AND_REVOCATION"
	}
	return DraftGovernanceEnvelope(GovActionRotateAndRevokePrincipal, PrincipalGovernancePayload{
		PrincipalID:          replacement.PrincipalID,
		Email:                replacement.Email,
		DisplayName:          replacement.DisplayName,
		Role:                 replacement.Role,
		KeyID:                replacement.KeyID,
		Alg:                  alg,
		PublicKeyB64:         replacement.PublicKeyB64,
		TargetPrincipalID:    targetPrincipalID,
		TargetKeyFingerprint: targetKeyFingerprint,
		ReasonCode:           reasonCode,
	}, ttl)
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

// VerifyOSCALBundleWithKeyRing verifies an exported NIST OSCAL 1.1.2 POA&M bundle against an append-only
// ring of historical and active Kernel Ed25519 public keys (preventing restart key-rotation invalidation).
func VerifyOSCALBundleWithKeyRing(bundleJSON []byte, keyRing []KernelPublicKeyRecord) (*OfflineVerificationResult, error) {
	var header struct {
		DSSEEnvelope        Envelope                `json:"dsse_envelope"`
		KernelPublicKeyRing []KernelPublicKeyRecord `json:"kernel_public_key_ring"`
	}
	if err := json.Unmarshal(bundleJSON, &header); err != nil {
		return nil, fmt.Errorf("decode OSCAL bundle JSON: %w", err)
	}
	if len(header.DSSEEnvelope.Signatures) == 0 {
		return nil, errors.New("DSSE envelope contains zero signatures")
	}
	targetKeyID := header.DSSEEnvelope.Signatures[0].KeyID
	candidates := keyRing
	if len(candidates) == 0 {
		candidates = header.KernelPublicKeyRing
	}
	for _, rec := range candidates {
		if rec.KeyID == targetKeyID {
			return VerifyOSCALBundleOffline(bundleJSON, rec.PublicKeyB64)
		}
	}
	return nil, fmt.Errorf("kernel signing key %q not found in verification public-key ring (%d keys)", targetKeyID, len(candidates))
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
