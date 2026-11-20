package crypto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// EnvelopeSigner abstracts cryptographic signing for the G1-Warrant Attestation Kernel
// so production deployments can delegate signing to non-exportable Cloud KMS / PKCS#11 HSM
// endpoints without loading raw private key bytes into warrantd process memory.
type EnvelopeSigner interface {
	PublicKey() PrincipalKey
	BackendMode() string
	SignEnvelope(ctx context.Context, slot int, env *Envelope) error
}

// AuthoritySigner extends EnvelopeSigner with raw canonical byte signing (e.g. for artifact provenance
// and rulepack authority signing tools via KMS, operator hex seed, 0600 key file, or sandbox ephemeral keys).
type AuthoritySigner interface {
	EnvelopeSigner
	SignBytes(ctx context.Context, msg []byte) ([]byte, error)
}

// IsLiveOrKubernetesPosture returns true when warrantd is configured for live or Kubernetes execution
// (WARRANT_CLUSTER_DRIVER=kubernetes or WARRANT_POSTURE=live).
func IsLiveOrKubernetesPosture(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	if strings.EqualFold(strings.TrimSpace(getenv("WARRANT_CLUSTER_DRIVER")), "kubernetes") {
		return true
	}
	posture := strings.ToLower(strings.TrimSpace(getenv("WARRANT_POSTURE")))
	if posture == "live" || posture == "production" || posture == "prod" {
		return true
	}
	return false
}

// MemoryEd25519Signer implements EnvelopeSigner using an in-memory Ed25519 key
// (generated ephemerally at boot or derived in explicitly flagged local dev environments).
type MemoryEd25519Signer struct {
	pub  PrincipalKey
	priv ed25519.PrivateKey
	mode string
}

// NewEphemeralEd25519Signer generates a fresh random Ed25519 kernel keypair in memory.
func NewEphemeralEd25519Signer() (*MemoryEd25519Signer, error) {
	pubBytes, privBytes, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	fp := SHA256Hex(pubBytes)
	pk := PrincipalKey{
		PrincipalID:    "sys-warrantd-kernel",
		Email:          "kernel-seal@g1163rt.sec",
		DisplayName:    "G1-Warrant Ephemeral Kernel Seal",
		Role:           RoleAttestationKernel,
		KeyID:          "kernel-ed25519-" + fp[:12],
		Alg:            AlgEd25519,
		PublicKeyBytes: pubBytes,
		KeyFingerprint: fp,
	}
	return &MemoryEd25519Signer{pub: pk, priv: privBytes, mode: "EPHEMERAL_MEMORY_ED25519"}, nil
}

// NewSeededDevEd25519Signer creates a deterministic Ed25519 signer strictly for local CI/sandbox reproducibility.
func NewSeededDevEd25519Signer(seed string) *MemoryEd25519Signer {
	pk, priv := KernelKeypair(seed)
	return &MemoryEd25519Signer{pub: pk, priv: priv, mode: "DEV_SEEDED_MEMORY_ED25519"}
}

// LoadOrCreateFileEd25519Signer loads an existing 0600 local kernel Ed25519 keypair from path
// or generates and atomically persists a new one on first boot so non-KMS Docker restarts retain seq_no=1.
// Enforces 0600 file permissions on POSIX filesystems while remaining NTFS-safe on Windows.
func LoadOrCreateFileEd25519Signer(path string) (*MemoryEd25519Signer, error) {
	type persistedKernelKey struct {
		KeyID         string `json:"key_id"`
		PublicKeyB64  string `json:"public_key_b64"`
		PrivateKeyB64 string `json:"private_key_b64"`
	}
	if raw, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(raw)) > 0 {
		if runtime.GOOS != "windows" {
			_ = os.Chmod(path, 0o600)
			if st, stErr := os.Stat(path); stErr == nil && st.Mode().Perm() != 0o600 {
				return nil, fmt.Errorf("kernel key file %s permissions %04o != 0600", path, st.Mode().Perm())
			}
		}
		var saved persistedKernelKey
		if err := json.Unmarshal(raw, &saved); err != nil {
			return nil, fmt.Errorf("parse kernel key file %s: %w", path, err)
		}
		privBytes, err := DecodeBase64Any(saved.PrivateKeyB64)
		if err != nil || len(privBytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 private key in %s", path)
		}
		pubBytes := ed25519.PrivateKey(privBytes).Public().(ed25519.PublicKey)
		fp := SHA256Hex(pubBytes)
		keyID := strings.TrimSpace(saved.KeyID)
		if keyID == "" {
			keyID = "kernel-ed25519-" + fp[:12]
		}
		return &MemoryEd25519Signer{
			pub: PrincipalKey{
				PrincipalID:    "sys-warrantd-kernel",
				Email:          "kernel-seal@g1163rt.sec",
				DisplayName:    "G1-Warrant Sealed Local Kernel Key",
				Role:           RoleAttestationKernel,
				KeyID:          keyID,
				Alg:            AlgEd25519,
				PublicKeyBytes: pubBytes,
				KeyFingerprint: fp,
			},
			priv: ed25519.PrivateKey(privBytes),
			mode: "PERSISTED_LOCAL_ED25519",
		}, nil
	}

	m, err := NewEphemeralEd25519Signer()
	if err != nil {
		return nil, err
	}
	m.mode = "PERSISTED_LOCAL_ED25519"
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
		return nil, fmt.Errorf("mkdir kernel key dir: %w", mkErr)
	}
	b, err := json.MarshalIndent(persistedKernelKey{
		KeyID:         m.pub.KeyID,
		PublicKeyB64:  base64.StdEncoding.EncodeToString(m.pub.PublicKeyBytes),
		PrivateKeyB64: base64.StdEncoding.EncodeToString(m.priv),
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, b, 0o600); err != nil {
		return nil, fmt.Errorf("write kernel key file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// NTFS fallback if target is held open or cross-handle locked on Windows
		if wErr := os.WriteFile(path, b, 0o600); wErr != nil {
			_ = os.Remove(tmpPath)
			return nil, fmt.Errorf("commit kernel key file: %w", err)
		}
		_ = os.Remove(tmpPath)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o600)
		if st, stErr := os.Stat(path); stErr != nil || st.Mode().Perm() != 0o600 {
			return nil, fmt.Errorf("verify 0600 permissions on kernel key file %s failed", path)
		}
	}
	return m, nil
}

func (m *MemoryEd25519Signer) PublicKey() PrincipalKey {
	return m.pub
}

func (m *MemoryEd25519Signer) BackendMode() string {
	return m.mode
}

func (m *MemoryEd25519Signer) SignEnvelope(_ context.Context, slot int, env *Envelope) error {
	if IsForbiddenLegacyPublicSeedKey(m.pub.PublicKeyBytes) {
		return fmt.Errorf("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: signer %s uses revoked public-string seed", m.pub.KeyID)
	}
	return env.SignEd25519(slot, m.pub, m.priv)
}

func (m *MemoryEd25519Signer) SignBytes(_ context.Context, msg []byte) ([]byte, error) {
	if IsForbiddenLegacyPublicSeedKey(m.pub.PublicKeyBytes) {
		return nil, fmt.Errorf("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: signer %s uses revoked public-string seed", m.pub.KeyID)
	}
	return ed25519.Sign(m.priv, msg), nil
}

// RemoteKMSSigner delegates DSSEv1 PAE or canonical byte signing over HTTPS to an external KMS / HSM signing service
// (e.g., Vault Transit, AWS KMS / GCP KMS proxy, or PKCS#11 daemon) so private keys remain non-exportable.
type RemoteKMSSigner struct {
	signURL     string
	bearerToken string
	pub         PrincipalKey
	httpClient  *http.Client
}

// NewRemoteKMSSigner constructs a RemoteKMSSigner backed by an external non-exportable KMS/HSM key.
func NewRemoteKMSSigner(signURL, bearerToken, keyID, publicKeyB64 string) (*RemoteKMSSigner, error) {
	return NewRemoteKMSSignerWithIdentity(
		signURL,
		bearerToken,
		keyID,
		publicKeyB64,
		"sys-warrantd-kms-seal",
		"kms-seal@g1163rt.sec",
		"G1-Warrant Non-Exportable KMS/HSM Seal",
		RoleAttestationKernel,
	)
}

// NewRemoteKMSSignerWithIdentity constructs a RemoteKMSSigner for any authority role (Kernel, Publisher, Rulepack).
func NewRemoteKMSSignerWithIdentity(signURL, bearerToken, keyID, publicKeyB64, principalID, email, displayName, role string) (*RemoteKMSSigner, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return nil, fmt.Errorf("decode KMS public key base64: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected 32-byte Ed25519 KMS public key, got %d", len(pubBytes))
	}
	if IsForbiddenLegacyPublicSeedKey(pubBytes) {
		return nil, fmt.Errorf("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: KMS public key matches revoked public-string seed")
	}
	fp := SHA256Hex(pubBytes)
	if strings.TrimSpace(keyID) == "" {
		keyID = "kms-ed25519-" + fp[:12]
	}
	return &RemoteKMSSigner{
		signURL:     strings.TrimRight(strings.TrimSpace(signURL), "/"),
		bearerToken: strings.TrimSpace(bearerToken),
		pub: PrincipalKey{
			PrincipalID:    principalID,
			Email:          email,
			DisplayName:    displayName,
			Role:           role,
			KeyID:          keyID,
			Alg:            AlgEd25519,
			PublicKeyBytes: pubBytes,
			KeyFingerprint: fp,
		},
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (r *RemoteKMSSigner) PublicKey() PrincipalKey {
	return r.pub
}

func (r *RemoteKMSSigner) BackendMode() string {
	return "NON_EXPORTABLE_EXTERNAL_KMS_HSM"
}

func (r *RemoteKMSSigner) SignBytes(ctx context.Context, msg []byte) ([]byte, error) {
	if IsForbiddenLegacyPublicSeedKey(r.pub.PublicKeyBytes) {
		return nil, fmt.Errorf("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: KMS key %s matches revoked public-string seed", r.pub.KeyID)
	}
	reqBody, _ := json.Marshal(map[string]string{
		"key_id":  r.pub.KeyID,
		"alg":     AlgEd25519,
		"pae_b64": base64.StdEncoding.EncodeToString(msg),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.signURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearerToken)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("remote KMS sign request failed: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("remote KMS signer returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	var sigResp struct {
		SignatureB64 string `json:"signature_b64"`
	}
	if err := json.Unmarshal(respBytes, &sigResp); err != nil {
		return nil, fmt.Errorf("decode KMS signature response: %w", err)
	}
	sigRaw, err := DecodeBase64Any(sigResp.SignatureB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 signature from KMS: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(r.pub.PublicKeyBytes), msg, sigRaw) {
		return nil, fmt.Errorf("remote KMS returned invalid signature for key %s", r.pub.KeyID)
	}
	return sigRaw, nil
}

func (r *RemoteKMSSigner) SignEnvelope(ctx context.Context, slot int, env *Envelope) error {
	rawPayload, err := env.DecodePayload()
	if err != nil {
		return err
	}
	pae := PAE(env.PayloadType, rawPayload)
	sigRaw, err := r.SignBytes(ctx, pae)
	if err != nil {
		return err
	}
	env.Signatures = append(env.Signatures, Signature{
		Slot:           slot,
		KeyID:          r.pub.KeyID,
		Alg:            AlgEd25519,
		Role:           r.pub.Role,
		PrincipalID:    r.pub.PrincipalID,
		PrincipalEmail: r.pub.Email,
		KeyFingerprint: r.pub.KeyFingerprint,
		Sig:            base64.StdEncoding.EncodeToString(sigRaw),
		SignedAt:       time.Now().UTC().Format(time.RFC3339),
	})
	return nil
}

// AuthorityCustodyConfig defines environment variable names and identity metadata for an authority custody ladder:
// Remote KMS Signer -> Operator hex seed -> Public-key verification-only -> 0600 key file -> Ephemeral (sandbox/demo only).
type AuthorityCustodyConfig struct {
	PrincipalID       string
	Email             string
	DisplayName       string
	Role              string
	KeyIDPrefix       string
	KMSSignURLEnv     string
	KMSBearerEnv      string
	KMSKeyIDEnv       string
	KMSPublicKeyEnv   string
	SeedHexEnv        string
	KeyPathEnv        string
	PublicKeyB64Env   string
	FallbackPubKeyEnv string
}

// NewEd25519SignerFromSeedHex constructs an in-memory Ed25519 AuthoritySigner from a 32-byte (64-hex-char) operator seed,
// rejecting legacy public-string-derived seeds fail-closed.
func NewEd25519SignerFromSeedHex(seedHex, principalID, email, displayName, role, keyIDPrefix string) (*MemoryEd25519Signer, error) {
	clean := strings.TrimSpace(seedHex)
	if IsForbiddenLegacySeedHex(clean) {
		return nil, fmt.Errorf("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: seed matches revoked public-string seed")
	}
	seedBytes, err := hex.DecodeString(clean)
	if err != nil || len(seedBytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid Ed25519 seed hex (expected 64 hex chars / 32 bytes)")
	}
	priv := ed25519.NewKeyFromSeed(seedBytes)
	pub := priv.Public().(ed25519.PublicKey)
	if IsForbiddenLegacyPublicSeedKey(pub) {
		return nil, fmt.Errorf("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: derived public key matches revoked public-string seed")
	}
	fp := SHA256Hex(pub)
	return &MemoryEd25519Signer{
		pub: PrincipalKey{
			PrincipalID:    principalID,
			Email:          email,
			DisplayName:    displayName,
			Role:           role,
			KeyID:          keyIDPrefix + "-" + fp[:12],
			Alg:            AlgEd25519,
			PublicKeyBytes: append([]byte{}, pub...),
			KeyFingerprint: fp,
		},
		priv: priv,
		mode: "OPERATOR_SEED_HEX_ED25519",
	}, nil
}

// NewEphemeralAuthoritySigner generates a fresh cryptographically random Ed25519 signer strictly for sandbox/demo mode.
func NewEphemeralAuthoritySigner(principalID, email, displayName, role, keyIDPrefix string) (*MemoryEd25519Signer, error) {
	pubBytes, privBytes, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	fp := SHA256Hex(pubBytes)
	return &MemoryEd25519Signer{
		pub: PrincipalKey{
			PrincipalID:    principalID,
			Email:          email,
			DisplayName:    displayName,
			Role:           role,
			KeyID:          keyIDPrefix + "-" + fp[:12],
			Alg:            AlgEd25519,
			PublicKeyBytes: pubBytes,
			KeyFingerprint: fp,
		},
		priv: privBytes,
		mode: "EPHEMERAL_SANDBOX_ED25519",
	}, nil
}

// ParseAuthoritativeEd25519PublicKey decodes a base64 Ed25519 public key and rejects legacy public-string-derived keys.
func ParseAuthoritativeEd25519PublicKey(pubB64, principalID, email, displayName, role, keyIDPrefix string) (PrincipalKey, error) {
	pubBytes, err := DecodeBase64Any(strings.TrimSpace(pubB64))
	if err != nil {
		return PrincipalKey{}, fmt.Errorf("decode authoritative public key base64: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return PrincipalKey{}, fmt.Errorf("expected 32-byte Ed25519 public key, got %d bytes", len(pubBytes))
	}
	if IsForbiddenLegacyPublicSeedKey(pubBytes) {
		return PrincipalKey{}, fmt.Errorf("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: configured public key matches revoked public-string seed")
	}
	fp := SHA256Hex(pubBytes)
	return PrincipalKey{
		PrincipalID:    principalID,
		Email:          email,
		DisplayName:    displayName,
		Role:           role,
		KeyID:          keyIDPrefix + "-" + fp[:12],
		Alg:            AlgEd25519,
		PublicKeyBytes: pubBytes,
		KeyFingerprint: fp,
	}, nil
}

// ResolveAuthorityCustody resolves an authority's signing and verification custody following the strict ladder:
// 1. Remote KMS Signer -> 2. Operator hex seed -> 3. Verification-only public key -> 4. 0600 local key file -> 5. Ephemeral (sandbox/demo ONLY).
// In live/Kubernetes posture, refuses ephemeral fallback and fails closed if no authoritative key is configured.
func ResolveAuthorityCustody(cfg AuthorityCustodyConfig, getenv func(string) string) (AuthoritySigner, PrincipalKey, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	isLive := IsLiveOrKubernetesPosture(getenv)

	// 1. Remote KMS Signer
	if cfg.KMSSignURLEnv != "" {
		if kmsURL := strings.TrimSpace(getenv(cfg.KMSSignURLEnv)); kmsURL != "" {
			pubEnv := strings.TrimSpace(getenv(cfg.KMSPublicKeyEnv))
			if pubEnv == "" && cfg.PublicKeyB64Env != "" {
				pubEnv = strings.TrimSpace(getenv(cfg.PublicKeyB64Env))
			}
			kmsSigner, err := NewRemoteKMSSignerWithIdentity(
				kmsURL,
				getenv(cfg.KMSBearerEnv),
				getenv(cfg.KMSKeyIDEnv),
				pubEnv,
				cfg.PrincipalID,
				cfg.Email,
				cfg.DisplayName,
				cfg.Role,
			)
			if err != nil {
				return nil, PrincipalKey{}, fmt.Errorf("configure %s KMS signer: %w", cfg.Role, err)
			}
			return kmsSigner, kmsSigner.PublicKey(), nil
		}
	}

	// 2. Operator seed from environment (WARRANT_PUBLISHER_SEED_HEX / WARRANT_RULEPACK_SEED_HEX)
	if cfg.SeedHexEnv != "" {
		if seedHex := strings.TrimSpace(getenv(cfg.SeedHexEnv)); seedHex != "" {
			s, err := NewEd25519SignerFromSeedHex(seedHex, cfg.PrincipalID, cfg.Email, cfg.DisplayName, cfg.Role, cfg.KeyIDPrefix)
			if err != nil {
				return nil, PrincipalKey{}, fmt.Errorf("%s (%s): %w", cfg.Role, cfg.SeedHexEnv, err)
			}
			return s, s.PublicKey(), nil
		}
	}

	// 3. Explicit verification-only public key (e.g., WARRANT_PUBLISHER_PUBLIC_KEY_B64 / WARRANT_RULEPACK_PUBLIC_KEY_B64)
	for _, pkEnv := range []string{cfg.PublicKeyB64Env, cfg.FallbackPubKeyEnv} {
		if pkEnv != "" {
			if rawPub := strings.TrimSpace(getenv(pkEnv)); rawPub != "" {
				pk, err := ParseAuthoritativeEd25519PublicKey(rawPub, cfg.PrincipalID, cfg.Email, cfg.DisplayName, cfg.Role, cfg.KeyIDPrefix)
				if err != nil {
					return nil, PrincipalKey{}, fmt.Errorf("%s (%s): %w", cfg.Role, pkEnv, err)
				}
				return nil, pk, nil
			}
		}
	}

	// 4. 0600 Local Key File
	if cfg.KeyPathEnv != "" {
		if keyPath := strings.TrimSpace(getenv(cfg.KeyPathEnv)); keyPath != "" {
			fsSigner, err := LoadOrCreateFileEd25519Signer(keyPath)
			if err != nil {
				return nil, PrincipalKey{}, fmt.Errorf("%s (%s): %w", cfg.Role, cfg.KeyPathEnv, err)
			}
			if IsForbiddenLegacyPublicSeedKey(fsSigner.pub.PublicKeyBytes) {
				return nil, PrincipalKey{}, fmt.Errorf("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: %s key file contains revoked public-string key", cfg.KeyPathEnv)
			}
			fsSigner.pub.PrincipalID = cfg.PrincipalID
			fsSigner.pub.Email = cfg.Email
			fsSigner.pub.DisplayName = cfg.DisplayName
			fsSigner.pub.Role = cfg.Role
			if strings.HasPrefix(fsSigner.pub.KeyID, "kernel-ed25519-") {
				fsSigner.pub.KeyID = cfg.KeyIDPrefix + "-" + fsSigner.pub.KeyFingerprint[:12]
			}
			return fsSigner, fsSigner.PublicKey(), nil
		}
	}

	// 5. Ephemeral (sandbox/demo ONLY — fail closed in live/Kubernetes posture!)
	if isLive {
		return nil, PrincipalKey{}, fmt.Errorf(
			"FATAL_SECURITY_GUARD: missing authoritative %s public key in live/Kubernetes posture; configure %s, %s, %s, or %s",
			cfg.Role, cfg.PublicKeyB64Env, cfg.KMSSignURLEnv, cfg.SeedHexEnv, cfg.KeyPathEnv,
		)
	}

	eph, err := NewEphemeralAuthoritySigner(cfg.PrincipalID, cfg.Email, cfg.DisplayName, cfg.Role, cfg.KeyIDPrefix)
	if err != nil {
		return nil, PrincipalKey{}, err
	}
	return eph, eph.PublicKey(), nil
}

// DefaultPublisherCustodyConfig returns the canonical custody ladder config for OCI/patch artifact provenance.
func DefaultPublisherCustodyConfig() AuthorityCustodyConfig {
	return AuthorityCustodyConfig{
		PrincipalID:     "pub-g1163rt-ci",
		Email:           "provenance@g1163rt.sec",
		DisplayName:     "G1-Warrant Trusted Build Provenance Authority",
		Role:            RoleArtifactPublisher,
		KeyIDPrefix:     "pub-provenance-ed25519",
		KMSSignURLEnv:   "WARRANT_PUBLISHER_KMS_SIGN_URL",
		KMSBearerEnv:    "WARRANT_PUBLISHER_KMS_BEARER_TOKEN",
		KMSKeyIDEnv:     "WARRANT_PUBLISHER_KMS_KEY_ID",
		KMSPublicKeyEnv: "WARRANT_PUBLISHER_KMS_PUBLIC_KEY_B64",
		SeedHexEnv:      "WARRANT_PUBLISHER_SEED_HEX",
		KeyPathEnv:      "WARRANT_PUBLISHER_KEY_PATH",
		PublicKeyB64Env: "WARRANT_PUBLISHER_PUBLIC_KEY_B64",
	}
}

// DefaultRulepackCustodyConfig returns the canonical custody ladder config for L7 virtual-patch rulepack verification.
func DefaultRulepackCustodyConfig() AuthorityCustodyConfig {
	return AuthorityCustodyConfig{
		PrincipalID:       "pub-g1163rt-rulepacks",
		Email:             "rulepacks@g1163rt.sec",
		DisplayName:       "G1-Warrant Signed Rulepack Authority",
		Role:              RoleRulepackAuthority,
		KeyIDPrefix:       "rulepack-authority-ed25519",
		KMSSignURLEnv:     "WARRANT_RULEPACK_KMS_SIGN_URL",
		KMSBearerEnv:      "WARRANT_RULEPACK_KMS_BEARER_TOKEN",
		KMSKeyIDEnv:       "WARRANT_RULEPACK_KMS_KEY_ID",
		KMSPublicKeyEnv:   "WARRANT_RULEPACK_KMS_PUBLIC_KEY_B64",
		SeedHexEnv:        "WARRANT_RULEPACK_SEED_HEX",
		KeyPathEnv:        "WARRANT_RULEPACK_KEY_PATH",
		PublicKeyB64Env:   "WARRANT_RULEPACK_PUBLIC_KEY_B64",
		FallbackPubKeyEnv: "WARRANT_PUBLISHER_PUBLIC_KEY_B64",
	}
}
