package crypto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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
	return env.SignEd25519(slot, m.pub, m.priv)
}

// RemoteKMSSigner delegates DSSEv1 PAE signing over HTTPS to an external KMS / HSM signing service
// (e.g., Vault Transit, AWS KMS / GCP KMS proxy, or PKCS#11 daemon) so private keys remain non-exportable.
type RemoteKMSSigner struct {
	signURL     string
	bearerToken string
	pub         PrincipalKey
	httpClient  *http.Client
}

// NewRemoteKMSSigner constructs a RemoteKMSSigner backed by an external non-exportable KMS/HSM key.
func NewRemoteKMSSigner(signURL, bearerToken, keyID, publicKeyB64 string) (*RemoteKMSSigner, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err != nil {
		return nil, fmt.Errorf("decode KMS public key base64: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected 32-byte Ed25519 KMS public key, got %d", len(pubBytes))
	}
	fp := SHA256Hex(pubBytes)
	if strings.TrimSpace(keyID) == "" {
		keyID = "kms-ed25519-" + fp[:12]
	}
	return &RemoteKMSSigner{
		signURL:     strings.TrimRight(strings.TrimSpace(signURL), "/"),
		bearerToken: strings.TrimSpace(bearerToken),
		pub: PrincipalKey{
			PrincipalID:    "sys-warrantd-kms-seal",
			Email:          "kms-seal@g1163rt.sec",
			DisplayName:    "G1-Warrant Non-Exportable KMS/HSM Seal",
			Role:           RoleAttestationKernel,
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

func (r *RemoteKMSSigner) SignEnvelope(ctx context.Context, slot int, env *Envelope) error {
	rawPayload, err := env.DecodePayload()
	if err != nil {
		return err
	}
	pae := PAE(env.PayloadType, rawPayload)
	reqBody, _ := json.Marshal(map[string]string{
		"key_id":  r.pub.KeyID,
		"alg":     AlgEd25519,
		"pae_b64": base64.StdEncoding.EncodeToString(pae),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.signURL, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearerToken)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("remote KMS sign request failed: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("remote KMS signer returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	var sigResp struct {
		SignatureB64 string `json:"signature_b64"`
	}
	if err := json.Unmarshal(respBytes, &sigResp); err != nil {
		return fmt.Errorf("decode KMS signature response: %w", err)
	}
	sigRaw, err := DecodeBase64Any(sigResp.SignatureB64)
	if err != nil {
		return fmt.Errorf("invalid base64 signature from KMS: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(r.pub.PublicKeyBytes), pae, sigRaw) {
		return fmt.Errorf("remote KMS returned invalid signature for key %s", r.pub.KeyID)
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
