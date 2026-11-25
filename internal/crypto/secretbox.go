package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	// SecretCipherPrefix tags AES-256-GCM ciphertext stored in PostgreSQL text columns.
	SecretCipherPrefix = "enc:v1:"
	secretKeyBytes     = 32
)

var (
	// ErrSecretKeyMissing is returned when encrypted data exists but no decryption key is loaded.
	ErrSecretKeyMissing = errors.New("db secret encryption key is not configured")
	// ErrSecretAuthFailed is returned when AES-256-GCM authentication fails (wrong key, tampered data, or cross-column AAD mismatch).
	ErrSecretAuthFailed = errors.New("aes-256-gcm authentication failed (invalid key or column AAD mismatch)")
)

// SecretBox provides deterministic, per-column AAD-bound AES-256-GCM encryption for database secrets.
// Every ciphertext is authenticated against "<table>.<column>" AAD so a ciphertext cannot be
// transplanted from one table or column into another.
type SecretBox struct {
	aead cipher.AEAD
}

// NewSecretBox constructs a SecretBox from a 32-byte AES-256 key.
func NewSecretBox(key []byte) (*SecretBox, error) {
	if len(key) != secretKeyBytes {
		return nil, fmt.Errorf("secret box key must be exactly %d bytes, got %d", secretKeyBytes, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return &SecretBox{aead: aead}, nil
}

// NewEphemeralSecretBox generates a random 32-byte AES-256-GCM SecretBox for sandbox/test use.
func NewEphemeralSecretBox() (*SecretBox, error) {
	key := make([]byte, secretKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate ephemeral secret key: %w", err)
	}
	return NewSecretBox(key)
}

// ParseSecretKey decodes a 32-byte key from hex (64 hex chars) or base64 (standard, raw, or URL).
func ParseSecretKey(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, ErrSecretKeyMissing
	}
	if len(s) == secretKeyBytes*2 {
		if b, err := hex.DecodeString(s); err == nil && len(b) == secretKeyBytes {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == secretKeyBytes {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid 32-byte secret key encoding (expected 64-char hex or 32-byte base64)")
}

// LoadSecretBoxFromEnv loads a SecretBox from WARRANT_DB_SECRET_KEY or WARRANT_DB_SECRET_KEY_FILE.
// Returns (nil, nil) if neither environment variable is set.
func LoadSecretBoxFromEnv(getenv func(string) string) (*SecretBox, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if raw := strings.TrimSpace(getenv("WARRANT_DB_SECRET_KEY")); raw != "" {
		key, err := ParseSecretKey(raw)
		if err != nil {
			return nil, fmt.Errorf("WARRANT_DB_SECRET_KEY: %w", err)
		}
		return NewSecretBox(key)
	}
	if path := strings.TrimSpace(getenv("WARRANT_DB_SECRET_KEY_FILE")); path != "" {
		rawBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read WARRANT_DB_SECRET_KEY_FILE %q: %w", path, err)
		}
		key, err := ParseSecretKey(string(rawBytes))
		if err != nil {
			return nil, fmt.Errorf("WARRANT_DB_SECRET_KEY_FILE %q: %w", path, err)
		}
		return NewSecretBox(key)
	}
	return nil, nil
}

// IsEncryptedValue reports whether s carries the SecretCipherPrefix.
func IsEncryptedValue(s string) bool {
	return strings.HasPrefix(s, SecretCipherPrefix)
}

func columnAAD(table, column string) ([]byte, error) {
	t := strings.ToLower(strings.TrimSpace(table))
	c := strings.ToLower(strings.TrimSpace(column))
	if t == "" || c == "" {
		return nil, fmt.Errorf("secret box AAD requires non-empty table and column names")
	}
	return []byte(t + "." + c), nil
}

// SealColumn encrypts plaintext with AES-256-GCM using a fresh random nonce and
// "<table>.<column>" as Additional Authenticated Data (AAD).
func (b *SecretBox) SealColumn(table, column, plaintext string) (string, error) {
	if b == nil || b.aead == nil {
		return "", ErrSecretKeyMissing
	}
	aad, err := columnAAD(table, column)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate gcm nonce: %w", err)
	}
	ct := b.aead.Seal(nonce, nonce, []byte(plaintext), aad)
	return SecretCipherPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// OpenColumn decrypts a value produced by SealColumn, verifying the "<table>.<column>" AAD.
// If stored does not have SecretCipherPrefix, it is returned unchanged.
func (b *SecretBox) OpenColumn(table, column, stored string) (string, error) {
	if !IsEncryptedValue(stored) {
		return stored, nil
	}
	if b == nil || b.aead == nil {
		return "", ErrSecretKeyMissing
	}
	aad, err := columnAAD(table, column)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, SecretCipherPrefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted secret: %w", err)
	}
	nonceSize := b.aead.NonceSize()
	if len(raw) < nonceSize+b.aead.Overhead() {
		return "", ErrSecretAuthFailed
	}
	nonce, ct := raw[:nonceSize], raw[nonceSize:]
	pt, err := b.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return "", ErrSecretAuthFailed
	}
	return string(pt), nil
}
