package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretBoxRoundTripAndCrossColumnTransplantRejection(t *testing.T) {
	box, err := NewEphemeralSecretBox()
	if err != nil {
		t.Fatalf("NewEphemeralSecretBox: %v", err)
	}

	const secret = "qualys-api-token-super-secret-987654"
	sealed, err := box.SealColumn("vendor_connector_configs", "value_text", secret)
	if err != nil {
		t.Fatalf("SealColumn: %v", err)
	}
	if !IsEncryptedValue(sealed) {
		t.Fatalf("expected enc:v1: prefix, got %q", sealed)
	}
	if bytes.Contains([]byte(sealed), []byte(secret)) {
		t.Fatalf("plaintext secret leaked into ciphertext")
	}

	// Correct table.column AAD succeeds
	opened, err := box.OpenColumn("vendor_connector_configs", "value_text", sealed)
	if err != nil {
		t.Fatalf("OpenColumn valid AAD: %v", err)
	}
	if opened != secret {
		t.Fatalf("expected %q, got %q", secret, opened)
	}

	// Cross-column ciphertext transplantation MUST fail authentication
	if _, err := box.OpenColumn("vendor_connector_configs", "other_column", sealed); !errors.Is(err, ErrSecretAuthFailed) {
		t.Fatalf("expected ErrSecretAuthFailed on cross-column transplant, got %v", err)
	}

	// Cross-table ciphertext transplantation MUST fail authentication
	if _, err := box.OpenColumn("other_table", "value_text", sealed); !errors.Is(err, ErrSecretAuthFailed) {
		t.Fatalf("expected ErrSecretAuthFailed on cross-table transplant, got %v", err)
	}

	// Wrong key MUST fail authentication
	otherBox, err := NewEphemeralSecretBox()
	if err != nil {
		t.Fatalf("NewEphemeralSecretBox (other): %v", err)
	}
	if _, err := otherBox.OpenColumn("vendor_connector_configs", "value_text", sealed); !errors.Is(err, ErrSecretAuthFailed) {
		t.Fatalf("expected ErrSecretAuthFailed with wrong key, got %v", err)
	}

	// Nil box on encrypted value MUST fail closed
	var nilBox *SecretBox
	if _, err := nilBox.OpenColumn("vendor_connector_configs", "value_text", sealed); !errors.Is(err, ErrSecretKeyMissing) {
		t.Fatalf("expected ErrSecretKeyMissing on nil box, got %v", err)
	}

	// Non-encrypted plaintext passes through untouched
	if pt, err := nilBox.OpenColumn("vendor_connector_configs", "value_text", "https://api.example.com"); err != nil || pt != "https://api.example.com" {
		t.Fatalf("expected plaintext passthrough, got %q, %v", pt, err)
	}
}

func TestParseSecretKeyAndLoadFromEnv(t *testing.T) {
	rawKey := bytes.Repeat([]byte{0x42}, 32)
	hexKey := hex.EncodeToString(rawKey)
	b64Key := base64.StdEncoding.EncodeToString(rawKey)

	if k, err := ParseSecretKey(hexKey); err != nil || !bytes.Equal(k, rawKey) {
		t.Fatalf("ParseSecretKey(hex) failed: %v", err)
	}
	if k, err := ParseSecretKey(b64Key); err != nil || !bytes.Equal(k, rawKey) {
		t.Fatalf("ParseSecretKey(base64) failed: %v", err)
	}
	if _, err := ParseSecretKey("too-short"); err == nil {
		t.Fatalf("expected error for invalid short key")
	}

	// Load from env file
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "db-secret.key")
	if err := os.WriteFile(keyFile, []byte(b64Key+"\n"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	box, err := LoadSecretBoxFromEnv(func(k string) string {
		if k == "WARRANT_DB_SECRET_KEY_FILE" {
			return keyFile
		}
		return ""
	})
	if err != nil || box == nil {
		t.Fatalf("LoadSecretBoxFromEnv(file) failed: box=%v err=%v", box, err)
	}
}
