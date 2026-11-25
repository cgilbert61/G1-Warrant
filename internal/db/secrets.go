package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
)

const (
	vendorConnectorTable  = "vendor_connector_configs"
	vendorConnectorColumn = "value_text"
)

// SetSecretBox installs the AES-256-GCM per-column AAD SecretBox on the Store.
func (s *Store) SetSecretBox(box *crypto.SecretBox) {
	s.secretBox = box
}

// SecretBox returns the configured SecretBox (or nil if unset).
func (s *Store) SecretBox() *crypto.SecretBox {
	return s.secretBox
}

// IsConnectorSecretEnvKey reports whether a connector configuration key carries secret material
// that must be encrypted at rest using per-column AAD AES-256-GCM.
func IsConnectorSecretEnvKey(envKey string) bool {
	u := strings.ToUpper(strings.TrimSpace(envKey))
	if u == "" || strings.HasSuffix(u, "_FILE") || strings.HasSuffix(u, "_URL") {
		return false
	}
	for _, suf := range []string{"_TOKEN", "_SECRET", "_PASSWORD", "_API_KEY", "_PRIVATE_KEY"} {
		if strings.HasSuffix(u, suf) {
			return true
		}
	}
	return false
}

// ValidateEncryptedSecretsAtStartup checks vendor_connector_configs for any enc:v1: rows.
// Fails closed if encrypted rows exist without a valid SecretBox or if any row fails AAD decryption.
func (s *Store) ValidateEncryptedSecretsAtStartup(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT env_key, value_text
		FROM vendor_connector_configs
		WHERE value_text LIKE $1
	`, crypto.SecretCipherPrefix+"%")
	if err != nil {
		return fmt.Errorf("query encrypted vendor connector secrets: %w", err)
	}
	defer rows.Close()

	var encryptedRows []struct {
		key string
		val string
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return fmt.Errorf("scan encrypted vendor connector secret: %w", err)
		}
		encryptedRows = append(encryptedRows, struct {
			key string
			val string
		}{key: k, val: v})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(encryptedRows) == 0 {
		return nil
	}
	if s.secretBox == nil {
		return fmt.Errorf(
			"FAIL_CLOSED_ENCRYPTED_SECRETS_WITHOUT_KEY: found %d encrypted row(s) in %s.%s but WARRANT_DB_SECRET_KEY is not configured",
			len(encryptedRows), vendorConnectorTable, vendorConnectorColumn,
		)
	}
	for _, r := range encryptedRows {
		if _, err := s.secretBox.OpenColumn(vendorConnectorTable, vendorConnectorColumn, r.val); err != nil {
			return fmt.Errorf(
				"FAIL_CLOSED_ENCRYPTED_SECRET_DECRYPT_FAILED: key %q in %s.%s failed AES-256-GCM AAD verification: %w",
				r.key, vendorConnectorTable, vendorConnectorColumn, err,
			)
		}
	}
	return nil
}

// UpsertVendorConnectorConfig persists a vendor connector or distributor setting in PostgreSQL.
// When isSecret is true (or IsConnectorSecretEnvKey(envKey) is true) and value is non-empty,
// value_text is encrypted with AES-256-GCM bound to "vendor_connector_configs.value_text" AAD.
func (s *Store) UpsertVendorConnectorConfig(ctx context.Context, envKey, sourceSystem, value string, isSecret bool) error {
	k := strings.TrimSpace(envKey)
	if k == "" {
		return fmt.Errorf("empty connector env_key")
	}
	if IsConnectorSecretEnvKey(k) {
		isSecret = true
	}
	storedVal := value
	if isSecret && value != "" {
		if s.secretBox == nil {
			return fmt.Errorf("DB_SECRET_BOX_REQUIRED: refusing to store plaintext secret for %q without SecretBox", k)
		}
		sealed, err := s.secretBox.SealColumn(vendorConnectorTable, vendorConnectorColumn, value)
		if err != nil {
			return fmt.Errorf("seal connector secret %q: %w", k, err)
		}
		storedVal = sealed
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO vendor_connector_configs (env_key, source_system, is_secret, value_text, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (env_key) DO UPDATE SET
			source_system = EXCLUDED.source_system,
			is_secret = EXCLUDED.is_secret,
			value_text = EXCLUDED.value_text,
			updated_at = EXCLUDED.updated_at
	`, k, strings.TrimSpace(sourceSystem), isSecret, storedVal, time.Now().UTC())
	return err
}

// DeleteVendorConnectorConfig removes a persisted vendor connector setting from PostgreSQL.
func (s *Store) DeleteVendorConnectorConfig(ctx context.Context, envKey string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM vendor_connector_configs WHERE env_key = $1`, strings.TrimSpace(envKey))
	return err
}

// LoadVendorConnectorConfigs loads all persisted vendor connector settings from PostgreSQL,
// decrypting any enc:v1: rows with AAD "vendor_connector_configs.value_text".
func (s *Store) LoadVendorConnectorConfigs(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT env_key, value_text
		FROM vendor_connector_configs
		ORDER BY env_key ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("load vendor connector configs: %w", err)
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		if crypto.IsEncryptedValue(v) {
			if s.secretBox == nil {
				return nil, fmt.Errorf(
					"FAIL_CLOSED_ENCRYPTED_SECRETS_WITHOUT_KEY: row %q in %s.%s is encrypted but no SecretBox is configured",
					k, vendorConnectorTable, vendorConnectorColumn,
				)
			}
			pt, err := s.secretBox.OpenColumn(vendorConnectorTable, vendorConnectorColumn, v)
			if err != nil {
				return nil, fmt.Errorf("decrypt connector secret %q: %w", k, err)
			}
			v = pt
		}
		out[k] = v
	}
	return out, rows.Err()
}
