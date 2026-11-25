package db

import (
	"errors"
	"testing"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
)

func TestIsConnectorSecretEnvKey(t *testing.T) {
	if !IsConnectorSecretEnvKey("QUALYS_VMDR_READ_TOKEN") {
		t.Errorf("expected QUALYS_VMDR_READ_TOKEN to be secret")
	}
	if !IsConnectorSecretEnvKey("WARRANT_ARGO_CD_TOKEN") {
		t.Errorf("expected WARRANT_ARGO_CD_TOKEN to be secret")
	}
	if !IsConnectorSecretEnvKey("TENABLE_API_KEY") {
		t.Errorf("expected TENABLE_API_KEY to be secret")
	}
	if IsConnectorSecretEnvKey("QUALYS_VMDR_READ_URL") {
		t.Errorf("expected URL key not to be secret")
	}
	if IsConnectorSecretEnvKey("WARRANT_ARGO_CD_TOKEN_FILE") {
		t.Errorf("expected _FILE key not to be secret")
	}
}

func TestVendorConnectorColumnAADRejectsTransplant(t *testing.T) {
	box, err := crypto.NewEphemeralSecretBox()
	if err != nil {
		t.Fatalf("NewEphemeralSecretBox: %v", err)
	}
	sealed, err := box.SealColumn(vendorConnectorTable, vendorConnectorColumn, "bearer-tok-999999")
	if err != nil {
		t.Fatalf("SealColumn: %v", err)
	}
	if got, err := box.OpenColumn(vendorConnectorTable, vendorConnectorColumn, sealed); err != nil || got != "bearer-tok-999999" {
		t.Fatalf("expected clean decrypt, got %q, %v", got, err)
	}
	// Transplanting ciphertext into another column or table must fail closed
	if _, err := box.OpenColumn(vendorConnectorTable, "source_system", sealed); !errors.Is(err, crypto.ErrSecretAuthFailed) {
		t.Fatalf("expected ErrSecretAuthFailed on same-table different-column transplant, got %v", err)
	}
	if _, err := box.OpenColumn("feed_runtime_config", vendorConnectorColumn, sealed); !errors.Is(err, crypto.ErrSecretAuthFailed) {
		t.Fatalf("expected ErrSecretAuthFailed on cross-table transplant, got %v", err)
	}
}
