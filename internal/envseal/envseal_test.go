package envseal

import (
	"testing"
)

func TestIsSecretEnvKey(t *testing.T) {
	secrets := []string{
		"DATABASE_URL",
		"POSTGRES_PASSWORD",
		"KERNEL_ATTESTATION_SEED",
		"WARRANT_DB_SECRET_KEY",
		"WARRANT_OPERATOR_TOKEN",
		"WARRANT_AUTOMATION_TOKEN",
		"WARRANT_INTAKE_TOKEN",
		"WARRANT_EXTRACTOR_SHARED_SECRET",
		"QUALYS_VMDR_READ_TOKEN",
		"CUSTOM_VENDOR_API_KEY",
		"MY_PRIVATE_KEY",
	}
	for _, k := range secrets {
		if !IsSecretEnvKey(k) {
			t.Errorf("expected %q to be classified as secret", k)
		}
	}

	nonSecrets := []string{
		"PATH",
		"HOME",
		"WARRANTD_LISTEN_ADDR",
		"DATABASE_URL_FILE",
		"WARRANT_DB_SECRET_KEY_FILE",
		"WARRANT_KMS_URL",
		"EXTRACTOR_URL",
		SealFDEnv,
		DisableEnv,
	}
	for _, k := range nonSecrets {
		if IsSecretEnvKey(k) {
			t.Errorf("expected %q NOT to be classified as secret", k)
		}
	}

	if !IsSecretEnvKey("EXTRA_CUSTOM_VAR", "EXTRA_CUSTOM_VAR") {
		t.Errorf("expected explicit extra key to be classified as secret")
	}
}

func TestBuildScrubbedEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"WARRANTD_LISTEN_ADDR=:8080",
		"DATABASE_URL=postgres://user:pass@pg:5432/warrant",
		"WARRANT_OPERATOR_TOKEN=super-secret-op-token",
		"WARRANT_DB_SECRET_KEY_FILE=/run/secrets/db.key",
		SealFDEnv + "=3",
		"EMPTY_SECRET_TOKEN=",
	}
	clean, secrets := BuildScrubbedEnv(in)

	if len(secrets) != 2 {
		t.Fatalf("expected 2 scrubbed secrets, got %d: %v", len(secrets), secrets)
	}
	if secrets["DATABASE_URL"] != "postgres://user:pass@pg:5432/warrant" {
		t.Errorf("DATABASE_URL not captured")
	}
	if secrets["WARRANT_OPERATOR_TOKEN"] != "super-secret-op-token" {
		t.Errorf("WARRANT_OPERATOR_TOKEN not captured")
	}
	for _, kv := range clean {
		if kv == "DATABASE_URL=postgres://user:pass@pg:5432/warrant" || kv == "WARRANT_OPERATOR_TOKEN=super-secret-op-token" || kv == SealFDEnv+"=3" {
			t.Errorf("sensitive or control entry leaked into clean env: %s", kv)
		}
	}
}

func TestSealedStoreGetenvPrecedence(t *testing.T) {
	t.Setenv("WARRANT_TEST_FALLBACK", "from-os")
	t.Setenv("WARRANT_OPERATOR_TOKEN", "from-os-old")

	s := NewSealedStore(map[string]string{
		"WARRANT_OPERATOR_TOKEN": "from-sealed-memory",
	}, true)
	SetGlobalStore(s)
	defer SetGlobalStore(nil)

	if got := Getenv("WARRANT_OPERATOR_TOKEN"); got != "from-sealed-memory" {
		t.Fatalf("expected sealed value, got %q", got)
	}
	if got := Getenv("WARRANT_TEST_FALLBACK"); got != "from-os" {
		t.Fatalf("expected os fallback value, got %q", got)
	}
	if !s.Sealed() || s.Count() != 1 {
		t.Fatalf("unexpected store state: sealed=%v count=%d", s.Sealed(), s.Count())
	}
}

func TestSealAndReexecDisabledNoOp(t *testing.T) {
	t.Setenv(DisableEnv, "1")
	t.Setenv("WARRANT_OPERATOR_TOKEN", "tok-1234567890123456")
	defer SetGlobalStore(nil)

	store, err := SealAndReexec()
	if err != nil {
		t.Fatalf("SealAndReexec failed: %v", err)
	}
	if store.Sealed() {
		t.Fatalf("expected unsealed store when disabled")
	}
	if got := store.Getenv("WARRANT_OPERATOR_TOKEN"); got != "tok-1234567890123456" {
		t.Fatalf("unexpected token: %q", got)
	}
}
