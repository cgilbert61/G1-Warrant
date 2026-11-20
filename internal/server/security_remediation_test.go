package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/ledger"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

func TestF1AndF2_StartupGuardsRefuseDefaultDBPasswordsAndMissingOrLegacyPublisherKeys(t *testing.T) {
	pubBytes, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	validPubB64 := base64.StdEncoding.EncodeToString(pubBytes)
	strongDB := "postgres://warrant:9f8e7d6c5b4a39281716151413121110fedcba98@postgres:5432/warrant?sslmode=require"

	// 1. F2: Refuse empty and known default DB passwords in live & kubernetes postures
	for _, postureEnv := range []map[string]string{
		{"WARRANT_POSTURE": "live"},
		{"WARRANT_CLUSTER_DRIVER": "kubernetes"},
	} {
		for _, badDSN := range []string{
			"",
			"postgres://warrant:warrant@postgres:5432/warrant?sslmode=disable",
			"postgres://postgres:postgres@postgres:5432/warrant?sslmode=disable",
			"postgres://warrant:password@postgres:5432/warrant?sslmode=disable",
			"host=postgres user=warrant password=warrant dbname=warrant",
		} {
			envMap := map[string]string{
				"DATABASE_URL":                 badDSN,
				"WARRANT_PUBLISHER_PUBLIC_KEY_B64": validPubB64,
			}
			for k, v := range postureEnv {
				envMap[k] = v
			}
			err := ValidateStartupSecurityGuards(func(k string) string { return envMap[k] })
			if err == nil || !strings.Contains(err.Error(), "DATABASE_URL") {
				t.Fatalf("expected startup guard to refuse bad DATABASE_URL %q in posture %v, got %v", badDSN, postureEnv, err)
			}
		}
	}

	// 2. F2: Demo/sandbox posture generates a unique random password when DATABASE_URL is unset
	sandboxDSN1, err := ResolveAndValidateDatabaseURL(func(string) string { return "" })
	if err != nil {
		t.Fatalf("unexpected error generating sandbox DSN: %v", err)
	}
	sandboxDSN2, err := ResolveAndValidateDatabaseURL(func(string) string { return "" })
	if err != nil {
		t.Fatalf("unexpected error generating second sandbox DSN: %v", err)
	}
	if strings.Contains(sandboxDSN1, ":warrant@") || sandboxDSN1 == sandboxDSN2 {
		t.Fatalf("expected unique cryptographically random sandbox DB password (never 'warrant'), got dsn1=%q dsn2=%q", sandboxDSN1, sandboxDSN2)
	}

	// 3. F1: Live/Kubernetes posture fails closed when no authoritative publisher public key is configured
	if err := ValidateStartupSecurityGuards(func(k string) string {
		switch k {
		case "WARRANT_POSTURE":
			return "live"
		case "DATABASE_URL":
			return strongDB
		default:
			return ""
		}
	}); err == nil || !strings.Contains(err.Error(), "ARTIFACT_PUBLISHER") {
		t.Fatalf("expected live startup to fail closed without publisher public key, got %v", err)
	}

	// 4. F1: Legacy public-string-derived seeds are rejected fail-closed even in sandbox mode
	legacySeed := sha256.Sum256([]byte("g1163rt-g1-warrant-v1:publisher:g1163rt-trusted-build-pipeline-v1"))
	legacySeedHex := hex.EncodeToString(legacySeed[:])
	if err := ValidateStartupSecurityGuards(func(k string) string {
		if k == "WARRANT_PUBLISHER_SEED_HEX" {
			return legacySeedHex
		}
		return ""
	}); err == nil || !strings.Contains(err.Error(), "FORBIDDEN_LEGACY_PUBLIC_SEED_KEY") {
		t.Fatalf("expected startup guard to reject legacy public-string seed hex, got %v", err)
	}

	// 5. Valid live configuration passes startup security guards cleanly
	if err := ValidateStartupSecurityGuards(func(k string) string {
		switch k {
		case "WARRANT_POSTURE":
			return "live"
		case "DATABASE_URL":
			return strongDB
		case "WARRANT_PUBLISHER_PUBLIC_KEY_B64":
			return validPubB64
		default:
			return ""
		}
	}); err != nil {
		t.Fatalf("expected valid live posture config to pass startup guards, got %v", err)
	}
}

func TestF5_PersonaSerializationNeverExposesPrivateSeedMaterial(t *testing.T) {
	personas := crypto.BuiltinTestPersonas()
	rawPersonasJSON, err := json.Marshal(personas)
	if err != nil {
		t.Fatal(err)
	}
	pubPersonasJSON, err := json.Marshal(crypto.BuiltinPublicTestPersonas())
	if err != nil {
		t.Fatal(err)
	}

	for _, payload := range []string{string(rawPersonasJSON), string(pubPersonasJSON)} {
		if strings.Contains(payload, "seed_hex") || strings.Contains(payload, "private_key") {
			t.Fatalf("serialized persona JSON leaked forbidden private field name: %s", payload)
		}
		for _, p := range personas {
			if p.SeedHex != "" && strings.Contains(payload, p.SeedHex) {
				t.Fatalf("serialized persona JSON leaked raw seed bytes for %s", p.PrincipalID)
			}
		}
	}
}

func TestF6_ExternalAnchorWarningAndWitnessModeReporting(t *testing.T) {
	warn := ExternalAnchorStartupWarning(func(k string) string {
		if k == "WARRANT_POSTURE" {
			return "live"
		}
		return ""
	})
	if !strings.Contains(warn, "EXTERNAL_ANCHOR_UNCONFIGURED") || !strings.Contains(warn, models.WitnessModeInProcessLocal) {
		t.Fatalf("expected high-visibility startup warning when WARRANT_EXTERNAL_ANCHOR_URL is unset in live mode, got %q", warn)
	}

	noWarn := ExternalAnchorStartupWarning(func(k string) string {
		switch k {
		case "WARRANT_POSTURE":
			return "live"
		case "WARRANT_EXTERNAL_ANCHOR_URL":
			return "https://notary.agency.gov/v1/anchor"
		default:
			return ""
		}
	})
	if noWarn != "" {
		t.Fatalf("expected no warning when WARRANT_EXTERNAL_ANCHOR_URL is configured, got %q", noWarn)
	}

	localAnchor := ledger.NewTransparencyAnchor("", "")
	if localAnchor.WitnessMode() != models.WitnessModeInProcessLocal {
		t.Fatalf("expected IN_PROCESS_LOCAL witness mode, got %s", localAnchor.WitnessMode())
	}
	extAnchor := ledger.NewTransparencyAnchor("", "https://notary.agency.gov/v1/anchor")
	if extAnchor.WitnessMode() != models.WitnessModeExternalNotary {
		t.Fatalf("expected EXTERNAL_NOTARY witness mode, got %s", extAnchor.WitnessMode())
	}
}
