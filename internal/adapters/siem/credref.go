package siem

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cgilbert61/G1-Warrant/internal/envseal"
)

var validEnvVarRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,127}$`)
var validVaultPathRe = regexp.MustCompile(`^[a-zA-Z0-9._/-]{2,256}$`)

// ParsedCredentialRef represents a validated external secret reference URI.
// G1-Warrant never accepts, stores, or echoes raw SIEM secrets in UI payloads or PostgreSQL.
type ParsedCredentialRef struct {
	Scheme string
	Target string
	RawURI string
}

// ParseAndValidateCredentialRef enforces Item 3:
// "Credential reference only - the UI never takes, stores, or shows a raw secret."
func ParseAndValidateCredentialRef(raw string) (ParsedCredentialRef, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "none://" {
		return ParsedCredentialRef{Scheme: "none", Target: "", RawURI: "none://"}, nil
	}
	if strings.ContainsAny(trimmed, " \t\r\n\x00") {
		return ParsedCredentialRef{}, errors.New("RAW_SECRET_FORBIDDEN_CREDENTIAL_REF_REQUIRED: whitespace/control characters forbidden in credential_ref")
	}
	idx := strings.Index(trimmed, "://")
	if idx <= 0 {
		return ParsedCredentialRef{}, errors.New("RAW_SECRET_FORBIDDEN_CREDENTIAL_REF_REQUIRED: credential_ref must be a reference URI (env://VAR, file:///run/secrets/name, k8s-secret://..., aws-sm://..., azure-kv://..., gcp-sm://..., or none://)")
	}
	scheme := strings.ToLower(trimmed[:idx])
	target := trimmed[idx+3:]

	switch scheme {
	case "none":
		if target != "" {
			return ParsedCredentialRef{}, errors.New("INVALID_CREDENTIAL_REF: none:// takes no path")
		}
		return ParsedCredentialRef{Scheme: "none", Target: "", RawURI: "none://"}, nil

	case "env":
		if !validEnvVarRe.MatchString(target) {
			return ParsedCredentialRef{}, fmt.Errorf("INVALID_CREDENTIAL_REF: env:// target %q must be an uppercase environment variable identifier ([A-Z][A-Z0-9_]+)", target)
		}
		return ParsedCredentialRef{Scheme: "env", Target: target, RawURI: "env://" + target}, nil

	case "file":
		if target == "" || strings.Contains(target, "..") {
			return ParsedCredentialRef{}, errors.New("INVALID_CREDENTIAL_REF: file:// path traversal (..) or empty path forbidden")
		}
		norm := filepath.ToSlash(target)
		allowedPrefixes := []string{"/run/secrets/", "/var/run/secrets/", "/var/lib/warrant-secrets/"}
		if extraDir := strings.TrimSpace(os.Getenv("WARRANT_SIEM_SECRETS_DIR")); extraDir != "" {
			cleanExtra := strings.TrimRight(filepath.ToSlash(filepath.Clean(extraDir)), "/") + "/"
			allowedPrefixes = append(allowedPrefixes, cleanExtra)
		}
		allowed := false
		for _, pfx := range allowedPrefixes {
			if strings.HasPrefix(norm, pfx) && len(norm) > len(pfx) {
				allowed = true
				break
			}
		}
		if !allowed {
			return ParsedCredentialRef{}, errors.New("INVALID_CREDENTIAL_REF: file:// path must reside under /run/secrets/, /var/run/secrets/, /var/lib/warrant-secrets/, or WARRANT_SIEM_SECRETS_DIR")
		}
		return ParsedCredentialRef{Scheme: "file", Target: target, RawURI: "file://" + norm}, nil

	case "k8s-secret", "aws-sm", "azure-kv", "gcp-sm":
		if strings.Contains(target, "..") || !validVaultPathRe.MatchString(target) {
			return ParsedCredentialRef{}, fmt.Errorf("INVALID_CREDENTIAL_REF: invalid %s:// reference target", scheme)
		}
		return ParsedCredentialRef{Scheme: scheme, Target: target, RawURI: scheme + "://" + target}, nil

	default:
		return ParsedCredentialRef{}, fmt.Errorf("RAW_SECRET_FORBIDDEN_CREDENTIAL_REF_REQUIRED: unsupported credential_ref scheme %q", scheme)
	}
}

// ResolveCredentialRef resolves a validated CredentialRef strictly in memory at send time.
func ResolveCredentialRef(raw string) (string, error) {
	parsed, err := ParseAndValidateCredentialRef(raw)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "none":
		return "", nil
	case "env":
		val := strings.TrimSpace(envseal.Getenv(parsed.Target))
		if val == "" {
			return "", fmt.Errorf("CREDENTIAL_REF_UNRESOLVED: environment variable %s is unset or empty", parsed.Target)
		}
		return val, nil
	case "file":
		b, err := os.ReadFile(parsed.Target)
		if err != nil {
			return "", fmt.Errorf("CREDENTIAL_REF_UNRESOLVED: read %s: %w", parsed.RawURI, err)
		}
		val := strings.TrimSpace(string(b))
		if val == "" {
			return "", fmt.Errorf("CREDENTIAL_REF_UNRESOLVED: secret file %s is empty", parsed.RawURI)
		}
		return val, nil
	default:
		// External KMS/Vault/SecretManager reference: check CSI-mounted secret under /run/secrets/<sanitized> if present
		flat := strings.NewReplacer("/", "_", ".", "_", "-", "_").Replace(parsed.Target)
		envMirror := "WARRANT_SECRET_" + strings.ToUpper(flat)
		if v := strings.TrimSpace(envseal.Getenv(envMirror)); v != "" {
			return v, nil
		}
		csiPath := filepath.Join("/run/secrets", filepath.FromSlash(parsed.Target))
		if b, rErr := os.ReadFile(csiPath); rErr == nil && strings.TrimSpace(string(b)) != "" {
			return strings.TrimSpace(string(b)), nil
		}
		return "", fmt.Errorf("CREDENTIAL_REF_UNRESOLVED: external secret %s is not mounted at /run/secrets/%s", parsed.RawURI, parsed.Target)
	}
}
