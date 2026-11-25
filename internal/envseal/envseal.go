package envseal

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	// SealFDEnv carries the inherited pipe read-end file descriptor across syscall.Exec on Linux.
	SealFDEnv = "WARRANT_ENVSEAL_FD"
	// DisableEnv disables /proc/<pid>/environ sealing when set to "1" or "true" (for local debugging only).
	DisableEnv = "WARRANT_DISABLE_ENVSEAL"
)

// DefaultSecretEnvKeys lists explicit environment variable names containing sensitive credentials
// for warrantd and warrant-extractor that must be scrubbed from /proc/<pid>/environ on Linux.
var DefaultSecretEnvKeys = []string{
	"DATABASE_URL",
	"POSTGRES_PASSWORD",
	"KERNEL_ATTESTATION_SEED",
	"WARRANT_DB_SECRET_KEY",
	"WARRANT_BOOTSTRAP_ADMIN_TOKEN",
	"WARRANT_OPERATOR_TOKEN",
	"WARRANT_AUTOMATION_TOKEN",
	"WARRANT_INTAKE_TOKEN",
	"WARRANT_ESTATE_READ_TOKEN",
	"WARRANT_TETRAGON_SENSOR_TOKEN",
	"WARRANT_TETRAGON_WEBHOOK_SECRET",
	"WARRANT_EXTRACTOR_SHARED_SECRET",
	"WARRANT_KMS_API_TOKEN",
	"WARRANT_EXTERNAL_ANCHOR_TOKEN",
}

var secretKeySuffixes = []string{
	"_TOKEN",
	"_SECRET",
	"_PASSWORD",
	"_API_KEY",
	"_PRIVATE_KEY",
	"_SEED",
}

// SealedStore holds secrets received over the one-shot pipe FD in process memory only,
// preventing disclosure via /proc/<pid>/environ.
type SealedStore struct {
	mu      sync.RWMutex
	secrets map[string]string
	sealed  bool
}

var (
	globalMu    sync.RWMutex
	globalStore *SealedStore
)

// NewSealedStore constructs an in-memory SealedStore from an initial secret map.
func NewSealedStore(initial map[string]string, sealed bool) *SealedStore {
	cp := make(map[string]string, len(initial))
	for k, v := range initial {
		cp[k] = v
	}
	return &SealedStore{
		secrets: cp,
		sealed:  sealed,
	}
}

// SetGlobalStore installs s as the process-wide lookup store used by Getenv.
func SetGlobalStore(s *SealedStore) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalStore = s
}

// Getenv returns the secret from the process-wide SealedStore if present,
// otherwise falling back to os.Getenv.
func Getenv(key string) string {
	globalMu.RLock()
	s := globalStore
	globalMu.RUnlock()
	if s != nil {
		if v, ok := s.Lookup(key); ok {
			return v
		}
	}
	return os.Getenv(key)
}

// Lookup returns a value from the SealedStore.
func (s *SealedStore) Lookup(key string) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.secrets[key]
	return v, ok
}

// Getenv checks the SealedStore first and falls back to os.Getenv.
func (s *SealedStore) Getenv(key string) string {
	if v, ok := s.Lookup(key); ok {
		return v
	}
	return os.Getenv(key)
}

// Sealed reports whether secrets were actively scrubbed via Linux syscall.Exec pipe handoff.
func (s *SealedStore) Sealed() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sealed
}

// Count returns the number of sealed secret keys held in memory.
func (s *SealedStore) Count() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.secrets)
}

// IsSecretEnvKey reports whether an environment variable name holds a secret value
// that should be scrubbed from /proc/<pid>/environ. Path-pointer variables (*_FILE, *_DIR, *_PATH)
// and control flags are excluded.
func IsSecretEnvKey(key string, extraKeys ...string) bool {
	k := strings.TrimSpace(key)
	if k == "" || k == SealFDEnv || k == DisableEnv {
		return false
	}
	upper := strings.ToUpper(k)
	if strings.HasSuffix(upper, "_FILE") || strings.HasSuffix(upper, "_DIR") || strings.HasSuffix(upper, "_PATH") || strings.HasSuffix(upper, "_URL") && upper != "DATABASE_URL" {
		return false
	}
	for _, explicit := range DefaultSecretEnvKeys {
		if upper == explicit {
			return true
		}
	}
	for _, extra := range extraKeys {
		if strings.EqualFold(strings.TrimSpace(extra), k) {
			return true
		}
	}
	for _, suf := range secretKeySuffixes {
		if strings.HasSuffix(upper, suf) {
			return true
		}
	}
	return false
}

// BuildScrubbedEnv partitions an os.Environ()-style slice into:
//   - cleanEnv: entries with secret keys and SealFDEnv removed
//   - secrets:  map of scrubbed secret key -> value
func BuildScrubbedEnv(environ []string, extraSecretKeys ...string) (cleanEnv []string, secrets map[string]string) {
	cleanEnv = make([]string, 0, len(environ))
	secrets = make(map[string]string)
	for _, entry := range environ {
		idx := strings.IndexByte(entry, '=')
		if idx <= 0 {
			cleanEnv = append(cleanEnv, entry)
			continue
		}
		k := entry[:idx]
		v := entry[idx+1:]
		if k == SealFDEnv {
			continue
		}
		if IsSecretEnvKey(k, extraSecretKeys...) && v != "" {
			secrets[k] = v
			continue
		}
		cleanEnv = append(cleanEnv, entry)
	}
	return cleanEnv, secrets
}

// SealAndReexec scrubs secret environment variables from /proc/<pid>/environ on Linux
// by re-execing the current binary with a clean environment and passing the secrets
// over a one-shot pipe FD. On non-Linux platforms (or when WARRANT_DISABLE_ENVSEAL=1),
// it acts as a safe no-op that registers an unsealed store backed by os.Getenv.
func SealAndReexec(extraSecretKeys ...string) (*SealedStore, error) {
	// Child path: receive sealed secrets from the one-shot pipe FD.
	if fdStr := strings.TrimSpace(os.Getenv(SealFDEnv)); fdStr != "" {
		fd, err := strconv.Atoi(fdStr)
		if err != nil || fd < 3 {
			return nil, fmt.Errorf("envseal: invalid %s=%q", SealFDEnv, fdStr)
		}
		payload, err := readAndCloseFD(fd)
		if err != nil {
			return nil, fmt.Errorf("envseal: read handoff pipe fd %d: %w", fd, err)
		}
		_ = os.Unsetenv(SealFDEnv)
		var secrets map[string]string
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &secrets); err != nil {
				return nil, fmt.Errorf("envseal: decode sealed payload: %w", err)
			}
		}
		store := NewSealedStore(secrets, true)
		SetGlobalStore(store)
		return store, nil
	}

	if disable := strings.ToLower(strings.TrimSpace(os.Getenv(DisableEnv))); disable == "1" || disable == "true" || disable == "yes" {
		store := NewSealedStore(nil, false)
		SetGlobalStore(store)
		return store, nil
	}

	cleanEnv, secrets := BuildScrubbedEnv(os.Environ(), extraSecretKeys...)
	if len(secrets) == 0 || !platformSupportsReexec() {
		store := NewSealedStore(secrets, false)
		SetGlobalStore(store)
		return store, nil
	}

	payload, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("envseal: marshal secrets: %w", err)
	}
	// On Linux, reexecSealed replaces the process image and does not return on success.
	if err := reexecSealed(cleanEnv, payload); err != nil {
		return nil, fmt.Errorf("envseal: reexec failed: %w", err)
	}
	store := NewSealedStore(secrets, true)
	SetGlobalStore(store)
	return store, nil
}
