package server

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/adapters/distributors"
	"github.com/cgilbert61/G1-Warrant/internal/adapters/estatereader"
	"github.com/cgilbert61/G1-Warrant/internal/adapters/shields"
	"github.com/cgilbert61/G1-Warrant/internal/adapters/vmtwins"
	"github.com/cgilbert61/G1-Warrant/internal/agentcp"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/envseal"
	"github.com/cgilbert61/G1-Warrant/internal/feeds"
	"github.com/cgilbert61/G1-Warrant/internal/gate"
	"github.com/cgilbert61/G1-Warrant/internal/ledger"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
	"github.com/cgilbert61/G1-Warrant/internal/verify"
	"github.com/cgilbert61/G1-Warrant/internal/warrant"
	"github.com/google/uuid"
)

// ControlPlaneOrchestrator wires N1-N5, Live Threat Feeds, and the Kubernetes/Cilium/SARIF Adapter Pack.
type ControlPlaneOrchestrator struct {
	Store       *db.Store
	Policy      *policy.Engine
	N1Warrant   *warrant.Engine
	N2Gate      *gate.Engine
	N3Verify    *verify.Engine
	N4AgentCP   *agentcp.ControlPlane
	N5Ledger    *ledger.Engine
	Feeds       *feeds.Manager
	SARIFIntake adapters.ScannerIntake
	FixProvider adapters.FixProvider
	Shield      adapters.ShieldEnforcer
	Deploy              adapters.DeploymentTarget
	Twin                adapters.TwinRunner
	Distributors         *adapters.DistributorRegistry
	EstateReaders        *estatereader.Registry
	Broker               *SSEBroker
	WebAuthnCfg          crypto.WebAuthnConfig
	fleetURL             string
	localK8sReader       estatereader.LocalK8sWorkloadReader
	connectorMu          sync.RWMutex
	connectorOverrides   map[string]string
	connectorPersistPath string
	tetragonSensorToken  string
	tetragonHMACSecret   string
	bootstrapAdminToken  string
	operatorToken        string
	automationToken      string
	intakeToken          string
	estateReadToken      string
	igaToken             string
	igaHMACSecret        string
}

func isWeakOrPlaceholderSecret(val string) bool {
	v := strings.ToLower(strings.TrimSpace(val))
	if len(v) < 16 {
		return true
	}
	badSubstrings := []string{
		"changeme", "placeholder", "example", "default", "demo", "password", "123456", "<", ">",
	}
	for _, b := range badSubstrings {
		if strings.Contains(v, b) {
			return true
		}
	}
	return false
}

func extractPasswordFromDatabaseDSN(dsn string) (string, bool) {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return "", false
	}
	if strings.Contains(trimmed, "://") {
		u, err := url.Parse(trimmed)
		if err != nil || u.User == nil {
			return "", false
		}
		return u.User.Password()
	}
	for _, field := range strings.Fields(trimmed) {
		if strings.HasPrefix(strings.ToLower(field), "password=") {
			val := strings.Trim(field[len("password="):], `'"`)
			return val, true
		}
	}
	return "", false
}

func isForbiddenDefaultDBPassword(pw string) bool {
	switch strings.ToLower(strings.TrimSpace(pw)) {
	case "", "warrant", "postgres", "password":
		return true
	default:
		return false
	}
}

// ResolveAndValidateDatabaseURL enforces database credential hygiene across postures:
//   - In live/Kubernetes posture (WARRANT_CLUSTER_DRIVER=kubernetes or WARRANT_POSTURE=live), refuses empty
//     DATABASE_URL or known default passwords (warrant, postgres, password).
//   - In demo/sandbox posture, generates a cryptographically random password per installation if DATABASE_URL is unset.
func ResolveAndValidateDatabaseURL(getenv func(string) string) (string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	isLive := crypto.IsLiveOrKubernetesPosture(getenv)
	dsn := strings.TrimSpace(getenv("DATABASE_URL"))
	if dsnFile := strings.TrimSpace(getenv("DATABASE_URL_FILE")); dsnFile != "" {
		if b, err := os.ReadFile(dsnFile); err == nil && strings.TrimSpace(string(b)) != "" {
			dsn = strings.TrimSpace(string(b))
		}
	}

	if isLive {
		if dsn == "" {
			return "", fmt.Errorf("FATAL_SECURITY_GUARD: DATABASE_URL must be explicitly configured in live/Kubernetes posture")
		}
		pw, hasPw := extractPasswordFromDatabaseDSN(dsn)
		if !hasPw || isForbiddenDefaultDBPassword(pw) {
			return "", fmt.Errorf("FATAL_SECURITY_GUARD: DATABASE_URL uses an empty or prohibited default password (warrant/postgres/password) in live/Kubernetes posture")
		}
		return dsn, nil
	}

	if dsn != "" {
		return dsn, nil
	}

	// Demo/sandbox posture with unset DATABASE_URL: generate a secure random password per installation.
	persistFile := strings.TrimSpace(getenv("WARRANT_SANDBOX_DB_DSN_FILE"))
	if persistFile != "" {
		if b, err := os.ReadFile(persistFile); err == nil && strings.TrimSpace(string(b)) != "" {
			return strings.TrimSpace(string(b)), nil
		}
	}
	var rnd [24]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", fmt.Errorf("generate random sandbox database password: %w", err)
	}
	generatedDSN := fmt.Sprintf("postgres://warrant:%s@postgres:5432/warrant?sslmode=disable", hex.EncodeToString(rnd[:]))
	if persistFile != "" {
		_ = os.WriteFile(persistFile, []byte(generatedDSN+"\n"), 0o600)
	}
	return generatedDSN, nil
}

// ExternalAnchorStartupWarning returns an explicit high-visibility warning when running in live/Kubernetes posture
// without an external transparency notary URL (WARRANT_EXTERNAL_ANCHOR_URL).
func ExternalAnchorStartupWarning(getenv func(string) string) string {
	if getenv == nil {
		getenv = os.Getenv
	}
	isLiveOrFeed := crypto.IsLiveOrKubernetesPosture(getenv) || strings.EqualFold(strings.TrimSpace(getenv("WARRANT_FEED_MODE")), "live")
	if isLiveOrFeed && strings.TrimSpace(getenv("WARRANT_EXTERNAL_ANCHOR_URL")) == "" {
		return "[SECURITY WARNING] EXTERNAL_ANCHOR_UNCONFIGURED: running in live/Kubernetes posture with WARRANT_EXTERNAL_ANCHOR_URL unset — ledger checkpoints are anchored IN_PROCESS_LOCAL only; configure WARRANT_EXTERNAL_ANCHOR_URL for EXTERNAL_NOTARY tamper-resistance"
	}
	return ""
}

// ValidateStartupSecurityGuards enforces fail-closed startup invariants so built-in test smartcard personas,
// weak/placeholder registrar/operator secrets, default database passwords, or unconfigured/legacy publisher keys
// can NEVER be enabled in live or Kubernetes postures.
func ValidateStartupSecurityGuards(getenv func(string) string) error {
	if getenv == nil {
		getenv = os.Getenv
	}
	isK8s := strings.EqualFold(strings.TrimSpace(getenv("WARRANT_CLUSTER_DRIVER")), "kubernetes")
	isLive := strings.EqualFold(strings.TrimSpace(getenv("WARRANT_FEED_MODE")), "live")
	isLivePosture := crypto.IsLiveOrKubernetesPosture(getenv)

	if strings.EqualFold(strings.TrimSpace(getenv("WARRANT_ENABLE_TEST_SMARTCARDS")), "true") {
		if isK8s {
			return fmt.Errorf("FATAL_SECURITY_GUARD: WARRANT_ENABLE_TEST_SMARTCARDS=true is strictly forbidden when WARRANT_CLUSTER_DRIVER=kubernetes")
		}
		if isLive {
			return fmt.Errorf("FATAL_SECURITY_GUARD: WARRANT_ENABLE_TEST_SMARTCARDS=true is strictly forbidden when WARRANT_FEED_MODE=live")
		}
		if isLivePosture {
			return fmt.Errorf("FATAL_SECURITY_GUARD: WARRANT_ENABLE_TEST_SMARTCARDS=true is strictly forbidden when WARRANT_POSTURE=live")
		}
	}

	if isLivePosture || isLive {
		for _, envKey := range []string{
			"WARRANT_BOOTSTRAP_ADMIN_TOKEN",
			"WARRANT_OPERATOR_TOKEN",
			"WARRANT_AUTOMATION_TOKEN",
			"WARRANT_INTAKE_TOKEN",
			"WARRANT_TETRAGON_SENSOR_TOKEN",
			"WARRANT_TETRAGON_HMAC_SECRET",
		} {
			if raw := strings.TrimSpace(getenv(envKey)); raw != "" && isWeakOrPlaceholderSecret(raw) {
				return fmt.Errorf("FATAL_SECURITY_GUARD: %s contains a weak or placeholder secret (<16 chars or well-known token)", envKey)
			}
		}
	}

	// Enforce F2: refuse empty or default database credentials (warrant, postgres, password) in live/Kubernetes posture
	if _, err := ResolveAndValidateDatabaseURL(getenv); err != nil {
		return err
	}

	// Enforce F1: require authoritative publisher & rulepack public keys in live/Kubernetes posture and ban legacy string seeds everywhere
	if _, _, err := crypto.ResolveAuthorityCustody(crypto.DefaultPublisherCustodyConfig(), getenv); err != nil {
		return err
	}
	if _, _, err := crypto.ResolveAuthorityCustody(crypto.DefaultRulepackCustodyConfig(), getenv); err != nil {
		return err
	}

	return nil
}

// TetragonSensorToken returns the dedicated sensor authentication token required by POST /api/v1/telemetry/tetragon.
func (o *ControlPlaneOrchestrator) TetragonSensorToken() string {
	return o.tetragonSensorToken
}

// BootstrapAdminToken returns the configured out-of-band IAM registrar token (if set).
func (o *ControlPlaneOrchestrator) BootstrapAdminToken() string {
	return o.bootstrapAdminToken
}

// OperatorToken returns the configured dedicated operator token (if set).
func (o *ControlPlaneOrchestrator) OperatorToken() string {
	return o.operatorToken
}

// AutomationToken returns the configured dedicated automation token (if set).
func (o *ControlPlaneOrchestrator) AutomationToken() string {
	return o.automationToken
}

// IntakeToken returns the configured scanner intake token (if set).
func (o *ControlPlaneOrchestrator) IntakeToken() string {
	return o.intakeToken
}

// IsProductionOrLivePosture returns true whenever WARRANT_CLUSTER_DRIVER=kubernetes, WARRANT_POSTURE=live, or feed mode is live.
func (o *ControlPlaneOrchestrator) IsProductionOrLivePosture(ctx context.Context) bool {
	if crypto.IsLiveOrKubernetesPosture(os.Getenv) {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("WARRANT_FEED_MODE")), "live") {
		return true
	}
	if o.Store != nil {
		if st, err := o.Store.GetLiveFeedStatus(ctx); err == nil && strings.EqualFold(st.Config.Mode, models.FeedModeLive) {
			return true
		}
	}
	return false
}

// VerifyBootstrapUnsealedAuth enforces one-shot genesis bootstrap enrollment:
// once bootstrap_state.sealed == TRUE, WARRANT_BOOTSTRAP_ADMIN_TOKEN is permanently disabled (HTTP 403).
func (o *ControlPlaneOrchestrator) VerifyBootstrapUnsealedAuth(ctx context.Context, r *http.Request) (int, error) {
	st, err := o.Store.GetBootstrapState(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("read bootstrap_state: %w", err)
	}
	if st.Sealed {
		return http.StatusForbidden, fmt.Errorf("BOOTSTRAP_SEALED_REQUIRES_DUAL_KEY_DSSE: genesis bootstrap was permanently sealed (%s); submit a 2-of-2 DSSE Principal Governance envelope", st.SealedReason)
	}
	return o.VerifyBootstrapAdminAuth(r)
}

// VerifyBootstrapAdminAuth enforces out-of-band IAM registrar authentication prior to bootstrap sealing.
func (o *ControlPlaneOrchestrator) VerifyBootstrapAdminAuth(r *http.Request) (int, error) {
	if strings.TrimSpace(o.bootstrapAdminToken) == "" {
		return http.StatusForbidden, fmt.Errorf("PRINCIPAL_ENROLLMENT_DISABLED: configure WARRANT_BOOTSTRAP_ADMIN_TOKEN to enable genesis principal enrollment")
	}
	tok := strings.TrimSpace(r.Header.Get("X-Warrant-Admin-Token"))
	if tok == "" {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			tok = strings.TrimSpace(auth[7:])
		}
	}
	if tok == "" {
		return http.StatusUnauthorized, fmt.Errorf("MISSING_BOOTSTRAP_ADMIN_TOKEN: X-Warrant-Admin-Token or Authorization Bearer required")
	}
	if strings.HasPrefix(tok, "g1aud_") || strings.HasPrefix(tok, "g1tet_") {
		return http.StatusForbidden, fmt.Errorf("INVALID_BOOTSTRAP_ADMIN_TOKEN: auditor and sensor tokens cannot enroll AC-5 principals")
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(o.bootstrapAdminToken)) != 1 {
		return http.StatusForbidden, fmt.Errorf("INVALID_BOOTSTRAP_ADMIN_TOKEN")
	}
	return http.StatusOK, nil
}

func (o *ControlPlaneOrchestrator) verifyRequestScopedDSSE(
	ctx context.Context,
	r *http.Request,
	expectedAction string,
	rawBody []byte,
) (string, *models.PrincipalGovernancePayload, bool, int, error) {
	bodyHash := crypto.SHA256Hex(rawBody)

	// 1. Check X-Warrant-Governance-DSSE detached header
	if hdrB64 := strings.TrimSpace(r.Header.Get("X-Warrant-Governance-DSSE")); hdrB64 != "" {
		envRaw, err := crypto.DecodeBase64Any(hdrB64)
		if err != nil {
			return "", nil, true, http.StatusUnauthorized, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: invalid X-Warrant-Governance-DSSE base64: %w", err)
		}
		var env crypto.Envelope
		if err := json.Unmarshal(envRaw, &env); err != nil {
			return "", nil, true, http.StatusUnauthorized, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: invalid X-Warrant-Governance-DSSE JSON: %w", err)
		}
		gp, singleRes, vErr := o.N1Warrant.VerifyRequestScopedSingleGovernanceEnvelope(ctx, env, expectedAction, r.Method, r.URL.Path, bodyHash, true)
		if vErr != nil {
			return "", nil, true, http.StatusUnauthorized, vErr
		}
		return singleRes.Signer.PrincipalID, gp, true, http.StatusOK, nil
	}

	// 2. Check if rawBody itself is a DSSE Principal Governance envelope
	if len(bytesTrimSpace(rawBody)) > 0 {
		var probe struct {
			PayloadType string `json:"payloadType"`
		}
		if json.Unmarshal(rawBody, &probe) == nil && probe.PayloadType != "" {
			var env crypto.Envelope
			if err := json.Unmarshal(rawBody, &env); err != nil {
				return "", nil, true, http.StatusUnauthorized, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: decode DSSE envelope: %w", err)
			}
			gp, singleRes, vErr := o.N1Warrant.VerifyRequestScopedSingleGovernanceEnvelope(ctx, env, expectedAction, r.Method, r.URL.Path, bodyHash, false)
			if vErr != nil {
				return "", nil, true, http.StatusUnauthorized, vErr
			}
			return singleRes.Signer.PrincipalID, gp, true, http.StatusOK, nil
		}
	}

	return "", nil, false, 0, nil
}

// VerifyOperatorOrSinglePrincipalAuth enforces NIST SP 800-53 Rev 5 IA-2 & AU-10 non-repudiation on human governance routes
// (/api/v1/freeze, /api/v1/pipeline/{id}/emergency-rollback, /api/v1/auditor-tokens, /api/v1/simulate/*):
//   - Always accepts a request-scoped 1-of-2 DSSE/WebAuthn Principal Governance signature (<=5m TTL, single-use nonce).
//   - Permanently rejects WARRANT_AUTOMATION_TOKEN (HTTP 403).
//   - Requires individual 1-of-2 DSSE/WebAuthn signatures whenever WARRANT_CLUSTER_DRIVER=kubernetes or feed mode is live,
//     permitting static WARRANT_OPERATOR_TOKEN fallback ONLY in offline simulator dev/demo mode.
func (o *ControlPlaneOrchestrator) VerifyOperatorOrSinglePrincipalAuth(
	ctx context.Context,
	r *http.Request,
	expectedAction string,
	rawBody []byte,
) (string, *models.PrincipalGovernancePayload, int, error) {
	if code, sepErr := o.RejectEstateReadCredentialOnMutation(r); sepErr != nil {
		return "", nil, code, sepErr
	}
	if actor, gp, attemptedDSSE, code, err := o.verifyRequestScopedDSSE(ctx, r, expectedAction, rawBody); attemptedDSSE {
		return actor, gp, code, err
	}

	autoHdr := strings.TrimSpace(r.Header.Get("X-Warrant-Automation-Token"))
	opHdr := strings.TrimSpace(r.Header.Get("X-Warrant-Operator-Token"))
	bearer := ""
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		bearer = strings.TrimSpace(auth[7:])
	}
	tok := opHdr
	if tok == "" {
		tok = autoHdr
	}
	if tok == "" {
		tok = bearer
	}

	if autoHdr != "" || (o.automationToken != "" && tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(o.automationToken)) == 1) {
		return "", nil, http.StatusForbidden, fmt.Errorf("AUTOMATION_TOKEN_FORBIDDEN_ON_HUMAN_GOVERNANCE_ROUTE: WARRANT_AUTOMATION_TOKEN is scoped strictly to /api/v1/feeds/* and /api/v1/ledger/checkpoints")
	}
	if strings.HasPrefix(tok, "g1aud_") || strings.HasPrefix(tok, "g1tet_") {
		return "", nil, http.StatusForbidden, fmt.Errorf("INVALID_OPERATOR_CREDENTIAL: auditor and sensor tokens cannot execute governance mutations")
	}
	if code, sepErr := o.RejectEstateReadCredentialOnMutation(r); sepErr != nil {
		return "", nil, code, sepErr
	}

	if o.IsProductionOrLivePosture(ctx) {
		if tok == "" {
			return "", nil, http.StatusUnauthorized, fmt.Errorf("HUMAN_PRINCIPAL_DSSE_REQUIRED: provide an individual 1-of-2 DSSE/WebAuthn signature in live or kubernetes mode (NIST SP 800-53 IA-2 / AU-10)")
		}
		return "", nil, http.StatusForbidden, fmt.Errorf("STATIC_OPERATOR_TOKEN_FORBIDDEN_IN_LIVE_OR_K8S_MODE: shared static bearer tokens cannot authorize human non-repudiation routes when feed mode is live or cluster driver is kubernetes")
	}

	if tok == "" {
		return "", nil, http.StatusUnauthorized, fmt.Errorf("MISSING_OPERATOR_OR_PRINCIPAL_AUTH: provide a request-scoped 1-of-2 DSSE Principal Governance signature or X-Warrant-Operator-Token")
	}
	if o.operatorToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(o.operatorToken)) == 1 {
		return "simulator-dev-operator-token", nil, http.StatusOK, nil
	}
	return "", nil, http.StatusForbidden, fmt.Errorf("INVALID_OPERATOR_CREDENTIAL")
}

// VerifyAutomationOrPrincipalAuth authenticates non-governance automation triggers (POST /api/v1/feeds/* and POST /api/v1/ledger/checkpoints)
// via a request-scoped 1-of-2 DSSE Principal Governance signature, dedicated WARRANT_AUTOMATION_TOKEN, or (in offline simulator mode) WARRANT_OPERATOR_TOKEN.
func (o *ControlPlaneOrchestrator) VerifyAutomationOrPrincipalAuth(
	ctx context.Context,
	r *http.Request,
	expectedAction string,
	rawBody []byte,
) (string, *models.PrincipalGovernancePayload, int, error) {
	if code, sepErr := o.RejectEstateReadCredentialOnMutation(r); sepErr != nil {
		return "", nil, code, sepErr
	}
	if actor, gp, attemptedDSSE, code, err := o.verifyRequestScopedDSSE(ctx, r, expectedAction, rawBody); attemptedDSSE {
		return actor, gp, code, err
	}

	tok := strings.TrimSpace(r.Header.Get("X-Warrant-Automation-Token"))
	if tok == "" {
		tok = strings.TrimSpace(r.Header.Get("X-Warrant-Operator-Token"))
	}
	if tok == "" {
		if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			tok = strings.TrimSpace(auth[7:])
		}
	}
	if tok == "" {
		return "", nil, http.StatusUnauthorized, fmt.Errorf("MISSING_AUTOMATION_OR_PRINCIPAL_AUTH: provide X-Warrant-Automation-Token or a request-scoped 1-of-2 DSSE signature")
	}
	if strings.HasPrefix(tok, "g1aud_") || strings.HasPrefix(tok, "g1tet_") {
		return "", nil, http.StatusForbidden, fmt.Errorf("INVALID_AUTOMATION_CREDENTIAL: auditor and sensor tokens cannot trigger feed or checkpoint automation")
	}
	if o.automationToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(o.automationToken)) == 1 {
		return "automation-token-authenticated", nil, http.StatusOK, nil
	}
	if !o.IsProductionOrLivePosture(ctx) && o.operatorToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(o.operatorToken)) == 1 {
		return "simulator-dev-operator-token", nil, http.StatusOK, nil
	}
	return "", nil, http.StatusForbidden, fmt.Errorf("INVALID_AUTOMATION_CREDENTIAL")
}

// VerifyIntakeAuth enforces scanner intake authentication on /api/v1/intake/* whenever WARRANT_CLUSTER_DRIVER=kubernetes,
// WARRANT_FEED_MODE=live (or runtime feed mode is live), or WARRANT_INTAKE_TOKEN is non-empty.
func (o *ControlPlaneOrchestrator) VerifyIntakeAuth(r *http.Request) (int, error) {
	ctx := r.Context()
	tok := strings.TrimSpace(r.Header.Get("X-Warrant-Intake-Token"))
	if tok == "" {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			tok = strings.TrimSpace(auth[7:])
		}
	}
	if strings.HasPrefix(tok, "g1aud_") || strings.HasPrefix(tok, "g1tet_") {
		return http.StatusForbidden, fmt.Errorf("INVALID_INTAKE_CREDENTIAL: auditor and sensor tokens cannot submit scanner intake")
	}

	isLiveOrK8s := o.IsProductionOrLivePosture(ctx)
	requireIntake := o.intakeToken != "" || isLiveOrK8s
	if !requireIntake {
		return http.StatusOK, nil
	}
	if tok == "" {
		return http.StatusUnauthorized, fmt.Errorf("MISSING_INTAKE_TOKEN: X-Warrant-Intake-Token or Authorization Bearer required")
	}
	if o.intakeToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(o.intakeToken)) == 1 {
		return http.StatusOK, nil
	}
	if isLiveOrK8s && o.intakeToken == "" {
		return http.StatusForbidden, fmt.Errorf("INTAKE_TOKEN_NOT_CONFIGURED_ON_SERVER: set WARRANT_INTAKE_TOKEN in .env / server environment when feed mode is live or cluster driver is kubernetes")
	}
	if !isLiveOrK8s && o.operatorToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(o.operatorToken)) == 1 {
		return http.StatusOK, nil
	}
	return http.StatusForbidden, fmt.Errorf("INVALID_INTAKE_CREDENTIAL")
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// IsSimulationAllowed returns false whenever WARRANT_CLUSTER_DRIVER=kubernetes or feed mode is live.
func (o *ControlPlaneOrchestrator) IsSimulationAllowed(ctx context.Context) (bool, string) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("WARRANT_CLUSTER_DRIVER")), "kubernetes") {
		return false, "SIMULATION_ROUTES_DISABLED: /api/v1/simulate/* fault-injection drills are disabled when WARRANT_CLUSTER_DRIVER=kubernetes"
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("WARRANT_FEED_MODE")), "live") {
		return false, "SIMULATION_ROUTES_DISABLED: /api/v1/simulate/* fault-injection drills are disabled when WARRANT_FEED_MODE=live"
	}
	if st, err := o.Store.GetLiveFeedStatus(ctx); err == nil && strings.EqualFold(st.Config.Mode, models.FeedModeLive) {
		return false, "SIMULATION_ROUTES_DISABLED: /api/v1/simulate/* fault-injection drills are disabled while runtime feed mode is live"
	}
	return true, ""
}

// Helper for base64 encoding DSSE header in internal tests if needed.
func EncodeGovernanceHeader(env crypto.Envelope) string {
	raw, _ := json.Marshal(env)
	return base64.StdEncoding.EncodeToString(raw)
}

// VerifyTetragonSensorAuth enforces dedicated eBPF/Tetragon DaemonSet authentication (distinct from operator and g1aud_* auditor tokens)
// via either HMAC-SHA256 (X-Tetragon-Signature-256) or constant-time dedicated sensor bearer token.
func (o *ControlPlaneOrchestrator) VerifyTetragonSensorAuth(r *http.Request, rawBody []byte) (int, error) {
	sigHdr := strings.TrimSpace(r.Header.Get("X-Tetragon-Signature-256"))
	authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
	sensorHdr := strings.TrimSpace(r.Header.Get("X-Tetragon-Sensor-Token"))

	bearer := sensorHdr
	if bearer == "" && strings.HasPrefix(strings.ToLower(authHdr), "bearer ") {
		bearer = strings.TrimSpace(authHdr[7:])
	}

	if sigHdr == "" && bearer == "" {
		return http.StatusUnauthorized, fmt.Errorf("MISSING_TETRAGON_SENSOR_AUTH: dedicated sensor bearer or HMAC signature required")
	}
	if strings.HasPrefix(bearer, "g1aud_") {
		return http.StatusForbidden, fmt.Errorf("INVALID_TETRAGON_SENSOR_CREDENTIAL: auditor tokens cannot submit Tetragon telemetry")
	}

	if o.tetragonHMACSecret != "" && sigHdr != "" {
		providedHex := strings.TrimPrefix(strings.ToLower(sigHdr), "sha256=")
		providedMAC, err := hex.DecodeString(providedHex)
		if err != nil {
			return http.StatusForbidden, fmt.Errorf("INVALID_TETRAGON_SENSOR_HMAC_HEX")
		}
		mac := hmac.New(sha256.New, []byte(o.tetragonHMACSecret))
		_, _ = mac.Write(rawBody)
		if hmac.Equal(providedMAC, mac.Sum(nil)) {
			return http.StatusOK, nil
		}
		return http.StatusForbidden, fmt.Errorf("INVALID_TETRAGON_SENSOR_HMAC_SIGNATURE")
	}

	if o.tetragonSensorToken != "" && bearer != "" {
		if subtle.ConstantTimeCompare([]byte(bearer), []byte(o.tetragonSensorToken)) == 1 {
			return http.StatusOK, nil
		}
	}
	return http.StatusForbidden, fmt.Errorf("INVALID_TETRAGON_SENSOR_CREDENTIAL")
}

// VerifyIGAAuth authenticates inbound HR/IAM lifecycle events on POST /api/v1/iga/events via:
//   1. 1-of-2 DSSE/WebAuthn Principal Governance signature (X-Warrant-Governance-DSSE or DSSE envelope body)
//   2. Constant-time HMAC-SHA256 webhook signature (X-Warrant-IGA-Signature-256 against WARRANT_IGA_WEBHOOK_HMAC_SECRET)
//   3. Dedicated IGA webhook bearer/header token (X-Warrant-IGA-Token / Authorization Bearer against WARRANT_IGA_TOKEN)
func (o *ControlPlaneOrchestrator) VerifyIGAAuth(ctx context.Context, r *http.Request, rawBody []byte) (string, string, *crypto.Envelope, int, error) {
	// Reject auditor and Tetragon sensor tokens immediately
	authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
	bearer := ""
	if strings.HasPrefix(strings.ToLower(authHdr), "bearer ") {
		bearer = strings.TrimSpace(authHdr[7:])
	}
	if strings.HasPrefix(bearer, "g1aud_") || strings.HasPrefix(bearer, "g1tet_") {
		return "", "", nil, http.StatusForbidden, fmt.Errorf("INVALID_IGA_CREDENTIAL: auditor and sensor tokens cannot emit IGA events")
	}

	// 1. Check 1-of-2 DSSE Principal Governance header (X-Warrant-Governance-DSSE)
	if hdrB64 := strings.TrimSpace(r.Header.Get("X-Warrant-Governance-DSSE")); hdrB64 != "" {
		envRaw, err := crypto.DecodeBase64Any(hdrB64)
		if err != nil {
			return "", "", nil, http.StatusUnauthorized, fmt.Errorf("INVALID_IGA_GOVERNANCE_HEADER: %w", err)
		}
		var env crypto.Envelope
		if err := json.Unmarshal(envRaw, &env); err != nil {
			return "", "", nil, http.StatusUnauthorized, fmt.Errorf("INVALID_IGA_GOVERNANCE_JSON: %w", err)
		}
		bodyHash := crypto.SHA256Hex(rawBody)
		_, singleRes, vErr := o.N1Warrant.VerifyRequestScopedSingleGovernanceEnvelope(ctx, env, models.GovActionEmitIGAEvent, r.Method, r.URL.Path, bodyHash, true)
		if vErr != nil {
			return "", "", nil, http.StatusUnauthorized, vErr
		}
		return singleRes.Signer.PrincipalID, models.LineageModePostSeal1Of2, &env, http.StatusOK, nil
	}

	// 2. Check HMAC-SHA256 webhook signature (X-Warrant-IGA-Signature-256)
	sigHdr := strings.TrimSpace(r.Header.Get("X-Warrant-IGA-Signature-256"))
	if sigHdr != "" {
		if o.igaHMACSecret == "" {
			return "", "", nil, http.StatusForbidden, fmt.Errorf("IGA_HMAC_UNCONFIGURED: WARRANT_IGA_WEBHOOK_HMAC_SECRET is not set")
		}
		providedHex := strings.TrimPrefix(strings.ToLower(sigHdr), "sha256=")
		providedMAC, err := hex.DecodeString(providedHex)
		if err != nil {
			return "", "", nil, http.StatusForbidden, fmt.Errorf("INVALID_IGA_HMAC_HEX")
		}
		mac := hmac.New(sha256.New, []byte(o.igaHMACSecret))
		_, _ = mac.Write(rawBody)
		if !hmac.Equal(providedMAC, mac.Sum(nil)) {
			return "", "", nil, http.StatusForbidden, fmt.Errorf("INVALID_IGA_HMAC_SIGNATURE")
		}
		return "iga-hmac-webhook", models.LineageModeIGAWebhookAuth, nil, http.StatusOK, nil
	}

	// 3. Check dedicated IGA token (X-Warrant-IGA-Token or Authorization: Bearer)
	igaHdrTok := strings.TrimSpace(r.Header.Get("X-Warrant-IGA-Token"))
	if igaHdrTok == "" {
		igaHdrTok = bearer
	}
	if o.igaToken != "" {
		if igaHdrTok == "" {
			return "", "", nil, http.StatusUnauthorized, fmt.Errorf("MISSING_IGA_AUTH: provide X-Warrant-Governance-DSSE, X-Warrant-IGA-Signature-256, or X-Warrant-IGA-Token")
		}
		if subtle.ConstantTimeCompare([]byte(igaHdrTok), []byte(o.igaToken)) != 1 {
			return "", "", nil, http.StatusForbidden, fmt.Errorf("INVALID_IGA_TOKEN")
		}
		return "iga-token-webhook", models.LineageModeIGAWebhookAuth, nil, http.StatusOK, nil
	}

	// 4. If neither WARRANT_IGA_TOKEN nor WARRANT_IGA_WEBHOOK_HMAC_SECRET is configured:
	//    require 1-of-2 DSSE or HMAC in live/K8s posture, or allow valid X-Warrant-Operator-Token in local offline simulator mode.
	if o.IsProductionOrLivePosture(ctx) || o.igaHMACSecret != "" {
		return "", "", nil, http.StatusUnauthorized, fmt.Errorf("MISSING_IGA_AUTH: provide 1-of-2 DSSE governance header or HMAC signature")
	}
	opProvided := strings.TrimSpace(r.Header.Get("X-Warrant-Operator-Token"))
	if opProvided == "" {
		opProvided = bearer
	}
	if opProvided == "" {
		return "", "", nil, http.StatusUnauthorized, fmt.Errorf("MISSING_IGA_AUTH: provide 1-of-2 DSSE governance header, HMAC signature, X-Warrant-IGA-Token, or X-Warrant-Operator-Token")
	}
	if o.operatorToken != "" && subtle.ConstantTimeCompare([]byte(opProvided), []byte(o.operatorToken)) == 1 {
		return "sandbox-operator-iga", models.LineageModeIGAWebhookAuth, nil, http.StatusOK, nil
	}
	return "", "", nil, http.StatusForbidden, fmt.Errorf("INVALID_IGA_CREDENTIAL")
}

// NewOrchestrator initializes all five control-plane engines (N1-N5), Live Feed Manager, and production adapters.
func NewOrchestrator(ctx context.Context, store *db.Store, extractorURL, fleetURL, kernelSeed string, webauthnCfg crypto.WebAuthnConfig) (*ControlPlaneOrchestrator, error) {
	pol, err := policy.NewEngine(ctx)
	if err != nil {
		return nil, err
	}
	broker := NewSSEBroker()

	var signer crypto.EnvelopeSigner
	if kmsURL := strings.TrimSpace(envseal.Getenv("WARRANT_KMS_SIGN_URL")); kmsURL != "" {
		kmsSigner, kErr := crypto.NewRemoteKMSSigner(
			kmsURL,
			envseal.Getenv("WARRANT_KMS_BEARER_TOKEN"),
			envseal.Getenv("WARRANT_KMS_KEY_ID"),
			envseal.Getenv("WARRANT_KMS_PUBLIC_KEY_B64"),
		)
		if kErr != nil {
			return nil, fmt.Errorf("configure RemoteKMSSigner: %w", kErr)
		}
		signer = kmsSigner
	} else if strings.TrimSpace(kernelSeed) != "" {
		signer = crypto.NewSeededDevEd25519Signer(kernelSeed)
	} else if keyPath := firstNonEmptyEnv("WARRANT_KERNEL_KEY_PATH", "WARRANT_KERNEL_KEY_FILE"); keyPath != "" {
		fileSigner, fErr := crypto.LoadOrCreateFileEd25519Signer(keyPath)
		if fErr != nil {
			return nil, fmt.Errorf("load/create WARRANT_KERNEL_KEY_PATH: %w", fErr)
		}
		signer = fileSigner
	} else {
		ephSigner, eErr := crypto.NewEphemeralEd25519Signer()
		if eErr != nil {
			return nil, fmt.Errorf("generate ephemeral Ed25519 kernel signer: %w", eErr)
		}
		signer = ephSigner
	}

	store.SetWebAuthnConfig(webauthnCfg)

	// Per-column AAD AES-256-GCM DB secret encryption: fail closed at startup if encrypted
	// rows exist in PostgreSQL without a valid key or with a mismatched key/AAD.
	secretBox, sbErr := crypto.LoadSecretBoxFromEnv(envseal.Getenv)
	if sbErr != nil {
		return nil, fmt.Errorf("configure DB secret encryption key: %w", sbErr)
	}
	if secretBox != nil {
		store.SetSecretBox(secretBox)
	}
	if err := store.ValidateEncryptedSecretsAtStartup(ctx); err != nil {
		return nil, err
	}
	if secretBox == nil && !crypto.IsLiveOrKubernetesPosture(envseal.Getenv) {
		if ephBox, eErr := crypto.NewEphemeralSecretBox(); eErr == nil {
			store.SetSecretBox(ephBox)
		}
	}

	var rotationDSSE *crypto.Envelope
	if prevSeed := strings.TrimSpace(envseal.Getenv("WARRANT_PREV_KERNEL_SEED")); prevSeed != "" {
		prevSigner := crypto.NewSeededDevEd25519Signer(prevSeed)
		if rotEnv, rErr := db.SignKernelKeyRotation(ctx, prevSigner, signer.PublicKey(), signer.BackendMode()); rErr == nil {
			rotationDSSE = rotEnv
		}
	} else if rotFile := strings.TrimSpace(os.Getenv("WARRANT_KERNEL_ROTATION_DSSE_FILE")); rotFile != "" {
		if b, rErr := os.ReadFile(rotFile); rErr == nil {
			var env crypto.Envelope
			if json.Unmarshal(b, &env) == nil {
				rotationDSSE = &env
			}
		}
	}

	// Persist the active kernel verification public key into the append-only PostgreSQL ring
	// so routine warrantd restarts never invalidate previously exported OSCAL 1.1.2 POA&M bundles.
	if err := store.RegisterKernelPublicKey(ctx, signer.PublicKey(), signer.BackendMode(), rotationDSSE); err != nil {
		return nil, fmt.Errorf("register kernel public key in append-only ring: %w", err)
	}
	_ = store.EnsureGenesisSealSigned(ctx, signer)

	if exportPubPath := strings.TrimSpace(os.Getenv("WARRANT_KERNEL_PUBLIC_KEY_EXPORT_PATH")); exportPubPath != "" {
		if dir := filepath.Dir(exportPubPath); dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		pubB64 := base64.StdEncoding.EncodeToString(signer.PublicKey().PublicKeyBytes)
		_ = os.WriteFile(exportPubPath, []byte(pubB64+"\n"), 0644)
	}

	tetToken := strings.TrimSpace(envseal.Getenv("WARRANT_TETRAGON_SENSOR_TOKEN"))
	if tetToken == "" {
		var rnd [16]byte
		_, _ = rand.Read(rnd[:])
		tetToken = "g1tet_" + hex.EncodeToString(rnd[:])
	}
	tetHMAC := strings.TrimSpace(envseal.Getenv("WARRANT_TETRAGON_HMAC_SECRET"))
	adminTok := strings.TrimSpace(envseal.Getenv("WARRANT_BOOTSTRAP_ADMIN_TOKEN"))
	opTok := strings.TrimSpace(envseal.Getenv("WARRANT_OPERATOR_TOKEN"))
	autoTok := strings.TrimSpace(envseal.Getenv("WARRANT_AUTOMATION_TOKEN"))
	inTok := strings.TrimSpace(envseal.Getenv("WARRANT_INTAKE_TOKEN"))
	estReadTok := strings.TrimSpace(envseal.Getenv("WARRANT_ESTATE_READ_TOKEN"))
	igaTok := strings.TrimSpace(envseal.Getenv("WARRANT_IGA_TOKEN"))
	igaHMAC := strings.TrimSpace(envseal.Getenv("WARRANT_IGA_WEBHOOK_HMAC_SECRET"))

	n1, err := warrant.NewEngine(ctx, store, pol, webauthnCfg, broker.Broadcast, signer)
	if err != nil {
		return nil, err
	}
	n4 := agentcp.NewControlPlane(store, signer, extractorURL, broker.Broadcast)
	n4.SetPolicyEngine(pol)
	if err := n1.BootstrapSystemControlPlaneIdentities(ctx, n4.InternalWorkerManifests()); err != nil {
		return nil, fmt.Errorf("bootstrap internal N4 agent workload identities: %w", err)
	}
	feedMgr, err := feeds.NewManager(ctx, store, n4, broker.Broadcast)
	if err != nil {
		return nil, err
	}

	rulepacks, err := adapters.NewRulepackRegistryFromEnv(os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("configure rulepack authority custody: %w", err)
	}
	var shield adapters.ShieldEnforcer
	var deploy adapters.DeploymentTarget
	var twin adapters.TwinRunner

	if strings.EqualFold(strings.TrimSpace(os.Getenv("WARRANT_CLUSTER_DRIVER")), "kubernetes") {
		liveK8s, kErr := adapters.NewLiveKubernetesAdapterFromEnv(rulepacks)
		if kErr != nil {
			return nil, fmt.Errorf("initialize LiveKubernetesAdapter: %w", kErr)
		}
		shield = liveK8s
		deploy = liveK8s
		twin = liveK8s
	} else {
		simShield := adapters.NewCiliumShieldAdapter(fleetURL, rulepacks)
		simShield.SetHTTPTransport(n4.NewGovernedRoundTripper("cilium-shield", nil))
		simK8s := adapters.NewK8sRolloutAdapter(fleetURL)
		simK8s.SetHTTPTransport(n4.NewGovernedRoundTripper("k8s-rollout", nil))
		shield = simShield
		deploy = simK8s
		twin = simK8s
	}

	fixProv, err := adapters.NewFixProviderFromEnv(os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("configure publisher authority custody: %w", err)
	}
	if dfp, ok := any(fixProv).(*adapters.DeterministicFixProvider); ok && dfp != nil {
		n1.SetPublisherPublicKey(ed25519.PublicKey(dfp.PublisherPublicKey().PublicKeyBytes))
	}
	sarifIn := adapters.NewSARIFIntakeAdapter(n4)

	connPersistPath := strings.TrimSpace(os.Getenv("WARRANT_CONNECTOR_CONFIG_PATH"))
	connOverrides := map[string]string{}
	if connPersistPath != "" {
		if rawCfg, rErr := os.ReadFile(connPersistPath); rErr == nil && len(rawCfg) > 0 {
			_ = json.Unmarshal(rawCfg, &connOverrides)
		}
	}
	if dbConns, dbErr := store.LoadVendorConnectorConfigs(ctx); dbErr == nil {
		for k, v := range dbConns {
			connOverrides[k] = v
		}
	}
	initGetenv := func(k string) string {
		if v, ok := connOverrides[k]; ok {
			return v
		}
		return envseal.Getenv(k)
	}

	// Wrap base K8s/Cilium ShieldEnforcer in the Multi-Substrate Shield Router (Kubernetes + AWS EC2 SG/IMDSv2 + Azure NSG + GCP Firewall + Linux nftables + Windows WFP)
	shield = shields.NewMultiSubstrateShieldRouter(shield, n4.NewGovernedRoundTripper("cilium-shield", nil), rulepacks, initGetenv)

	n2 := gate.NewEngine(store, pol, n1, n4, deploy, broker.Broadcast)
	n3 := verify.NewEngine(store, pol, n1, n4, shield, deploy, twin, broker.Broadcast, rulepacks)
	if vmTwinProv, vmErr := vmtwins.NewVMTwinProviderFromEnv(n4.NewGovernedRoundTripper("distributor-gateway", nil), os.Getenv); vmErr != nil {
		return nil, fmt.Errorf("initialize VMTwinProvider: %w", vmErr)
	} else if vmTwinProv != nil {
		n3.SetVMTwinProvider(vmTwinProv)
	}

	n5 := ledger.NewEngine(store, pol, n1, signer, broker.Broadcast)
	distReg := adapters.NewDistributorRegistry()
	distributors.RegisterAllBuiltinDistributors(distReg, deploy, n4.NewGovernedRoundTripper("distributor-gateway", nil), initGetenv)

	estateReg := estatereader.NewRegistry()
	localK8sReader := func(rCtx context.Context, scopeServices []string) ([]models.EstateService, error) {
		allSvcs, sErr := store.ListEstateServices(rCtx)
		if sErr != nil {
			return nil, sErr
		}
		if len(scopeServices) == 0 {
			return allSvcs, nil
		}
		want := map[string]bool{}
		for _, s := range scopeServices {
			if s == "*" {
				return allSvcs, nil
			}
			want[strings.TrimSpace(s)] = true
		}
		var filtered []models.EstateService
		for _, svc := range allSvcs {
			if want[svc.ServiceID] {
				filtered = append(filtered, svc)
			}
		}
		return filtered, nil
	}
	if erErr := estatereader.RegisterAllBuiltinEstateReaders(estateReg, localK8sReader, n4.NewGovernedRoundTripper("estate-reader", nil), initGetenv); erErr != nil {
		return nil, fmt.Errorf("initialize EstateReader registry: %w", erErr)
	}
	n3.SetEstateReaders(estateReg)
	store.SetBootstrapSealAnchorFunc(n5.CreateCheckpoint)

	if warn := ExternalAnchorStartupWarning(os.Getenv); warn != "" {
		log.Printf("%s", warn)
	}

	// Anchor initial 9-chain Merkle checkpoint covering kernel_public_keys & system workload identities
	_, _ = n5.CreateCheckpoint(ctx)

	return &ControlPlaneOrchestrator{
		Store:                store,
		Policy:               pol,
		N1Warrant:            n1,
		N2Gate:               n2,
		N3Verify:             n3,
		N4AgentCP:            n4,
		N5Ledger:             n5,
		Feeds:                feedMgr,
		SARIFIntake:          sarifIn,
		FixProvider:          fixProv,
		Shield:               shield,
		Deploy:               deploy,
		Twin:                 twin,
		Distributors:         distReg,
		EstateReaders:        estateReg,
		Broker:               broker,
		WebAuthnCfg:          webauthnCfg,
		fleetURL:             strings.TrimRight(strings.TrimSpace(fleetURL), "/"),
		localK8sReader:       localK8sReader,
		connectorOverrides:   connOverrides,
		connectorPersistPath: connPersistPath,
		tetragonSensorToken:  tetToken,
		tetragonHMACSecret:   tetHMAC,
		bootstrapAdminToken:  adminTok,
		operatorToken:        opTok,
		automationToken:      autoTok,
		intakeToken:          inTok,
		estateReadToken:      estReadTok,
		igaToken:             igaTok,
		igaHMACSecret:        igaHMAC,
	}, nil
}

// ExecuteSARIFRemediation runs the deterministic 5-stage Race Pipeline for an incoming SARIF 2.1.0 report.
func (o *ControlPlaneOrchestrator) ExecuteSARIFRemediation(ctx context.Context, rawSARIF []byte, patchProfile string) ([]models.RemediationItem, error) {
	return o.ExecuteSARIFRemediationWithOptions(ctx, rawSARIF, patchProfile, "", "", 0)
}

// ExecuteSARIFRemediationWithOptions ingests Wiz/GitHub/Tenable or native aquasec/trivy SARIF 2.1.0 reports,
// cross-references findings against the synced CISA KEV catalog, and drives the 5-stage Race Pipeline.
func (o *ControlPlaneOrchestrator) ExecuteSARIFRemediationWithOptions(
	ctx context.Context,
	rawSARIF []byte,
	patchProfile string,
	targetService string,
	vulnDigest string,
	maxFindings int,
) ([]models.RemediationItem, error) {
	if patchProfile == "" {
		patchProfile = "STATELESS_CLEAN"
	}

	// If targetService was passed (e.g., from Trivy sidecar) without an explicit digest, default to service's current digest
	if targetService != "" && vulnDigest == "" {
		if svc, err := o.Store.GetEstateService(ctx, targetService); err == nil {
			vulnDigest = svc.CurrentDigest
		}
	}

	// Stage 1: Zero-privilege SARIF extraction via N4 -> warrant-extractor (agt-warrant-extractor / AUTONOMOUS_WORKLOAD_SPONSORED)
	findingSet, err := o.N4AgentCP.ExtractSARIFWithOptionsGoverned(
		ctx, models.AuthorityModeAutonomousSponsored, "", "sarif-intake-stream", "NONE", "NONE",
		rawSARIF, targetService, vulnDigest, maxFindings,
	)
	if err != nil {
		return nil, err
	}

	// Live CISA KEV Catalog Cross-Check
	kevCatalog, _ := o.Store.LookupCISAKEVSet(ctx)
	kevMatchCount := 0
	for i := range findingSet.Findings {
		if _, inKEV := kevCatalog[strings.ToUpper(findingSet.Findings[i].CVEID)]; inKEV {
			findingSet.Findings[i].IsKEV = true
		}
		if findingSet.Findings[i].IsKEV {
			kevMatchCount++
		}
	}
	if strings.EqualFold(findingSet.ScannerToolID, "Trivy") && o.Feeds != nil {
		o.Feeds.RecordTrivyIntake(ctx, findingSet, kevMatchCount)
	}

	// Avoid duplicating identical (service_id, cve_id) items when periodic Trivy scanner loops run
	existingByKey := map[string]models.RemediationItem{}
	if maxFindings > 0 {
		if existingList, lErr := o.Store.ListRemediations(ctx); lErr == nil {
			for _, ex := range existingList {
				existingByKey[ex.ServiceID+"|"+strings.ToUpper(ex.CVEID)] = ex
			}
		}
	}

	results := make([]models.RemediationItem, 0, len(findingSet.Findings))
	for _, f := range findingSet.Findings {
		if maxFindings > 0 {
			if prev, exists := existingByKey[f.TargetServiceID+"|"+strings.ToUpper(f.CVEID)]; exists {
				results = append(results, prev)
				continue
			}
		}
		svc, err := o.Store.GetEstateService(ctx, f.TargetServiceID)
		if err != nil {
			return nil, fmt.Errorf("unknown target service %q: %w", f.TargetServiceID, err)
		}

		remID := "rem-" + uuid.NewString()[:8]
		now := time.Now().UTC()
		item := models.RemediationItem{
			RemediationID:         remID,
			RemediationKind:       models.RemediationKindImagePatch,
			CVEID:                 f.CVEID,
			CWEID:                 f.CWEID,
			IsKEV:                 f.IsKEV,
			ChainedExploitEnabler: f.ChainedExploitEnabler,
			CVSSScore:             f.CVSSScore,
			ServiceID:             svc.ServiceID,
			VulnerableDigest:      f.VulnerableDigest,
			PatchedDigest:         f.PatchedDigest,
			PackagePURL:           f.PackagePURL,
			VulnerableSymbol:      f.VulnerableSymbol,
			ExploitVector:         f.ExploitVector,
			Stage:                 models.StageIntakeRepro,
			StatusHealth:          models.HealthNormal,
			PodSweepTotal:         svc.Replicas,
			BridgeSLAMIN:          60,
			CreatedAt:             now,
			UpdatedAt:             now,
		}

		// Match governing active N1 Standing Warrant (with Attack-Path CWE Weighting for CWE-209/918/434)
		matchedWarrant, wErr := o.Store.FindMatchingWarrant(ctx, svc.ServiceID, f.CVSSScore, f.CWEID)
		s1ID, s2ID := "UNBOUND", "UNBOUND"
		if wErr == nil {
			item.WarrantID = matchedWarrant.WarrantID
			item.ClassBindingStatus = models.ClassBindingStatusBound
			item.BridgeSLAMIN = matchedWarrant.SLABridgeMinutes
			s1ID = matchedWarrant.Slot1PrincipalID
			s2ID = matchedWarrant.Slot2PrincipalID
		} else {
			item.ClassBindingStatus = models.ClassBindingStatusUnbound
		}

		if err := o.Store.UpsertRemediation(ctx, &item); err != nil {
			return nil, err
		}
		_ = o.Store.AppendTrace(ctx, models.TraceEvent{
			TraceID:       "trc-" + uuid.NewString()[:8],
			RemediationID: remID,
			Engine:        "N4",
			StepCode:      "SARIF_EXTRACTED_TYPED_SCHEMA",
			Outcome:       "PASS",
			ActorOrToken:  "warrant-extractor",
			EvidenceHash:  findingSet.TypedOutputSHA256,
			Fields: map[string]string{
				"cve_id":           f.CVEID,
				"raw_input_sha256": findingSet.RawInputSHA256,
				"scanner":          findingSet.ScannerToolID,
			},
			OccurredAt: now,
		})

		// Stage 2: Bridge Before Patch — deploy CiliumNetworkPolicy + K8s NetPol + Envoy mTLS containment bridge immediately
		bridgeID := "brg-" + uuid.NewString()[:8]
		blockerReason := "AUTONOMOUS_CANARY_IN_PROGRESS"
		if patchProfile == "UPSTREAM_VENDOR_PENDING" {
			blockerReason = "AWAITING_UPSTREAM_VENDOR_PATCH"
		} else if wErr != nil {
			blockerReason = "NO_VALID_STANDING_WARRANT_FAIL_CLOSED"
		}
		bridge, err := o.Shield.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
			BridgeID:                 bridgeID,
			RemediationID:            remID,
			ServiceID:                svc.ServiceID,
			Namespace:                svc.Namespace,
			CVEID:                    f.CVEID,
			CWEID:                    f.CWEID,
			ExploitVector:            f.ExploitVector,
			AffectedPort:             f.AffectedPort,
			BlockedPaths:             f.BlockedPaths,
			AllowedEgressServices:    svc.AllowedEgressServices,
			AllowKubeAPIServerEgress: svc.AllowKubeAPIServerEgress,
			SLABridgeMinutes:         item.BridgeSLAMIN,
			BlockerReasonCode:        blockerReason,
		})
		if err != nil {
			return nil, err
		}
		if err := o.Store.UpsertBridge(ctx, *bridge); err != nil {
			return nil, err
		}
		if item.WarrantID != "" {
			_ = o.N4AgentCP.RecordGovernedAdapterAction(
				ctx, item.WarrantID, remID, "cilium_shield", svc.ServiceID,
				"APPLY_CILIUM_CONTAINMENT_BRIDGE", s1ID, s2ID, "INTERNAL_CLUSTER_ONLY",
				findingSet.TypedOutputSHA256, crypto.SHA256Hex([]byte(bridge.CiliumManifestYAML)),
			)
		}

		bridgedTime := time.Now().UTC()
		item.Stage = models.StageBridgedContained
		item.StatusHealth = models.HealthBridged
		item.BridgeID = bridge.BridgeID
		item.BridgedAt = &bridgedTime
		_ = o.Store.UpsertRemediation(ctx, &item)
		_ = o.Store.AppendTrace(ctx, models.TraceEvent{
			TraceID:       "trc-" + uuid.NewString()[:8],
			RemediationID: remID,
			Engine:        "ADAPTER",
			StepCode:      "CILIUM_SHIELD_BRIDGE_ARMED",
			Outcome:       "PASS",
			ActorOrToken:  bridge.BridgeID,
			EvidenceHash:  crypto.SHA256Hex([]byte(bridge.CiliumManifestYAML)),
			Fields: map[string]string{
				"bridge_type": bridge.BridgeType,
				"sla_minutes": fmt.Sprintf("%d", bridge.SLABridgeMinutes),
			},
			OccurredAt: bridgedTime,
		})
		o.Broker.Broadcast("BRIDGE_ARMED", bridge)
		o.Broker.Broadcast("REMEDIATION_UPDATED", item)

		// Item 1 Doctrine: Never set EXCEPTION_ROUTED or create Four-Eyes PENDING_DUAL_KEY rows on ingest!
		// Containment bridge is armed autonomously; unbound findings wait passively until a separate 2-of-2 class act.
		if wErr != nil {
			item.StatusHealth = models.HealthBridged
			item.ClassBindingStatus = models.ClassBindingStatusUnbound
			item.BlockerCode = "NO_ACTIVE_WARRANT_FAIL_CLOSED"
			_ = o.Store.UpsertRemediation(ctx, &item)
			_ = o.Store.AppendTrace(ctx, models.TraceEvent{
				TraceID:       "trc-" + uuid.NewString()[:8],
				RemediationID: remID,
				Engine:        "N1",
				StepCode:      "WARRANT_LOOKUP",
				Outcome:       "BLOCK",
				ActorOrToken:  "n1-kernel",
				EvidenceHash:  crypto.SHA256Hex([]byte(wErr.Error())),
				Fields:        map[string]string{"reason": wErr.Error(), "class_binding_status": models.ClassBindingStatusUnbound},
			})
			o.Broker.Broadcast("REMEDIATION_UPDATED", item)
			results = append(results, item)
			continue
		}

		// Hold safely at Bridged / Contained if upstream vendor patch is not yet available
		if patchProfile == "UPSTREAM_VENDOR_PENDING" {
			item.BlockerCode = "AWAITING_UPSTREAM_VENDOR_PATCH"
			_ = o.Store.UpsertRemediation(ctx, &item)
			results = append(results, item)
			continue
		}

		// Resolve & verify cryptographic publisher provenance on patch artifact
		signedArt, err := o.FixProvider.ResolveSignedPatch(ctx, f, patchProfile)
		if err != nil {
			return nil, err
		}
		if err := o.FixProvider.VerifyProvenance(*signedArt); err != nil {
			item.StatusHealth = models.HealthRollbackFailed
			item.BlockerCode = err.Error()
			_ = o.Store.UpsertRemediation(ctx, &item)
			results = append(results, item)
			continue
		}
		item.PatchedDigest = signedArt.PatchedDigest
		_ = o.Store.AppendTrace(ctx, models.TraceEvent{
			TraceID:       "trc-" + uuid.NewString()[:8],
			RemediationID: remID,
			Engine:        "N4",
			StepCode:      "ARTIFACT_PROVENANCE_VERIFIED",
			Outcome:       "PASS",
			ActorOrToken:  signedArt.PublisherKeyID,
			EvidenceHash:  crypto.SHA256Hex([]byte(signedArt.ProvenanceSigB64)),
			Fields: map[string]string{
				"patched_digest": signedArt.PatchedDigest,
				"publisher_id":   signedArt.PublisherID,
			},
		})

		// Extract untrusted unified diff through isolated warrant-extractor (enforcing N4 Build/Agent Config Exclusion)
		patchMeta, err := o.N4AgentCP.ExtractDiffGoverned(
			ctx, item.WarrantID, remID, svc.ServiceID, s1ID, s2ID, signedArt.PatchedDigest, signedArt.UnifiedDiff,
		)
		if err != nil {
			if strings.Contains(err.Error(), "N4_FORBIDDEN_CONFIG_POISONING_BLOCKED") {
				item.PatchMetadata = patchMeta
				item.StatusHealth = models.HealthExceptionRouted
				item.BlockerCode = err.Error()
				_ = o.Store.UpsertRemediation(ctx, &item)
				_ = o.Store.AppendTrace(ctx, models.TraceEvent{
					TraceID:       "trc-" + uuid.NewString()[:8],
					RemediationID: remID,
					Engine:        "N4",
					StepCode:      "BUILD_OR_AGENT_CONFIG_POISONING_BLOCKED",
					Outcome:       "BLOCK",
					ActorOrToken:  "n4-control-plane",
					EvidenceHash:  crypto.SHA256Hex([]byte(err.Error())),
					Fields:        map[string]string{"violation": err.Error(), "active_bridge": item.BridgeID},
				})
				o.Broker.Broadcast("REMEDIATION_UPDATED", item)
				results = append(results, item)
				continue
			}
			return nil, err
		}

		// Stage 2.5 (v1.3.0 Item 2): Run 3-Clone Isolated Proving Ground BEFORE N2 Canary Promotion
		if _, pErr := o.N3Verify.RunCloneTwinProving(ctx, &item, svc, nil, patchMeta); pErr != nil {
			results = append(results, item)
			continue
		}

		// Stage 3: N2 Gate + Differential Shadow Canary
		if err := o.N2Gate.EvaluateAndRollout(ctx, &item, svc, patchMeta, false); err != nil {
			// Routed to Four-Eyes Exception Queue, Frozen, or Rolled Back safely with Bridge still armed
			results = append(results, item)
			continue
		}

		// Stage 4: N3 Twin Replay + Passive Fleet Attestation + Permanent Admission Lockout + Bridge Retirement
		verBundle, err := o.N3Verify.VerifyLockAndRetireBridge(ctx, &item, svc)
		if err != nil {
			results = append(results, item)
			continue
		}

		// Stage 5: N5 OSCAL 1.1.2 POA&M Minting & DSSE Attestation Closure
		if _, err := o.N5Ledger.MintOSCALAttestation(ctx, &item, svc, verBundle); err != nil {
			results = append(results, item)
			continue
		}
		results = append(results, item)
	}

	return results, nil
}

// ApproveOrRejectException processes a 2-of-2 Four-Eyes Exception decision and resumes rollout if APPROVED.
func (o *ControlPlaneOrchestrator) ApproveOrRejectException(ctx context.Context, exceptionID, decision string, env crypto.Envelope) (*models.CeilingException, *models.RemediationItem, error) {
	ex, err := o.N1Warrant.ResolveCeilingException(ctx, exceptionID, decision, env)
	if err != nil {
		return nil, nil, err
	}
	rem, err := o.Store.GetRemediation(ctx, ex.RemediationID)
	if err != nil {
		return ex, nil, err
	}
	if decision == "REJECTED" {
		rem.BlockerCode = "FOUR_EYES_EXCEPTION_REJECTED_HOLDING_BRIDGE"
		_ = o.Store.UpsertRemediation(ctx, rem)
		return ex, rem, nil
	}

	svc, err := o.Store.GetEstateService(ctx, rem.ServiceID)
	if err != nil {
		return ex, rem, err
	}
	if hasProv, _ := o.N3Verify.DeriveVerifiedArtifactProvenance(ctx, rem); !hasProv {
		signedArt, rErr := o.FixProvider.ResolveSignedPatch(ctx, models.ExtractedFinding{
			CVEID:            rem.CVEID,
			CWEID:            rem.CWEID,
			CVSSScore:        rem.CVSSScore,
			TargetServiceID:  svc.ServiceID,
			VulnerableDigest: rem.VulnerableDigest,
			PatchedDigest:    rem.PatchedDigest,
			VulnerableSymbol: rem.VulnerableSymbol,
			ExploitVector:    rem.ExploitVector,
		}, "STATELESS_CLEAN")
		if rErr != nil {
			return ex, rem, rErr
		}
		if vErr := o.FixProvider.VerifyProvenance(*signedArt); vErr != nil {
			return ex, rem, vErr
		}
		rem.PatchedDigest = signedArt.PatchedDigest
		_ = o.Store.AppendTrace(ctx, models.TraceEvent{
			TraceID:       "trc-" + uuid.NewString()[:8],
			RemediationID: rem.RemediationID,
			Engine:        "N4",
			StepCode:      "ARTIFACT_PROVENANCE_VERIFIED",
			Outcome:       "PASS",
			ActorOrToken:  signedArt.PublisherKeyID,
			EvidenceHash:  crypto.SHA256Hex([]byte(signedArt.ProvenanceSigB64)),
			Fields: map[string]string{
				"patched_digest": signedArt.PatchedDigest,
				"publisher_id":   signedArt.PublisherID,
			},
			OccurredAt: time.Now().UTC(),
		})
	}
	patchMeta := rem.PatchMetadata
	if patchMeta == nil {
		patchMeta = &models.ExtractedPatchMetadata{
			PatchedDigest:         rem.PatchedDigest,
			APIBackwardCompatible: true,
			StatelessEligible:     true,
		}
	}
	_ = o.Store.AppendTrace(ctx, models.TraceEvent{
		TraceID:       "trc-" + uuid.NewString()[:8],
		RemediationID: rem.RemediationID,
		Engine:        "N1",
		StepCode:      "FOUR_EYES_EXCEPTION_APPROVED",
		Outcome:       "PASS",
		ActorOrToken:  exceptionID,
		EvidenceHash:  crypto.SHA256Hex([]byte(exceptionID)),
		Fields:        map[string]string{"decision": "APPROVED"},
	})
	if _, pErr := o.N3Verify.RunCloneTwinProving(ctx, rem, svc, nil, patchMeta); pErr != nil {
		return ex, rem, pErr
	}
	if err := o.N2Gate.EvaluateAndRollout(ctx, rem, svc, patchMeta, true); err != nil {
		return ex, rem, err
	}
	verBundle, err := o.N3Verify.VerifyLockAndRetireBridge(ctx, rem, svc)
	if err != nil {
		return ex, rem, err
	}
	if _, err := o.N5Ledger.MintOSCALAttestation(ctx, rem, svc, verBundle); err != nil {
		return ex, rem, err
	}
	return ex, rem, nil
}

// IngestOSVAdvisoryToPipeline routes a sanitized OSV.dev SBOM advisory into the 5-stage Race Pipeline.
func (o *ControlPlaneOrchestrator) IngestOSVAdvisoryToPipeline(ctx context.Context, osvID, serviceID string) ([]models.RemediationItem, error) {
	advisories, err := o.Store.ListOSVAdvisories(ctx)
	if err != nil {
		return nil, err
	}
	for _, adv := range advisories {
		if strings.EqualFold(adv.OSVID, osvID) && (serviceID == "" || adv.ServiceID == serviceID) {
			svc, err := o.Store.GetEstateService(ctx, adv.ServiceID)
			if err != nil {
				return nil, err
			}
			cve := adv.CVEID
			if cve == "" || cve == "CVE-0000-0000" {
				cve = "CVE-2023-44487"
			}
			patchedDigest := "sha256:" + crypto.SHA256Hex([]byte(svc.ServiceID+"|"+adv.OSVID+"|"+adv.FixedVersion))
			sarif := BuildDeterministicSARIF(
				cve, adv.CWEID, adv.CVSSScore, adv.IsKEV, svc.ServiceID,
				svc.CurrentDigest, patchedDigest, "", "HTTP2_RAPID_RESET", 8080,
			)
			return o.ExecuteSARIFRemediationWithOptions(ctx, sarif, "STATELESS_CLEAN", svc.ServiceID, svc.CurrentDigest, 1)
		}
	}
	return nil, fmt.Errorf("OSV advisory %q not found", osvID)
}

// ExecuteSecretRotationRemediation ingests Gitleaks / GitGuardian / cloud secret-exposure scan findings
// through warrant-extractor (stripping raw secrets), clamps egress & 169.254.169.254 metadata access immediately,
// verifies a 2-of-2 SECRET-ROTATION-STATELESS Standing Warrant, revokes/rotates the workload ExternalSecret or SA token
// with rolling restart in seconds, and mints a DSSE-signed NIST OSCAL 1.1.2 POA&M closure attestation.
func (o *ControlPlaneOrchestrator) ExecuteSecretRotationRemediation(ctx context.Context, rawSecretScan []byte, targetService string) ([]models.RemediationItem, error) {
	intakeAsset := targetService
	if intakeAsset == "" {
		intakeAsset = "secret-intake-stream"
	}
	secretSet, err := o.N4AgentCP.ExtractSecretFindingsGoverned(
		ctx, models.AuthorityModeAutonomousSponsored, "", intakeAsset, "NONE", "NONE", rawSecretScan,
	)
	if err != nil {
		return nil, err
	}

	results := make([]models.RemediationItem, 0, len(secretSet.Findings))
	for _, sf := range secretSet.Findings {
		svc, err := o.Store.GetEstateService(ctx, sf.TargetServiceID)
		if err != nil {
			return nil, fmt.Errorf("unknown target service %q: %w", sf.TargetServiceID, err)
		}

		remID := "rem-sec-" + uuid.NewString()[:8]
		now := time.Now().UTC()
		item := models.RemediationItem{
			RemediationID:      remID,
			RemediationKind:    models.RemediationKindSecretRotation,
			CVEID:              sf.FindingID,
			CWEID:              "CWE-798",
			IsKEV:              true,
			CVSSScore:          9.6,
			ServiceID:          svc.ServiceID,
			SecretResourceName: sf.SecretResourceName,
			VulnerableDigest:   svc.CurrentDigest,
			PatchedDigest:      svc.CurrentDigest,
			PackagePURL:        svc.CurrentPURL,
			ExploitVector:      "GENERIC_RCE",
			Stage:              models.StageIntakeRepro,
			StatusHealth:       models.HealthNormal,
			PodSweepTotal:      svc.Replicas,
			BridgeSLAMIN:       15,
			CreatedAt:          now,
			UpdatedAt:          now,
		}

		matchedWarrant, wErr := o.Store.FindMatchingSecretWarrant(ctx, svc.ServiceID)
		s1ID, s2ID := "UNBOUND", "UNBOUND"
		if wErr == nil {
			item.WarrantID = matchedWarrant.WarrantID
			item.ClassBindingStatus = models.ClassBindingStatusBound
			item.BridgeSLAMIN = matchedWarrant.SLABridgeMinutes
			s1ID = matchedWarrant.Slot1PrincipalID
			s2ID = matchedWarrant.Slot2PrincipalID
		} else {
			item.ClassBindingStatus = models.ClassBindingStatusUnbound
		}

		if err := o.Store.UpsertRemediation(ctx, &item); err != nil {
			return nil, err
		}
		_ = o.Store.AppendTrace(ctx, models.TraceEvent{
			TraceID:       "trc-" + uuid.NewString()[:8],
			RemediationID: remID,
			Engine:        "N4",
			StepCode:      "SECRET_EXPOSURE_FINGERPRINTED_AND_SANITIZED",
			Outcome:       "PASS",
			ActorOrToken:  "warrant-extractor",
			EvidenceHash:  secretSet.TypedOutputSHA256,
			Fields: map[string]string{
				"finding_id":        sf.FindingID,
				"detector":          sf.DetectorTool,
				"rule_id":           sf.RuleID,
				"secret_resource":   sf.SecretResourceName,
				"secret_fp_sha256":  sf.SecretFingerprintSHA256[:16],
				"plaintext_dropped": "true",
			},
			OccurredAt: now,
		})

		// Immediate N3 Egress & Cloud Metadata (169.254.169.254) Quarantine while rotating credentials
		bridgeID := "brg-sec-" + uuid.NewString()[:8]
		bridge, err := o.Shield.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
			BridgeID:                 bridgeID,
			RemediationID:            remID,
			ServiceID:                svc.ServiceID,
			Namespace:                svc.Namespace,
			CVEID:                    sf.FindingID,
			CWEID:                    "CWE-798",
			AffectedPort:             8080,
			AllowedEgressServices:    svc.AllowedEgressServices,
			AllowKubeAPIServerEgress: svc.AllowKubeAPIServerEgress,
			SLABridgeMinutes:         item.BridgeSLAMIN,
			BlockerReasonCode:        "SECRET_ROTATION_IN_PROGRESS",
		})
		if err != nil {
			return nil, err
		}
		_ = o.Store.UpsertBridge(ctx, *bridge)
		bridgedTime := time.Now().UTC()
		item.Stage = models.StageBridgedContained
		item.StatusHealth = models.HealthBridged
		item.BridgeID = bridge.BridgeID
		item.BridgedAt = &bridgedTime
		_ = o.Store.UpsertRemediation(ctx, &item)

		// Hold passively at BRIDGED (never EXCEPTION_ROUTED or Four-Eyes queue on ingest!) if no active SECRET-ROTATION-STATELESS warrant covers this service
		if wErr != nil {
			item.StatusHealth = models.HealthBridged
			item.ClassBindingStatus = models.ClassBindingStatusUnbound
			item.BlockerCode = "NO_ACTIVE_SECRET_ROTATION_WARRANT_FAIL_CLOSED"
			_ = o.Store.UpsertRemediation(ctx, &item)
			results = append(results, item)
			continue
		}
		if _, revErr := o.N1Warrant.ReverifyWarrantForExecution(ctx, item.WarrantID, svc.ServiceID, 0, svc.Replicas, models.RemediationKindSecretRotation); revErr != nil {
			item.StatusHealth = models.HealthBridged
			item.ClassBindingStatus = models.ClassBindingStatusUnbound
			item.BlockerCode = revErr.Error()
			_ = o.Store.UpsertRemediation(ctx, &item)
			results = append(results, item)
			continue
		}

		// Respect Emergency Freeze
		freeze := o.N1Warrant.CurrentFreezeState()
		if freeze.Mode != models.FreezeModeOperational {
			item.StatusHealth = models.HealthFrozen
			item.BlockerCode = freeze.Mode
			_ = o.Store.UpsertRemediation(ctx, &item)
			results = append(results, item)
			continue
		}

		// Rotate ExternalSecret / Workload SA Token & Rolling Restart under N4 Task Warrant
		rotRes, err := o.Deploy.RotateWorkloadSecret(ctx, svc.ServiceID, sf.SecretResourceKind, sf.SecretResourceName)
		if err != nil {
			return nil, err
		}
		_ = o.N4AgentCP.RecordGovernedAdapterAction(
			ctx, item.WarrantID, remID, "secret_rotator", svc.ServiceID,
			"ROTATE_AND_REVOKE_WORKLOAD_SECRET", s1ID, s2ID, "INTERNAL_CLUSTER_ONLY",
			sf.SecretFingerprintSHA256, rotRes.NewSecretVersionHash,
		)
		item.CanaryWeight = 100
		// Fail closed if upstream secret manager has not rotated the credential value (empty or identical SHA-256)
		secretChanged := strings.TrimSpace(rotRes.NewSecretVersionHash) != "" &&
			strings.TrimSpace(sf.SecretFingerprintSHA256) != "" &&
			!strings.EqualFold(strings.TrimSpace(rotRes.NewSecretVersionHash), strings.TrimSpace(sf.SecretFingerprintSHA256))

		_ = o.Store.AppendTrace(ctx, models.TraceEvent{
			TraceID:       "trc-" + uuid.NewString()[:8],
			RemediationID: remID,
			Engine:        "N4",
			StepCode:      "WORKLOAD_SECRET_ROTATED_AND_REVOKED",
			Outcome:       map[bool]string{true: "PASS", false: "BLOCK"}[secretChanged],
			ActorOrToken:  sf.SecretResourceName,
			EvidenceHash:  rotRes.NewSecretVersionHash,
			Fields: map[string]string{
				"resource_kind":        sf.SecretResourceKind,
				"resource_name":        sf.SecretResourceName,
				"restarted_pods":       fmt.Sprintf("%d", rotRes.RestartedPods),
				"revoked_old_tok":      fmt.Sprintf("%t", rotRes.PreviousTokenRevoked),
				"secret_hash_distinct": fmt.Sprintf("%t", secretChanged),
			},
			OccurredAt: rotRes.RotatedAt,
		})

		verBundle, err := o.N3Verify.VerifyAndRetireSecretRotationBridge(ctx, &item, svc, sf.SecretFingerprintSHA256, rotRes)
		if err != nil {
			results = append(results, item)
			continue
		}
		if _, err := o.N5Ledger.MintOSCALAttestation(ctx, &item, svc, verBundle); err != nil {
			results = append(results, item)
			continue
		}
		results = append(results, item)
	}
	return results, nil
}
