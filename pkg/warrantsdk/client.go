package warrantsdk

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
)

// Client is a thread-safe Go SDK client for the G1-Warrant Control Plane (warrantd).
type Client struct {
	baseURL         string
	httpClient      *http.Client
	auditorToken    string
	sensorToken     string
	adminToken      string
	operatorToken   string
	automationToken string
	intakeToken     string
	estateReadToken string
	signerBundle    *SignerKeyBundle
	userAgent       string
}

// Option configures a Client instance.
type Option func(*Client)

// WithHTTPClient overrides the underlying *http.Client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// WithTimeout configures the HTTP client request timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// WithAuditorToken attaches a scoped 3PAO external auditor bearer token (g1aud_...)
// to outgoing requests. Note that warrantd strictly restricts auditor tokens to /api/v1/auditor/*.
func WithAuditorToken(bearer string) Option {
	return func(c *Client) {
		c.auditorToken = strings.TrimSpace(bearer)
	}
}

// WithSensorToken attaches a dedicated Tetragon/eBPF sensor authentication token (g1tet_...)
// required when submitting runtime drift events to POST /api/v1/telemetry/tetragon.
func WithSensorToken(token string) Option {
	return func(c *Client) {
		c.sensorToken = strings.TrimSpace(token)
	}
}

// WithAdminToken attaches the one-shot genesis registrar token (WARRANT_BOOTSTRAP_ADMIN_TOKEN)
// accepted by POST /api/v1/principals/register prior to bootstrap sealing.
func WithAdminToken(token string) Option {
	return func(c *Client) {
		c.adminToken = strings.TrimSpace(token)
	}
}

// WithOperatorToken attaches a dedicated operator credential (WARRANT_OPERATOR_TOKEN)
// accepted in offline simulator dev/demo mode.
func WithOperatorToken(token string) Option {
	return func(c *Client) {
		c.operatorToken = strings.TrimSpace(token)
	}
}

// WithAutomationToken attaches a dedicated non-governance automation credential (WARRANT_AUTOMATION_TOKEN)
// scoped strictly to /api/v1/feeds/* and POST /api/v1/ledger/checkpoints.
func WithAutomationToken(token string) Option {
	return func(c *Client) {
		c.automationToken = strings.TrimSpace(token)
	}
}

// WithIntakeToken attaches a dedicated scanner intake credential (WARRANT_INTAKE_TOKEN)
// for /api/v1/intake/sarif and /api/v1/intake/secrets.
func WithIntakeToken(token string) Option {
	return func(c *Client) {
		c.intakeToken = strings.TrimSpace(token)
	}
}

// WithEstateReadToken attaches a dedicated read-only Estate Loader credential (WARRANT_ESTATE_READ_TOKEN)
// scoped strictly to /api/v1/estate-loader/* decision-time reading routes.
func WithEstateReadToken(token string) Option {
	return func(c *Client) {
		c.estateReadToken = strings.TrimSpace(token)
	}
}

// WithSignerBundle configures an active enrolled Principal SignerKeyBundle so 1-of-2
// asymmetric governance & emergency operations (RevokePrincipal, TriggerFreeze, EmergencyRollback,
// MintAuditorToken, SealBootstrap) are automatically signed with single-use DSSE envelopes.
func WithSignerBundle(bundle *SignerKeyBundle) Option {
	return func(c *Client) {
		c.signerBundle = bundle
	}
}

// WithUserAgent sets a custom User-Agent header on SDK requests.
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		if strings.TrimSpace(ua) != "" {
			c.userAgent = strings.TrimSpace(ua)
		}
	}
}

// NewClient constructs a new G1-Warrant SDK client targeting baseURL (e.g., "http://localhost:8080").
func NewClient(baseURL string, opts ...Option) *Client {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		trimmed = "http://localhost:8080"
	}
	c := &Client{
		baseURL:    trimmed,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		userAgent:  "g1-warrant-go-sdk/" + Version,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// BaseURL returns the configured control-plane base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// Health queries GET /healthz.
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	var out HealthStatus
	if err := c.doJSON(ctx, http.MethodGet, "/healthz", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Scoreboard queries GET /api/v1/scoreboard for live fleet KPIs and emergency freeze posture.
func (c *Client) Scoreboard(ctx context.Context) (*GlobalScoreboard, error) {
	var out GlobalScoreboard
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/scoreboard", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Bootstrap queries GET /api/v1/bootstrap for the full consolidated control-plane snapshot.
func (c *Client) Bootstrap(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/bootstrap", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// KernelPublicKey fetches the active Ed25519 Kernel Attestation Seal public key (base64 & key_id).
func (c *Client) KernelPublicKey(ctx context.Context) (keyID string, pubKeyB64 string, fingerprint string, err error) {
	snap, err := c.Bootstrap(ctx)
	if err != nil {
		return "", "", "", err
	}
	kMap, _ := snap["kernel_public_key"].(map[string]any)
	keyID, _ = kMap["key_id"].(string)
	pubKeyB64, _ = kMap["public_key_b64"].(string)
	fingerprint, _ = kMap["key_fingerprint"].(string)
	if pubKeyB64 == "" {
		return "", "", "", fmt.Errorf("warrantsdk: kernel_public_key missing in bootstrap response")
	}
	return keyID, pubKeyB64, fingerprint, nil
}

// KernelPublicKeyRing fetches the append-only ring of historical and active Kernel Ed25519 verification keys.
func (c *Client) KernelPublicKeyRing(ctx context.Context) ([]KernelPublicKeyRecord, error) {
	var ring []KernelPublicKeyRecord
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/kernel-keys", nil, &ring); err != nil {
		return nil, err
	}
	return ring, nil
}

// ListPrincipals returns all registered cryptographic principals and WebAuthn/PIV authenticators.
func (c *Client) ListPrincipals(ctx context.Context) ([]Principal, error) {
	var out []Principal
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/principals", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RegisterPrincipal enrolls a public Ed25519 AC-5 signing identity (Slot 1 SERVICE_OWNER or Slot 2 AUTHORIZING_OFFICIAL)
// into N1 via POST /api/v1/principals/register (requires WithAdminToken prior to bootstrap sealing; once sealed, use RegisterPrincipalDualSigned).
func (c *Client) RegisterPrincipal(ctx context.Context, req RegisterPrincipalRequest) (*Principal, error) {
	var out Principal
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/principals/register", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RegisterPrincipalDualSigned enrolls a new or rotated principal public key after genesis bootstrap has been sealed,
// submitting a 2-of-2 DSSE Principal Governance envelope (ENROLL_PRINCIPAL) signed by active SO + AO principals.
func (c *Client) RegisterPrincipalDualSigned(ctx context.Context, env Envelope) (*Principal, error) {
	var out Principal
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/principals/register", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SealBootstrap permanently seals one-shot genesis bootstrap enrollment via POST /api/v1/bootstrap/seal
// (requires >=1 active SERVICE_OWNER and >=1 active AUTHORIZING_OFFICIAL).
func (c *Client) SealBootstrap(ctx context.Context) (*BootstrapState, error) {
	var out BootstrapState
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/bootstrap/seal", GovActionSealBootstrap, PrincipalGovernancePayload{}, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SealBootstrapSigned permanently seals genesis bootstrap using an explicit DSSE Principal Governance envelope.
func (c *Client) SealBootstrapSigned(ctx context.Context, env Envelope) (*BootstrapState, error) {
	var out BootstrapState
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/bootstrap/seal", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokePrincipal revokes a principal or hardware key fingerprint in N1 using a 1-of-2 DSSE Principal Governance signature
// (automatically signed when WithSignerBundle is configured on Client).
func (c *Client) RevokePrincipal(ctx context.Context, req RevokePrincipalRequest) (*PrincipalRevocation, error) {
	if c.signerBundle != nil {
		env, _, err := DraftPrincipalRevokeEnvelope(req.PrincipalID, req.KeyFingerprint, req.ReasonCode, 5*time.Minute)
		if err != nil {
			return nil, err
		}
		if err := c.signerBundle.SignEnvelope(1, env); err != nil {
			return nil, err
		}
		return c.RevokePrincipalSigned(ctx, *env)
	}
	var out PrincipalRevocation
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/principals/revoke", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokePrincipalSigned submits a pre-signed 1-of-2 DSSE Principal Governance envelope (REVOKE_PRINCIPAL)
// signed by any single active enrolled principal to POST /api/v1/principals/revoke.
func (c *Client) RevokePrincipalSigned(ctx context.Context, env Envelope) (*PrincipalRevocation, error) {
	var out PrincipalRevocation
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/principals/revoke", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateAndRevokePrincipal submits an atomic 2-of-2 ROTATE_AND_REVOKE_PRINCIPAL DSSE envelope
// to POST /api/v1/principals/rotate-and-revoke (enrolling the replacement principal and revoking the target in one transaction).
func (c *Client) RotateAndRevokePrincipal(ctx context.Context, env Envelope) (*RotateAndRevokeResult, error) {
	var out RotateAndRevokeResult
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/principals/rotate-and-revoke", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListWarrants returns all append-only Standing Warrants with live revocation/expiration status.
func (c *Client) ListWarrants(ctx context.Context) ([]WarrantRecord, error) {
	var out []WarrantRecord
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/warrants", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateWarrant submits a 2-of-2 dual-signed DSSEv1 Standing Warrant envelope to N1.
func (c *Client) CreateWarrant(ctx context.Context, env Envelope) (*WarrantRecord, error) {
	var out WarrantRecord
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/warrants", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyWarrant triggers live N1 cryptographic + OPA AC-5 + revocation re-verification of a Standing Warrant.
func (c *Client) VerifyWarrant(ctx context.Context, warrantID string) (*WarrantVerifyResponse, error) {
	var out WarrantVerifyResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/v1/warrants/"+url.PathEscape(warrantID)+"/verify", map[string]any{}, &out)
	if err != nil {
		// On 422 fail-closed, decode structured valid=false reason if present
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusUnprocessableEntity {
			return &WarrantVerifyResponse{Valid: false, Reason: apiErr.Message}, nil
		}
		return nil, err
	}
	return &out, nil
}

// TriggerFreeze activates Asymmetric Emergency Freeze (FREEZE_HOLD or FREEZE_ROLLBACK).
func (c *Client) TriggerFreeze(ctx context.Context, mode, actor, reasonCode string) (*FreezeState, error) {
	var out FreezeState
	body := map[string]string{
		"mode":        mode,
		"actor":       actor,
		"reason_code": reasonCode,
	}
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/freeze", GovActionEmergencyFreeze, PrincipalGovernancePayload{
		FreezeMode: mode,
		ReasonCode: reasonCode,
	}, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ThawFreeze restores OPERATIONAL posture using a 2-of-2 co-signed DSSEv1 Thaw envelope.
func (c *Client) ThawFreeze(ctx context.Context, env Envelope) (*FreezeState, error) {
	var out FreezeState
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/freeze/thaw", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListPipeline returns all vulnerability remediation items across the 5-stage Race Pipeline.
func (c *Client) ListPipeline(ctx context.Context) ([]RemediationItem, error) {
	var out []RemediationItem
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/pipeline", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListTraces returns millisecond-timestamped deterministic state traces for a remediation item.
func (c *Client) ListTraces(ctx context.Context, remediationID string) ([]TraceEvent, error) {
	var out []TraceEvent
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/pipeline/"+url.PathEscape(remediationID)+"/traces", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// EmergencyRollback executes the atomic 3-step Contain-Before-Unban Quarantined Rollback
// (re-arming containment bridge FIRST, suspending AdmissionLockout SECOND, and reverting digest THIRD).
func (c *Client) EmergencyRollback(ctx context.Context, remediationID, actor, reason string) (*RemediationItem, error) {
	var out RemediationItem
	body := map[string]string{
		"actor":  actor,
		"reason": reason,
	}
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/pipeline/"+url.PathEscape(remediationID)+"/emergency-rollback", GovActionEmergencyRollback, PrincipalGovernancePayload{
		RemediationID: remediationID,
		ReasonCode:    reason,
	}, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IngestSARIF submits an untrusted SARIF 2.1.0 JSON report to /api/v1/intake/sarif
// (automatically sanitized through the zero-egress warrant-extractor service).
func (c *Client) IngestSARIF(ctx context.Context, rawSARIF []byte, opts SARIFIntakeOptions) ([]RemediationItem, error) {
	q := url.Values{}
	if opts.Profile != "" {
		q.Set("profile", opts.Profile)
	}
	if opts.TargetService != "" {
		q.Set("target_service", opts.TargetService)
	}
	if opts.VulnerableDigest != "" {
		q.Set("vulnerable_digest", opts.VulnerableDigest)
	}
	if opts.MaxFindings > 0 {
		q.Set("max_findings", strconv.Itoa(opts.MaxFindings))
	}
	path := "/api/v1/intake/sarif"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	respBytes, err := c.doRaw(ctx, http.MethodPost, path, "application/json", rawSARIF)
	if err != nil {
		return nil, err
	}
	var out []RemediationItem
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("warrantsdk: decode SARIF intake response: %w", err)
	}
	return out, nil
}

// IngestSecretScan submits an untrusted Gitleaks (JSON/SARIF) or GitGuardian secret-exposure report
// to /api/v1/intake/secrets for zero-prose credential fingerprinting and SECRET-ROTATION-STATELESS execution.
func (c *Client) IngestSecretScan(ctx context.Context, rawScan []byte, targetService string) ([]RemediationItem, error) {
	q := url.Values{}
	if targetService != "" {
		q.Set("target_service", targetService)
	}
	path := "/api/v1/intake/secrets"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	respBytes, err := c.doRaw(ctx, http.MethodPost, path, "application/json", rawScan)
	if err != nil {
		return nil, err
	}
	var out []RemediationItem
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("warrantsdk: decode secret intake response: %w", err)
	}
	return out, nil
}

// SendTetragonEvent reports an eBPF/Tetragon container filesystem write or untracked process execution
// to /api/v1/telemetry/tetragon, triggering immediate N3 quarantine bridge re-arming + pod cordon & recycle.
func (c *Client) SendTetragonEvent(ctx context.Context, ev TetragonDriftEvent) (*DriftIncident, error) {
	var out DriftIncident
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/telemetry/tetragon", ev, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SimulateScenario triggers one of the deterministic control-plane drills:
// "inject-kev", "bad-syscall", "stateful-ddl", "runtime-drift", "secret-exposure", "in-pod-webshell", or "poisoned-config".
func (c *Client) SimulateScenario(ctx context.Context, scenario string) (map[string]any, error) {
	var out map[string]any
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/simulate/"+url.PathEscape(scenario), GovActionSimulationDrill, PrincipalGovernancePayload{
		Scenario: scenario,
	}, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListExceptions returns all Four-Eyes Ceiling Exception items.
func (c *Client) ListExceptions(ctx context.Context) ([]CeilingException, error) {
	var out []CeilingException
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/exceptions", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ResolveException submits a 2-of-2 co-signed DSSEv1 decision ("APPROVED" or "REJECTED") for a Ceiling Exception.
func (c *Client) ResolveException(ctx context.Context, exceptionID, decision string, env Envelope) (*CeilingException, *RemediationItem, error) {
	var out struct {
		Exception   *CeilingException `json:"exception"`
		Remediation *RemediationItem  `json:"remediation"`
	}
	body := map[string]any{
		"decision":      decision,
		"dsse_envelope": env,
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/exceptions/"+url.PathEscape(exceptionID)+"/resolve", body, &out); err != nil {
		return nil, nil, err
	}
	return out.Exception, out.Remediation, nil
}

// ListEstate returns all services and N2 Autonomous Eligibility Scorecard checklists.
func (c *Client) ListEstate(ctx context.Context) ([]EstateService, error) {
	var out []EstateService
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/estate", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListShadowRuns returns all N2 Differential Shadow comparison reports.
func (c *Client) ListShadowRuns(ctx context.Context) ([]ShadowComparisonReport, error) {
	var out []ShadowComparisonReport
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/shadow/runs", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListBridges returns all Cilium L7 / Envoy / Kubernetes NetworkPolicy containment bridges.
func (c *Client) ListBridges(ctx context.Context) ([]ContainmentBridge, error) {
	var out []ContainmentBridge
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/bridges", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListLockouts returns all permanent ValidatingAdmissionPolicy + Gatekeeper digest lockouts.
func (c *Client) ListLockouts(ctx context.Context) ([]AdmissionLockout, error) {
	var out []AdmissionLockout
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/lockouts", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListDriftIncidents returns all runtime pod digest drift & sub-second re-arming incidents.
func (c *Client) ListDriftIncidents(ctx context.Context) ([]DriftIncident, error) {
	var out []DriftIncident
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/drift", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListAttestations returns all DSSE-sealed NIST OSCAL 1.1.2 POA&M closure records.
func (c *Client) ListAttestations(ctx context.Context) ([]AttestationRecord, error) {
	var out []AttestationRecord
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/attestations", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ExportOSCALBundle downloads the raw signed NIST OSCAL 1.1.2 JSON bundle for an attestation or remediation ID.
func (c *Client) ExportOSCALBundle(ctx context.Context, attestationOrRemediationID string) ([]byte, error) {
	return c.doRaw(ctx, http.MethodGet, "/api/v1/attestations/"+url.PathEscape(attestationOrRemediationID)+"/oscal", "", nil)
}

// MintAuditorToken creates a time-bounded, read-only external 3PAO auditor bearer token.
func (c *Client) MintAuditorToken(ctx context.Context, label string, scopedAttestationIDs []string, ttlHours int) (*MintedAuditorLink, error) {
	if ttlHours <= 0 {
		ttlHours = 24
	}
	var out MintedAuditorLink
	body := map[string]any{
		"label":                  label,
		"scoped_attestation_ids": scopedAttestationIDs,
		"ttl_hours":              ttlHours,
	}
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/auditor-tokens", GovActionMintAuditorToken, PrincipalGovernancePayload{
		AuditorLabel:         label,
		ScopedAttestationIDs: scopedAttestationIDs,
		TTLHours:             ttlHours,
	}, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetAuditorVault queries GET /api/v1/auditor/vault using either an explicit bearer token or the client's configured auditor token.
func (c *Client) GetAuditorVault(ctx context.Context, bearerToken string) (*AuditorVaultSnapshot, error) {
	clone := *c
	if strings.TrimSpace(bearerToken) != "" {
		clone.auditorToken = strings.TrimSpace(bearerToken)
	}
	var out AuditorVaultSnapshot
	if err := clone.doJSON(ctx, http.MethodGet, "/api/v1/auditor/vault", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAgentActions returns all hash-chained governed worker & extractor ledger entries (N4).
func (c *Client) ListAgentActions(ctx context.Context) ([]AgentLedgerEntry, error) {
	var out []AgentLedgerEntry
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/ledger/actions", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// VerifyLedgerChains triggers genesis-to-tip SHA-256 chain + External Merkle Checkpoint verification across all 3 ledger tables.
func (c *Client) VerifyLedgerChains(ctx context.Context) (*LedgerVerificationReport, error) {
	var out LedgerVerificationReport
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/ledger/verify", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListLedgerCheckpoints returns all DSSE-signed Merkle Root transparency checkpoints.
func (c *Client) ListLedgerCheckpoints(ctx context.Context) ([]LedgerCheckpoint, error) {
	var out []LedgerCheckpoint
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/ledger/checkpoints", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateLedgerCheckpoint anchors a new DSSE-signed Merkle Root checkpoint across all 6 immutable tables.
func (c *Client) CreateLedgerCheckpoint(ctx context.Context) (*LedgerCheckpoint, error) {
	var out LedgerCheckpoint
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/ledger/checkpoints", GovActionCreateCheckpoint, PrincipalGovernancePayload{}, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetFeedStatus returns current CISA KEV, Google OSV.dev, and Trivy runtime configuration & sync counters.
func (c *Client) GetFeedStatus(ctx context.Context) (*LiveFeedStatus, error) {
	var out LiveFeedStatus
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/feeds/status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateFeedConfig updates runtime threat feed settings (e.g. toggling "offline" vs "live" mode).
func (c *Client) UpdateFeedConfig(ctx context.Context, cfg FeedRuntimeConfig) (*FeedRuntimeConfig, error) {
	var out FeedRuntimeConfig
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/feeds/config", GovActionFeedMutation, PrincipalGovernancePayload{}, cfg, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SyncCISAKEV triggers an immediate CISA Known Exploited Vulnerabilities pull sanitized via warrant-extractor.
func (c *Client) SyncCISAKEV(ctx context.Context) (*FeedSyncRun, error) {
	var out FeedSyncRun
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/feeds/sync/kev", GovActionFeedMutation, PrincipalGovernancePayload{}, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SyncOSV queries Google OSV.dev against registered estate SBOM PURLs sanitized via warrant-extractor.
func (c *Client) SyncOSV(ctx context.Context, autoIngestFirst bool) (*OSVSyncResponse, error) {
	path := "/api/v1/feeds/sync/osv"
	if autoIngestFirst {
		path += "?ingest=true"
	}
	var out OSVSyncResponse
	if err := c.doActionJSON(ctx, http.MethodPost, path, GovActionFeedMutation, PrincipalGovernancePayload{}, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IngestOSVAdvisory routes a discovered Google OSV.dev advisory into the 5-stage Race Pipeline.
func (c *Client) IngestOSVAdvisory(ctx context.Context, osvID, serviceID string) ([]RemediationItem, error) {
	var out []RemediationItem
	body := map[string]string{
		"osv_id":     osvID,
		"service_id": serviceID,
	}
	if err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/feeds/osv/ingest", GovActionFeedMutation, PrincipalGovernancePayload{}, body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ClassBindingRequest specifies parameters for POST /api/v1/remediations/{id}/bind-class.
type ClassBindingRequest struct {
	WarrantID       string    `json:"warrant_id,omitempty"`
	WarrantEnvelope *Envelope `json:"warrant_envelope,omitempty"`
	DistributorID   string    `json:"distributor_id,omitempty"`
	AutoExecute     bool      `json:"auto_execute,omitempty"`
}

// BindRemediationToWarrantClass binds an ingested unbound/unmapped remediation item to a 2-of-2 Standing Warrant class.
func (c *Client) BindRemediationToWarrantClass(ctx context.Context, remediationID string, req ClassBindingRequest) (*RemediationItem, error) {
	var out RemediationItem
	path := "/api/v1/remediations/" + url.PathEscape(strings.TrimSpace(remediationID)) + "/bind-class"
	if err := c.doJSON(ctx, http.MethodPost, path, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StreamEvents subscribes to the real-time Server-Sent Events stream (GET /api/v1/events/stream)
// until ctx is cancelled or handler returns a non-nil error.
func (c *Client) StreamEvents(ctx context.Context, handler func(SSEEvent) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/events/stream", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", c.userAgent)

	streamClient := &http.Client{Transport: c.httpClient.Transport}
	resp, err := streamClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return parseAPIError(http.MethodGet, "/api/v1/events/stream", resp.StatusCode, body)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	var curEvent string
	var dataBuf bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if dataBuf.Len() > 0 {
				ev := SSEEvent{
					Event: curEvent,
					Data:  append([]byte(nil), bytes.TrimSuffix(dataBuf.Bytes(), []byte("\n"))...),
				}
				if ev.Event == "" {
					ev.Event = "message"
				}
				if err := handler(ev); err != nil {
					return err
				}
			}
			curEvent = ""
			dataBuf.Reset()
			continue
		}
		if strings.HasPrefix(line, "event:") {
			curEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			dataBuf.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			dataBuf.WriteByte('\n')
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return scanner.Err()
}

func (c *Client) doActionJSON(ctx context.Context, method, path, govAction string, govFields PrincipalGovernancePayload, reqBody any, dst any) error {
	var payload []byte
	var contentType string
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("warrantsdk: marshal request for %s: %w", path, err)
		}
		payload = raw
		contentType = "application/json"
	}

	var extraHeaders map[string]string
	if c.signerBundle != nil && govAction != "" {
		canonicalPath := path
		if u, pErr := url.Parse(path); pErr == nil && u.Path != "" {
			canonicalPath = u.Path
		}
		govFields.HTTPMethod = method
		govFields.CanonicalPath = canonicalPath
		govFields.RequestBodySHA256 = crypto.SHA256Hex(payload)

		env, _, err := DraftGovernanceEnvelope(govAction, govFields, 5*time.Minute)
		if err != nil {
			return err
		}
		if err := c.signerBundle.SignEnvelope(1, env); err != nil {
			return err
		}
		envRaw, err := json.Marshal(env)
		if err != nil {
			return err
		}
		extraHeaders = map[string]string{
			"X-Warrant-Governance-DSSE": base64.StdEncoding.EncodeToString(envRaw),
		}
	}

	respBytes, err := c.doRawWithHeaders(ctx, method, path, contentType, payload, extraHeaders)
	if err != nil {
		return err
	}
	if dst != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, dst); err != nil {
			return fmt.Errorf("warrantsdk: decode response from %s: %w", path, err)
		}
	}
	return nil
}

// ListEstateSources lists all registered v1.4.0 EstateReader descriptors across Tiers A, B, and C.
func (c *Client) ListEstateSources(ctx context.Context) ([]EstateSourceDescriptor, error) {
	var out []EstateSourceDescriptor
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/estate-loader/sources", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ProposeEstateClass queries a connected Tier A/B system (and optional Tier C corroborating scanner)
// via POST /api/v1/estate-loader/propose to propose class profile and candidate clone sources at drafting time.
func (c *Client) ProposeEstateClass(ctx context.Context, req EstateProposalRequest) (*EstateProposalResponse, error) {
	var out EstateProposalResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/estate-loader/propose", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListEstateEvidence retrieves append-only WORM estate_read_evidence rows (optionally filtered by source or warrant).
func (c *Client) ListEstateEvidence(ctx context.Context, sourceSystem, warrantID string) ([]EstateReadEvidenceRecord, error) {
	q := url.Values{}
	if strings.TrimSpace(sourceSystem) != "" {
		q.Set("source_system", strings.TrimSpace(sourceSystem))
	}
	if strings.TrimSpace(warrantID) != "" {
		q.Set("warrant_id", strings.TrimSpace(warrantID))
	}
	path := "/api/v1/estate-loader/evidence"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var out []EstateReadEvidenceRecord
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqBody any, dst any) error {
	return c.doJSONWithHeaders(ctx, method, path, reqBody, dst, nil)
}

func (c *Client) doJSONWithHeaders(ctx context.Context, method, path string, reqBody any, dst any, extraHeaders map[string]string) error {
	var payload []byte
	var contentType string
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("warrantsdk: marshal request for %s: %w", path, err)
		}
		payload = raw
		contentType = "application/json"
	}
	respBytes, err := c.doRawWithHeaders(ctx, method, path, contentType, payload, extraHeaders)
	if err != nil {
		return err
	}
	if dst != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, dst); err != nil {
			return fmt.Errorf("warrantsdk: decode response from %s: %w", path, err)
		}
	}
	return nil
}

func (c *Client) doRaw(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {
	return c.doRawWithHeaders(ctx, method, path, contentType, body, nil)
}

func (c *Client) doRawWithHeaders(ctx context.Context, method, path, contentType string, body []byte, extraHeaders map[string]string) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.auditorToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.auditorToken)
	}
	if c.sensorToken != "" {
		req.Header.Set("X-Tetragon-Sensor-Token", c.sensorToken)
	}
	if c.adminToken != "" {
		req.Header.Set("X-Warrant-Admin-Token", c.adminToken)
	}
	if c.operatorToken != "" {
		req.Header.Set("X-Warrant-Operator-Token", c.operatorToken)
	}
	if c.automationToken != "" {
		req.Header.Set("X-Warrant-Automation-Token", c.automationToken)
	}
	if c.intakeToken != "" {
		req.Header.Set("X-Warrant-Intake-Token", c.intakeToken)
	}
	if c.estateReadToken != "" {
		req.Header.Set("X-Warrant-Estate-Read-Token", c.estateReadToken)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, parseAPIError(method, path, resp.StatusCode, respBytes)
	}
	return respBytes, nil
}

func parseAPIError(method, path string, status int, raw []byte) error {
	msg := strings.TrimSpace(string(raw))
	var errObj struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal(raw, &errObj) == nil {
		if errObj.Error != "" {
			msg = errObj.Error
		} else if errObj.Reason != "" {
			msg = errObj.Reason
		}
	}
	return &APIError{
		StatusCode: status,
		Method:     method,
		Endpoint:   path,
		Message:    msg,
	}
}
