// Package warrantsdk provides the official typed Go Client SDK and offline
// cryptographic DSSE/OSCAL ceremony toolkit for G1-Warrant.
package warrantsdk

import (
	"fmt"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// Version is the semantic version of the G1-Warrant Go SDK.
const Version = "1.0.2"

// Re-exported protocol constants for callers outside internal/.
const (
	RoleServiceOwner        = crypto.RoleServiceOwner
	RoleAuthorizingOfficial = crypto.RoleAuthorizingOfficial

	FreezeModeOperational = models.FreezeModeOperational
	FreezeModeHold        = models.FreezeModeHold
	FreezeModeRollback    = models.FreezeModeRollback

	FeedModeOffline = models.FeedModeOffline
	FeedModeLive    = models.FeedModeLive

	PayloadTypeWarrant             = crypto.PayloadTypeWarrant
	PayloadTypeThaw                = crypto.PayloadTypeThaw
	PayloadTypeException           = crypto.PayloadTypeException
	PayloadTypeAttestation         = crypto.PayloadTypeAttestation
	PayloadTypePrincipalGovernance = crypto.PayloadTypePrincipalGovernance
	PayloadTypeGenesisSeal         = crypto.PayloadTypeGenesisSeal
	PayloadTypeKernelKeyRotation   = crypto.PayloadTypeKernelKeyRotation

	WarrantClassSecretRotation = models.WarrantClassSecretRotation
	AssuranceTierSecretRotated = models.AssuranceTierSecretRotated

	GovActionEnrollPrincipal          = models.GovActionEnrollPrincipal
	GovActionRevokePrincipal          = models.GovActionRevokePrincipal
	GovActionRotateAndRevokePrincipal = models.GovActionRotateAndRevokePrincipal
	GovActionSealBootstrap            = models.GovActionSealBootstrap
	GovActionEmergencyFreeze          = models.GovActionEmergencyFreeze
	GovActionEmergencyRollback        = models.GovActionEmergencyRollback
	GovActionMintAuditorToken         = models.GovActionMintAuditorToken
	GovActionFeedMutation             = models.GovActionFeedMutation
	GovActionCreateCheckpoint         = models.GovActionCreateCheckpoint
	GovActionSimulationDrill          = models.GovActionSimulationDrill
)

// Public type aliases re-exported cleanly for external Go SDK consumers.
type (
	Envelope                   = crypto.Envelope
	Signature                  = crypto.Signature
	PrincipalKey               = crypto.PrincipalKey
	GlobalScoreboard           = models.GlobalScoreboard
	BootstrapState             = models.BootstrapState
	Principal                  = models.Principal
	PrincipalRevocation        = models.PrincipalRevocation
	PrincipalGovernancePayload = models.PrincipalGovernancePayload
	ThawPayload                = models.ThawPayload
	ExceptionResolutionPayload = models.ExceptionResolutionPayload
	KernelKeyRotationPayload   = models.KernelKeyRotationPayload
	WarrantPayload           = models.WarrantPayload
	WarrantRecord            = models.WarrantRecord
	FreezeState              = models.FreezeState
	EstateService            = models.EstateService
	ShadowComparisonReport   = models.ShadowComparisonReport
	RemediationItem          = models.RemediationItem
	TraceEvent               = models.TraceEvent
	CeilingException         = models.CeilingException
	ContainmentBridge        = models.ContainmentBridge
	AdmissionLockout         = models.AdmissionLockout
	DriftIncident            = models.DriftIncident
	TetragonDriftEvent       = models.TetragonDriftEvent
	KernelPublicKeyRecord    = models.KernelPublicKeyRecord
	AgentLedgerEntry         = models.AgentLedgerEntry
	AttestationRecord        = models.AttestationRecord
	AuditorShareToken        = models.AuditorShareToken
	LedgerVerificationReport = models.LedgerVerificationReport
	LedgerCheckpoint         = models.LedgerCheckpoint
	FeedRuntimeConfig        = models.FeedRuntimeConfig
	FeedSyncRun              = models.FeedSyncRun
	LiveFeedStatus           = models.LiveFeedStatus
	ExtractedOSVEntry        = models.ExtractedOSVEntry
)

// APIError represents a structured non-2xx HTTP response from warrantd.
type APIError struct {
	StatusCode int
	Method     string
	Endpoint   string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("warrantsdk: %s %s returned HTTP %d: %s", e.Method, e.Endpoint, e.StatusCode, e.Message)
}

// IsAuditorScopeViolation reports whether an external 3PAO auditor bearer token
// was blocked from accessing an operational control-plane endpoint (NIST AC-3).
func (e *APIError) IsAuditorScopeViolation() bool {
	return e != nil && e.StatusCode == 403
}

// IsPolicyOrCeremonyRejection reports whether N1/N2/N3 OPA policy or DSSE verification rejected the request.
func (e *APIError) IsPolicyOrCeremonyRejection() bool {
	return e != nil && e.StatusCode == 422
}

// HealthStatus represents the response from GET /healthz.
type HealthStatus struct {
	Status       string `json:"status"`
	Service      string `json:"service"`
	Organization string `json:"organization"`
	FreezeMode   string `json:"freeze_mode"`
}

// WarrantVerifyResponse represents the response from POST /api/v1/warrants/{id}/verify.
type WarrantVerifyResponse struct {
	Valid   bool           `json:"valid"`
	Reason  string         `json:"reason,omitempty"`
	Warrant *WarrantRecord `json:"warrant,omitempty"`
}

// RevokePrincipalRequest specifies parameters for POST /api/v1/principals/revoke.
type RevokePrincipalRequest struct {
	PrincipalID    string `json:"principal_id"`
	KeyFingerprint string `json:"key_fingerprint"`
	ReasonCode     string `json:"reason_code"`
	RevokedBy      string `json:"revoked_by"`
}

// RotateAndRevokeResult represents the atomic response from POST /api/v1/principals/rotate-and-revoke.
type RotateAndRevokeResult struct {
	EnrolledPrincipal Principal           `json:"enrolled_principal"`
	Revocation        PrincipalRevocation `json:"revocation"`
}

// RegisterPrincipalRequest carries public identity material (never private keys) to POST /api/v1/principals/register.
type RegisterPrincipalRequest struct {
	PrincipalID  string `json:"principal_id"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	Role         string `json:"role"`
	KeyID        string `json:"key_id"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
}

// SARIFIntakeOptions configures optional query parameters on POST /api/v1/intake/sarif.
type SARIFIntakeOptions struct {
	Profile          string // e.g. "STATELESS_CLEAN", "STATEFUL_DDL", "BAD_SYSCALL_EXECVE"
	TargetService    string
	VulnerableDigest string
	MaxFindings      int
}

// OSVSyncResponse represents the response from POST /api/v1/feeds/sync/osv.
type OSVSyncResponse struct {
	SyncRun    FeedSyncRun         `json:"sync_run"`
	Advisories []ExtractedOSVEntry `json:"advisories"`
	Ingested   []RemediationItem   `json:"ingested,omitempty"`
}

// MintedAuditorLink represents the response from POST /api/v1/auditor-tokens.
type MintedAuditorLink struct {
	Token      AuditorShareToken `json:"token"`
	Bearer     string            `json:"bearer"`
	AuditorURL string            `json:"auditor_url"`
}

// AuditorVaultSnapshot represents the scoped read-only response from GET /api/v1/auditor/vault.
type AuditorVaultSnapshot struct {
	TokenMetadata   AuditorShareToken        `json:"token_metadata"`
	Attestations    []AttestationRecord      `json:"attestations"`
	LedgerProof     LedgerVerificationReport `json:"ledger_proof"`
	KernelPublicKey map[string]string        `json:"kernel_public_key"`
}

// SSEEvent represents a single real-time control-plane event from GET /api/v1/events/stream.
type SSEEvent struct {
	Event string
	Data  []byte
}
