// Package warrantsdk provides the official typed Go Client SDK and offline
// cryptographic DSSE/OSCAL ceremony toolkit for G1-Warrant.
package warrantsdk

import (
	"fmt"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// Version is the semantic version of the G1-Warrant Go SDK.
const Version = "1.4.0"

// Trust-basis identifiers emitted by offline OSCAL bundle verifiers (WN-4).
const (
	TrustBasisExternalPinnedPubKey = "EXTERNAL_PINNED_PUBKEY"
	TrustBasisExternalKeyRing      = "EXTERNAL_KEYRING"
	TrustBasisEmbeddedKeyRingOptIn = "EMBEDDED_BUNDLE_KEYRING_UNTRUSTED_OPT_IN"
)

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
	PayloadTypeTaskWarrant         = crypto.PayloadTypeTaskWarrant
	PayloadTypeAgentTokenExchange  = crypto.PayloadTypeAgentTokenExchange
	PayloadTypePrincipalGovernance = crypto.PayloadTypePrincipalGovernance
	PayloadTypeGenesisSeal         = crypto.PayloadTypeGenesisSeal
	PayloadTypeKernelKeyRotation   = crypto.PayloadTypeKernelKeyRotation

	WarrantClassSecretRotation = models.WarrantClassSecretRotation
	AssuranceTierSecretRotated = models.AssuranceTierSecretRotated

	AgentKindInternalWorker     = models.AgentKindInternalWorker
	AgentKindExternalAutonomous = models.AgentKindExternalAutonomous

	AuthorityModeWarrantComposite    = models.AuthorityModeWarrantComposite
	AuthorityModeAutonomousSponsored = models.AuthorityModeAutonomousSponsored

	EgressProfileZeroIsolated    = models.EgressProfileZeroIsolated
	EgressProfileInternalCluster = models.EgressProfileInternalCluster

	SponsorshipActive              = models.SponsorshipActive
	SponsorshipSecondaryContinuity = models.SponsorshipSecondaryContinuity
	SponsorshipGraceEscalated      = models.SponsorshipGraceEscalated
	SponsorshipOrphanQuarantined   = models.SponsorshipOrphanQuarantined
	SponsorshipLeaseExpired        = models.SponsorshipLeaseExpired
	SponsorshipRevokedCompromise   = models.SponsorshipRevokedCompromise
	SponsorshipRevokedKillSwitch   = models.SponsorshipRevokedKillSwitch

	IGAEventRoleTransfer   = models.IGAEventRoleTransfer
	IGAEventOrgReorg       = models.IGAEventOrgReorg
	IGAEventLeaveOfAbsence = models.IGAEventLeaveOfAbsence
	IGAEventTermination    = models.IGAEventTermination
	IGAEventKeyCompromise  = models.IGAEventKeyCompromise

	GovActionEnrollPrincipal              = models.GovActionEnrollPrincipal
	GovActionRevokePrincipal              = models.GovActionRevokePrincipal
	GovActionRotateAndRevokePrincipal     = models.GovActionRotateAndRevokePrincipal
	GovActionRotateKernelKey              = models.GovActionRotateKernelKey
	GovActionSealBootstrap                = models.GovActionSealBootstrap
	GovActionEmergencyFreeze              = models.GovActionEmergencyFreeze
	GovActionEmergencyRollback            = models.GovActionEmergencyRollback
	GovActionMintAuditorToken             = models.GovActionMintAuditorToken
	GovActionFeedMutation                 = models.GovActionFeedMutation
	GovActionCreateCheckpoint             = models.GovActionCreateCheckpoint
	GovActionSimulationDrill              = models.GovActionSimulationDrill
	GovActionUpsertCommissioningFunction  = models.GovActionUpsertCommissioningFunction
	GovActionTransferCommissioningSponsor = models.GovActionTransferCommissioningSponsor
	GovActionEnrollAgentIdentity          = models.GovActionEnrollAgentIdentity
	GovActionRecertifyAgentIdentity       = models.GovActionRecertifyAgentIdentity
	GovActionRevokeAgentIdentity          = models.GovActionRevokeAgentIdentity
	GovActionEmitIGAEvent                 = models.GovActionEmitIGAEvent

	AssuranceTier0DistributorDispatchOnly = models.AssuranceTier0DistributorDispatchOnly

	FinderVendorSARIF    = models.FinderVendorSARIFGeneric
	FinderVendorQualys   = models.FinderVendorQualysVMDR
	FinderVendorTenable  = models.FinderVendorTenableIOSC
	FinderVendorRapid7   = models.FinderVendorRapid7InsightVM
	FinderVendorTrivy    = models.FinderVendorTrivy
	FinderVendorWiz      = models.FinderVendorWiz
	FinderVendorSemgrep  = models.FinderVendorSemgrep
	FinderVendorSnyk     = models.FinderVendorSnyk

	CVEMappingStatusMapped         = models.CVEMappingStatusMapped
	CVEMappingStatusUnmappedVendor = models.CVEMappingStatusUnmappedVendor
	CVEMappingStatusAbsent         = models.CVEMappingStatusAbsent

	ClassBindingStatusBound   = models.ClassBindingStatusBound
	ClassBindingStatusUnbound = models.ClassBindingStatusUnbound

	PatchTargetLayerUserspace = models.PatchTargetLayerUserspace
	PatchTargetLayerKernel    = models.PatchTargetLayerKernel
	PatchTargetLayerBoot      = models.PatchTargetLayerBoot

	TwinRuntimeContainer = models.TwinRuntimeContainer
	TwinRuntimeVM        = models.TwinRuntimeVM

	DefaultCloneTwinCount = models.DefaultCloneTwinCount

	EstateSourceTierAMachine               = models.EstateSourceTierAMachine
	EstateSourceTierBWorkload              = models.EstateSourceTierBWorkload
	EstateSourceTierCCensus                = models.EstateSourceTierCCensus
	CloneSourceModeEstateLoader            = models.CloneSourceModeEstateLoader
	CloneSourceModeManual                  = models.CloneSourceModeManual
	EstateDriftPolicyRecordOnly            = models.EstateDriftPolicyRecordOnly
	EstateDriftPolicyFailClosed            = models.EstateDriftPolicyFailClosed
	CloneSourceResolutionSignedClass       = models.CloneSourceResolutionSignedClass
	CloneSourceResolutionSignedClassManual = models.CloneSourceResolutionSignedClassManual
	CloneSourceResolutionEnvFallback       = models.CloneSourceResolutionEnvFallback

	ClosureCompletenessFull         = models.ClosureCompletenessFull
	ClosureCompletenessPartial      = models.ClosureCompletenessPartial
	ClosureCompletenessDispatchOnly = models.ClosureCompletenessDispatchOnly

	DistributorK8sCiliumNative    = models.DistributorK8sCiliumNative
	DistributorArgoCD             = models.DistributorArgoCD
	DistributorFlux               = models.DistributorFlux
	DistributorMSIntune           = models.DistributorMSIntune
	DistributorMSMECM             = models.DistributorMSMECM
	DistributorMSWSUS             = models.DistributorMSWSUS
	DistributorAnsibleAWX         = models.DistributorAnsibleAWX
	DistributorRedHatSatellite    = models.DistributorRedHatSatellite
	DistributorJamfPro            = models.DistributorJamfPro
	DistributorAWSSSM             = models.DistributorAWSSSM
	DistributorAzureUpdateManager = models.DistributorAzureUpdateManager
	DistributorGCPOSConfig        = models.DistributorGCPOSConfig
	DistributorTaniumPatch        = models.DistributorTaniumPatch
	DistributorIvantiNeurons      = models.DistributorIvantiNeurons
	DistributorAutomox            = models.DistributorAutomox
)

// Public type aliases re-exported cleanly for external Go SDK consumers.
type (
	Envelope                    = crypto.Envelope
	Signature                   = crypto.Signature
	PrincipalKey                = crypto.PrincipalKey
	GlobalScoreboard            = models.GlobalScoreboard
	BootstrapState              = models.BootstrapState
	Principal                   = models.Principal
	PrincipalRevocation         = models.PrincipalRevocation
	PrincipalGovernancePayload  = models.PrincipalGovernancePayload
	CommissioningFunction       = models.CommissioningFunction
	AgentIdentity               = models.AgentIdentity
	AgentLifecycleEvent         = models.AgentLifecycleEvent
	IGAEventRequest             = models.IGAEventRequest
	PendingSponsorTransfer      = models.PendingSponsorTransfer
	ActorClaim                  = models.ActorClaim
	ConfirmationClaim           = models.ConfirmationClaim
	AgentTokenExchangePayload   = models.AgentTokenExchangePayload
	AgentTokenExchangeResponse  = models.AgentTokenExchangeResponse
	EphemeralTaskWarrantPayload = models.EphemeralTaskWarrantPayload
	ThawPayload                 = models.ThawPayload
	ExceptionResolutionPayload  = models.ExceptionResolutionPayload
	KernelKeyRotationPayload    = models.KernelKeyRotationPayload
	WarrantPayload              = models.WarrantPayload
	WarrantRecord               = models.WarrantRecord
	FreezeState                 = models.FreezeState
	EstateService               = models.EstateService
	ShadowComparisonReport      = models.ShadowComparisonReport
	RemediationItem             = models.RemediationItem
	TraceEvent                  = models.TraceEvent
	CeilingException            = models.CeilingException
	ContainmentBridge           = models.ContainmentBridge
	AdmissionLockout            = models.AdmissionLockout
	DriftIncident               = models.DriftIncident
	TetragonDriftEvent          = models.TetragonDriftEvent
	KernelPublicKeyRecord       = models.KernelPublicKeyRecord
	AgentLedgerEntry            = models.AgentLedgerEntry
	AttestationRecord           = models.AttestationRecord
	AuditorShareToken           = models.AuditorShareToken
	LedgerVerificationReport    = models.LedgerVerificationReport
	LedgerCheckpoint            = models.LedgerCheckpoint
	FeedRuntimeConfig           = models.FeedRuntimeConfig
	FeedSyncRun                 = models.FeedSyncRun
	LiveFeedStatus              = models.LiveFeedStatus
	ExtractedOSVEntry           = models.ExtractedOSVEntry
	AssetIdentity               = models.AssetIdentity
	AssetIdentityAlias          = models.AssetIdentityAlias
	FixIdentity                 = models.FixIdentity
	AssetTarget                 = models.AssetTarget
	RolloutWave                 = models.RolloutWave
	RolloutPlan                 = models.RolloutPlan
	NativeRollbackSpec          = models.NativeRollbackSpec
	DeploymentOrder             = models.DeploymentOrder
	DeploymentDispatchReceipt   = models.DeploymentDispatchReceipt
	AssetDeploymentStatus       = models.AssetDeploymentStatus
	DeploymentResult            = models.DeploymentResult
	DistributorCapabilities     = models.DistributorCapabilities
	DistributorDescriptor       = models.DistributorDescriptor
	CloneTwinInstanceResult     = models.CloneTwinInstanceResult
	CloneTwinProvingManifest    = models.CloneTwinProvingManifest
	DeclaredCloneSource         = models.DeclaredCloneSource
	ResolvedCloneSourceEvidence = models.ResolvedCloneSourceEvidence
	OSKernelBucket              = models.OSKernelBucket
	SoftwareBucket              = models.SoftwareBucket
	CloneSourceCandidate        = models.CloneSourceCandidate
	EstateSnapshot              = models.EstateSnapshot
	EstateReadEvidenceRecord    = models.EstateReadEvidenceRecord
	EstateSourceDescriptor      = models.EstateSourceDescriptor
	EstateProposalRequest       = models.EstateProposalRequest
	EstateProposalResponse      = models.EstateProposalResponse
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
