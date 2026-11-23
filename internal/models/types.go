package models

import (
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
)

// System Freeze Modes (N1)
const (
	FreezeModeOperational = "OPERATIONAL"
	FreezeModeHold        = "FREEZE_HOLD"
	FreezeModeRollback    = "FREEZE_ROLLBACK"
)

// 5-Stage Race Pipeline Stages
const (
	StageIntakeRepro      = "INTAKE_REPRO"
	StageBridgedContained = "BRIDGED_CONTAINED"
	StageShadowCanary     = "SHADOW_CANARY"
	StageVerifyingLocking = "VERIFYING_LOCKING"
	StageAttestedClosed   = "ATTESTED_CLOSED"
)

// Health / Exception States
const (
	HealthNormal              = "NORMAL"
	HealthBridged             = "BRIDGED"
	HealthIngestedUnbound     = "INGESTED_UNBOUND"
	HealthExceptionRouted     = "EXCEPTION_ROUTED"
	HealthRollbackFailed      = "ROLLBACK_FAILED"
	HealthQuarantinedRollback = "QUARANTINED_ROLLBACK"
	HealthDriftViolation      = "DRIFT_VIOLATION"
	HealthFrozen              = "FROZEN"
	HealthAttested            = "ATTESTED"
)

// v1.3.0 Class-Binding & Clone-Twin Runtime-Follows-Patch Constants
const (
	ClassBindingStatusBound   = "BOUND"
	ClassBindingStatusUnbound = "UNBOUND"

	PatchTargetLayerUserspace = "USERSPACE_SOFTWARE"
	PatchTargetLayerKernel    = "KERNEL"
	PatchTargetLayerBoot      = "BOOT_LAYER"

	TwinRuntimeContainer = "CONTAINER_TWIN"
	TwinRuntimeVM        = "VM_TWIN"

	DefaultCloneTwinCount = 3

	// v1.4.0 Estate Loader Source Tiers, Handler Families, Drift Policies & Clone-Source Resolution Paths
	EstateSourceTierAMachine  = "TIER_A_MACHINE"  // 12 Machine Estate Truth systems
	EstateSourceTierBWorkload = "TIER_B_WORKLOAD" // 3 Kubernetes-native Workload Estate Truth systems
	EstateSourceTierCCensus   = "TIER_C_CENSUS"   // 3 Scanner Corroborating Census systems (0 clone sources)

	EstateHandlerFamilyMicrosoft       = "FAMILY_MICROSOFT"
	EstateHandlerFamilyCloud           = "FAMILY_CLOUD"
	EstateHandlerFamilyKubernetes      = "FAMILY_KUBERNETES"
	EstateHandlerFamilyRESTDeclarative = "FAMILY_REST_DECLARATIVE"
	EstateHandlerFamilyScanners        = "FAMILY_SCANNERS"

	EstateReadPhaseSigningProposal = "SIGNING_PROPOSAL"
	EstateReadPhaseProvingReread   = "PROVING_REREAD"

	CloneSourceModeEstateLoader = "ESTATE_LOADER"
	CloneSourceModeManual       = "MANUAL"

	EstateDriftPolicyRecordOnly = "RECORD_ONLY"
	EstateDriftPolicyFailClosed = "FAIL_CLOSED"

	CloneSourceResolutionSignedClass       = "SIGNED_CLASS"
	CloneSourceResolutionSignedClassManual = "SIGNED_CLASS_MANUAL"
	CloneSourceResolutionEnvFallback       = "ENV_BOOTSTRAP_FALLBACK"

	AgentActionReadEstateSnapshot      = "READ_ESTATE_SNAPSHOT"
	AgentActionDispatchDeploymentOrder = "DISPATCH_DEPLOYMENT_ORDER"

	OCSFInventoryInfoClassUID = 5001
	DefaultEstateDriftTolPct  = 10.0
)

// Autonomy Tiers for Brownfield vs. Greenfield Estate Services (N2)
const (
	AutonomyTier1FullAutonomous = "TIER_1_FULL_AUTONOMOUS"
	AutonomyTier2GuardedCanary  = "TIER_2_GUARDED_CANARY"
	AutonomyTier3ContainAndCAB  = "TIER_3_CONTAIN_AND_CAB"
)

// Containment Modes Separating Coarse Zero-Prose Quarantine from Signed L7 Rulepacks (N3)
const (
	ContainmentModeZeroProseQuarantine = "ZERO_PROSE_EGRESS_MESH_QUARANTINE"
	ContainmentModeSignedRulepackL7    = "SIGNED_RULEPACK_L7_SHIELD"
)

// Closure Assurance Tiers Distinguishing Dispatch-Only, Passive Digest/SBOM Proof, Differential PoC Proof, and Secret Rotation (N3/N5)
const (
	AssuranceTier0DistributorDispatchOnly = "ASSURANCE_TIER_0_DISTRIBUTOR_DISPATCH_ONLY"
	AssuranceTier1PassiveDigestSBOM       = "ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM"
	AssuranceTier2DifferentialTwin        = "ASSURANCE_TIER_2_DIFFERENTIAL_TWIN"
	AssuranceTierSecretRotated            = "ASSURANCE_TIER_SECRET_ROTATED"
)

// WN-7 Finder Vendors, CVE Mapping Statuses & Normalized Detection States (v1.2.0)
const (
	FinderVendorSARIFGeneric    = "SARIF_GENERIC"
	FinderVendorQualysVMDR      = "QUALYS_VMDR"
	FinderVendorTenableIOSC     = "TENABLE_IO_SC"
	FinderVendorRapid7InsightVM = "RAPID7_INSIGHTVM"
	FinderVendorTrivy           = "TRIVY"
	FinderVendorWiz             = "WIZ"
	FinderVendorSemgrep         = "SEMGREP"
	FinderVendorSnyk            = "SNYK"

	CVEMappingStatusMapped         = "MAPPED"
	CVEMappingStatusUnmappedVendor = "UNMAPPED_VENDOR_ADVISORY"
	CVEMappingStatusAbsent         = "ABSENT"

	DetectionStateActive        = "ACTIVE"
	DetectionStateReopened      = "REOPENED"
	DetectionStateNew           = "NEW"
	DetectionStateFixedReported = "FIXED_REPORTED"
)

// AssetIdentity is the prose-free canonical normalized host/workload asset identity emitted by WN-7 Finder translators.
type AssetIdentity struct {
	AssetKey        string `json:"asset_key"`
	Hostname        string `json:"hostname,omitempty"`
	IPv4            string `json:"ipv4,omitempty"`
	IPv6            string `json:"ipv6,omitempty"`
	ScannerAssetID  string `json:"scanner_asset_id,omitempty"`
	CloudInstanceID string `json:"cloud_instance_id,omitempty"`
	PlatformFamily  string `json:"platform_family,omitempty"`
}

// AssetIdentityAlias maps scanner-specific hostnames, IPs, cloud instance IDs, or scanner UUIDs to canonical Warrant EstateService / AssetKey entries.
type AssetIdentityAlias struct {
	AliasKey        string    `json:"alias_key"`
	AliasType       string    `json:"alias_type"` // "HOSTNAME" | "IPV4" | "IPV6" | "SCANNER_ASSET_ID" | "CLOUD_INSTANCE_ID" | "ASSET_KEY"
	ServiceID       string    `json:"service_id"`
	AssetKey        string    `json:"asset_key"`
	Hostname        string    `json:"hostname,omitempty"`
	IPv4            string    `json:"ipv4,omitempty"`
	IPv6            string    `json:"ipv6,omitempty"`
	ScannerAssetID  string    `json:"scanner_asset_id,omitempty"`
	CloudInstanceID string    `json:"cloud_instance_id,omitempty"`
	PlatformFamily  string    `json:"platform_family,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// Warrant Classes & Remediation Kinds (N1–N4)
const (
	WarrantClassSecretRotation = "SECRET-ROTATION-STATELESS"

	RemediationKindImagePatch     = "IMAGE_PATCH"
	RemediationKindSecretRotation = "SECRET_ROTATION"
	RemediationKindInPodDrift     = "IN_POD_DRIFT_QUARANTINE"

	DriftKindBannedDigest       = "BANNED_IMAGE_DIGEST"
	DriftKindFilesystemWebshell = "FILESYSTEM_WEBSHELL_DROP"
	DriftKindUntrackedProcess   = "UNTRACKED_PROCESS_EXEC"
)

// DefaultForbiddenDiffPrefixes lists CI/CD workflows, container build hooks, Makefile targets,
// and autonomous coding-agent configuration files that upstream N4 patch workers are cryptographically forbidden to touch.
var DefaultForbiddenDiffPrefixes = []string{
	".github/",
	".gitlab-ci",
	"Dockerfile",
	"Makefile",
	"AGENTS.md",
	"CLAUDE.md",
	".cursor",
	".gemini/",
	".windsurf",
	".copilot/",
	".vscode/",
	".git/",
}

// ExtractedFinding is a prose-free, strictly bounded canonical vulnerability record
// emitted exclusively by the isolated warrant-extractor service.
type ExtractedFinding struct {
	RuleID           string   `json:"rule_id"`
	CVEID            string   `json:"cve_id"`
	CWEID            string   `json:"cwe_id"`
	CVSSScore        float64  `json:"cvss_score"`
	IsKEV            bool     `json:"is_kev"`
	TargetServiceID  string   `json:"target_service_id"`
	PackagePURL      string   `json:"package_purl"`
	VulnerableDigest string   `json:"vulnerable_digest"`
	PatchedDigest    string   `json:"patched_digest"`
	VulnerableSymbol string   `json:"vulnerable_symbol"`
	ExploitVector    string   `json:"exploit_vector"` // "HTTP_PATH_TRAVERSAL" | "JNDI_LOOKUP" | "PROTO_DESERIALIZE" | "TLS_HEARTBEAT" | "HTTP2_RAPID_RESET"
	AffectedPort             int            `json:"affected_port"`
	BlockedPaths             []string       `json:"blocked_paths"`
	ArtifactPaths            []string       `json:"artifact_paths"`
	ChainedExploitEnabler    bool           `json:"chained_exploit_enabler,omitempty"`
	FinderVendor             string         `json:"finder_vendor,omitempty"`
	AssetIdentity            *AssetIdentity `json:"asset_identity,omitempty"`
	VendorDetectionID        string         `json:"vendor_detection_id,omitempty"`
	CVEMappingStatus         string         `json:"cve_mapping_status,omitempty"`
	NormalizedDetectionState string         `json:"normalized_detection_state,omitempty"`
	FirstSeenAt              string         `json:"first_seen_at,omitempty"`
	LastSeenAt               string         `json:"last_seen_at,omitempty"`
	KBArticleID              string         `json:"kb_article_id,omitempty"`
	PackageNEVRA             string         `json:"package_nevra,omitempty"`
	AdvisoryID               string         `json:"advisory_id,omitempty"`
}

// ExtractedFindingSet wraps extracted findings with input/output cryptographic digests.
type ExtractedFindingSet struct {
	SchemaVersion     string             `json:"schema_version"`
	ScannerToolID     string             `json:"scanner_tool_id"`
	Findings          []ExtractedFinding `json:"findings"`
	RawInputSHA256    string             `json:"raw_input_sha256"`
	TypedOutputSHA256 string             `json:"typed_output_sha256"`
	ExtractorDigest   string             `json:"extractor_digest"`
}

// ExtractedPatchMetadata is the prose-free canonical diff analysis emitted by warrant-extractor.
type ExtractedPatchMetadata struct {
	SchemaVersion          string   `json:"schema_version"`
	PatchedDigest          string   `json:"patched_digest"`
	FilesChanged           int      `json:"files_changed"`
	TouchedFiles           []string `json:"touched_files,omitempty"`
	ForbiddenConfigTouches []string `json:"forbidden_config_touches,omitempty"`
	DDLMigrations          int      `json:"ddl_migrations"`
	DetectedDDLKeywords    []string `json:"detected_ddl_keywords"`
	ORMModelMutations      int      `json:"orm_model_mutations"`
	DetectedORMTokens      []string `json:"detected_orm_tokens"`
	SerializationBreaks    int      `json:"serialization_breaks"`
	APIBackwardCompatible  bool     `json:"api_backward_compatible"`
	DeclaredSyscallDelta   []string `json:"declared_syscall_delta"`
	StatelessEligible      bool     `json:"stateless_eligible"`
	RawInputSHA256         string   `json:"raw_input_sha256"`
	TypedOutputSHA256      string   `json:"typed_output_sha256"`
	ExtractorDigest        string   `json:"extractor_digest"`
}

// ExtractedSecretFinding is a zero-secret, prose-free credential exposure record emitted by warrant-extractor
// from Gitleaks, GitGuardian, or cloud secret-exposure scanners (raw secret material is irreversibly hashed and stripped).
type ExtractedSecretFinding struct {
	FindingID               string `json:"finding_id"`
	DetectorTool            string `json:"detector_tool"` // "Gitleaks" | "GitGuardian" | "CloudSecretScanner"
	RuleID                  string `json:"rule_id"`       // e.g. "github-pat", "aws-access-token", "k8s-sa-jwt"
	TargetServiceID         string `json:"target_service_id"`
	SecretResourceKind      string `json:"secret_resource_kind"` // "EXTERNAL_SECRET" | "WORKLOAD_SA_TOKEN" | "K8S_SECRET"
	SecretResourceName      string `json:"secret_resource_name"`
	SecretFingerprintSHA256 string `json:"secret_fingerprint_sha256"`
	FilePath                string `json:"file_path,omitempty"`
}

// ExtractedSecretFindingSet wraps sanitized secret-exposure findings with cryptographic input/output lineage.
type ExtractedSecretFindingSet struct {
	SchemaVersion     string                   `json:"schema_version"`
	DetectorTool      string                   `json:"detector_tool"`
	Findings          []ExtractedSecretFinding `json:"findings"`
	RawInputSHA256    string                   `json:"raw_input_sha256"`
	TypedOutputSHA256 string                   `json:"typed_output_sha256"`
	ExtractorDigest   string                   `json:"extractor_digest"`
}

// ExtractedAdvisory represents bounded CycloneDX/VEX or CISA KEV metadata stripped of prose.
type ExtractedAdvisory struct {
	SchemaVersion     string   `json:"schema_version"`
	CVEID             string   `json:"cve_id"`
	VEXStatus         string   `json:"vex_status"` // "AFFECTED" | "FIXED" | "NOT_AFFECTED"
	IsKEV             bool     `json:"is_kev"`
	CVSSScore         float64  `json:"cvss_score"`
	AffectedPURLs     []string `json:"affected_purls"`
	FixedDigest       string   `json:"fixed_digest"`
	RawInputSHA256    string   `json:"raw_input_sha256"`
	TypedOutputSHA256 string   `json:"typed_output_sha256"`
	ExtractorDigest   string   `json:"extractor_digest"`
}

// Authority Lineage Modes (v1.0.2+ SQL INSERT Notarization Protection)
const (
	LineageModeGenesisSealed     = "GENESIS_SEALED"
	LineageModePostSeal2Of2      = "POST_SEAL_2OF2_DSSE"
	LineageModePostSeal1Of2      = "POST_SEAL_1OF2_DSSE"
	LineageModeKernelSystemBoot  = "KERNEL_SYSTEM_BOOT"
	LineageModeIGAWebhookAuth    = "IGA_AUTHENTICATED_WEBHOOK"
	LineageModeAgentSelfRevoke   = "AGENT_SELF_REVOCATION_DSSE"
)

// Principal represents a registered human or system cryptographic identity.
type Principal struct {
	PrincipalID       string           `json:"principal_id"`
	Email             string           `json:"email"`
	DisplayName       string           `json:"display_name"`
	Role              string           `json:"role"`
	KeyID             string           `json:"key_id"`
	Alg               string           `json:"alg"`
	PublicKeyB64      string           `json:"public_key_b64"`
	KeyFingerprint    string           `json:"key_fingerprint"`
	AuthenticatorMode string           `json:"authenticator_mode"` // "WEBAUTHN_HARDWARE" | "FIPS_PIV_SMARTCARD" | "ED25519_ENROLLED"
	CredentialID      string           `json:"credential_id,omitempty"`
	LineageMode       string           `json:"lineage_mode,omitempty"`
	GovernanceDSSE    *crypto.Envelope `json:"governance_dsse,omitempty"`
	Revoked           bool             `json:"revoked"`
	RevokeReason      string           `json:"revoke_reason,omitempty"`
	PrevHash          string           `json:"prev_hash,omitempty"`
	EntryHash         string           `json:"entry_hash,omitempty"`
	CreatedAt         time.Time        `json:"created_at"`
}

// PrincipalRevocation represents an active role departure or hardware key revocation in N1.
type PrincipalRevocation struct {
	RevocationID   string           `json:"revocation_id"`
	PrincipalID    string           `json:"principal_id"`
	KeyFingerprint string           `json:"key_fingerprint"`
	ReasonCode     string           `json:"reason_code"`
	RevokedBy      string           `json:"revoked_by"`
	LineageMode    string           `json:"lineage_mode,omitempty"`
	GovernanceDSSE *crypto.Envelope `json:"governance_dsse,omitempty"`
	PrevHash       string           `json:"prev_hash,omitempty"`
	EntryHash      string           `json:"entry_hash,omitempty"`
	RevokedAt      time.Time        `json:"revoked_at"`
}

// BootstrapState tracks whether one-shot genesis bootstrap enrollment has been permanently sealed
// along with its kernel-signed Genesis Seal Manifest digest.
type BootstrapState struct {
	Sealed                  bool             `json:"sealed"`
	SealedBy                string           `json:"sealed_by,omitempty"`
	SealedReason            string           `json:"sealed_reason,omitempty"`
	SealedAt                *time.Time       `json:"sealed_at,omitempty"`
	GenesisPrincipalMaxSeq  int64            `json:"genesis_principal_max_seq"`
	GenesisRevocationMaxSeq int64            `json:"genesis_revocation_max_seq"`
	GenesisManifestSHA256   string           `json:"genesis_manifest_sha256,omitempty"`
	GenesisSealDSSE         *crypto.Envelope `json:"genesis_seal_dsse,omitempty"`
}

// PrincipalGovernanceActions enumerates DSSE-signed governance & emergency actions.
const (
	GovActionEnrollPrincipal              = "ENROLL_PRINCIPAL"
	GovActionRevokePrincipal              = "REVOKE_PRINCIPAL"
	GovActionRotateAndRevokePrincipal     = "ROTATE_AND_REVOKE_PRINCIPAL"
	GovActionRotateKernelKey              = "ROTATE_KERNEL_KEY"
	GovActionSealBootstrap                = "SEAL_BOOTSTRAP"
	GovActionEmergencyFreeze              = "EMERGENCY_FREEZE"
	GovActionEmergencyRollback            = "EMERGENCY_ROLLBACK"
	GovActionMintAuditorToken             = "MINT_AUDITOR_TOKEN"
	GovActionFeedMutation                 = "FEED_MUTATION"
	GovActionCreateCheckpoint             = "CREATE_CHECKPOINT"
	GovActionSimulationDrill              = "SIMULATION_DRILL"
	GovActionUpsertCommissioningFunction  = "UPSERT_COMMISSIONING_FUNCTION"
	GovActionTransferCommissioningSponsor = "TRANSFER_COMMISSIONING_SPONSOR"
	GovActionEnrollAgentIdentity          = "ENROLL_AGENT_IDENTITY"
	GovActionRecertifyAgentIdentity       = "RECERTIFY_AGENT_IDENTITY"
	GovActionRevokeAgentIdentity          = "REVOKE_AGENT_IDENTITY"
	GovActionEmitIGAEvent                 = "EMIT_IGA_EVENT"
)

// PrincipalGovernancePayload is the RFC 8785 JCS payload inside a Principal Governance DSSEv1 envelope
// (2-of-2 required for ENROLL_PRINCIPAL, ROTATE_AND_REVOKE_PRINCIPAL, UPSERT_COMMISSIONING_FUNCTION,
// TRANSFER_COMMISSIONING_SPONSOR, ENROLL_AGENT_IDENTITY, and RECERTIFY_AGENT_IDENTITY; 1-of-2 active principal
// accepted for self REVOKE_PRINCIPAL, REVOKE_AGENT_IDENTITY, EMIT_IGA_EVENT & request-scoped emergency actions).
type PrincipalGovernancePayload struct {
	EnvelopeID           string   `json:"envelope_id"`
	Action               string   `json:"action"`
	IssuedAt             string   `json:"issued_at"`
	ExpiresAt            string   `json:"expires_at"`
	HTTPMethod           string   `json:"http_method,omitempty"`
	CanonicalPath        string   `json:"canonical_path,omitempty"`
	RequestBodySHA256    string   `json:"request_body_sha256,omitempty"`
	PrincipalID          string   `json:"principal_id,omitempty"`
	Email                string   `json:"email,omitempty"`
	DisplayName          string   `json:"display_name,omitempty"`
	Role                 string   `json:"role,omitempty"`
	KeyID                string   `json:"key_id,omitempty"`
	Alg                  string   `json:"alg,omitempty"`
	PublicKeyB64         string   `json:"public_key_b64,omitempty"`
	CredentialID         string   `json:"credential_id,omitempty"`
	AttestationObject    string   `json:"attestation_object,omitempty"`
	PublicKeySPKI        string   `json:"public_key_spki,omitempty"`
	TargetPrincipalID    string   `json:"target_principal_id,omitempty"`
	TargetKeyFingerprint string   `json:"target_key_fingerprint,omitempty"`
	ReasonCode           string   `json:"reason_code,omitempty"`
	FreezeMode           string   `json:"freeze_mode,omitempty"`
	RemediationID        string   `json:"remediation_id,omitempty"`
	AuditorLabel         string   `json:"auditor_label,omitempty"`
	ScopedAttestationIDs []string `json:"scoped_attestation_ids,omitempty"`
	TTLHours             int      `json:"ttl_hours,omitempty"`
	Scenario             string   `json:"scenario,omitempty"`

	// v1.1.0 Commissioning Function & Agent Identity Governance Fields
	FunctionID              string   `json:"function_id,omitempty"`
	OwningOrgUnit           string   `json:"owning_org_unit,omitempty"`
	CostCenter              string   `json:"cost_center,omitempty"`
	PrimarySOPrincipalID    string   `json:"primary_so_principal_id,omitempty"`
	SecondarySOPrincipalID  string   `json:"secondary_so_principal_id,omitempty"`
	PrimaryAOPrincipalID    string   `json:"primary_ao_principal_id,omitempty"`
	SecondaryAOPrincipalID  string   `json:"secondary_ao_principal_id,omitempty"`
	EscalationContact       string   `json:"escalation_contact,omitempty"`
	OrphanGraceHours        *int     `json:"orphan_grace_hours,omitempty"`
	AgentID                 string   `json:"agent_id,omitempty"`
	AgentKind               string   `json:"agent_kind,omitempty"`
	CommissioningFunctionID string   `json:"commissioning_function_id,omitempty"`
	SPIFFEID                string   `json:"spiffe_id,omitempty"`
	ArtifactDigest          string   `json:"artifact_digest,omitempty"`
	BuilderPrincipalID      string   `json:"builder_principal_id,omitempty"`
	BuilderPublicKeyB64     string   `json:"builder_public_key_b64,omitempty"`
	BuilderKeyFingerprint   string   `json:"builder_key_fingerprint,omitempty"`
	BuilderProvenanceSigB64 string   `json:"builder_provenance_sig_b64,omitempty"`
	AllowedActions          []string `json:"allowed_actions,omitempty"`
	AllowedServices         []string `json:"allowed_services,omitempty"`
	AllowedEgressProfile    string   `json:"allowed_egress_profile,omitempty"`
	MaxTTLSeconds           int      `json:"max_ttl_seconds,omitempty"`
	MaxDelegationDepth      int      `json:"max_delegation_depth,omitempty"`
	AllowAutonomousIntake   bool     `json:"allow_autonomous_intake,omitempty"`
	RecertifyExpiresAt      string   `json:"recertify_expires_at,omitempty"`
	RecertifyDays           int      `json:"recertify_days,omitempty"`
	IGAEventType            string   `json:"iga_event_type,omitempty"`
}

// ThawPayload is the JCS-canonicalized body inside a 2-of-2 freeze-thaw DSSE envelope,
// bound to a monotonic freeze_epoch and single-use envelope_id to block cross-epoch replay.
type ThawPayload struct {
	EnvelopeID  string `json:"envelope_id"`
	Action      string `json:"action"`
	FreezeEpoch int64  `json:"freeze_epoch"`
	IssuedAt    string `json:"issued_at,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// ExceptionResolutionPayload is the JCS-canonicalized body inside a 2-of-2 Four-Eyes Exception DSSE envelope.
type ExceptionResolutionPayload struct {
	EnvelopeID    string `json:"envelope_id"`
	ExceptionID   string `json:"exception_id"`
	RemediationID string `json:"remediation_id,omitempty"`
	ServiceID     string `json:"service_id,omitempty"`
	CVEID         string `json:"cve_id,omitempty"`
	Decision      string `json:"decision,omitempty"`
	IssuedAt      string `json:"issued_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

// KernelKeyRotationPayload attests a kernel signing key rotation in kernel_public_keys beyond seq_no=1.
type KernelKeyRotationPayload struct {
	EnvelopeID        string `json:"envelope_id"`
	NewKeyID          string `json:"new_key_id"`
	NewAlg            string `json:"new_alg"`
	NewPublicKeyB64   string `json:"new_public_key_b64"`
	NewKeyFingerprint string `json:"new_key_fingerprint"`
	BackendMode       string `json:"backend_mode"`
	IssuedAt          string `json:"issued_at"`
}

// DeclaredCloneSource binds an estate-read or explicitly manual clone image/template identity into a 2-of-2 Standing Warrant class.
type DeclaredCloneSource struct {
	SourceSystem          string `json:"source_system"`
	ImageIdentity         string `json:"image_identity"`
	PlatformFamily        string `json:"platform_family,omitempty"`
	SnapshotSHA256        string `json:"snapshot_sha256,omitempty"`
	QueryIdentity         string `json:"query_identity,omitempty"`
	SourceMode            string `json:"source_mode"` // "ESTATE_LOADER" | "MANUAL"
	ImageCreatedAt        string `json:"image_created_at,omitempty"`
	ImageAgeSecondsAtSign int64  `json:"image_age_seconds_at_sign,omitempty"`
	DeclaredAt            string `json:"declared_at"`
}

// WarrantPayload is the JCS-canonicalized body inside a dual-signed Standing Warrant DSSE envelope.
type WarrantPayload struct {
	WarrantID                  string                `json:"warrant_id"`
	WarrantClass               string                `json:"warrant_class"`
	ScopeServices              []string              `json:"scope_services"`
	ScopeAssets                []string              `json:"scope_assets,omitempty"`
	AuthorizedVendorDetections []string              `json:"authorized_vendor_detections,omitempty"`
	MaxCVSS                    float64               `json:"max_cvss"`
	KEVEligible                bool                  `json:"kev_eligible"`
	MaxBlastRadiusReplicas     int                   `json:"max_blast_radius_replicas"`
	AllowStatefulPatches       bool                  `json:"allow_stateful_patches"`
	AllowGuardedCanary         bool                  `json:"allow_guarded_canary,omitempty"`
	AllowSecretRotation        bool                  `json:"allow_secret_rotation,omitempty"`
	AutoRemediateCWEs          []string              `json:"auto_remediate_cwes,omitempty"`
	MinCanarySamples           int                   `json:"min_canary_samples,omitempty"`
	StageDwellSeconds          int                   `json:"stage_dwell_seconds,omitempty"`
	CloneTwinCount             int                   `json:"clone_twin_count,omitempty"`
	CloneSources               []DeclaredCloneSource `json:"clone_sources,omitempty"`
	EstateSnapshotSHA256       string                `json:"estate_snapshot_sha256,omitempty"`
	EstateDriftPolicy          string                `json:"estate_drift_policy,omitempty"`
	EstateDriftTolerancePct    float64               `json:"estate_drift_tolerance_pct,omitempty"`
	MaxEstateStalenessSec      int64                 `json:"max_estate_staleness_seconds,omitempty"`
	SLABridgeMinutes           int                   `json:"sla_bridge_minutes"`
	MaxP99LatencyMs            float64               `json:"max_p99_latency_ms"`
	IssuedAt                   string                `json:"issued_at"`
	ExpiresAt                  string                `json:"expires_at"`
}

// WarrantRecord represents an immutable Standing Warrant row in warrant_envelopes.
type WarrantRecord struct {
	WarrantID                  string                `json:"warrant_id"`
	WarrantClass               string                `json:"warrant_class"`
	ScopeServices              []string              `json:"scope_services"`
	ScopeAssets                []string              `json:"scope_assets,omitempty"`
	AuthorizedVendorDetections []string              `json:"authorized_vendor_detections,omitempty"`
	MaxCVSS                    float64               `json:"max_cvss"`
	KEVEligible                bool                  `json:"kev_eligible"`
	MaxBlastRadiusReplicas     int                   `json:"max_blast_radius_replicas"`
	AllowStatefulPatches       bool                  `json:"allow_stateful_patches"`
	AllowGuardedCanary         bool                  `json:"allow_guarded_canary"`
	AllowSecretRotation        bool                  `json:"allow_secret_rotation"`
	AutoRemediateCWEs          []string              `json:"auto_remediate_cwes,omitempty"`
	MinCanarySamples           int                   `json:"min_canary_samples"`
	StageDwellSeconds          int                   `json:"stage_dwell_seconds"`
	CloneTwinCount             int                   `json:"clone_twin_count,omitempty"`
	CloneSources               []DeclaredCloneSource `json:"clone_sources,omitempty"`
	EstateSnapshotSHA256       string                `json:"estate_snapshot_sha256,omitempty"`
	EstateDriftPolicy          string                `json:"estate_drift_policy,omitempty"`
	EstateDriftTolerancePct    float64               `json:"estate_drift_tolerance_pct,omitempty"`
	MaxEstateStalenessSec      int64                 `json:"max_estate_staleness_seconds,omitempty"`
	SLABridgeMinutes       int             `json:"sla_bridge_minutes"`
	MaxP99LatencyMs        float64         `json:"max_p99_latency_ms"`
	IssuedAt               time.Time       `json:"issued_at"`
	ExpiresAt              time.Time       `json:"expires_at"`
	DSSEEnvelope           crypto.Envelope `json:"dsse_envelope"`
	Slot1PrincipalID       string          `json:"slot1_principal_id"`
	Slot1Email             string          `json:"slot1_email"`
	Slot1KeyFP             string          `json:"slot1_key_fp"`
	Slot1Role              string          `json:"slot1_role"`
	Slot2PrincipalID       string          `json:"slot2_principal_id"`
	Slot2Email             string          `json:"slot2_email"`
	Slot2KeyFP             string          `json:"slot2_key_fp"`
	Slot2Role              string          `json:"slot2_role"`
	LiveStatus             string          `json:"live_status"` // "ACTIVE" | "EXPIRED" | "REVOKED_SIGNER"
	RevocationReason       string          `json:"revocation_reason,omitempty"`
	PrevHash               string          `json:"prev_hash"`
	EntryHash              string          `json:"entry_hash"`
	CreatedAt              time.Time       `json:"created_at"`
}

// FreezeState captures the current fleet-wide Asymmetric Emergency Freeze posture.
type FreezeState struct {
	Mode        string           `json:"mode"`
	Actor       string           `json:"actor"`
	ReasonCode  string           `json:"reason_code"`
	FreezeEpoch int64            `json:"freeze_epoch"`
	UpdatedAt   time.Time        `json:"updated_at"`
	ThawDSSE    *crypto.Envelope `json:"thaw_dsse,omitempty"`
}

// ApprovalPressureStat tracks exception depth and override velocity per Warrant Class.
type ApprovalPressureStat struct {
	WarrantClass      string  `json:"warrant_class"`
	ActiveWarrants    int     `json:"active_warrants"`
	PendingExceptions int     `json:"pending_exceptions"`
	OverridesLast24h  int     `json:"overrides_last_24h"`
	PressureScore     float64 `json:"pressure_score"`
	PressureStatus    string  `json:"pressure_status"` // "NOMINAL" | "ELEVATED" | "PRESSURE_HIGH"
}

// EligibilityCheckItem is a deterministic pass/fail remediation check for Platform Engineers.
type EligibilityCheckItem struct {
	CriterionCode     string `json:"criterion_code"`
	Passed            bool   `json:"passed"`
	ObservedValue     string `json:"observed_value"`
	RequiredThreshold string `json:"required_threshold"`
	ActionCode        string `json:"action_code"`
}

// EstateService represents a workload registered in G1-Warrant's Estate Readiness Grader.
type EstateService struct {
	ServiceID                  string                 `json:"service_id"`
	DisplayName                string                 `json:"display_name"`
	Namespace                  string                 `json:"namespace"`
	Tier                       string                 `json:"tier"`
	WarrantClass               string                 `json:"warrant_class"`
	CurrentDigest              string                 `json:"current_digest"`
	CurrentPURL                string                 `json:"current_purl"`
	SBOMPURLs                  []string               `json:"sbom_purls,omitempty"`
	Replicas                   int                    `json:"replicas"`
	TestCoveragePct            float64                `json:"test_coverage_pct"`
	OtelHealthProbes           bool                   `json:"otel_health_probes"`
	ReadonlyShadowReplica      bool                   `json:"readonly_shadow_replica"`
	ShadowDBMode               string                 `json:"shadow_db_mode"` // "EPHEMERAL_COW_BRANCH" | "READONLY_REPLICA" | "NONE"
	RollbackAutomationVerified bool                   `json:"rollback_automation_verified"`
	ReadOnlyRootFilesystem     bool                   `json:"readonly_root_filesystem"`
	NoExecTmpMounts            bool                   `json:"noexec_tmp_mounts"`
	AllowedEgressServices      []string               `json:"allowed_egress_services,omitempty"`
	AllowKubeAPIServerEgress   bool                   `json:"allow_kube_apiserver_egress,omitempty"`
	BaselineSyscalls           []string               `json:"baseline_syscalls"`
	VolatileJSONPaths          []string               `json:"volatile_json_paths,omitempty"`
	UnorderedArrayPaths        []string               `json:"unordered_array_paths,omitempty"`
	Eligible                   bool                   `json:"eligible"`
	AutonomyTier               string                 `json:"autonomy_tier"` // "TIER_1_FULL_AUTONOMOUS" | "TIER_2_GUARDED_CANARY" | "TIER_3_CONTAIN_AND_CAB"
	EligibilityChecklist       []EligibilityCheckItem `json:"eligibility_checklist"`
	UpdatedAt                  time.Time              `json:"updated_at"`
}

// LatencySummary captures deterministic p50/p95/p99 latency percentiles.
type LatencySummary struct {
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
}

// SchemaFieldDiff records a normalized structural JSON schema divergence.
type SchemaFieldDiff struct {
	JSONPath     string `json:"json_path"`
	BaselineType string `json:"baseline_type"`
	CanaryType   string `json:"canary_type"`
	ChangeKind   string `json:"change_kind"` // "MISSING_KEY" | "TYPE_CHANGED" | "ADDED_NULLABLE"
	Breaking     bool   `json:"breaking"`
}

// ShadowComparisonReport captures N2 Differential Shadow execution results.
type ShadowComparisonReport struct {
	RunID                      string            `json:"run_id"`
	RemediationID              string            `json:"remediation_id"`
	ServiceID                  string            `json:"service_id"`
	StageWeight                int               `json:"stage_weight"`
	ShadowIsolationVerified    bool              `json:"shadow_isolation_verified"`
	ReadonlyDBBound            bool              `json:"readonly_db_bound"`
	OutboundMutationSinkActive bool              `json:"outbound_mutation_sink_active"`
	NormalizedBaselineSample   string            `json:"normalized_baseline_sample"`
	NormalizedCanarySample     string            `json:"normalized_canary_sample"`
	VolatileFieldsMasked       []string          `json:"volatile_fields_masked"`
	SchemaBreakingDiffs        int               `json:"schema_breaking_diffs"`
	SchemaFieldDiffs           []SchemaFieldDiff `json:"schema_field_diffs"`
	StatusCodeDriftPct         float64           `json:"status_code_drift_pct"`
	BaselineLatency            LatencySummary    `json:"baseline_latency"`
	CanaryLatency              LatencySummary    `json:"canary_latency"`
	MaxP99LatencyMs            float64           `json:"max_p99_latency_ms"`
	BaselineSyscalls           []string          `json:"baseline_syscalls"`
	CanarySyscalls             []string          `json:"canary_syscalls"`
	UnauthorizedSyscalls       []string          `json:"unauthorized_syscalls"`
	SensitiveFilesAccessed     []string          `json:"sensitive_files_accessed,omitempty"`
	UnexpectedEgressEndpoints  []string          `json:"unexpected_egress_endpoints,omitempty"`
	SampleCount                int               `json:"sample_count,omitempty"`
	ObservedDwellSeconds       int               `json:"observed_dwell_seconds,omitempty"`
	Passed                     bool              `json:"passed"`
	FailureCode                string            `json:"failure_code,omitempty"`
	EvaluatedAt                time.Time         `json:"evaluated_at"`
}

// RemediationItem represents an end-to-end remediation progressing across the 5-stage Race Pipeline.
type RemediationItem struct {
	RemediationID         string                  `json:"remediation_id"`
	RemediationKind       string                  `json:"remediation_kind,omitempty"`
	CVEID                 string                  `json:"cve_id"`
	CWEID                 string                  `json:"cwe_id"`
	IsKEV                 bool                    `json:"is_kev"`
	ChainedExploitEnabler bool                    `json:"chained_exploit_enabler,omitempty"`
	CVSSScore             float64                 `json:"cvss_score"`
	ServiceID             string                  `json:"service_id"`
	WarrantID             string                  `json:"warrant_id"`
	SecretResourceName    string                  `json:"secret_resource_name,omitempty"`
	VulnerableDigest      string                  `json:"vulnerable_digest"`
	PatchedDigest    string                  `json:"patched_digest"`
	PackagePURL      string                  `json:"package_purl"`
	VulnerableSymbol string                  `json:"vulnerable_symbol"`
	ExploitVector    string                  `json:"exploit_vector"`
	Stage            string                  `json:"stage"`
	StatusHealth     string                  `json:"status_health"`
	BlockerCode      string                  `json:"blocker_code,omitempty"`
	CanaryWeight     int                     `json:"canary_weight"`
	StatelessPassed  *bool                   `json:"stateless_passed"`
	SchemaDiffPassed *bool                   `json:"schema_diff_passed"`
	SyscallPassed    *bool                   `json:"syscall_diff_passed"`
	TwinReplayStatus string                  `json:"twin_replay_status"`
	AssuranceTier    string                  `json:"assurance_tier,omitempty"`
	PodSweepMatched  int                     `json:"pod_sweep_matched"`
	PodSweepTotal    int                     `json:"pod_sweep_total"`
	LockoutPolicyID  string                  `json:"lockout_policy_id,omitempty"`
	BridgeID         string                  `json:"bridge_id,omitempty"`
	BridgeSLAMIN     int                     `json:"bridge_sla_minutes"`
	AttestationID            string                  `json:"attestation_id,omitempty"`
	FinderVendor             string                  `json:"finder_vendor,omitempty"`
	VendorDetectionID        string                  `json:"vendor_detection_id,omitempty"`
	CVEMappingStatus         string                     `json:"cve_mapping_status,omitempty"`
	ClassBindingStatus       string                     `json:"class_binding_status,omitempty"`
	PatchTargetLayer         string                     `json:"patch_target_layer,omitempty"`
	NormalizedDetectionState string                     `json:"normalized_detection_state,omitempty"`
	AssetIdentity            *AssetIdentity             `json:"asset_identity,omitempty"`
	FirstSeenAt              *time.Time                 `json:"first_seen_at,omitempty"`
	LastSeenAt               *time.Time                 `json:"last_seen_at,omitempty"`
	DistributorID            string                     `json:"distributor_id,omitempty"`
	LatestOrderID            string                     `json:"latest_order_id,omitempty"`
	ClosureCompleteness      string                     `json:"closure_completeness,omitempty"`
	TargetedAssetCount       int                        `json:"targeted_asset_count,omitempty"`
	LandedAssetCount         int                        `json:"landed_asset_count,omitempty"`
	FailedAssetCount         int                        `json:"failed_asset_count,omitempty"`
	PendingAssetCount        int                        `json:"pending_asset_count,omitempty"`
	RebootWaitingCount       int                        `json:"reboot_waiting_count,omitempty"`
	RolledBackAssetCount     int                        `json:"rolled_back_asset_count,omitempty"`
	PatchMetadata            *ExtractedPatchMetadata    `json:"patch_metadata,omitempty"`
	ShadowReport             *ShadowComparisonReport    `json:"shadow_report,omitempty"`
	CloneTwinProving         *CloneTwinProvingManifest  `json:"clone_twin_proving,omitempty"`
	CreatedAt        time.Time               `json:"created_at"`
	BridgedAt        *time.Time              `json:"bridged_at,omitempty"`
	ClosedAt         *time.Time              `json:"closed_at,omitempty"`
	UpdatedAt        time.Time               `json:"updated_at"`
}

// TraceEvent is a millisecond-timestamped deterministic state transition in the Execution Trace Drawer.
type TraceEvent struct {
	TraceID       string            `json:"trace_id"`
	RemediationID string            `json:"remediation_id"`
	Engine        string            `json:"engine"` // "N1" | "N2" | "N3" | "N4" | "N5" | "ADAPTER"
	StepCode      string            `json:"step_code"`
	Outcome       string            `json:"outcome"` // "PASS" | "BLOCK" | "ROLLBACK" | "REARM" | "ATTESTED"
	ActorOrToken  string            `json:"actor_or_token"`
	EvidenceHash  string            `json:"evidence_hash"`
	Fields        map[string]string `json:"fields"`
	OccurredAt    time.Time         `json:"occurred_at"`
}

// CeilingException represents an item routed to the N1 Four-Eyes Exception Cockpit.
type CeilingException struct {
	ExceptionID           string           `json:"exception_id"`
	RemediationID         string           `json:"remediation_id"`
	ServiceID             string           `json:"service_id"`
	CVEID                 string           `json:"cve_id"`
	WarrantClass          string           `json:"warrant_class"`
	TriggerCode           string           `json:"trigger_code"`
	DDLCount              int              `json:"ddl_count"`
	ORMMutations          int              `json:"orm_mutations"`
	SerializationBreaks   int              `json:"serialization_breaks"`
	APIBackwardCompatible bool             `json:"api_backward_compatible"`
	ShadowReplayStatus    string           `json:"shadow_replay_status"`
	SyscallDiffSummary    string           `json:"syscall_diff_summary"`
	ActiveBridgeID        string           `json:"active_bridge_id"`
	Status                string           `json:"status"` // "PENDING_DUAL_KEY" | "APPROVED" | "REJECTED"
	ResolutionDSSE        *crypto.Envelope `json:"resolution_dsse,omitempty"`
	CreatedAt             time.Time        `json:"created_at"`
	ResolvedAt            *time.Time       `json:"resolved_at,omitempty"`
}

// ContainmentBridge represents a temporary Cilium / K8s NetworkPolicy / Envoy mTLS containment rule.
type ContainmentBridge struct {
	BridgeID           string     `json:"bridge_id"`
	RemediationID      string     `json:"remediation_id"`
	ServiceID          string     `json:"service_id"`
	CVEID              string     `json:"cve_id"`
	BridgeType         string     `json:"bridge_type"`      // "CILIUM_L7_NETPOL" | "ENVOY_MTLS_WAF" | "K8S_NETPOL"
	ContainmentMode      string     `json:"containment_mode"` // "ZERO_PROSE_EGRESS_MESH_QUARANTINE" | "SIGNED_RULEPACK_L7_SHIELD"
	RulepackID           string     `json:"rulepack_id,omitempty"`
	MetadataPlaneBlocked bool       `json:"metadata_plane_blocked"`
	AllowedEgressPeers   []string   `json:"allowed_egress_peers,omitempty"`
	Status               string     `json:"status"` // "ARMED" | "RETIRED" | "REARMED_DRIFT"
	SLABridgeMinutes   int        `json:"sla_minutes"`
	BlockerReasonCode  string     `json:"blocker_reason_code"`
	CiliumManifestYAML string     `json:"cilium_manifest_yaml"`
	K8sNetpolYAML      string     `json:"k8s_netpol_yaml"`
	EnvoyFilterJSON    string     `json:"envoy_filter_json"`
	ArmedAt            time.Time  `json:"armed_at"`
	RetiredAt          *time.Time `json:"retired_at,omitempty"`
	RearmedCount       int        `json:"rearmed_count"`
}

// AdmissionLockout represents a permanent ValidatingAdmissionPolicy + Gatekeeper digest lockout.
type AdmissionLockout struct {
	LockoutID       string     `json:"lockout_id"`
	RemediationID   string     `json:"remediation_id"`
	ServiceID       string     `json:"service_id"`
	CVEID           string     `json:"cve_id"`
	BannedDigest    string     `json:"banned_digest"`
	PatchedDigest   string     `json:"patched_digest"`
	PolicyName      string     `json:"policy_name"`
	Status          string     `json:"status"` // "ENFORCED" | "SUSPENDED_FOR_QUARANTINED_ROLLBACK"
	SuspendedReason string     `json:"suspended_reason,omitempty"`
	VAPManifestYAML string     `json:"vap_manifest_yaml"`
	GatekeeperRego  string     `json:"gatekeeper_rego"`
	EnforcedAt      time.Time  `json:"enforced_at"`
	DriftCount      int        `json:"drift_count"`
	LastDriftAt     *time.Time `json:"last_drift_at,omitempty"`
}

// DriftIncident records a sub-second runtime drift detection (banned image digest OR in-pod Tetragon/eBPF
// filesystem webshell / untracked process violation) and automatic Shield re-arming + pod cordon/recycle.
type DriftIncident struct {
	IncidentID         string     `json:"incident_id"`
	DriftKind          string     `json:"drift_kind"` // "BANNED_IMAGE_DIGEST" | "FILESYSTEM_WEBSHELL_DROP" | "UNTRACKED_PROCESS_EXEC"
	LockoutID          string     `json:"lockout_id"`
	RemediationID      string     `json:"remediation_id"`
	ServiceID          string     `json:"service_id"`
	CVEID              string     `json:"cve_id"`
	DetectedDigest     string     `json:"detected_digest"`
	ViolatingArtifact  string     `json:"violating_artifact,omitempty"`
	RoguePodName       string     `json:"rogue_pod_name"`
	PodCordoned        bool       `json:"pod_cordoned"`
	PodRecycled        bool       `json:"pod_recycled"`
	RearmedBridgeID    string     `json:"rearmed_bridge_id"`
	DetectionLatencyMs int64      `json:"detection_latency_ms"`
	DetectedAt         time.Time  `json:"detected_at"`
	ResolvedAt         *time.Time `json:"resolved_at,omitempty"`
}

// TetragonDriftEvent represents a Cilium Tetragon / eBPF runtime immutability alert emitted when
// a running container writes a file (e.g., artex-probe, JSP webshell) or spawns an untracked binary.
type TetragonDriftEvent struct {
	ServiceID          string `json:"service_id"`
	Namespace          string `json:"namespace,omitempty"`
	PodName            string `json:"pod_name"`
	RunningDigest      string `json:"running_digest,omitempty"`
	ViolationType      string `json:"violation_type"` // "FILESYSTEM_WRITE" | "UNTRACKED_EXEC"
	TargetPathOrBinary string `json:"target_path_or_binary"`
	ObservedAtUnixMs   int64  `json:"observed_at_unix_ms,omitempty"`
}

// Agent Kinds, Authority Modes, Egress Profiles, Sponsorship States & IGA Event Types (v1.1.0)
const (
	AgentKindInternalWorker     = "INTERNAL_WORKER"
	AgentKindExternalAutonomous = "EXTERNAL_AUTONOMOUS_AGENT"

	AuthorityModeWarrantComposite    = "WARRANT_DELEGATED_COMPOSITE"
	AuthorityModeAutonomousSponsored = "AUTONOMOUS_WORKLOAD_SPONSORED"

	EgressProfileZeroIsolated    = "ZERO_EGRESS_ISOLATED"
	EgressProfileInternalCluster = "INTERNAL_CLUSTER_ONLY"

	SponsorshipActive              = "ACTIVE"
	SponsorshipSecondaryContinuity = "ACTIVE_SECONDARY_CONTINUITY"
	SponsorshipGraceEscalated      = "SPONSOR_GRACE_ESCALATED"
	SponsorshipOrphanQuarantined   = "ORPHAN_QUARANTINED"
	SponsorshipLeaseExpired        = "LEASE_EXPIRED_QUARANTINED"
	SponsorshipRevokedCompromise   = "REVOKED_COMPROMISE"
	SponsorshipRevokedKillSwitch   = "REVOKED_KILL_SWITCH"

	IGAEventRoleTransfer   = "ROLE_TRANSFER"
	IGAEventOrgReorg       = "ORG_REORG"
	IGAEventLeaveOfAbsence = "LEAVE_OF_ABSENCE"
	IGAEventTermination    = "TERMINATION"
	IGAEventKeyCompromise  = "KEY_COMPROMISE"

	SystemCommissioningFunctionID = "fn-g1-system-control-plane"
)

// CommissioningFunction anchors agent sponsorship to an organizational function (org unit, cost center,
// primary + backup SO/AO sponsors, escalation target, and bounded orphan grace window) rather than brittle single-user IDs.
type CommissioningFunction struct {
	FunctionID               string           `json:"function_id"`
	DisplayName              string           `json:"display_name"`
	OwningOrgUnit            string           `json:"owning_org_unit"`
	CostCenter               string           `json:"cost_center"`
	PrimarySOPrincipalID     string           `json:"primary_so_principal_id"`
	SecondarySOPrincipalID   string           `json:"secondary_so_principal_id,omitempty"`
	PrimaryAOPrincipalID     string           `json:"primary_ao_principal_id"`
	SecondaryAOPrincipalID   string           `json:"secondary_ao_principal_id,omitempty"`
	EscalationContact        string           `json:"escalation_contact"`
	OrphanGraceHours         int              `json:"orphan_grace_hours"`
	ActiveSOCount            int              `json:"active_so_count"`
	ActiveAOCount            int              `json:"active_ao_count"`
	ContinuityStatus         string           `json:"continuity_status"`
	PendingSponsorSuccession bool             `json:"pending_sponsor_succession"`
	DepartedSponsors         []string         `json:"departed_sponsors,omitempty"`
	LineageMode              string           `json:"lineage_mode,omitempty"`
	GovernanceDSSE           *crypto.Envelope `json:"governance_dsse,omitempty"`
	PrevHash                 string           `json:"prev_hash,omitempty"`
	EntryHash                string           `json:"entry_hash,omitempty"`
	CreatedAt                time.Time        `json:"created_at"`
}

// AgentIdentity represents an immutable, cryptographically enrolled workload/agent identity in agent_identities
// with 3-Way Builder != Commissioner Separation of Duties and live IGA sponsorship health.
type AgentIdentity struct {
	AgentID                   string           `json:"agent_id"`
	DisplayName               string           `json:"display_name"`
	AgentKind                 string           `json:"agent_kind"` // "INTERNAL_WORKER" | "EXTERNAL_AUTONOMOUS_AGENT"
	CommissioningFunctionID   string           `json:"commissioning_function_id"`
	KeyID                     string           `json:"key_id"`
	Alg                       string           `json:"alg"`
	PublicKeyB64              string           `json:"public_key_b64"`
	KeyFingerprint            string           `json:"key_fingerprint"`
	SPIFFEID                  string           `json:"spiffe_id,omitempty"`
	ArtifactDigest            string           `json:"artifact_digest"`
	BuilderPrincipalID        string           `json:"builder_principal_id"`
	BuilderPublicKeyB64       string           `json:"builder_public_key_b64,omitempty"`
	BuilderKeyFingerprint     string           `json:"builder_key_fingerprint"`
	BuilderProvenanceSigB64   string           `json:"builder_provenance_sig_b64"`
	AllowedActions            []string         `json:"allowed_actions"`
	AllowedServices           []string         `json:"allowed_services"`
	AllowedEgressProfile      string           `json:"allowed_egress_profile"`
	MaxTTLSeconds             int              `json:"max_ttl_seconds"`
	MaxDelegationDepth        int              `json:"max_delegation_depth"`
	AllowAutonomousIntake     bool             `json:"allow_autonomous_intake"`
	RecertifyExpiresAt        time.Time        `json:"recertify_expires_at"`
	CommissionerSOPrincipalID string           `json:"commissioner_so_principal_id"`
	CommissionerSOKeyFP       string           `json:"commissioner_so_key_fp"`
	CommissionerAOPrincipalID string           `json:"commissioner_ao_principal_id"`
	CommissionerAOKeyFP       string           `json:"commissioner_ao_key_fp"`
	SponsorshipState          string           `json:"sponsorship_state"`
	SponsorCompromised        bool             `json:"sponsor_compromised"`
	GraceActive               bool             `json:"grace_active"`
	GraceExpiresAt            *time.Time       `json:"grace_expires_at,omitempty"`
	Revoked                   bool             `json:"revoked"`
	RevokeReason              string           `json:"revoke_reason,omitempty"`
	LineageMode               string           `json:"lineage_mode,omitempty"`
	GovernanceDSSE            *crypto.Envelope `json:"governance_dsse,omitempty"`
	PrevHash                  string           `json:"prev_hash,omitempty"`
	EntryHash                 string           `json:"entry_hash,omitempty"`
	EnrolledAt                time.Time        `json:"enrolled_at"`
}

// AgentLifecycleEvent records an append-only WORM transition in agent_lifecycle_events
// (IGA HR transfer/reorg/LOA/termination/compromise, recertification renewal, or agent kill-switch revocation).
type AgentLifecycleEvent struct {
	EventID             string           `json:"event_id"`
	EventType           string           `json:"event_type"`
	TargetAgentID       string           `json:"target_agent_id,omitempty"`
	TargetFunctionID    string           `json:"target_function_id,omitempty"`
	AffectedPrincipalID string           `json:"affected_principal_id,omitempty"`
	NewSponsorshipState string           `json:"new_sponsorship_state"`
	GraceExpiresAt      *time.Time       `json:"grace_expires_at,omitempty"`
	RecertifyExpiresAt  *time.Time       `json:"recertify_expires_at,omitempty"`
	ReasonCode          string           `json:"reason_code"`
	TriggeredBy         string           `json:"triggered_by"`
	LineageMode         string           `json:"lineage_mode,omitempty"`
	GovernanceDSSE      *crypto.Envelope `json:"governance_dsse,omitempty"`
	PrevHash            string           `json:"prev_hash,omitempty"`
	EntryHash           string           `json:"entry_hash,omitempty"`
	OccurredAt          time.Time        `json:"occurred_at"`
}

// IGAEventRequest represents an inbound HR/IAM lifecycle event on POST /api/v1/iga/events.
type IGAEventRequest struct {
	EventID       string     `json:"event_id,omitempty"`
	EventType     string     `json:"event_type"` // ROLE_TRANSFER | ORG_REORG | LEAVE_OF_ABSENCE | TERMINATION | KEY_COMPROMISE
	PrincipalID   string     `json:"principal_id"`
	ReasonCode    string     `json:"reason_code,omitempty"`
	SourceSystem  string     `json:"source_system,omitempty"`
	EffectiveTime *time.Time `json:"effective_time,omitempty"`
}

// PendingSponsorTransfer surfaces a CommissioningFunction awaiting a 2-of-2 TRANSFER_COMMISSIONING_SPONSOR ceremony in the Console Action Inbox.
type PendingSponsorTransfer struct {
	FunctionID            string     `json:"function_id"`
	DisplayName           string     `json:"display_name"`
	OwningOrgUnit         string     `json:"owning_org_unit"`
	EscalationContact     string     `json:"escalation_contact"`
	ContinuityStatus      string     `json:"continuity_status"`
	DepartedPrincipals    []string   `json:"departed_principals"`
	AffectedAgentsCount   int        `json:"affected_agents_count"`
	EarliestGraceExpiryAt *time.Time `json:"earliest_grace_expiry_at,omitempty"`
}

// ActorClaim implements RFC 8693 Section 4.1 nested "act" delegation lineage inside an EphemeralTaskWarrant.
type ActorClaim struct {
	AgentID                 string      `json:"agent_id"`
	KeyID                   string      `json:"key_id"`
	KeyFingerprint          string      `json:"key_fingerprint"`
	CommissioningFunctionID string      `json:"commissioning_function_id"`
	SponsorshipState        string      `json:"sponsorship_state"`
	ParentActor             *ActorClaim `json:"act,omitempty"`
}

// ConfirmationClaim implements RFC 7800 / RFC 8693 "cnf" Holder-of-Key binding for wire-level X-Warrant-Agent-PoP.
type ConfirmationClaim struct {
	Alg            string `json:"alg"`
	KeyID          string `json:"kid"`
	PublicKeyB64   string `json:"public_key_b64"`
	KeyFingerprint string `json:"jkt_sha256"`
}

// AgentTokenExchangePayload is the JCS body inside a caller-signed DSSE PoP request on POST /api/v1/agents/token-exchange.
type AgentTokenExchangePayload struct {
	EnvelopeID             string           `json:"envelope_id"`
	AgentID                string           `json:"agent_id"`
	AuthorityMode          string           `json:"authority_mode"`
	WarrantID              string           `json:"warrant_id,omitempty"`
	RemediationID          string           `json:"remediation_id,omitempty"`
	TargetAsset            string           `json:"target_asset"`
	RequestedAction        string           `json:"requested_action"`
	RequestedEgressProfile string           `json:"requested_egress_profile,omitempty"`
	RequestedTTLSeconds    int              `json:"requested_ttl_seconds"`
	ParentTaskWarrant      *crypto.Envelope `json:"parent_task_warrant,omitempty"`
	ParentHolderPoPSigB64  string           `json:"parent_holder_pop_sig_b64,omitempty"`
	IssuedAt               string           `json:"issued_at"`
	ExpiresAt              string           `json:"expires_at"`
}

// AgentTokenExchangeResponse returns the kernel-signed RFC 8693 EphemeralTaskWarrant envelope and resolved claims.
type AgentTokenExchangeResponse struct {
	TaskWarrantDSSE     crypto.Envelope             `json:"task_warrant_dsse"`
	Payload             EphemeralTaskWarrantPayload `json:"payload"`
	EffectiveTTLSeconds int                         `json:"effective_ttl_seconds"`
	SponsorshipState    string                      `json:"sponsorship_state"`
}

// EphemeralTaskWarrantPayload is the JCS body of an N4 short-lived (TTL <= 300s) RFC 8693 composite task token.
type EphemeralTaskWarrantPayload struct {
	TaskTokenID             string             `json:"task_token_id"`
	WarrantID               string             `json:"warrant_id"`
	RemediationID           string             `json:"remediation_id"`
	AuthorityMode           string             `json:"authority_mode,omitempty"`
	CommissioningFunctionID string             `json:"commissioning_function_id,omitempty"`
	Sub                     string             `json:"sub,omitempty"`
	WorkerName              string             `json:"worker_name"`
	TargetAsset             string             `json:"target_asset"`
	AllowedAction           string             `json:"allowed_action"`
	EgressProfile           string             `json:"egress_profile,omitempty"`
	ForbiddenPathPrefixes   []string           `json:"forbidden_path_prefixes,omitempty"`
	Slot1PrincipalID        string             `json:"slot1_principal_id"`
	Slot2PrincipalID        string             `json:"slot2_principal_id"`
	Act                     *ActorClaim        `json:"act,omitempty"`
	Cnf                     *ConfirmationClaim `json:"cnf,omitempty"`
	ParentTaskTokenID       string             `json:"parent_task_token_id,omitempty"`
	DelegationDepth         int                `json:"delegation_depth,omitempty"`
	MaxDelegationDepth      int                `json:"max_delegation_depth,omitempty"`
	TTLSeconds              int                `json:"ttl_seconds"`
	IssuedUnix              int64              `json:"issued_unix"`
	ExpiresUnix             int64              `json:"expires_unix"`
}

// AgentLedgerEntry is an immutable, hash-chained row in agent_action_ledger (N4).
type AgentLedgerEntry struct {
	ActionID                string      `json:"action_id"`
	TaskTokenID             string      `json:"task_token_id"`
	WarrantID               string      `json:"warrant_id"`
	RemediationID           string      `json:"remediation_id"`
	AuthorityMode           string      `json:"authority_mode,omitempty"`
	CommissioningFunctionID string      `json:"commissioning_function_id,omitempty"`
	AgentID                 string      `json:"agent_id,omitempty"`
	DelegationDepth         int         `json:"delegation_depth,omitempty"`
	ActChain                *ActorClaim `json:"act_chain,omitempty"`
	WorkerName              string      `json:"worker_name"`
	TargetAsset             string      `json:"target_asset"`
	ActionType              string      `json:"action_type"`
	Slot1PrincipalID        string      `json:"slot1_principal_id"`
	Slot2PrincipalID        string      `json:"slot2_principal_id"`
	EgressProfile           string      `json:"egress_profile"` // "ZERO_EGRESS_ISOLATED" | "INTERNAL_CLUSTER_ONLY"
	RawInputSHA256          string      `json:"raw_input_sha256"`
	ExtractorDigest         string      `json:"extractor_digest"`
	TypedOutputSHA256       string      `json:"typed_output_sha256"`
	TokenTTLSec             int         `json:"token_ttl_sec"`
	Status                  string      `json:"status"` // "EXECUTED" | "SECURITY_VIOLATION"
	ViolationCode           string      `json:"violation_code,omitempty"`
	PrevHash                string      `json:"prev_hash"`
	EntryHash               string      `json:"entry_hash"`
	ExecutedAt              time.Time   `json:"executed_at"`
}

// PodDigestEntry records a verified live pod digest in N3/N5.
type PodDigestEntry struct {
	PodName       string   `json:"pod_name"`
	NodeName      string   `json:"node_name"`
	RunningDigest string   `json:"running_digest"`
	LoadedLibs    []string `json:"loaded_libs"`
}

// KernelPublicKeyRecord represents an immutable verification key entry in kernel_public_keys.
type KernelPublicKeyRecord struct {
	KeyID          string           `json:"key_id"`
	Alg            string           `json:"alg"`
	PublicKeyB64   string           `json:"public_key_b64"`
	KeyFingerprint string           `json:"key_fingerprint"`
	BackendMode    string           `json:"backend_mode"`
	RotationDSSE   *crypto.Envelope `json:"rotation_dsse,omitempty"`
	PrevHash       string           `json:"prev_hash,omitempty"`
	EntryHash      string           `json:"entry_hash,omitempty"`
	RegisteredAt   time.Time        `json:"registered_at"`
}

// AttestationRecord is an immutable, hash-chained closure record in attestation_records (N5).
type AttestationRecord struct {
	AttestationID        string           `json:"attestation_id"`
	RemediationID        string           `json:"remediation_id"`
	ServiceID            string           `json:"service_id"`
	CVEID                string           `json:"cve_id"`
	IsKEV                bool             `json:"is_kev"`
	WarrantID            string           `json:"warrant_id"`
	Slot1PrincipalID     string           `json:"slot1_principal_id"`
	Slot1Email           string           `json:"slot1_email"`
	Slot2PrincipalID     string           `json:"slot2_principal_id"`
	Slot2Email           string           `json:"slot2_email"`
	TwinTranscriptSHA256    string           `json:"twin_transcript_sha256"`
	AssuranceTier           string           `json:"assurance_tier"`
	ClosureCompleteness     string           `json:"closure_completeness,omitempty"`
	TargetedAssetCount      int              `json:"targeted_asset_count,omitempty"`
	LandedAssetCount        int              `json:"landed_asset_count,omitempty"`
	FailedAssetCount        int              `json:"failed_asset_count,omitempty"`
	PendingAssetCount       int              `json:"pending_asset_count,omitempty"`
	RebootWaitingCount      int              `json:"reboot_waiting_count,omitempty"`
	DistributorID           string           `json:"distributor_id,omitempty"`
	DistributorOrderID      string           `json:"distributor_order_id,omitempty"`
	DistributorReportSHA256 string           `json:"distributor_report_sha256,omitempty"`
	SignerBackend           string           `json:"signer_backend"`
	FleetDigestManifest  []PodDigestEntry `json:"fleet_digest_manifest"`
	LockoutPolicyID      string           `json:"lockout_policy_id"`
	ReverifyExpiresAt    time.Time        `json:"reverify_expires_at"`
	DSSEEnvelope         crypto.Envelope  `json:"dsse_envelope"`
	OSCALPOAM            map[string]any   `json:"oscal_poam_json"`
	TTVRSeconds          int64            `json:"ttvr_seconds"`
	PrevHash             string           `json:"prev_hash"`
	EntryHash            string           `json:"entry_hash"`
	MintedAt             time.Time        `json:"minted_at"`
}

// AuditorShareToken represents a scoped read-only bearer link for external 3PAO/FedRAMP auditors.
type AuditorShareToken struct {
	TokenID              string    `json:"token_id"`
	Label                string    `json:"label"`
	ScopedAttestationIDs []string  `json:"scoped_attestation_ids"`
	CreatedBy            string    `json:"created_by"`
	ExpiresAt            time.Time `json:"expires_at"`
	Revoked              bool      `json:"revoked"`
	CreatedAt            time.Time `json:"created_at"`
}

// ChainTableStatus summarizes cryptographic hash-chain integrity for one immutable ledger table.
type ChainTableStatus struct {
	TableName        string `json:"table_name"`
	RowCount         int    `json:"row_count"`
	Valid            bool   `json:"valid"`
	TerminalHash     string `json:"terminal_hash"`
	BrokenAtRowIndex int    `json:"broken_at_row_index"`
	FailureDetail    string `json:"failure_detail,omitempty"`
}

// Transparency Witness Modes (N5 External Anchoring)
const (
	WitnessModeExternalNotary = "EXTERNAL_NOTARY"
	WitnessModeInProcessLocal = "IN_PROCESS_LOCAL"
)

// LedgerVerificationReport summarizes hash-chain integrity across all 6 core + 3 agent-authority append-only tables
// and cross-verifies against External Transparency Checkpoints to detect DB superuser tampering.
type LedgerVerificationReport struct {
	AllValid                bool               `json:"all_valid"`
	WitnessMode             string             `json:"witness_mode,omitempty"`
	ExternalAnchorVerified  bool               `json:"external_anchor_verified"`
	LatestCheckpointID      string             `json:"latest_checkpoint_id,omitempty"`
	LatestCombinedMerkleHex string             `json:"latest_combined_merkle_root,omitempty"`
	SuperuserTamperDetail   string             `json:"superuser_tamper_detail,omitempty"`
	VerifiedAt              time.Time          `json:"verified_at"`
	Tables                  []ChainTableStatus `json:"tables"`
	AgentAuthorityTables    []ChainTableStatus `json:"agent_authority_tables,omitempty"`
	EstateEvidenceTables    []ChainTableStatus `json:"estate_evidence_tables,omitempty"`
}

// LedgerCheckpoint represents a periodic DSSE-signed Merkle Root receipt shipped to an
// external WORM / Transparency boundary (S3 Object Lock, Rekor, RFC 3161 TSA, or immutable external sink).
type LedgerCheckpoint struct {
	CheckpointID           string          `json:"checkpoint_id"`
	MerkleVersion          int             `json:"merkle_version"`
	WarrantHeadHash        string          `json:"warrant_head_hash"`
	WarrantRowCount        int             `json:"warrant_row_count"`
	AgentHeadHash          string          `json:"agent_head_hash"`
	AgentRowCount          int             `json:"agent_row_count"`
	AttestationHeadHash    string          `json:"attestation_head_hash"`
	AttestationRowCount    int             `json:"attestation_row_count"`
	PrincipalHeadHash      string          `json:"principal_head_hash"`
	PrincipalRowCount      int             `json:"principal_row_count"`
	RevocationHeadHash     string          `json:"revocation_head_hash"`
	RevocationRowCount     int             `json:"revocation_row_count"`
	KernelKeyHeadHash      string          `json:"kernel_key_head_hash"`
	KernelKeyRowCount      int             `json:"kernel_key_row_count"`
	CommissioningHeadHash  string          `json:"commissioning_head_hash,omitempty"`
	CommissioningRowCount  int             `json:"commissioning_row_count,omitempty"`
	AgentIdentityHeadHash  string          `json:"agent_identity_head_hash,omitempty"`
	AgentIdentityRowCount  int             `json:"agent_identity_row_count,omitempty"`
	AgentLifecycleHeadHash string          `json:"agent_lifecycle_head_hash,omitempty"`
	AgentLifecycleRowCount int             `json:"agent_lifecycle_row_count,omitempty"`
	CombinedMerkleRoot     string          `json:"combined_merkle_root"`
	DSSEEnvelope           crypto.Envelope `json:"dsse_envelope"`
	WitnessMode            string          `json:"witness_mode,omitempty"`
	ExternalAnchorTarget   string          `json:"external_anchor_target"`
	ExternalReceiptHash    string          `json:"external_receipt_hash"`
	AnchoredAt             time.Time       `json:"anchored_at"`
}

// GlobalScoreboard aggregates the persistent Global Command Bar KPIs.
type GlobalScoreboard struct {
	FreezeState                  FreezeState `json:"freeze_state"`
	WitnessMode                  string      `json:"witness_mode,omitempty"`
	ActiveWarrantsCount          int         `json:"active_warrants_count"`
	ActiveAgentsCount            int         `json:"active_agents_count"`
	QuarantinedAgentsCount       int         `json:"quarantined_agents_count"`
	PendingSponsorTransfersCount int         `json:"pending_sponsor_transfers_count"`
	FleetMedianTTVRSeconds       int64       `json:"fleet_median_ttvr_seconds"`
	ActiveBridgesArmed           int         `json:"active_bridges_armed"`
	MedianBridgeAgeSeconds       int64       `json:"median_bridge_age_seconds"`
	AutonomousEligibilityPct     float64     `json:"autonomous_eligibility_pct"`
	EligibleServicesCount        int         `json:"eligible_services_count"`
	TotalServicesCount           int         `json:"total_services_count"`
	AwaitingDualKeyInboxCount    int         `json:"awaiting_dual_key_inbox_count"`
	ActiveDriftViolationsCount   int         `json:"active_drift_violations_count"`
	RollbackFailuresCount        int         `json:"rollback_failures_count"`
	UnmappedAdvisoriesCount      int         `json:"unmapped_advisories_count,omitempty"`
	PartialClosuresCount         int         `json:"partial_closures_count,omitempty"`
}

// FeedMode constants for offline air-gapped enclaves vs. live public threat feeds.
const (
	FeedModeOffline = "offline"
	FeedModeLive    = "live"
)

// FeedRuntimeConfig holds runtime environment/toggle settings for CISA KEV, Google OSV.dev, and Trivy sidecar intake.
type FeedRuntimeConfig struct {
	Mode            string    `json:"mode"` // "offline" | "live"
	CISAKEVURL      string    `json:"cisa_kev_url"`
	KEVPollInterval string    `json:"kev_poll_interval"`
	OSVAPIURL       string    `json:"osv_api_url"`
	TrivyEnabled    bool      `json:"trivy_enabled"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ExtractedKEVEntry is a prose-free, regex-validated CISA Known Exploited Vulnerability entry emitted by warrant-extractor.
type ExtractedKEVEntry struct {
	CVEID              string `json:"cve_id"`
	CWEID              string `json:"cwe_id"`
	DateAdded          string `json:"date_added"`
	DueDate            string `json:"due_date"`
	RansomwareCampaign string `json:"ransomware_campaign"` // "Known" | "Unknown"
}

// ExtractedKEVCatalog wraps the sanitized CISA KEV catalog emitted by warrant-extractor.
type ExtractedKEVCatalog struct {
	SchemaVersion     string              `json:"schema_version"`
	CatalogVersion    string              `json:"catalog_version"`
	DateReleased      string              `json:"date_released"`
	Entries           []ExtractedKEVEntry `json:"entries"`
	RawInputSHA256    string              `json:"raw_input_sha256"`
	TypedOutputSHA256 string              `json:"typed_output_sha256"`
	ExtractorDigest   string              `json:"extractor_digest"`
}

// ExtractedOSVEntry is a prose-free vulnerability entry derived from Google OSV.dev and sanitized by warrant-extractor.
type ExtractedOSVEntry struct {
	OSVID        string  `json:"osv_id"`
	CVEID        string  `json:"cve_id"`
	CWEID        string  `json:"cwe_id"`
	ServiceID    string  `json:"service_id"`
	PackagePURL  string  `json:"package_purl"`
	CVSSScore    float64 `json:"cvss_score"`
	FixedVersion string  `json:"fixed_version"`
	IsKEV        bool    `json:"is_kev"`
}

// ExtractedOSVReport wraps sanitized Google OSV.dev SBOM query results emitted by warrant-extractor.
type ExtractedOSVReport struct {
	SchemaVersion     string              `json:"schema_version"`
	Advisories        []ExtractedOSVEntry `json:"advisories"`
	RawInputSHA256    string              `json:"raw_input_sha256"`
	TypedOutputSHA256 string              `json:"typed_output_sha256"`
	ExtractorDigest   string              `json:"extractor_digest"`
}

// FeedSyncRun records an execution of CISA KEV polling, OSV.dev SBOM querying, or Trivy SARIF sidecar intake.
type FeedSyncRun struct {
	SyncID            string    `json:"sync_id"`
	FeedSource        string    `json:"feed_source"` // "CISA_KEV" | "GOOGLE_OSV" | "TRIVY_SARIF"
	Status            string    `json:"status"`      // "SUCCESS" | "ERROR" | "SKIPPED_OFFLINE"
	CatalogVersion    string    `json:"catalog_version,omitempty"`
	ItemsIngested     int       `json:"items_ingested"`
	KEVMatches        int       `json:"kev_matches"`
	RawInputSHA256    string    `json:"raw_input_sha256"`
	TypedOutputSHA256 string    `json:"typed_output_sha256"`
	ExtractorDigest   string    `json:"extractor_digest"`
	ErrorMessage      string    `json:"error_message,omitempty"`
	SyncedAt          time.Time `json:"synced_at"`
}

// LiveFeedStatus aggregates current feed configuration, catalog counts, OSV advisories, and recent sync runs.
type LiveFeedStatus struct {
	Config               FeedRuntimeConfig   `json:"config"`
	CISAKEVCatalogCount  int                 `json:"cisa_kev_catalog_count"`
	LatestCatalogVersion string              `json:"latest_catalog_version,omitempty"`
	LastKEVSyncAt        *time.Time          `json:"last_kev_sync_at,omitempty"`
	OSVAdvisories        []ExtractedOSVEntry `json:"osv_advisories"`
	RecentSyncRuns       []FeedSyncRun       `json:"recent_sync_runs"`
}

// CloneTwinInstanceResult records readiness, smoke, and authorization-class acceptance checks for a single ephemeral clone.
type CloneTwinInstanceResult struct {
	CloneIndex            int     `json:"clone_index"`
	CloneName             string  `json:"clone_name"`
	NodeOrHost            string  `json:"node_or_host,omitempty"`
	PodIP                 string  `json:"pod_ip,omitempty"`
	RunningDigest         string  `json:"running_digest"`
	ServiceUpPassed       bool    `json:"service_up_passed"`
	SmokeTestPassed       bool    `json:"smoke_test_passed"`
	ClassAcceptancePassed bool    `json:"class_acceptance_passed"`
	ObservedLatencyMs     float64 `json:"observed_latency_ms"`
	ExitCode              int     `json:"exit_code"`
	EvidenceSHA256        string  `json:"evidence_sha256"`
	LogSummary            string  `json:"log_summary,omitempty"`
}

// ResolvedCloneSourceEvidence records each clone source identity and image age used during a proving run.
type ResolvedCloneSourceEvidence struct {
	SourceSystem    string `json:"source_system"`
	ImageIdentity   string `json:"image_identity"`
	SourceMode      string `json:"source_mode"`
	ImageCreatedAt  string `json:"image_created_at,omitempty"`
	ImageAgeSeconds int64  `json:"image_age_seconds"`
}

// CloneTwinProvingManifest captures the 3-clone isolated proving ground evidence bound into N3, OPA, and OSCAL 1.1.2 POA&M.
type CloneTwinProvingManifest struct {
	ProvingRunID              string                        `json:"proving_run_id"`
	RemediationID             string                        `json:"remediation_id"`
	ServiceID                 string                        `json:"service_id"`
	WarrantID                 string                        `json:"warrant_id"`
	WarrantClass              string                        `json:"warrant_class"`
	CVEID                     string                        `json:"cve_id"`
	CandidateDigest           string                        `json:"candidate_digest"`
	PatchTargetLayer          string                        `json:"patch_target_layer"` // "USERSPACE_SOFTWARE" | "KERNEL" | "BOOT_LAYER"
	TwinRuntime               string                        `json:"twin_runtime"`       // "CONTAINER_TWIN" | "VM_TWIN"
	ProvingNamespace          string                        `json:"proving_namespace"`
	ZeroProductionEgress      bool                          `json:"zero_production_egress"`
	CloneCount                int                           `json:"clone_count"`
	ServicesUpCount           int                           `json:"services_up_count"`
	SmokePassedCount          int                           `json:"smoke_passed_count"`
	AcceptancePassedCount     int                           `json:"acceptance_passed_count"`
	AllPassed                 bool                          `json:"all_passed"`
	FailureReasonCode         string                        `json:"failure_reason_code,omitempty"`
	Clones                    []CloneTwinInstanceResult     `json:"clones"`
	CloneSourceResolutionPath string                        `json:"clone_source_resolution_path,omitempty"` // "SIGNED_CLASS" | "SIGNED_CLASS_MANUAL" | "ENV_BOOTSTRAP_FALLBACK"
	EstateSourceSystem        string                        `json:"estate_source_system,omitempty"`
	EstateQueryIdentity       string                        `json:"estate_query_identity,omitempty"`
	SigningReadAt             *time.Time                    `json:"signing_read_at,omitempty"`
	ProvingReadAt             *time.Time                    `json:"proving_read_at,omitempty"`
	SigningSnapshotSHA256     string                        `json:"signing_snapshot_sha256,omitempty"`
	ProvingSnapshotSHA256     string                        `json:"proving_snapshot_sha256,omitempty"`
	EstateDriftPolicy         string                        `json:"estate_drift_policy,omitempty"`
	EstateDriftTolerancePct   float64                       `json:"estate_drift_tolerance_pct,omitempty"`
	ObservedDriftPct          float64                       `json:"observed_drift_pct,omitempty"`
	DriftExceeded             bool                          `json:"drift_exceeded,omitempty"`
	DriftDeltaSummary         string                        `json:"drift_delta_summary,omitempty"`
	ResolvedCloneSources      []ResolvedCloneSourceEvidence `json:"resolved_clone_sources,omitempty"`
	TranscriptSHA256          string                        `json:"transcript_sha256"`
	ProvedAt                  time.Time                     `json:"proved_at"`
}

// OSKernelBucket summarizes OS build and kernel release counts inside a bounded EstateSnapshot (OCSF Inventory Info + CPE 2.3).
type OSKernelBucket struct {
	OSFamily         string `json:"os_family"`
	OSVersionOrBuild string `json:"os_version_or_build"`
	KernelRelease    string `json:"kernel_release,omitempty"`
	CPE23            string `json:"cpe23,omitempty"`
	Count            int    `json:"count"`
}

// SoftwareBucket summarizes installed software/component versions inside a bounded EstateSnapshot (CPE 2.3 / SWID / PURL).
type SoftwareBucket struct {
	ComponentName string `json:"component_name"`
	Version       string `json:"version"`
	CPE23         string `json:"cpe23,omitempty"`
	SWIDTagID     string `json:"swid_tag_id,omitempty"`
	PURL          string `json:"purl,omitempty"`
	Count         int    `json:"count"`
}

// CloneSourceCandidate represents a candidate golden image/template/OCI digest proposed by a Tier A or Tier B EstateReader.
type CloneSourceCandidate struct {
	SourceSystem      string            `json:"source_system"`
	ImageIdentity     string            `json:"image_identity"`
	PlatformFamily    string            `json:"platform_family"`
	PatchTargetLayers []string          `json:"patch_target_layers"`
	CreatedAt         string            `json:"created_at"`
	ImageAgeSeconds   int64             `json:"image_age_seconds"`
	Tags              map[string]string `json:"tags,omitempty"`
}

// EstateSnapshot is the bounded, prose-free OCSF Inventory Info (class_uid=5001) & NIST OSCAL inventory-item summary
// returned by an EstateReader. Warrant stores only summary digests and cryptographic evidence — never per-host tables.
type EstateSnapshot struct {
	SnapshotID                  string                 `json:"snapshot_id"`
	OCSFClassUID                int                    `json:"ocsf_class_uid"`
	SourceSystem                string                 `json:"source_system"`
	SourceTier                  string                 `json:"source_tier"` // "TIER_A_MACHINE" | "TIER_B_WORKLOAD" | "TIER_C_CENSUS"
	HandlerFamily               string                 `json:"handler_family"`
	QueryIdentity               string                 `json:"query_identity"`
	ClassScope                  []string               `json:"class_scope"`
	ClassMembershipCount        int                    `json:"class_membership_count"`
	OSBuildKernelDistribution   []OSKernelBucket       `json:"os_build_kernel_distribution"`
	SoftwareVersionDistribution []SoftwareBucket       `json:"software_version_distribution"`
	CandidateCloneSources       []CloneSourceCandidate `json:"candidate_clone_sources"`
	SourceInventoryFreshnessAt  time.Time              `json:"source_inventory_freshness_at"`
	SourceFreshnessAgeSeconds   int64                  `json:"source_freshness_age_seconds"`
	ObservedAt                  time.Time              `json:"observed_at"`
	SnapshotSHA256              string                 `json:"snapshot_sha256"`
}

// EstateReadEvidenceRecord is an append-only, hash-chained WORM evidence row in estate_read_evidence.
type EstateReadEvidenceRecord struct {
	EvidenceID            string                 `json:"evidence_id"`
	SourceSystem          string                 `json:"source_system"`
	SourceTier            string                 `json:"source_tier"`
	HandlerFamily         string                 `json:"handler_family"`
	Phase                 string                 `json:"phase"` // "SIGNING_PROPOSAL" | "PROVING_REREAD"
	WarrantID             string                 `json:"warrant_id,omitempty"`
	RemediationID         string                 `json:"remediation_id,omitempty"`
	QueryIdentity         string                 `json:"query_identity"`
	ClassMembershipCount  int                    `json:"class_membership_count"`
	OSDistSummary         []OSKernelBucket       `json:"os_dist_summary"`
	SWDistSummary         []SoftwareBucket       `json:"sw_dist_summary"`
	CandidateSources      []CloneSourceCandidate `json:"candidate_sources"`
	SourceFreshnessAt     time.Time              `json:"source_freshness_at"`
	SourceFreshnessAgeSec int64                  `json:"source_freshness_age_sec"`
	ObservedAt            time.Time              `json:"observed_at"`
	SnapshotSHA256        string                 `json:"snapshot_sha256"`
	PrevHash              string                 `json:"prev_hash"`
	EntryHash             string                 `json:"entry_hash"`
}

// EstateSourceDescriptor describes a registered EstateReader in GET /api/v1/estate-loader/sources.
type EstateSourceDescriptor struct {
	SourceSystem           string `json:"source_system"`
	DisplayName            string `json:"display_name"`
	SourceTier             string `json:"source_tier"`
	HandlerFamily          string `json:"handler_family"`
	ReadEnvPrefix          string `json:"read_env_prefix"`
	ReadConfigured         bool   `json:"read_configured"`
	CanProposeCloneSources bool   `json:"can_propose_clone_sources"`
}

// EstateProposalRequest asks the Estate Loader to read bounded class state at Standing Warrant drafting time.
type EstateProposalRequest struct {
	SourceSystem         string   `json:"source_system"`
	CorroboratingScanner string   `json:"corroborating_scanner,omitempty"`
	WarrantClass         string   `json:"warrant_class"`
	ScopeServices        []string `json:"scope_services"`
	ScopeFilter          string   `json:"scope_filter,omitempty"`
	EstateDriftPolicy    string   `json:"estate_drift_policy,omitempty"`
	DriftTolerancePct    float64  `json:"estate_drift_tolerance_pct,omitempty"`
}

// EstateProposalResponse returns the system's proposed class profile, freshness, Tier C census cross-check, and candidate clone sources.
type EstateProposalResponse struct {
	ProposalID                   string                `json:"proposal_id"`
	PrimarySnapshot              EstateSnapshot        `json:"primary_snapshot"`
	PrimaryEvidenceID            string                `json:"primary_evidence_id"`
	CensusSnapshot               *EstateSnapshot       `json:"census_snapshot,omitempty"`
	CensusEvidenceID             string                `json:"census_evidence_id,omitempty"`
	CensusCountDelta             int                   `json:"census_count_delta,omitempty"`
	CensusDeltaPct               float64               `json:"census_delta_pct,omitempty"`
	CensusAdvisory               string                `json:"census_advisory,omitempty"`
	ProposedCloneSources         []DeclaredCloneSource `json:"proposed_clone_sources"`
	ProposedEstateSnapshotSHA256 string                `json:"proposed_estate_snapshot_sha256"`
	RecommendedDriftPolicy       string                `json:"recommended_drift_policy"`
	RecommendedDriftTolerancePct float64               `json:"recommended_drift_tolerance_pct"`
}
