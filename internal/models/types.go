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
	HealthExceptionRouted     = "EXCEPTION_ROUTED"
	HealthRollbackFailed      = "ROLLBACK_FAILED"
	HealthQuarantinedRollback = "QUARANTINED_ROLLBACK"
	HealthDriftViolation      = "DRIFT_VIOLATION"
	HealthFrozen              = "FROZEN"
	HealthAttested            = "ATTESTED"
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

// Closure Assurance Tiers Distinguishing Differential PoC Proof, Passive Digest/SBOM Proof, and Secret Rotation (N3/N5)
const (
	AssuranceTier1PassiveDigestSBOM = "ASSURANCE_TIER_1_PASSIVE_DIGEST_SBOM"
	AssuranceTier2DifferentialTwin  = "ASSURANCE_TIER_2_DIFFERENTIAL_TWIN"
	AssuranceTierSecretRotated      = "ASSURANCE_TIER_SECRET_ROTATED"
)

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
	AffectedPort          int      `json:"affected_port"`
	BlockedPaths          []string `json:"blocked_paths"`
	ArtifactPaths         []string `json:"artifact_paths"`
	ChainedExploitEnabler bool     `json:"chained_exploit_enabler,omitempty"`
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

// Authority Lineage Modes (v1.0.2 SQL INSERT Notarization Protection)
const (
	LineageModeGenesisSealed = "GENESIS_SEALED"
	LineageModePostSeal2Of2  = "POST_SEAL_2OF2_DSSE"
	LineageModePostSeal1Of2  = "POST_SEAL_1OF2_DSSE"
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
	GovActionEnrollPrincipal          = "ENROLL_PRINCIPAL"
	GovActionRevokePrincipal          = "REVOKE_PRINCIPAL"
	GovActionRotateAndRevokePrincipal = "ROTATE_AND_REVOKE_PRINCIPAL"
	GovActionRotateKernelKey          = "ROTATE_KERNEL_KEY"
	GovActionSealBootstrap            = "SEAL_BOOTSTRAP"
	GovActionEmergencyFreeze          = "EMERGENCY_FREEZE"
	GovActionEmergencyRollback        = "EMERGENCY_ROLLBACK"
	GovActionMintAuditorToken         = "MINT_AUDITOR_TOKEN"
	GovActionFeedMutation             = "FEED_MUTATION"
	GovActionCreateCheckpoint         = "CREATE_CHECKPOINT"
	GovActionSimulationDrill          = "SIMULATION_DRILL"
)

// PrincipalGovernancePayload is the RFC 8785 JCS payload inside a Principal Governance DSSEv1 envelope
// (2-of-2 required for ENROLL_PRINCIPAL and ROTATE_AND_REVOKE_PRINCIPAL; 1-of-2 active principal accepted for
// same-role/self REVOKE_PRINCIPAL & request-scoped emergency actions).
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

// WarrantPayload is the JCS-canonicalized body inside a dual-signed Standing Warrant DSSE envelope.
type WarrantPayload struct {
	WarrantID              string   `json:"warrant_id"`
	WarrantClass           string   `json:"warrant_class"`
	ScopeServices          []string `json:"scope_services"`
	MaxCVSS                float64  `json:"max_cvss"`
	KEVEligible            bool     `json:"kev_eligible"`
	MaxBlastRadiusReplicas int      `json:"max_blast_radius_replicas"`
	AllowStatefulPatches   bool     `json:"allow_stateful_patches"`
	AllowGuardedCanary     bool     `json:"allow_guarded_canary,omitempty"`
	AllowSecretRotation    bool     `json:"allow_secret_rotation,omitempty"`
	AutoRemediateCWEs      []string `json:"auto_remediate_cwes,omitempty"`
	MinCanarySamples       int      `json:"min_canary_samples,omitempty"`
	StageDwellSeconds      int      `json:"stage_dwell_seconds,omitempty"`
	SLABridgeMinutes       int      `json:"sla_bridge_minutes"`
	MaxP99LatencyMs        float64  `json:"max_p99_latency_ms"`
	IssuedAt               string   `json:"issued_at"`
	ExpiresAt              string   `json:"expires_at"`
}

// WarrantRecord represents an immutable Standing Warrant row in warrant_envelopes.
type WarrantRecord struct {
	WarrantID              string          `json:"warrant_id"`
	WarrantClass           string          `json:"warrant_class"`
	ScopeServices          []string        `json:"scope_services"`
	MaxCVSS                float64         `json:"max_cvss"`
	KEVEligible            bool            `json:"kev_eligible"`
	MaxBlastRadiusReplicas int             `json:"max_blast_radius_replicas"`
	AllowStatefulPatches   bool            `json:"allow_stateful_patches"`
	AllowGuardedCanary     bool            `json:"allow_guarded_canary"`
	AllowSecretRotation    bool            `json:"allow_secret_rotation"`
	AutoRemediateCWEs      []string        `json:"auto_remediate_cwes,omitempty"`
	MinCanarySamples       int             `json:"min_canary_samples"`
	StageDwellSeconds      int             `json:"stage_dwell_seconds"`
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
	AttestationID    string                  `json:"attestation_id,omitempty"`
	PatchMetadata    *ExtractedPatchMetadata `json:"patch_metadata,omitempty"`
	ShadowReport     *ShadowComparisonReport `json:"shadow_report,omitempty"`
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

// EphemeralTaskWarrantPayload is the JCS body of an N4 short-lived (TTL <= 300s) task token.
type EphemeralTaskWarrantPayload struct {
	TaskTokenID           string   `json:"task_token_id"`
	WarrantID             string   `json:"warrant_id"`
	RemediationID         string   `json:"remediation_id"`
	WorkerName            string   `json:"worker_name"`
	TargetAsset           string   `json:"target_asset"`
	AllowedAction         string   `json:"allowed_action"`
	ForbiddenPathPrefixes []string `json:"forbidden_path_prefixes,omitempty"`
	Slot1PrincipalID      string   `json:"slot1_principal_id"`
	Slot2PrincipalID      string   `json:"slot2_principal_id"`
	TTLSeconds            int      `json:"ttl_seconds"`
	IssuedUnix            int64    `json:"issued_unix"`
	ExpiresUnix           int64    `json:"expires_unix"`
}

// AgentLedgerEntry is an immutable, hash-chained row in agent_action_ledger (N4).
type AgentLedgerEntry struct {
	ActionID          string    `json:"action_id"`
	TaskTokenID       string    `json:"task_token_id"`
	WarrantID         string    `json:"warrant_id"`
	RemediationID     string    `json:"remediation_id"`
	WorkerName        string    `json:"worker_name"`
	TargetAsset       string    `json:"target_asset"`
	ActionType        string    `json:"action_type"`
	Slot1PrincipalID  string    `json:"slot1_principal_id"`
	Slot2PrincipalID  string    `json:"slot2_principal_id"`
	EgressProfile     string    `json:"egress_profile"` // "ZERO_EGRESS_ISOLATED" | "INTERNAL_CLUSTER_ONLY"
	RawInputSHA256    string    `json:"raw_input_sha256"`
	ExtractorDigest   string    `json:"extractor_digest"`
	TypedOutputSHA256 string    `json:"typed_output_sha256"`
	TokenTTLSec       int       `json:"token_ttl_sec"`
	Status            string    `json:"status"` // "EXECUTED" | "SECURITY_VIOLATION"
	ViolationCode     string    `json:"violation_code,omitempty"`
	PrevHash          string    `json:"prev_hash"`
	EntryHash         string    `json:"entry_hash"`
	ExecutedAt        time.Time `json:"executed_at"`
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
	TwinTranscriptSHA256 string           `json:"twin_transcript_sha256"`
	AssuranceTier        string           `json:"assurance_tier"`
	SignerBackend        string           `json:"signer_backend"`
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

// LedgerVerificationReport summarizes hash-chain integrity across all 3 append-only tables
// and cross-verifies against External Transparency Checkpoints to detect DB superuser tampering.
type LedgerVerificationReport struct {
	AllValid                bool               `json:"all_valid"`
	ExternalAnchorVerified  bool               `json:"external_anchor_verified"`
	LatestCheckpointID      string             `json:"latest_checkpoint_id,omitempty"`
	LatestCombinedMerkleHex string             `json:"latest_combined_merkle_root,omitempty"`
	SuperuserTamperDetail   string             `json:"superuser_tamper_detail,omitempty"`
	VerifiedAt              time.Time          `json:"verified_at"`
	Tables                  []ChainTableStatus `json:"tables"`
}

// LedgerCheckpoint represents a periodic DSSE-signed Merkle Root receipt shipped to an
// external WORM / Transparency boundary (S3 Object Lock, Rekor, RFC 3161 TSA, or immutable external sink).
type LedgerCheckpoint struct {
	CheckpointID         string          `json:"checkpoint_id"`
	MerkleVersion        int             `json:"merkle_version"`
	WarrantHeadHash      string          `json:"warrant_head_hash"`
	WarrantRowCount      int             `json:"warrant_row_count"`
	AgentHeadHash        string          `json:"agent_head_hash"`
	AgentRowCount        int             `json:"agent_row_count"`
	AttestationHeadHash  string          `json:"attestation_head_hash"`
	AttestationRowCount  int             `json:"attestation_row_count"`
	PrincipalHeadHash    string          `json:"principal_head_hash"`
	PrincipalRowCount    int             `json:"principal_row_count"`
	RevocationHeadHash   string          `json:"revocation_head_hash"`
	RevocationRowCount   int             `json:"revocation_row_count"`
	KernelKeyHeadHash    string          `json:"kernel_key_head_hash"`
	KernelKeyRowCount    int             `json:"kernel_key_row_count"`
	CombinedMerkleRoot   string          `json:"combined_merkle_root"`
	DSSEEnvelope         crypto.Envelope `json:"dsse_envelope"`
	ExternalAnchorTarget string          `json:"external_anchor_target"`
	ExternalReceiptHash  string          `json:"external_receipt_hash"`
	AnchoredAt           time.Time       `json:"anchored_at"`
}

// GlobalScoreboard aggregates the persistent Global Command Bar KPIs.
type GlobalScoreboard struct {
	FreezeState                FreezeState `json:"freeze_state"`
	ActiveWarrantsCount        int         `json:"active_warrants_count"`
	FleetMedianTTVRSeconds     int64       `json:"fleet_median_ttvr_seconds"`
	ActiveBridgesArmed         int         `json:"active_bridges_armed"`
	MedianBridgeAgeSeconds     int64       `json:"median_bridge_age_seconds"`
	AutonomousEligibilityPct   float64     `json:"autonomous_eligibility_pct"`
	EligibleServicesCount      int         `json:"eligible_services_count"`
	TotalServicesCount         int         `json:"total_services_count"`
	AwaitingDualKeyInboxCount  int         `json:"awaiting_dual_key_inbox_count"`
	ActiveDriftViolationsCount int         `json:"active_drift_violations_count"`
	RollbackFailuresCount      int         `json:"rollback_failures_count"`
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
