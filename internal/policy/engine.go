package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/policies"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Engine wraps precompiled in-process Open Policy Agent (OPA) Rego queries
// for N1 (AC-5 Warrant Verification), N2 (Gate & Shadow Safety), N3/N5 (Verify & Closure),
// and N4 (Agent Commissioning Health & Permission Intersection).
type Engine struct {
	ac5Query    rego.PreparedEvalQuery
	gateQuery   rego.PreparedEvalQuery
	verifyQuery rego.PreparedEvalQuery
	agentQuery  rego.PreparedEvalQuery
}

// AC5Input represents structured input to data.warrant.ac5.
type AC5Input struct {
	Slot1                  SignerInput `json:"slot1"`
	Slot2                  SignerInput `json:"slot2"`
	NowUnix                int64       `json:"now_unix"`
	ExpiresUnix            int64       `json:"expires_unix"`
	WarrantClass           string      `json:"warrant_class,omitempty"`
	AllowSecretRotation    bool        `json:"allow_secret_rotation,omitempty"`
	ActionKind             string      `json:"action_kind,omitempty"`
	ScopeServices          []string    `json:"scope_services"`
	TargetService          string      `json:"target_service"`
	MinCVSS                float64     `json:"min_cvss,omitempty"`
	MaxCVSS                float64     `json:"max_cvss"`
	FindingCVSS            float64     `json:"finding_cvss"`
	FindingIsKEV           bool        `json:"finding_is_kev,omitempty"`
	FindingCWE             string      `json:"finding_cwe,omitempty"`
	AutoRemediateCWEs      []string    `json:"auto_remediate_cwes,omitempty"`
	MaxBlastRadiusReplicas int                          `json:"max_blast_radius_replicas"`
	TargetReplicas         int                          `json:"target_replicas"`
	CloneSources           []models.DeclaredCloneSource `json:"clone_sources,omitempty"`
	EstateDriftPolicy      string                       `json:"estate_drift_policy,omitempty"`
}

// SignerInput represents one signer slot in AC-5 evaluation.
type SignerInput struct {
	PrincipalID    string `json:"principal_id"`
	Email          string `json:"email"`
	KeyFingerprint string `json:"key_fingerprint"`
	Role           string `json:"role"`
	Revoked        bool   `json:"revoked"`
}

// AC5Decision is the deterministic policy decision from data.warrant.ac5.
type AC5Decision struct {
	Allow              bool     `json:"allow"`
	ChainedCWEElevated bool     `json:"chained_cwe_elevated"`
	Violations         []string `json:"violations"`
}

// GateInput represents structured input to data.warrant.gate.
type GateInput struct {
	FreezeMode          string           `json:"freeze_mode"`
	BlastRadiusExceeded bool             `json:"blast_radius_exceeded"`
	AllowGuardedCanary  bool             `json:"allow_guarded_canary"`
	ShadowEvaluated     bool             `json:"shadow_evaluated"`
	Service             GateServiceInput `json:"service"`
	Patch               GatePatchInput   `json:"patch"`
	Shadow              GateShadowInput  `json:"shadow"`
}

type GateServiceInput struct {
	TestCoveragePct            float64 `json:"test_coverage_pct"`
	OtelHealthProbes           bool    `json:"otel_health_probes"`
	ReadonlyShadowReplica      bool    `json:"readonly_shadow_replica"`
	ShadowDBMode               string  `json:"shadow_db_mode,omitempty"`
	RollbackAutomationVerified bool    `json:"rollback_automation_verified"`
	ReadOnlyRootFilesystem     bool    `json:"readonly_root_filesystem"`
	NoExecTmpMounts            bool    `json:"noexec_tmp_mounts"`
}

type GatePatchInput struct {
	DDLMigrations          int      `json:"ddl_migrations"`
	ORMModelMutations      int      `json:"orm_model_mutations"`
	SerializationBreaks    int      `json:"serialization_breaks"`
	APIBackwardCompatible  bool     `json:"api_backward_compatible"`
	ForbiddenConfigTouches []string `json:"forbidden_config_touches,omitempty"`
}

type GateShadowInput struct {
	SchemaBreakingDiffs       int      `json:"schema_breaking_diffs"`
	StatusCodeDriftPct        float64  `json:"status_code_drift_pct"`
	P99LatencyMs              float64  `json:"p99_latency_ms"`
	MaxP99LatencyMs           float64  `json:"max_p99_latency_ms"`
	BaselineSyscalls          []string `json:"baseline_syscalls"`
	CanarySyscalls            []string `json:"canary_syscalls"`
	SensitiveFilesAccessed    []string `json:"sensitive_files_accessed,omitempty"`
	UnexpectedEgressEndpoints []string `json:"unexpected_egress_endpoints,omitempty"`
	HasMutatingTraffic        bool     `json:"has_mutating_traffic,omitempty"`
}

// GateDecision is the deterministic decision from data.warrant.gate.
type GateDecision struct {
	ServiceEligible         bool     `json:"service_eligible"`
	GuardedCanaryEligible   bool     `json:"guarded_canary_eligible"`
	AutonomyTier            string   `json:"autonomy_tier"`
	PatchStateless          bool     `json:"patch_stateless"`
	ShadowSafe              bool     `json:"shadow_safe"`
	FreezeBlocked           bool     `json:"freeze_blocked"`
	TriggerCanaryRollback   bool     `json:"trigger_canary_rollback"`
	RouteToExceptionCockpit bool     `json:"route_to_exception_cockpit"`
	AllowAutonomousRollout  bool     `json:"allow_autonomous_rollout"`
	UnauthorizedSyscalls    []string `json:"unauthorized_syscalls"`
	Reasons                 []string `json:"reasons"`
}

// VerifyInput represents structured input to data.warrant.verify.
type VerifyInput struct {
	RemediationKind           string `json:"remediation_kind,omitempty"`
	SecretRotatedAndRevoked   bool   `json:"secret_rotated_and_revoked,omitempty"`
	ExposedSecretSHA256       string `json:"exposed_secret_sha256,omitempty"`
	RotatedSecretSHA256       string `json:"rotated_secret_sha256,omitempty"`
	HasSignedProbe            bool   `json:"has_signed_probe"`
	UnpatchedTwinStatus       string `json:"unpatched_twin_status"`
	TwinReplayStatus          string `json:"twin_replay_status"`
	ProvenanceVerified        bool   `json:"provenance_verified"`
	VulnerablePkgAbsentInSBOM bool   `json:"vulnerable_pkg_absent_in_sbom"`
	AttestedPods              int    `json:"attested_pods"`
	TotalPods                 int    `json:"total_pods"`
	EvidenceGranularity       string `json:"evidence_granularity,omitempty"`
	TargetedAssets            int    `json:"targeted_assets,omitempty"`
	LandedAssets              int    `json:"landed_assets,omitempty"`
	FailedAssets              int    `json:"failed_assets,omitempty"`
	PendingAssets             int    `json:"pending_assets,omitempty"`
	RebootWaitingAssets       int    `json:"reboot_waiting_assets,omitempty"`
	AdmissionLockoutEnforced  bool   `json:"admission_lockout_enforced"`
	WarrantReverified         bool   `json:"warrant_reverified"`
	PatchTargetLayer          string `json:"patch_target_layer,omitempty"`
	TwinRuntime               string `json:"twin_runtime,omitempty"`
	CloneTwinProvingPresent   bool   `json:"clone_twin_proving_present,omitempty"`
	CloneTwinCount            int    `json:"clone_twin_count,omitempty"`
	CloneTwinAllPassed        bool   `json:"clone_twin_all_passed,omitempty"`
	EstateDriftPolicy         string `json:"estate_drift_policy,omitempty"`
	EstateDriftExceeded       bool   `json:"estate_drift_exceeded,omitempty"`
}

// VerifyDecision is the deterministic decision from data.warrant.verify.
type VerifyDecision struct {
	AllowBridgeRetirement       bool     `json:"allow_bridge_retirement"`
	AllowAttestationMint        bool     `json:"allow_attestation_mint"`
	AllowPartialAttestationMint bool     `json:"allow_partial_attestation_mint"`
	AllowDispatchOnlyRecord     bool     `json:"allow_dispatch_only_record"`
	ClosureCompleteness         string   `json:"closure_completeness"`
	AssuranceTier               string   `json:"assurance_tier"`
	Blockers                    []string `json:"blockers"`
}

// AgentProfileInput represents the enrolled AgentIdentity & live sponsorship health passed to data.warrant.agent.
type AgentProfileInput struct {
	AgentID                      string   `json:"agent_id"`
	CommissioningFunctionID      string   `json:"commissioning_function_id"`
	Revoked                      bool     `json:"revoked"`
	SponsorshipState             string   `json:"sponsorship_state"`
	SponsorCompromised           bool     `json:"sponsor_compromised"`
	GraceActive                  bool     `json:"grace_active"`
	GraceExpiresUnix             int64    `json:"grace_expires_unix"`
	RecertifyExpiresUnix         int64    `json:"recertify_expires_unix"`
	AllowedActions               []string `json:"allowed_actions"`
	AllowedServices              []string `json:"allowed_services"`
	AllowedEgressProfile         string   `json:"allowed_egress_profile"`
	MaxTTLSeconds                int      `json:"max_ttl_seconds"`
	MaxDelegationDepth           int      `json:"max_delegation_depth"`
	AllowAutonomousIntake        bool     `json:"allow_autonomous_intake"`
	BuilderPrincipalID           string   `json:"builder_principal_id,omitempty"`
	BuilderKeyFingerprint        string   `json:"builder_key_fingerprint,omitempty"`
	CommissionerSOPrincipalID    string   `json:"commissioner_so_principal_id,omitempty"`
	CommissionerSOKeyFingerprint string   `json:"commissioner_so_key_fingerprint,omitempty"`
	CommissionerAOPrincipalID    string   `json:"commissioner_ao_principal_id,omitempty"`
	CommissionerAOKeyFingerprint string   `json:"commissioner_ao_key_fingerprint,omitempty"`
}

// AgentWarrantScopeInput represents the governing Standing Warrant scope in WARRANT_DELEGATED_COMPOSITE mode.
type AgentWarrantScopeInput struct {
	Present        bool     `json:"present"`
	Active         bool     `json:"active"`
	ScopeServices  []string `json:"scope_services,omitempty"`
	AllowedActions []string `json:"allowed_actions,omitempty"`
	ExpiresUnix    int64    `json:"expires_unix,omitempty"`
}

// AgentParentTaskInput represents the parent EphemeralTaskWarrant scope during sub-agent attenuation (depth > 0).
type AgentParentTaskInput struct {
	Present            bool   `json:"present"`
	TargetAsset        string `json:"target_asset,omitempty"`
	AllowedAction      string `json:"allowed_action,omitempty"`
	EgressProfile      string `json:"egress_profile,omitempty"`
	ExpiresUnix        int64  `json:"expires_unix,omitempty"`
	MaxDelegationDepth int    `json:"max_delegation_depth,omitempty"`
	SponsorshipState   string `json:"sponsorship_state,omitempty"`
}

// AgentInput represents structured input to data.warrant.agent.
type AgentInput struct {
	NowUnix                int64                  `json:"now_unix"`
	AuthorityMode          string                 `json:"authority_mode"`
	RequestedAction        string                 `json:"requested_action"`
	TargetAsset            string                 `json:"target_asset"`
	RequestedEgressProfile string                 `json:"requested_egress_profile"`
	RequestedTTLSeconds    int                    `json:"requested_ttl_seconds"`
	DelegationDepth             int                    `json:"delegation_depth"`
	RemediationExchangeCount    int                    `json:"remediation_exchange_count,omitempty"`
	MaxExchangesPerRemediation  int                    `json:"max_exchanges_per_remediation,omitempty"`
	WindowExchangeCount         int                    `json:"window_exchange_count,omitempty"`
	MaxExchangesPerWindow       int                    `json:"max_exchanges_per_window,omitempty"`
	Agent                       AgentProfileInput      `json:"agent"`
	StandingWarrant        AgentWarrantScopeInput `json:"standing_warrant"`
	ParentTask             AgentParentTaskInput   `json:"parent_task"`
}

// AgentDecision is the deterministic decision from data.warrant.agent.
type AgentDecision struct {
	Allow               bool     `json:"allow"`
	EffectiveTTLSeconds int      `json:"effective_ttl_seconds"`
	Violations          []string `json:"violations"`
}

// NewEngine loads and precompiles all embedded OPA Rego policies.
func NewEngine(ctx context.Context) (*Engine, error) {
	entries, err := fs.ReadDir(policies.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded policies: %w", err)
	}
	var modules []func(*rego.Rego)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego") {
			continue
		}
		src, err := fs.ReadFile(policies.FS, name)
		if err != nil {
			return nil, fmt.Errorf("read policy %s: %w", name, err)
		}
		modules = append(modules, rego.Module(name, string(src)))
	}

	compile := func(query string) (rego.PreparedEvalQuery, error) {
		opts := append([]func(*rego.Rego){rego.Query(query)}, modules...)
		return rego.New(opts...).PrepareForEval(ctx)
	}

	ac5Q, err := compile("data.warrant.ac5")
	if err != nil {
		return nil, fmt.Errorf("compile data.warrant.ac5: %w", err)
	}
	gateQ, err := compile("data.warrant.gate")
	if err != nil {
		return nil, fmt.Errorf("compile data.warrant.gate: %w", err)
	}
	verifyQ, err := compile("data.warrant.verify")
	if err != nil {
		return nil, fmt.Errorf("compile data.warrant.verify: %w", err)
	}
	agentQ, err := compile("data.warrant.agent")
	if err != nil {
		return nil, fmt.Errorf("compile data.warrant.agent: %w", err)
	}

	return &Engine{
		ac5Query:    ac5Q,
		gateQuery:   gateQ,
		verifyQuery: verifyQ,
		agentQuery:  agentQ,
	}, nil
}

// EvalAC5 evaluates NIST SP 800-53 AC-5 separation of duties and warrant bounds.
func (e *Engine) EvalAC5(ctx context.Context, in AC5Input) (*AC5Decision, error) {
	rs, err := e.ac5Query.Eval(ctx, rego.EvalInput(in))
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("eval ac5 failed: %w", err)
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected ac5 result type %T", rs[0].Expressions[0].Value)
	}
	allow, _ := m["allow"].(bool)
	elevated, _ := m["chained_cwe_elevated"].(bool)
	violations := extractSortedStrings(m["violations"])
	return &AC5Decision{
		Allow:              allow,
		ChainedCWEElevated: elevated,
		Violations:         violations,
	}, nil
}

// EvalGate evaluates N2 service eligibility, patch statelessness, freeze posture, and shadow safety.
func (e *Engine) EvalGate(ctx context.Context, in GateInput) (*GateDecision, error) {
	rs, err := e.gateQuery.Eval(ctx, rego.EvalInput(in))
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("eval gate failed: %w", err)
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected gate result type %T", rs[0].Expressions[0].Value)
	}
	boolField := func(k string) bool {
		b, _ := m[k].(bool)
		return b
	}
	autonomyTier, _ := m["autonomy_tier"].(string)
	return &GateDecision{
		ServiceEligible:         boolField("service_eligible"),
		GuardedCanaryEligible:   boolField("guarded_canary_eligible"),
		AutonomyTier:            autonomyTier,
		PatchStateless:          boolField("patch_stateless"),
		ShadowSafe:              boolField("shadow_safe"),
		FreezeBlocked:           boolField("freeze_blocked"),
		TriggerCanaryRollback:   boolField("trigger_canary_rollback"),
		RouteToExceptionCockpit: boolField("route_to_exception_cockpit"),
		AllowAutonomousRollout:  boolField("allow_autonomous_rollout"),
		UnauthorizedSyscalls:    extractSortedStrings(m["unauthorized_syscalls"]),
		Reasons:                 extractSortedStrings(m["reasons"]),
	}, nil
}

// EvalVerify evaluates N3 bridge retirement and N5 OSCAL attestation preconditions.
func (e *Engine) EvalVerify(ctx context.Context, in VerifyInput) (*VerifyDecision, error) {
	rs, err := e.verifyQuery.Eval(ctx, rego.EvalInput(in))
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("eval verify failed: %w", err)
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected verify result type %T", rs[0].Expressions[0].Value)
	}
	retire, _ := m["allow_bridge_retirement"].(bool)
	mint, _ := m["allow_attestation_mint"].(bool)
	partialMint, _ := m["allow_partial_attestation_mint"].(bool)
	dispatchOnly, _ := m["allow_dispatch_only_record"].(bool)
	completeness, _ := m["closure_completeness"].(string)
	tier, _ := m["assurance_tier"].(string)
	return &VerifyDecision{
		AllowBridgeRetirement:       retire,
		AllowAttestationMint:        mint,
		AllowPartialAttestationMint: partialMint,
		AllowDispatchOnlyRecord:     dispatchOnly,
		ClosureCompleteness:         completeness,
		AssuranceTier:               tier,
		Blockers:                    extractSortedStrings(m["blockers"]),
	}, nil
}

// EvalAgent evaluates N4 agent commissioning health, 3-Way Builder != Commissioner SoD,
// RFC 8693 sub-agent act attenuation, and formal permission intersection.
func (e *Engine) EvalAgent(ctx context.Context, in AgentInput) (*AgentDecision, error) {
	rs, err := e.agentQuery.Eval(ctx, rego.EvalInput(in))
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("eval agent intersection failed: %w", err)
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected agent intersection result type %T", rs[0].Expressions[0].Value)
	}
	allow, _ := m["allow"].(bool)
	effTTL := extractInt(m["effective_ttl_seconds"])
	return &AgentDecision{
		Allow:               allow,
		EffectiveTTLSeconds: effTTL,
		Violations:          extractSortedStrings(m["violations"]),
	}, nil
}

func extractInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
		if f, err := n.Float64(); err == nil {
			return int(f)
		}
	}
	return 0
}

func extractSortedStrings(v any) []string {
	var out []string
	switch s := v.(type) {
	case []any:
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
	case []string:
		out = append(out, s...)
	case map[string]any:
		for k, val := range s {
			if b, ok := val.(bool); ok && b {
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}
