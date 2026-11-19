package policy

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/g1163rt-labs/g1-warrant/policies"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Engine wraps precompiled in-process Open Policy Agent (OPA) Rego queries
// for N1 (AC-5 Warrant Verification), N2 (Gate & Shadow Safety), and N3/N5 (Verify & Closure).
type Engine struct {
	ac5Query    rego.PreparedEvalQuery
	gateQuery   rego.PreparedEvalQuery
	verifyQuery rego.PreparedEvalQuery
}

// AC5Input represents structured input to data.warrant.ac5.
type AC5Input struct {
	Slot1                  SignerInput `json:"slot1"`
	Slot2                  SignerInput `json:"slot2"`
	NowUnix                int64       `json:"now_unix"`
	ExpiresUnix            int64       `json:"expires_unix"`
	ScopeServices          []string    `json:"scope_services"`
	TargetService          string      `json:"target_service"`
	MaxCVSS                float64     `json:"max_cvss"`
	FindingCVSS            float64     `json:"finding_cvss"`
	MaxBlastRadiusReplicas int         `json:"max_blast_radius_replicas"`
	TargetReplicas         int         `json:"target_replicas"`
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
	Allow      bool     `json:"allow"`
	Violations []string `json:"violations"`
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
}

type GatePatchInput struct {
	DDLMigrations         int  `json:"ddl_migrations"`
	ORMModelMutations     int  `json:"orm_model_mutations"`
	SerializationBreaks   int  `json:"serialization_breaks"`
	APIBackwardCompatible bool `json:"api_backward_compatible"`
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
	HasSignedProbe           bool   `json:"has_signed_probe"`
	UnpatchedTwinStatus      string `json:"unpatched_twin_status"`
	TwinReplayStatus         string `json:"twin_replay_status"`
	ProvenanceVerified       bool   `json:"provenance_verified"`
	AttestedPods             int    `json:"attested_pods"`
	TotalPods                int    `json:"total_pods"`
	VulnerableSymbolsLoaded  int    `json:"vulnerable_symbols_loaded"`
	AdmissionLockoutEnforced bool   `json:"admission_lockout_enforced"`
	WarrantReverified        bool   `json:"warrant_reverified"`
}

// VerifyDecision is the deterministic decision from data.warrant.verify.
type VerifyDecision struct {
	AllowBridgeRetirement bool     `json:"allow_bridge_retirement"`
	AllowAttestationMint  bool     `json:"allow_attestation_mint"`
	AssuranceTier         string   `json:"assurance_tier"`
	Blockers              []string `json:"blockers"`
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

	return &Engine{
		ac5Query:    ac5Q,
		gateQuery:   gateQ,
		verifyQuery: verifyQ,
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
	violations := extractSortedStrings(m["violations"])
	return &AC5Decision{
		Allow:      allow,
		Violations: violations,
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
	tier, _ := m["assurance_tier"].(string)
	return &VerifyDecision{
		AllowBridgeRetirement: retire,
		AllowAttestationMint:  mint,
		AssuranceTier:         tier,
		Blockers:              extractSortedStrings(m["blockers"]),
	}, nil
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
