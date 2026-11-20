package fleetsim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/google/uuid"
)

// ImageBehaviorProfile configures how a specific container digest behaves in canary/twin execution.
type ImageBehaviorProfile struct {
	Digest                  string   `json:"digest"`
	InjectSyscalls          []string `json:"inject_syscalls,omitempty"`
	BreakingSchemaKey       bool     `json:"breaking_schema_key,omitempty"`
	P99LatencyMs            float64  `json:"p99_latency_ms,omitempty"`
	ExploitStillWorks       bool     `json:"exploit_still_works,omitempty"`
	ObservedSamples         *int     `json:"observed_samples,omitempty"`
	ObservedDwellSeconds    *int     `json:"observed_dwell_seconds,omitempty"`
	ObservedDDLMigrations   int      `json:"observed_ddl_migrations,omitempty"`
	ObservedORMMutations    int      `json:"observed_orm_mutations,omitempty"`
	SensitiveFilesAccessed  []string `json:"sensitive_files_accessed,omitempty"`
	UnexpectedEgressTargets []string `json:"unexpected_egress_endpoints,omitempty"`
}

// PodState represents a simulated Kubernetes Pod in fleet-sim.
type PodState struct {
	PodName                string    `json:"pod_name"`
	NodeName               string    `json:"node_name"`
	RunningDigest          string    `json:"running_digest"`
	LoadedLibs             []string  `json:"loaded_libs"`
	LoadedSymbols          []string  `json:"loaded_symbols"`
	FilesystemMutatedPaths []string  `json:"filesystem_mutated_paths,omitempty"`
	UntrackedProcesses     []string  `json:"untracked_processes,omitempty"`
	SecretGeneration       int       `json:"secret_generation,omitempty"`
	Cordoned               bool      `json:"cordoned,omitempty"`
	StartedAt              time.Time `json:"started_at"`
}

// SecretRotationResult captures rapid ExternalSecret / ServiceAccount token revocation & rolling restart proof.
type SecretRotationResult struct {
	ServiceID            string    `json:"service_id"`
	SecretResourceKind   string    `json:"secret_resource_kind"`
	SecretResourceName   string    `json:"secret_resource_name"`
	PreviousTokenRevoked bool      `json:"previous_token_revoked"`
	NewSecretGeneration  int       `json:"new_secret_generation"`
	NewSecretVersionHash string    `json:"new_secret_version_hash"`
	RestartedPods        int       `json:"restarted_pods"`
	RotatedAt            time.Time `json:"rotated_at"`
}

// BridgePolicyState represents an active CiliumNetworkPolicy + Envoy mTLS bridge on fleet-sim.
type BridgePolicyState struct {
	BridgeID           string    `json:"bridge_id"`
	ServiceID          string    `json:"service_id"`
	CVEID              string    `json:"cve_id"`
	CiliumManifestYAML string    `json:"cilium_manifest_yaml"`
	K8sNetpolYAML      string    `json:"k8s_netpol_yaml"`
	EnvoyFilterJSON    string    `json:"envoy_filter_json"`
	AppliedAt          time.Time `json:"applied_at"`
}

// LockoutPolicyState represents an active Kubernetes ValidatingAdmissionPolicy banning an image digest.
type LockoutPolicyState struct {
	LockoutID       string    `json:"lockout_id"`
	PolicyName      string    `json:"policy_name"`
	ServiceID       string    `json:"service_id"`
	BannedDigest    string    `json:"banned_digest"`
	Suspended       bool      `json:"suspended,omitempty"`
	SuspendedReason string    `json:"suspended_reason,omitempty"`
	VAPManifestYAML string    `json:"vap_manifest_yaml"`
	EnforcedAt      time.Time `json:"enforced_at"`
}

// WorkloadState represents a deployed Kubernetes Deployment + Shadow Service in fleet-sim.
type WorkloadState struct {
	ServiceID                  string    `json:"service_id"`
	Namespace                  string    `json:"namespace"`
	Replicas                   int       `json:"replicas"`
	BaselineDigest             string    `json:"baseline_digest"`
	CanaryDigest               string    `json:"canary_digest,omitempty"`
	CanaryWeight               int       `json:"canary_weight"`
	ReadonlyShadowBound        bool      `json:"readonly_shadow_bound"`
	OutboundMutationSinkActive bool      `json:"outbound_mutation_sink_active"`
	BaselineSyscalls           []string   `json:"baseline_syscalls"`
	SecretGeneration           int        `json:"secret_generation"`
	Pods                       []PodState `json:"pods"`
	LastDriftInjectedAtUnixMs  int64      `json:"last_drift_injected_at_unix_ms,omitempty"`
}

// StageRolloutRequest drives shadow/canary traffic progression on fleet-sim.
type StageRolloutRequest struct {
	PatchedDigest        string   `json:"patched_digest"`
	StageWeight          int      `json:"stage_weight"`
	ClearSymbol          string   `json:"clear_symbol"`
	InjectSyscalls       []string `json:"inject_syscalls,omitempty"`
	BreakingSchema       bool     `json:"breaking_schema,omitempty"`
	SimulatedP99Ms       float64  `json:"simulated_p99_ms,omitempty"`
	ObservedSamples      *int     `json:"observed_samples,omitempty"`
	ObservedDwellSeconds *int     `json:"observed_dwell_seconds,omitempty"`
}

// StageRolloutResponse returns live telemetry from the baseline vs. shadow/canary execution.
type StageRolloutResponse struct {
	ServiceID                     string   `json:"service_id"`
	StageWeight                   int      `json:"stage_weight"`
	ObservedSamples               int      `json:"observed_samples"`
	ObservedDwellSeconds          int      `json:"observed_dwell_seconds"`
	ReadonlyDBBound               bool     `json:"readonly_db_bound"`
	OutboundMutationSinkActive    bool     `json:"outbound_mutation_sink_active"`
	OtelHealthProbes              *bool    `json:"otel_health_probes,omitempty"`
	RollbackAutomationVerified    *bool    `json:"rollback_automation_verified,omitempty"`
	ObservedDDLMigrations         int      `json:"observed_ddl_migrations,omitempty"`
	ObservedORMMutations          int      `json:"observed_orm_mutations,omitempty"`
	ObservedSerializationBreaks   int      `json:"observed_serialization_breaks,omitempty"`
	ObservedAPIBackwardCompatible *bool    `json:"observed_api_backward_compatible,omitempty"`
	BaselineHTTPBody              string   `json:"baseline_http_body"`
	CanaryHTTPBody                string   `json:"canary_http_body"`
	StatusCodeDriftPct            float64  `json:"status_code_drift_pct"`
	BaselineP50Ms                 float64  `json:"baseline_p50_ms"`
	BaselineP95Ms                 float64  `json:"baseline_p95_ms"`
	BaselineP99Ms                 float64  `json:"baseline_p99_ms"`
	CanaryP50Ms                   float64  `json:"canary_p50_ms"`
	CanaryP95Ms                   float64  `json:"canary_p95_ms"`
	CanaryP99Ms                   float64  `json:"canary_p99_ms"`
	BaselineSyscalls              []string `json:"baseline_syscalls"`
	CanarySyscalls                []string `json:"canary_syscalls"`
	SensitiveFilesAccessed        []string `json:"sensitive_files_accessed,omitempty"`
	UnexpectedEgressEndpoints     []string `json:"unexpected_egress_endpoints,omitempty"`
	HasMutatingTraffic            bool     `json:"has_mutating_traffic,omitempty"`
}

// TwinReplayRequest executes a differential isolated exploit replay against ephemeral unpatched & patched twin pods.
type TwinReplayRequest struct {
	ServiceID        string `json:"service_id"`
	CVEID            string `json:"cve_id"`
	VulnerableDigest string `json:"vulnerable_digest,omitempty"`
	PatchedDigest    string `json:"patched_digest"`
	ExploitVector    string `json:"exploit_vector"`
	VulnerableSymbol string `json:"vulnerable_symbol"`
	HasSignedProbe   bool   `json:"has_signed_probe"`
	BrokenProbe      bool   `json:"broken_probe,omitempty"`
}

// TwinReplayResponse returns deterministic proof from both the positive-control unpatched twin and patched twin.
type TwinReplayResponse struct {
	UnpatchedStatus     string `json:"unpatched_status"` // "EXPLOIT_SUCCEEDED" | "EXPLOIT_BLOCKED" | "NOT_APPLICABLE"
	Status              string `json:"status"`           // "EXPLOIT_BLOCKED" | "EXPLOIT_SUCCEEDED" | "NO_PROBE_PASSIVE_ONLY"
	IsolatedNamespace   string `json:"isolated_namespace"`
	TwinPodName         string `json:"twin_pod_name"`
	TestedDigest        string `json:"tested_digest"`
	ExitCode            int    `json:"exit_code"`
	TranscriptSHA256    string `json:"transcript_sha256"`
	ProductionUntouched bool   `json:"production_untouched"`
}

// ClusterSimulator maintains the in-memory state of the simulated 6-service Kubernetes/Cilium cluster.
type ClusterSimulator struct {
	mu        sync.RWMutex
	workloads map[string]*WorkloadState
	bridges   map[string]BridgePolicyState
	lockouts  map[string]LockoutPolicyState
	profiles  map[string]ImageBehaviorProfile
}

// DefaultInitialWorkloads returns the deterministic 6-service enterprise cluster topology.
func DefaultInitialWorkloads() []*WorkloadState {
	stdSyscalls := []string{"accept4", "close", "epoll_ctl", "epoll_wait", "fcntl", "fstat", "futex", "getsockopt", "mmap", "munmap", "nanosleep", "openat", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask", "sendto", "setsockopt", "socket", "write"}

	defs := []struct {
		id       string
		ns       string
		replicas int
		digest   string
		libs     []string
		symbols  []string
		shadow   bool
	}{
		{
			id:       "payments-ledger-api",
			ns:       "fin-core",
			replicas: 6,
			digest:   "sha256:a100000000000000000000000000000000000000000000000000000000000001",
			libs:     []string{"libc.so.6", "libcrypto.so.3", "libssl.so.3"},
			symbols:  []string{"tls_heartbeat_ext_parse_vuln"},
			shadow:   true,
		},
		{
			id:       "identity-sso-gateway",
			ns:       "sec-authn",
			replicas: 4,
			digest:   "sha256:b200000000000000000000000000000000000000000000000000000000000002",
			libs:     []string{"libc.so.6", "libxml2.so.2"},
			symbols:  []string{"saml_dsig_xpath_eval_v1"},
			shadow:   true,
		},
		{
			id:       "fedramp-audit-ingestor",
			ns:       "gov-audit",
			replicas: 4,
			digest:   "sha256:c300000000000000000000000000000000000000000000000000000000000003",
			libs:     []string{"libc.so.6", "libnghttp2.so.14"},
			symbols:  []string{},
			shadow:   true,
		},
		{
			id:       "checkout-cart-svc",
			ns:       "commerce-edge",
			replicas: 6,
			digest:   "sha256:d400000000000000000000000000000000000000000000000000000000000004",
			libs:     []string{"libc.so.6", "libprotobuf.so.32"},
			symbols:  []string{"proto_unmarshal_unbounded_depth"},
			shadow:   true,
		},
		{
			id:       "fulfillment-worker",
			ns:       "ops-fulfill",
			replicas: 3,
			digest:   "sha256:e500000000000000000000000000000000000000000000000000000000000005",
			libs:     []string{"libc.so.6", "libcurl.so.4"},
			symbols:  []string{"curl_socks5_heap_overflow"},
			shadow:   false,
		},
		{
			id:       "legacy-billing-monolith",
			ns:       "fin-legacy",
			replicas: 2,
			digest:   "sha256:f600000000000000000000000000000000000000000000000000000000000006",
			libs:     []string{"libc.so.6", "libz.so.1"},
			symbols:  []string{"legacy_jndi_lookup_dispatch"},
			shadow:   false,
		},
	}

	out := make([]*WorkloadState, 0, len(defs))
	now := time.Now().UTC()
	for _, d := range defs {
		pods := make([]PodState, 0, d.replicas)
		for i := 0; i < d.replicas; i++ {
			pods = append(pods, PodState{
				PodName:       fmt.Sprintf("%s-%d", d.id, i),
				NodeName:      fmt.Sprintf("k8s-fed-node-%02d", (i%3)+1),
				RunningDigest: d.digest,
				LoadedLibs:    append([]string{}, d.libs...),
				LoadedSymbols: append([]string{}, d.symbols...),
				StartedAt:     now.Add(-2 * time.Hour),
			})
		}
		out = append(out, &WorkloadState{
			ServiceID:                  d.id,
			Namespace:                  d.ns,
			Replicas:                   d.replicas,
			BaselineDigest:             d.digest,
			CanaryWeight:               0,
			ReadonlyShadowBound:        d.shadow,
			OutboundMutationSinkActive: d.shadow,
			BaselineSyscalls:           append([]string{}, stdSyscalls...),
			Pods:                       pods,
		})
	}
	return out
}

// NewClusterSimulator creates a live 6-service Kubernetes/Cilium cluster simulator.
func NewClusterSimulator() *ClusterSimulator {
	cs := &ClusterSimulator{
		workloads: make(map[string]*WorkloadState),
		bridges:   make(map[string]BridgePolicyState),
		lockouts:  make(map[string]LockoutPolicyState),
		profiles:  make(map[string]ImageBehaviorProfile),
	}
	for _, w := range DefaultInitialWorkloads() {
		cs.workloads[w.ServiceID] = w
	}
	return cs
}

// Handler returns the REST API handler for fleet-sim.
func (cs *ClusterSimulator) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		cs.mu.RLock()
		defer cs.mu.RUnlock()
		writeSimJSON(w, http.StatusOK, map[string]any{
			"status":           "OK",
			"service":          "fleet-sim",
			"workloads_count":  len(cs.workloads),
			"active_bridges":   len(cs.bridges),
			"active_lockouts":  len(cs.lockouts),
		})
	})

	mux.HandleFunc("GET /v1/workloads", func(w http.ResponseWriter, r *http.Request) {
		cs.mu.RLock()
		defer cs.mu.RUnlock()
		list := make([]*WorkloadState, 0, len(cs.workloads))
		for _, wl := range cs.workloads {
			list = append(list, wl)
		}
		writeSimJSON(w, http.StatusOK, map[string]any{
			"workloads": list,
			"bridges":   cs.bridges,
			"lockouts":  cs.lockouts,
		})
	})

	mux.HandleFunc("GET /v1/workloads/{service_id}", func(w http.ResponseWriter, r *http.Request) {
		svcID := r.PathValue("service_id")
		cs.mu.RLock()
		defer cs.mu.RUnlock()
		wl, ok := cs.workloads[svcID]
		if !ok {
			writeSimJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
			return
		}
		writeSimJSON(w, http.StatusOK, wl)
	})

	mux.HandleFunc("POST /v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		var prof ImageBehaviorProfile
		if err := json.NewDecoder(r.Body).Decode(&prof); err != nil {
			writeSimJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		cs.mu.Lock()
		cs.profiles[prof.Digest] = prof
		cs.mu.Unlock()
		writeSimJSON(w, http.StatusOK, prof)
	})

	mux.HandleFunc("POST /v1/cilium/bridges", func(w http.ResponseWriter, r *http.Request) {
		var b BridgePolicyState
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			writeSimJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if b.AppliedAt.IsZero() {
			b.AppliedAt = time.Now().UTC()
		}
		cs.mu.Lock()
		cs.bridges[b.BridgeID] = b
		cs.mu.Unlock()
		writeSimJSON(w, http.StatusOK, b)
	})

	mux.HandleFunc("DELETE /v1/cilium/bridges/{bridge_id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("bridge_id")
		cs.mu.Lock()
		delete(cs.bridges, id)
		cs.mu.Unlock()
		writeSimJSON(w, http.StatusOK, map[string]string{"retired": id})
	})

	mux.HandleFunc("POST /v1/rollouts/{service_id}/stage", func(w http.ResponseWriter, r *http.Request) {
		svcID := r.PathValue("service_id")
		var req StageRolloutRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeSimJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		cs.mu.Lock()
		defer cs.mu.Unlock()

		wl, ok := cs.workloads[svcID]
		if !ok {
			writeSimJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
			return
		}

		// Admission Lockout check: reject banned digests at admission time unless explicitly suspended for quarantined rollback
		for _, lo := range cs.lockouts {
			if !lo.Suspended && lo.ServiceID == svcID && lo.BannedDigest == req.PatchedDigest {
				writeSimJSON(w, http.StatusForbidden, map[string]string{
					"error":  "ADMISSION_DENIED_LOCKED_DIGEST",
					"policy": lo.PolicyName,
				})
				return
			}
		}

		prof := cs.profiles[req.PatchedDigest]
		injectSyscalls := append([]string{}, prof.InjectSyscalls...)
		injectSyscalls = append(injectSyscalls, req.InjectSyscalls...)
		breakingSchema := prof.BreakingSchemaKey || req.BreakingSchema

		wl.CanaryDigest = req.PatchedDigest
		wl.CanaryWeight = req.StageWeight

		canarySyscalls := append([]string{}, wl.BaselineSyscalls...)
		for _, sc := range injectSyscalls {
			canarySyscalls = appendUnique(canarySyscalls, sc)
		}

		// Build realistic HTTP responses containing volatile fields AND unordered SQL-style array results
		nowBase := time.Now().UTC().Format(time.RFC3339Nano)
		nowCanary := time.Now().UTC().Add(3 * time.Millisecond).Format(time.RFC3339Nano)
		baseMap := map[string]any{
			"service":      svcID,
			"status":       "SETTLED",
			"request_id":   uuid.NewString(),
			"responded_at": nowBase,
			"trace_nonce":  crypto.SHA256Hex([]byte(nowBase))[:32],
			"schema_ver":   2,
			"ledger_ok":    true,
			"shard_nodes":  []any{"shard-east-1", "shard-west-2", "shard-central-3"},
		}
		canaryMap := map[string]any{
			"service":      svcID,
			"status":       "SETTLED",
			"request_id":   uuid.NewString(),
			"responded_at": nowCanary,
			"trace_nonce":  crypto.SHA256Hex([]byte(nowCanary))[:32],
			"schema_ver":   2,
			"ledger_ok":    true,
			"shard_nodes":  []any{"shard-west-2", "shard-central-3", "shard-east-1"}, // intentionally unordered array!
		}
		if breakingSchema {
			delete(canaryMap, "ledger_ok")
			canaryMap["schema_ver"] = "v2-string-breaking"
		}
		baseJSON, _ := json.Marshal(baseMap)
		canaryJSON, _ := json.Marshal(canaryMap)

		canaryP99 := 38.4
		if prof.P99LatencyMs > 0 {
			canaryP99 = prof.P99LatencyMs
		}
		if req.SimulatedP99Ms > 0 {
			canaryP99 = req.SimulatedP99Ms
		}

		// If promoted to 100%, roll all pods to PatchedDigest and unload vulnerable symbol
		if req.StageWeight >= 100 {
			wl.BaselineDigest = req.PatchedDigest
			wl.CanaryDigest = ""
			wl.CanaryWeight = 100
			wl.LastDriftInjectedAtUnixMs = 0
			now := time.Now().UTC()
			for i := range wl.Pods {
				wl.Pods[i].RunningDigest = req.PatchedDigest
				wl.Pods[i].StartedAt = now
				if req.ClearSymbol != "" {
					filtered := make([]string, 0, len(wl.Pods[i].LoadedSymbols))
					for _, sym := range wl.Pods[i].LoadedSymbols {
						if sym != req.ClearSymbol {
							filtered = append(filtered, sym)
						}
					}
					wl.Pods[i].LoadedSymbols = filtered
				} else {
					wl.Pods[i].LoadedSymbols = []string{}
				}
			}
		}

		observedSamples := 1200
		if prof.ObservedSamples != nil {
			observedSamples = *prof.ObservedSamples
		}
		if req.ObservedSamples != nil {
			observedSamples = *req.ObservedSamples
		}
		observedDwellSec := 360
		if prof.ObservedDwellSeconds != nil {
			observedDwellSec = *prof.ObservedDwellSeconds
		}
		if req.ObservedDwellSeconds != nil {
			observedDwellSec = *req.ObservedDwellSeconds
		}

		writeSimJSON(w, http.StatusOK, StageRolloutResponse{
			ServiceID:                  svcID,
			StageWeight:                req.StageWeight,
			ObservedSamples:            observedSamples,
			ObservedDwellSeconds:       observedDwellSec,
			ReadonlyDBBound:            wl.ReadonlyShadowBound,
			OutboundMutationSinkActive: wl.OutboundMutationSinkActive,
			ObservedDDLMigrations:      prof.ObservedDDLMigrations,
			ObservedORMMutations:       prof.ObservedORMMutations,
			BaselineHTTPBody:           string(baseJSON),
			CanaryHTTPBody:             string(canaryJSON),
			StatusCodeDriftPct:         0.02,
			BaselineP50Ms:              11.2,
			BaselineP95Ms:              24.6,
			BaselineP99Ms:              36.8,
			CanaryP50Ms:                11.6,
			CanaryP95Ms:                25.1,
			CanaryP99Ms:                canaryP99,
			BaselineSyscalls:           wl.BaselineSyscalls,
			CanarySyscalls:             canarySyscalls,
			SensitiveFilesAccessed:     prof.SensitiveFilesAccessed,
			UnexpectedEgressEndpoints:  prof.UnexpectedEgressTargets,
		})
	})

	mux.HandleFunc("POST /v1/rollouts/{service_id}/rollback", func(w http.ResponseWriter, r *http.Request) {
		svcID := r.PathValue("service_id")
		var req struct {
			TargetDigest string `json:"target_digest"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		cs.mu.Lock()
		defer cs.mu.Unlock()
		wl, ok := cs.workloads[svcID]
		if !ok {
			writeSimJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
			return
		}
		targetDigest := wl.BaselineDigest
		if req.TargetDigest != "" {
			// Enforce admission lockout even during rollback unless lockout was explicitly suspended after containment re-arm!
			for _, lo := range cs.lockouts {
				if !lo.Suspended && lo.ServiceID == svcID && lo.BannedDigest == req.TargetDigest {
					writeSimJSON(w, http.StatusForbidden, map[string]string{
						"error":  "ROLLBACK_BLOCKED_BY_ACTIVE_ADMISSION_LOCKOUT",
						"policy": lo.PolicyName,
					})
					return
				}
			}
			targetDigest = req.TargetDigest
			wl.BaselineDigest = targetDigest
		}
		wl.CanaryDigest = ""
		wl.CanaryWeight = 0
		for i := range wl.Pods {
			wl.Pods[i].RunningDigest = targetDigest
		}
		writeSimJSON(w, http.StatusOK, map[string]any{
			"service_id":     svcID,
			"rolled_back_to": targetDigest,
			"canary_weight":  0,
		})
	})

	mux.HandleFunc("POST /v1/twins/replay", func(w http.ResponseWriter, r *http.Request) {
		var req TwinReplayRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeSimJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		ns := fmt.Sprintf("twin-ephemeral-%s", crypto.SHA256Hex([]byte(req.CVEID+":"+req.PatchedDigest))[:10])
		pod := fmt.Sprintf("twin-%s-repro", req.ServiceID)

		if !req.HasSignedProbe {
			transcriptMaterial := fmt.Sprintf("TWIN_PASSIVE_V2|%s|%s|%s|NO_SIGNED_PROBE_ADVISORY_ONLY", req.ServiceID, req.CVEID, req.PatchedDigest)
			writeSimJSON(w, http.StatusOK, TwinReplayResponse{
				UnpatchedStatus:     "NOT_APPLICABLE",
				Status:              "NO_PROBE_PASSIVE_ONLY",
				IsolatedNamespace:   ns,
				TwinPodName:         pod,
				TestedDigest:        req.PatchedDigest,
				ExitCode:            0,
				TranscriptSHA256:    crypto.SHA256Hex([]byte(transcriptMaterial)),
				ProductionUntouched: true,
			})
			return
		}

		cs.mu.RLock()
		prof := cs.profiles[req.PatchedDigest]
		cs.mu.RUnlock()

		// Step A: Differential Positive Control against unpatched VulnerableDigest
		unpatchedStatus := "EXPLOIT_SUCCEEDED"
		if req.BrokenProbe {
			unpatchedStatus = "EXPLOIT_BLOCKED" // broken PoC fails to reproduce on vulnerable binary!
		}

		// Step B: Replay identical signed probe against PatchedDigest
		status := "EXPLOIT_BLOCKED"
		exitCode := 0
		if prof.ExploitStillWorks {
			status = "EXPLOIT_SUCCEEDED"
			exitCode = 42
		}
		transcriptMaterial := fmt.Sprintf("TWIN_DIFF_V2|%s|%s|unpatched=%s:%s|patched=%s:%s|PROD_ISOLATED=true",
			req.ServiceID, req.CVEID, req.VulnerableDigest, unpatchedStatus, req.PatchedDigest, status)
		writeSimJSON(w, http.StatusOK, TwinReplayResponse{
			UnpatchedStatus:     unpatchedStatus,
			Status:              status,
			IsolatedNamespace:   ns,
			TwinPodName:         pod,
			TestedDigest:        req.PatchedDigest,
			ExitCode:            exitCode,
			TranscriptSHA256:    crypto.SHA256Hex([]byte(transcriptMaterial)),
			ProductionUntouched: true,
		})
	})

	mux.HandleFunc("POST /v1/admission/lockouts", func(w http.ResponseWriter, r *http.Request) {
		var lo LockoutPolicyState
		if err := json.NewDecoder(r.Body).Decode(&lo); err != nil {
			writeSimJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if lo.EnforcedAt.IsZero() {
			lo.EnforcedAt = time.Now().UTC()
		}
		cs.mu.Lock()
		cs.lockouts[lo.LockoutID] = lo
		cs.mu.Unlock()
		writeSimJSON(w, http.StatusOK, lo)
	})

	mux.HandleFunc("POST /v1/admission/lockouts/{lockout_id}/suspend", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("lockout_id")
		var req struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		cs.mu.Lock()
		defer cs.mu.Unlock()
		lo, ok := cs.lockouts[id]
		if !ok {
			writeSimJSON(w, http.StatusNotFound, map[string]string{"error": "lockout not found"})
			return
		}
		lo.Suspended = true
		lo.SuspendedReason = req.Reason
		cs.lockouts[id] = lo
		writeSimJSON(w, http.StatusOK, lo)
	})

	// POST /v1/chaos/drift simulates an out-of-band node/autoscaler drift event instantiating a banned digest.
	mux.HandleFunc("POST /v1/chaos/drift", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ServiceID    string `json:"service_id"`
			BannedDigest string `json:"banned_digest"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeSimJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		cs.mu.Lock()
		defer cs.mu.Unlock()
		wl, ok := cs.workloads[req.ServiceID]
		if !ok || len(wl.Pods) == 0 {
			writeSimJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
			return
		}
		nowMs := time.Now().UTC().UnixMilli()
		wl.Pods[0].RunningDigest = req.BannedDigest
		wl.Pods[0].PodName = fmt.Sprintf("%s-rogue-drift-0", req.ServiceID)
		wl.LastDriftInjectedAtUnixMs = nowMs
		writeSimJSON(w, http.StatusOK, map[string]any{
			"service_id":       req.ServiceID,
			"rogue_pod_name":   wl.Pods[0].PodName,
			"injected_digest":  req.BannedDigest,
			"injected_unix_ms": nowMs,
		})
	})

	// POST /v1/drift/{service_id}/inject-webshell simulates an ARTEX in-pod webshell / probe file drop
	// while the pod continues reporting a valid container image digest.
	mux.HandleFunc("POST /v1/drift/{service_id}/inject-webshell", func(w http.ResponseWriter, r *http.Request) {
		svcID := r.PathValue("service_id")
		var req struct {
			FilePath string `json:"file_path"`
			Process  string `json:"process"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.FilePath == "" {
			req.FilePath = "/var/www/html/artex-probe-01.jsp"
		}

		cs.mu.Lock()
		defer cs.mu.Unlock()
		wl, ok := cs.workloads[svcID]
		if !ok || len(wl.Pods) == 0 {
			writeSimJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
			return
		}
		nowMs := time.Now().UTC().UnixMilli()
		wl.Pods[0].FilesystemMutatedPaths = appendUnique(wl.Pods[0].FilesystemMutatedPaths, req.FilePath)
		if req.Process != "" {
			wl.Pods[0].UntrackedProcesses = appendUnique(wl.Pods[0].UntrackedProcesses, req.Process)
		}
		wl.LastDriftInjectedAtUnixMs = nowMs
		writeSimJSON(w, http.StatusOK, map[string]any{
			"service_id":       svcID,
			"pod_name":         wl.Pods[0].PodName,
			"running_digest":   wl.Pods[0].RunningDigest,
			"mutated_path":     req.FilePath,
			"injected_unix_ms": nowMs,
		})
	})

	// POST /v1/workloads/{service_id}/cordon-recycle cordons a compromised pod and recycles a fresh clean replica.
	mux.HandleFunc("POST /v1/workloads/{service_id}/cordon-recycle", func(w http.ResponseWriter, r *http.Request) {
		svcID := r.PathValue("service_id")
		var req struct {
			PodName     string `json:"pod_name"`
			CleanDigest string `json:"clean_digest"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		cs.mu.Lock()
		defer cs.mu.Unlock()
		wl, ok := cs.workloads[svcID]
		if !ok {
			writeSimJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
			return
		}
		cleanDigest := req.CleanDigest
		if cleanDigest == "" {
			cleanDigest = wl.BaselineDigest
		}
		recycledPod := ""
		now := time.Now().UTC()
		for i := range wl.Pods {
			if wl.Pods[i].PodName == req.PodName || req.PodName == "" {
				recycledPod = fmt.Sprintf("%s-clean-recycled-%s", svcID, uuid.NewString()[:6])
				wl.Pods[i] = PodState{
					PodName:                recycledPod,
					NodeName:               wl.Pods[i].NodeName,
					RunningDigest:          cleanDigest,
					LoadedLibs:             wl.Pods[i].LoadedLibs,
					LoadedSymbols:          []string{},
					FilesystemMutatedPaths: nil,
					UntrackedProcesses:     nil,
					SecretGeneration:       wl.SecretGeneration,
					Cordoned:               false,
					StartedAt:              now,
				}
				break
			}
		}
		wl.LastDriftInjectedAtUnixMs = 0
		writeSimJSON(w, http.StatusOK, map[string]any{
			"service_id":    svcID,
			"cordoned_pod":  req.PodName,
			"recycled_pod":  recycledPod,
			"clean_digest":  cleanDigest,
			"recycled_at":   now,
		})
	})

	// POST /v1/secrets/{service_id}/rotate revokes compromised ExternalSecret / SA tokens and rolls all replicas.
	mux.HandleFunc("POST /v1/secrets/{service_id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		svcID := r.PathValue("service_id")
		var req struct {
			SecretResourceKind string `json:"secret_resource_kind"`
			SecretResourceName string `json:"secret_resource_name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		cs.mu.Lock()
		defer cs.mu.Unlock()
		wl, ok := cs.workloads[svcID]
		if !ok {
			writeSimJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
			return
		}
		wl.SecretGeneration++
		now := time.Now().UTC()
		verHash := crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|gen=%d|%d", svcID, req.SecretResourceName, wl.SecretGeneration, now.UnixNano())))
		for i := range wl.Pods {
			wl.Pods[i].SecretGeneration = wl.SecretGeneration
			wl.Pods[i].StartedAt = now
		}
		writeSimJSON(w, http.StatusOK, SecretRotationResult{
			ServiceID:            svcID,
			SecretResourceKind:   req.SecretResourceKind,
			SecretResourceName:   req.SecretResourceName,
			PreviousTokenRevoked: true,
			NewSecretGeneration:  wl.SecretGeneration,
			NewSecretVersionHash: verHash,
			RestartedPods:        len(wl.Pods),
			RotatedAt:            now,
		})
	})

	return mux
}

func appendUnique(list []string, item string) []string {
	for _, existing := range list {
		if existing == item {
			return list
		}
	}
	return append(list, item)
}

func writeSimJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
