package vmtwins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// HyperVConfig configures the live Windows Hyper-V VM_TWIN driver (`scripts/hyperv_vm_twin_agent.ps1`).
type HyperVConfig struct {
	AgentURL          string
	AgentToken        string
	QAParentVHDX      string
	IsolatedSwitch    string
	VMMemoryMB        int
	VMProcessorCount  int
	VMGeneration      int    // 1 or 2 (default 2)
	SecureBootProfile string // "MicrosoftWindows" | "MicrosoftUEFICertificateAuthority" (Linux) | "Off"
	PatchStageDir     string // Optional host directory containing .msu/.rpm/.deb artifacts copied into clones via Copy-VMFile
	SmokeCommand      string
	AcceptanceCommand string
}

type HyperVVMTwinProvider struct {
	cfg        HyperVConfig
	httpClient *http.Client
}

func NewHyperVVMTwinProvider(cfg HyperVConfig, rt http.RoundTripper) (*HyperVVMTwinProvider, error) {
	cleanURL := strings.TrimRight(strings.TrimSpace(cfg.AgentURL), "/")
	if cleanURL == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (hyperv): WARRANT_HYPERV_AGENT_URL is required")
	}
	u, err := url.Parse(cleanURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_INVALID (hyperv): invalid WARRANT_HYPERV_AGENT_URL %q", cfg.AgentURL)
	}
	if strings.TrimSpace(cfg.QAParentVHDX) == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (hyperv): WARRANT_HYPERV_QA_PARENT_VHDX is required")
	}
	cfg.AgentURL = cleanURL
	if strings.TrimSpace(cfg.IsolatedSwitch) == "" {
		cfg.IsolatedSwitch = "g1-twin-proving-private"
	}
	if cfg.VMMemoryMB <= 0 {
		cfg.VMMemoryMB = 2048
	}
	if cfg.VMProcessorCount <= 0 {
		cfg.VMProcessorCount = 2
	}
	if cfg.VMGeneration != 1 && cfg.VMGeneration != 2 {
		cfg.VMGeneration = 2
	}
	if strings.TrimSpace(cfg.SecureBootProfile) == "" {
		cfg.SecureBootProfile = "MicrosoftWindows"
	}
	cli := &http.Client{Timeout: 5 * time.Minute}
	if rt != nil {
		cli.Transport = rt
	}
	return &HyperVVMTwinProvider{cfg: cfg, httpClient: cli}, nil
}

func NewHyperVVMTwinProviderFromEnv(rt http.RoundTripper, getenv func(string) string) (*HyperVVMTwinProvider, error) {
	mem := 2048
	if v := strings.TrimSpace(getenv("WARRANT_HYPERV_VM_MEMORY_MB")); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &mem)
	}
	cpus := 2
	if v := strings.TrimSpace(getenv("WARRANT_HYPERV_VM_CPU_COUNT")); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &cpus)
	}
	gen := 2
	if v := strings.TrimSpace(getenv("WARRANT_HYPERV_VM_GENERATION")); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &gen)
	}
	return NewHyperVVMTwinProvider(HyperVConfig{
		AgentURL:          getenv("WARRANT_HYPERV_AGENT_URL"),
		AgentToken:        getenv("WARRANT_HYPERV_AGENT_TOKEN"),
		QAParentVHDX:      getenv("WARRANT_HYPERV_QA_PARENT_VHDX"),
		IsolatedSwitch:    getenv("WARRANT_HYPERV_ISOLATED_SWITCH"),
		VMMemoryMB:        mem,
		VMProcessorCount:  cpus,
		VMGeneration:      gen,
		SecureBootProfile: getenv("WARRANT_HYPERV_SECURE_BOOT_TEMPLATE"),
		PatchStageDir:     getenv("WARRANT_HYPERV_PATCH_STAGE_DIR"),
		SmokeCommand:      getenv("WARRANT_VM_TWIN_SMOKE_CMD"),
		AcceptanceCommand: getenv("WARRANT_VM_TWIN_ACCEPTANCE_CMD"),
	}, rt)
}

func (h *HyperVVMTwinProvider) doAgentJSON(ctx context.Context, method, path string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.cfg.AgentURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(h.cfg.AgentToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(h.cfg.AgentToken))
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VM_TWIN_TRANSPORT_ERROR (hyperv %s %s): %w", method, path, err)
	}
	defer resp.Body.Close()
	rawResp, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("VM_TWIN_REMOTE_ERROR (hyperv %s %s -> HTTP %d): %s",
			method, path, resp.StatusCode, strings.TrimSpace(string(rawResp)))
	}
	return rawResp, nil
}

func (h *HyperVVMTwinProvider) RunVMTwinProving(ctx context.Context, req adapters.CloneTwinProvingRequest) (*models.CloneTwinProvingManifest, error) {
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	runID := "hv-" + crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%d", req.ServiceID, req.CVEID, time.Now().UnixNano())))[:8]

	rawCreate, err := h.doAgentJSON(ctx, http.MethodPost, "/v1/hyperv/clones", map[string]any{
		"run_id":               runID,
		"service_id":           req.ServiceID,
		"clone_count":          cloneCount,
		"parent_vhdx":          firstNonEmptyStr(req.BaseCloneImageIdentity, h.cfg.QAParentVHDX),
		"isolated_switch":      h.cfg.IsolatedSwitch,
		"memory_mb":            h.cfg.VMMemoryMB,
		"cpu_count":            h.cfg.VMProcessorCount,
		"generation":           h.cfg.VMGeneration,
		"secure_boot_template": h.cfg.SecureBootProfile,
		"patch_stage_dir":      h.cfg.PatchStageDir,
		"switch_type":          "Private",
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = h.doAgentJSON(cleanCtx, http.MethodDelete, "/v1/hyperv/clones/"+url.PathEscape(runID), nil)
	}()

	var created struct {
		HostName string   `json:"host_name"`
		VMNames  []string `json:"vm_names"`
	}
	if err := json.Unmarshal(rawCreate, &created); err != nil {
		return nil, fmt.Errorf("VM_TWIN_UNPARSEABLE_RESPONSE (hyperv create): %w", err)
	}

	rawProve, err := h.doAgentJSON(ctx, http.MethodPost, "/v1/hyperv/prove", map[string]any{
		"run_id":             runID,
		"vm_names":           created.VMNames,
		"service_id":         req.ServiceID,
		"warrant_class":      req.WarrantClass,
		"cve_id":             req.CVEID,
		"kb_article_id":      req.KBArticleID,
		"package_nevra":      req.PackageNEVRA,
		"candidate_digest":   req.CandidateDigest,
		"patch_target_layer": req.PatchTargetLayer,
		"smoke_command":      h.cfg.SmokeCommand,
		"acceptance_command": h.cfg.AcceptanceCommand,
		"require_reboot":     true,
		"max_p99_ms":         req.MaxP99LatencyMs,
	})
	if err != nil {
		return nil, err
	}
	var proveResp struct {
		Clones []vmCloneRawOutcome `json:"clones"`
	}
	if err := json.Unmarshal(rawProve, &proveResp); err != nil {
		return nil, fmt.Errorf("VM_TWIN_UNPARSEABLE_RESPONSE (hyperv prove): %w", err)
	}
	return assembleVMProvingManifest(DriverHyperV, "hyperv://"+h.cfg.IsolatedSwitch, req, proveResp.Clones)
}
