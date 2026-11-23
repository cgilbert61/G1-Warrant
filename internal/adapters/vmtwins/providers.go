package vmtwins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

const (
	DriverHyperV  = "hyperv"
	DriverAWSEC2  = "aws-ec2"
	DriverAzureVM = "azure-vm"
	DriverGCPGCE  = "gcp-gce"
)

// NewVMTwinProviderFromEnv constructs a non-Docker VM_TWIN QA Clone Proving driver when WARRANT_VM_TWIN_DRIVER
// is set to "hyperv", "aws-ec2", "azure-vm", or "gcp-gce". Returns (nil, nil) when unset so unconfigured
// KERNEL / BOOT_LAYER patches continue to fail closed with KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME.
func NewVMTwinProviderFromEnv(rt http.RoundTripper, getenv func(string) string) (adapters.VMTwinProvider, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	driver := strings.ToLower(strings.TrimSpace(getenv("WARRANT_VM_TWIN_DRIVER")))
	switch driver {
	case "", "none":
		return nil, nil
	case DriverHyperV:
		return NewHyperVVMTwinProviderFromEnv(rt, getenv)
	case DriverAWSEC2:
		return NewAWSEC2VMTwinProviderFromEnv(rt, getenv)
	case DriverAzureVM:
		return NewAzureComputeVMTwinProviderFromEnv(rt, getenv)
	case DriverGCPGCE:
		return NewGCPComputeVMTwinProviderFromEnv(rt, getenv)
	default:
		return nil, fmt.Errorf("UNSUPPORTED_VM_TWIN_DRIVER %q: expected hyperv, aws-ec2, azure-vm, or gcp-gce", driver)
	}
}

type baseHTTPVMClient struct {
	driverID   string
	baseURL    string
	token      string
	httpClient *http.Client
}

func newBaseHTTPVMClient(driverID, rawURL, token string, rt http.RoundTripper) (baseHTTPVMClient, error) {
	cleanURL := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if cleanURL == "" {
		return baseHTTPVMClient{}, fmt.Errorf("VM_TWIN_CONFIG_MISSING (%s): endpoint URL is required", driverID)
	}
	u, err := url.Parse(cleanURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return baseHTTPVMClient{}, fmt.Errorf("VM_TWIN_CONFIG_INVALID (%s): invalid endpoint URL %q", driverID, rawURL)
	}
	client := &http.Client{Timeout: 120 * time.Second}
	if rt != nil {
		client.Transport = rt
	}
	return baseHTTPVMClient{
		driverID:   driverID,
		baseURL:    cleanURL,
		token:      strings.TrimSpace(token),
		httpClient: client,
	}, nil
}

func (b *baseHTTPVMClient) doJSON(ctx context.Context, method, path string, payload any) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VM_TWIN_TRANSPORT_ERROR (%s %s %s): %w", b.driverID, method, path, err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("VM_TWIN_REMOTE_ERROR (%s %s %s -> HTTP %d): %s",
			b.driverID, method, path, resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	return respBytes, nil
}

type vmCloneRawOutcome struct {
	CloneIndex            int     `json:"clone_index"`
	CloneName             string  `json:"clone_name"`
	HostOrZone            string  `json:"host_or_zone"`
	PrivateIP             string  `json:"private_ip"`
	BootedKernelOrBuild   string  `json:"booted_kernel_or_build"`
	RebootVerified        bool    `json:"reboot_verified"`
	ServiceUpPassed       bool    `json:"service_up_passed"`
	SmokeTestPassed       bool    `json:"smoke_test_passed"`
	ClassAcceptancePassed bool    `json:"class_acceptance_passed"`
	ObservedLatencyMs     float64 `json:"observed_latency_ms"`
	ExitCode              int     `json:"exit_code"`
	RawLog                string  `json:"raw_log"`
}

func assembleVMProvingManifest(
	driverID string,
	isolationDomain string,
	req adapters.CloneTwinProvingRequest,
	outcomes []vmCloneRawOutcome,
) (*models.CloneTwinProvingManifest, error) {
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	maxP99 := req.MaxP99LatencyMs
	if maxP99 <= 0 {
		maxP99 = 250.0
	}
	if len(outcomes) != cloneCount {
		return nil, fmt.Errorf("VM_TWIN_INCOMPLETE_CLONES (%s): expected %d VM clones, got %d", driverID, cloneCount, len(outcomes))
	}

	runHash := crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%s|%s|%d",
		driverID, req.ServiceID, req.CVEID, req.CandidateDigest, time.Now().UnixNano())))[:8]
	provingRunID := fmt.Sprintf("prv-vm-%s-%s", driverID, runHash)

	clones := make([]models.CloneTwinInstanceResult, 0, len(outcomes))
	upCount, smokeCount, accCount := 0, 0, 0
	allPassed := true
	failureReason := ""
	var transcriptBuilder strings.Builder
	fmt.Fprintf(&transcriptBuilder, "G1_VM_TWIN_V1|driver=%s|isolation=%s|service=%s|cve=%s|layer=%s\n",
		driverID, isolationDomain, req.ServiceID, req.CVEID, req.PatchTargetLayer)

	requiresReboot := req.PatchTargetLayer == models.PatchTargetLayerKernel || req.PatchTargetLayer == models.PatchTargetLayerBoot

	for _, oc := range outcomes {
		latOK := oc.ObservedLatencyMs <= maxP99
		rebootOK := !requiresReboot || oc.RebootVerified
		accOK := oc.ServiceUpPassed && oc.SmokeTestPassed && oc.ClassAcceptancePassed && latOK && rebootOK && oc.ExitCode == 0

		if oc.ServiceUpPassed {
			upCount++
		}
		if oc.SmokeTestPassed {
			smokeCount++
		}
		if accOK {
			accCount++
		} else {
			allPassed = false
			if failureReason == "" {
				switch {
				case !rebootOK:
					failureReason = "VM_CLONE_REBOOT_VERIFICATION_FAILED"
				case !oc.ServiceUpPassed:
					failureReason = "VM_CLONE_SERVICE_READINESS_FAILED"
				case !oc.SmokeTestPassed:
					failureReason = "VM_CLONE_SMOKE_TEST_FAILED"
				default:
					failureReason = "VM_CLONE_CLASS_ACCEPTANCE_FAILED"
				}
			}
		}

		evLine := fmt.Sprintf("clone=%d|vm=%s|host=%s|build=%s|reboot=%t|up=%t|smoke=%t|acc=%t|lat=%.2f|exit=%d|log=%s",
			oc.CloneIndex, oc.CloneName, oc.HostOrZone, oc.BootedKernelOrBuild, oc.RebootVerified,
			oc.ServiceUpPassed, oc.SmokeTestPassed, accOK, oc.ObservedLatencyMs, oc.ExitCode, strings.TrimSpace(oc.RawLog))
		transcriptBuilder.WriteString(evLine + "\n")

		runningDigest := req.CandidateDigest
		if runningDigest == "" {
			runningDigest = oc.BootedKernelOrBuild
		}
		clones = append(clones, models.CloneTwinInstanceResult{
			CloneIndex:            oc.CloneIndex,
			CloneName:             oc.CloneName,
			NodeOrHost:            oc.HostOrZone,
			PodIP:                 oc.PrivateIP,
			RunningDigest:         runningDigest,
			ServiceUpPassed:       oc.ServiceUpPassed,
			SmokeTestPassed:       oc.SmokeTestPassed,
			ClassAcceptancePassed: accOK,
			ObservedLatencyMs:     oc.ObservedLatencyMs,
			ExitCode:              oc.ExitCode,
			EvidenceSHA256:        crypto.SHA256Hex([]byte(evLine)),
			LogSummary:            fmt.Sprintf("driver=%s reboot=%t build=%s", driverID, oc.RebootVerified, oc.BootedKernelOrBuild),
		})
	}

	manifest := &models.CloneTwinProvingManifest{
		ProvingRunID:          provingRunID,
		RemediationID:         req.RemediationID,
		ServiceID:             req.ServiceID,
		WarrantID:             req.WarrantID,
		WarrantClass:          req.WarrantClass,
		CVEID:                 req.CVEID,
		CandidateDigest:       req.CandidateDigest,
		PatchTargetLayer:      req.PatchTargetLayer,
		TwinRuntime:           models.TwinRuntimeVM,
		ProvingNamespace:      isolationDomain,
		ZeroProductionEgress:  true,
		CloneCount:            cloneCount,
		ServicesUpCount:       upCount,
		SmokePassedCount:      smokeCount,
		AcceptancePassedCount: accCount,
		AllPassed:             allPassed,
		FailureReasonCode:     failureReason,
		Clones:                clones,
		TranscriptSHA256:      crypto.SHA256Hex([]byte(transcriptBuilder.String())),
		ProvedAt:              time.Now().UTC(),
	}
	if !allPassed {
		return manifest, fmt.Errorf("VM_TWIN_PROVING_FAILED (%s): %s (up=%d/%d smoke=%d/%d acceptance=%d/%d)",
			driverID, failureReason, upCount, cloneCount, smokeCount, cloneCount, accCount, cloneCount)
	}
	return manifest, nil
}

// =============================================================================
// 1. Live Hyper-V Differencing-VHDX + Private Switch + PowerShell Direct Driver
// =============================================================================

type HyperVConfig struct {
	AgentURL       string
	AgentToken     string
	QAParentVHDX   string
	IsolatedSwitch string
	VMMemoryMB     int
}

type HyperVVMTwinProvider struct {
	baseHTTPVMClient
	cfg HyperVConfig
}

func NewHyperVVMTwinProvider(cfg HyperVConfig, rt http.RoundTripper) (*HyperVVMTwinProvider, error) {
	if strings.TrimSpace(cfg.QAParentVHDX) == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (hyperv): WARRANT_HYPERV_QA_PARENT_VHDX is required")
	}
	if strings.TrimSpace(cfg.IsolatedSwitch) == "" {
		cfg.IsolatedSwitch = "g1-twin-proving-private"
	}
	if cfg.VMMemoryMB <= 0 {
		cfg.VMMemoryMB = 2048
	}
	base, err := newBaseHTTPVMClient(DriverHyperV, cfg.AgentURL, cfg.AgentToken, rt)
	if err != nil {
		return nil, err
	}
	return &HyperVVMTwinProvider{baseHTTPVMClient: base, cfg: cfg}, nil
}

func NewHyperVVMTwinProviderFromEnv(rt http.RoundTripper, getenv func(string) string) (*HyperVVMTwinProvider, error) {
	mem := 2048
	if v := strings.TrimSpace(getenv("WARRANT_HYPERV_VM_MEMORY_MB")); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &mem)
	}
	return NewHyperVVMTwinProvider(HyperVConfig{
		AgentURL:       getenv("WARRANT_HYPERV_AGENT_URL"),
		AgentToken:     getenv("WARRANT_HYPERV_AGENT_TOKEN"),
		QAParentVHDX:   getenv("WARRANT_HYPERV_QA_PARENT_VHDX"),
		IsolatedSwitch: getenv("WARRANT_HYPERV_ISOLATED_SWITCH"),
		VMMemoryMB:     mem,
	}, rt)
}

func (h *HyperVVMTwinProvider) RunVMTwinProving(ctx context.Context, req adapters.CloneTwinProvingRequest) (*models.CloneTwinProvingManifest, error) {
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	runID := "hv-" + crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%d", req.ServiceID, req.CVEID, time.Now().UnixNano())))[:8]

	rawCreate, err := h.doJSON(ctx, http.MethodPost, "/v1/hyperv/clones", map[string]any{
		"run_id":          runID,
		"service_id":      req.ServiceID,
		"clone_count":     cloneCount,
		"parent_vhdx":     h.cfg.QAParentVHDX,
		"isolated_switch": h.cfg.IsolatedSwitch,
		"memory_mb":       h.cfg.VMMemoryMB,
		"switch_type":     "Private",
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = h.doJSON(cleanCtx, http.MethodDelete, "/v1/hyperv/clones/"+url.PathEscape(runID), nil)
	}()

	var created struct {
		HostName string   `json:"host_name"`
		VMNames  []string `json:"vm_names"`
	}
	_ = json.Unmarshal(rawCreate, &created)

	rawProve, err := h.doJSON(ctx, http.MethodPost, "/v1/hyperv/prove", map[string]any{
		"run_id":             runID,
		"vm_names":           created.VMNames,
		"service_id":         req.ServiceID,
		"warrant_class":      req.WarrantClass,
		"cve_id":             req.CVEID,
		"kb_article_id":      req.KBArticleID,
		"package_nevra":      req.PackageNEVRA,
		"candidate_digest":   req.CandidateDigest,
		"patch_target_layer": req.PatchTargetLayer,
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
		return nil, fmt.Errorf("VM_TWIN_UNPARSEABLE_RESPONSE (hyperv): %w", err)
	}
	return assembleVMProvingManifest(DriverHyperV, "hyperv://"+h.cfg.IsolatedSwitch, req, proveResp.Clones)
}

// =============================================================================
// 2. AWS EC2 QA AMI Clone + Zero-Egress Security Group + SSM RunCommand Driver
// =============================================================================

type AWSEC2Config struct {
	EndpointURL  string
	Token        string
	QAAMIID      string
	SubnetID     string
	IsolatedSGID string
	InstanceType string
}

type AWSEC2VMTwinProvider struct {
	baseHTTPVMClient
	cfg AWSEC2Config
}

func NewAWSEC2VMTwinProvider(cfg AWSEC2Config, rt http.RoundTripper) (*AWSEC2VMTwinProvider, error) {
	if strings.TrimSpace(cfg.QAAMIID) == "" || strings.TrimSpace(cfg.SubnetID) == "" || strings.TrimSpace(cfg.IsolatedSGID) == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (aws-ec2): WARRANT_AWS_TWIN_AMI_ID, SUBNET_ID, and ISOLATED_SG_ID are required")
	}
	if strings.TrimSpace(cfg.InstanceType) == "" {
		cfg.InstanceType = "m6i.large"
	}
	base, err := newBaseHTTPVMClient(DriverAWSEC2, cfg.EndpointURL, cfg.Token, rt)
	if err != nil {
		return nil, err
	}
	return &AWSEC2VMTwinProvider{baseHTTPVMClient: base, cfg: cfg}, nil
}

func NewAWSEC2VMTwinProviderFromEnv(rt http.RoundTripper, getenv func(string) string) (*AWSEC2VMTwinProvider, error) {
	return NewAWSEC2VMTwinProvider(AWSEC2Config{
		EndpointURL:  getenv("WARRANT_AWS_TWIN_URL"),
		Token:        getenv("WARRANT_AWS_TWIN_TOKEN"),
		QAAMIID:      getenv("WARRANT_AWS_TWIN_AMI_ID"),
		SubnetID:     getenv("WARRANT_AWS_TWIN_SUBNET_ID"),
		IsolatedSGID: getenv("WARRANT_AWS_TWIN_ISOLATED_SG_ID"),
		InstanceType: getenv("WARRANT_AWS_TWIN_INSTANCE_TYPE"),
	}, rt)
}

func (a *AWSEC2VMTwinProvider) RunVMTwinProving(ctx context.Context, req adapters.CloneTwinProvingRequest) (*models.CloneTwinProvingManifest, error) {
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	rawLaunch, err := a.doJSON(ctx, http.MethodPost, "/ec2/RunInstances", map[string]any{
		"ImageId":                  a.cfg.QAAMIID,
		"InstanceType":             a.cfg.InstanceType,
		"MinCount":                 cloneCount,
		"MaxCount":                 cloneCount,
		"SubnetId":                 a.cfg.SubnetID,
		"SecurityGroupIds":         []string{a.cfg.IsolatedSGID},
		"AssociatePublicIpAddress": false,
		"TagSpecifications": map[string]string{
			"g1.warrant/proving-ground":         "true",
			"g1.warrant/zero-production-egress": "true",
			"g1.warrant/service-id":             req.ServiceID,
			"g1.warrant/cve-id":                 req.CVEID,
		},
	})
	if err != nil {
		return nil, err
	}
	var launchResp struct {
		Instances []struct {
			InstanceID       string `json:"InstanceId"`
			PrivateIPAddress string `json:"PrivateIpAddress"`
			AvailabilityZone string `json:"AvailabilityZone"`
		} `json:"Instances"`
	}
	if err := json.Unmarshal(rawLaunch, &launchResp); err != nil || len(launchResp.Instances) == 0 {
		return nil, fmt.Errorf("VM_TWIN_LAUNCH_FAILED (aws-ec2): invalid RunInstances response")
	}
	instIDs := make([]string, 0, len(launchResp.Instances))
	for _, inst := range launchResp.Instances {
		instIDs = append(instIDs, inst.InstanceID)
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = a.doJSON(cleanCtx, http.MethodPost, "/ec2/TerminateInstances", map[string]any{"InstanceIds": instIDs})
	}()

	rawCmd, err := a.doJSON(ctx, http.MethodPost, "/ssm/SendCommand", map[string]any{
		"DocumentName": "G1Warrant-ProveAndRebootQAClone",
		"InstanceIds":  instIDs,
		"Parameters": map[string][]string{
			"CVEID":            {req.CVEID},
			"KBArticleID":      {req.KBArticleID},
			"PackageNEVRA":     {req.PackageNEVRA},
			"CandidateDigest":  {req.CandidateDigest},
			"PatchTargetLayer": {req.PatchTargetLayer},
			"RebootOption":     {"RebootAndVerify"},
		},
	})
	if err != nil {
		return nil, err
	}
	var cmdResp struct {
		CommandID string              `json:"CommandId"`
		Clones    []vmCloneRawOutcome `json:"Clones"`
	}
	if err := json.Unmarshal(rawCmd, &cmdResp); err != nil {
		return nil, fmt.Errorf("VM_TWIN_UNPARSEABLE_RESPONSE (aws-ec2): %w", err)
	}
	return assembleVMProvingManifest(DriverAWSEC2, fmt.Sprintf("aws-ec2://%s/%s", a.cfg.SubnetID, a.cfg.IsolatedSGID), req, cmdResp.Clones)
}

// =============================================================================
// 3. Azure Compute Gallery/Snapshot Clone + Deny-Outbound NSG + RunCommand
// =============================================================================

type AzureComputeConfig struct {
	EndpointURL    string
	Token          string
	SubscriptionID string
	ResourceGroup  string
	QAImageID      string
	SubnetID       string
	DenyEgressNSG  string
	VMSize         string
}

type AzureComputeVMTwinProvider struct {
	baseHTTPVMClient
	cfg AzureComputeConfig
}

func NewAzureComputeVMTwinProvider(cfg AzureComputeConfig, rt http.RoundTripper) (*AzureComputeVMTwinProvider, error) {
	if strings.TrimSpace(cfg.SubscriptionID) == "" || strings.TrimSpace(cfg.ResourceGroup) == "" ||
		strings.TrimSpace(cfg.QAImageID) == "" || strings.TrimSpace(cfg.SubnetID) == "" || strings.TrimSpace(cfg.DenyEgressNSG) == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (azure-vm): SUBSCRIPTION_ID, RESOURCE_GROUP, IMAGE_ID, SUBNET_ID, and NSG_ID are required")
	}
	if strings.TrimSpace(cfg.VMSize) == "" {
		cfg.VMSize = "Standard_D2s_v5"
	}
	base, err := newBaseHTTPVMClient(DriverAzureVM, cfg.EndpointURL, cfg.Token, rt)
	if err != nil {
		return nil, err
	}
	return &AzureComputeVMTwinProvider{baseHTTPVMClient: base, cfg: cfg}, nil
}

func NewAzureComputeVMTwinProviderFromEnv(rt http.RoundTripper, getenv func(string) string) (*AzureComputeVMTwinProvider, error) {
	return NewAzureComputeVMTwinProvider(AzureComputeConfig{
		EndpointURL:    getenv("WARRANT_AZURE_TWIN_URL"),
		Token:          getenv("WARRANT_AZURE_TWIN_TOKEN"),
		SubscriptionID: getenv("WARRANT_AZURE_TWIN_SUBSCRIPTION_ID"),
		ResourceGroup:  getenv("WARRANT_AZURE_TWIN_RESOURCE_GROUP"),
		QAImageID:      getenv("WARRANT_AZURE_TWIN_IMAGE_ID"),
		SubnetID:       getenv("WARRANT_AZURE_TWIN_SUBNET_ID"),
		DenyEgressNSG:  getenv("WARRANT_AZURE_TWIN_NSG_ID"),
		VMSize:         getenv("WARRANT_AZURE_TWIN_VM_SIZE"),
	}, rt)
}

func (az *AzureComputeVMTwinProvider) RunVMTwinProving(ctx context.Context, req adapters.CloneTwinProvingRequest) (*models.CloneTwinProvingManifest, error) {
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	runSlug := crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%d", req.ServiceID, req.CVEID, time.Now().UnixNano())))[:8]
	basePath := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachines",
		url.PathEscape(az.cfg.SubscriptionID), url.PathEscape(az.cfg.ResourceGroup))

	vmNames := make([]string, 0, cloneCount)
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, vm := range vmNames {
			_, _ = az.doJSON(cleanCtx, http.MethodDelete, fmt.Sprintf("%s/%s?forceDeletion=true&api-version=2024-03-01", basePath, url.PathEscape(vm)), nil)
		}
	}()

	outcomes := make([]vmCloneRawOutcome, 0, cloneCount)
	for i := 0; i < cloneCount; i++ {
		vmName := fmt.Sprintf("g1-az-twin-%s-%d", runSlug, i)
		_, err := az.doJSON(ctx, http.MethodPut, fmt.Sprintf("%s/%s?api-version=2024-03-01", basePath, url.PathEscape(vmName)), map[string]any{
			"properties": map[string]any{
				"hardwareProfile": map[string]string{"vmSize": az.cfg.VMSize},
				"storageProfile":  map[string]any{"imageReference": map[string]string{"id": az.cfg.QAImageID}},
				"networkProfile": map[string]any{
					"subnetId":               az.cfg.SubnetID,
					"networkSecurityGroupId": az.cfg.DenyEgressNSG,
					"publicIPAddress":        nil,
				},
			},
			"tags": map[string]string{
				"g1.warrant/proving-ground":         "true",
				"g1.warrant/zero-production-egress": "true",
			},
		})
		if err != nil {
			return nil, err
		}
		vmNames = append(vmNames, vmName)

		rawRun, err := az.doJSON(ctx, http.MethodPost, fmt.Sprintf("%s/%s/runCommand?api-version=2024-03-01", basePath, url.PathEscape(vmName)), map[string]any{
			"commandId":        "RunShellScript",
			"cve_id":           req.CVEID,
			"kb_article_id":    req.KBArticleID,
			"package_nevra":    req.PackageNEVRA,
			"candidate_digest": req.CandidateDigest,
			"clone_index":      i,
			"require_reboot":   true,
		})
		if err != nil {
			return nil, err
		}
		var oc vmCloneRawOutcome
		if err := json.Unmarshal(rawRun, &oc); err != nil {
			return nil, fmt.Errorf("VM_TWIN_UNPARSEABLE_RESPONSE (azure-vm %s): %w", vmName, err)
		}
		oc.CloneIndex = i
		if oc.CloneName == "" {
			oc.CloneName = vmName
		}
		outcomes = append(outcomes, oc)
	}
	return assembleVMProvingManifest(DriverAzureVM, "azure-nsg://"+az.cfg.DenyEgressNSG, req, outcomes)
}

// =============================================================================
// 4. Google Cloud Compute Engine Machine-Image Clone + OS Config Driver
// =============================================================================

type GCPComputeConfig struct {
	EndpointURL    string
	Token          string
	ProjectID      string
	Zone           string
	QAMachineImage string
	Subnet         string
	IsolatedTag    string
}

type GCPComputeVMTwinProvider struct {
	baseHTTPVMClient
	cfg GCPComputeConfig
}

func NewGCPComputeVMTwinProvider(cfg GCPComputeConfig, rt http.RoundTripper) (*GCPComputeVMTwinProvider, error) {
	if strings.TrimSpace(cfg.ProjectID) == "" || strings.TrimSpace(cfg.Zone) == "" ||
		strings.TrimSpace(cfg.QAMachineImage) == "" || strings.TrimSpace(cfg.Subnet) == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (gcp-gce): PROJECT, ZONE, MACHINE_IMAGE, and SUBNET are required")
	}
	if strings.TrimSpace(cfg.IsolatedTag) == "" {
		cfg.IsolatedTag = "g1-twin-proving-zero-egress"
	}
	base, err := newBaseHTTPVMClient(DriverGCPGCE, cfg.EndpointURL, cfg.Token, rt)
	if err != nil {
		return nil, err
	}
	return &GCPComputeVMTwinProvider{baseHTTPVMClient: base, cfg: cfg}, nil
}

func NewGCPComputeVMTwinProviderFromEnv(rt http.RoundTripper, getenv func(string) string) (*GCPComputeVMTwinProvider, error) {
	return NewGCPComputeVMTwinProvider(GCPComputeConfig{
		EndpointURL:    getenv("WARRANT_GCP_TWIN_URL"),
		Token:          getenv("WARRANT_GCP_TWIN_TOKEN"),
		ProjectID:      getenv("WARRANT_GCP_TWIN_PROJECT"),
		Zone:           getenv("WARRANT_GCP_TWIN_ZONE"),
		QAMachineImage: getenv("WARRANT_GCP_TWIN_MACHINE_IMAGE"),
		Subnet:         getenv("WARRANT_GCP_TWIN_SUBNET"),
		IsolatedTag:    getenv("WARRANT_GCP_TWIN_ISOLATED_TAG"),
	}, rt)
}

func (g *GCPComputeVMTwinProvider) RunVMTwinProving(ctx context.Context, req adapters.CloneTwinProvingRequest) (*models.CloneTwinProvingManifest, error) {
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	runSlug := crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%d", req.ServiceID, req.CVEID, time.Now().UnixNano())))[:8]
	instBase := fmt.Sprintf("/compute/v1/projects/%s/zones/%s/instances",
		url.PathEscape(g.cfg.ProjectID), url.PathEscape(g.cfg.Zone))

	prefix := "g1-gcp-twin-" + runSlug
	vmNames := make([]string, 0, cloneCount)
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, vm := range vmNames {
			_, _ = g.doJSON(cleanCtx, http.MethodDelete, instBase+"/"+url.PathEscape(vm), nil)
		}
	}()

	for i := 0; i < cloneCount; i++ {
		vmName := fmt.Sprintf("%s-%d", prefix, i)
		_, err := g.doJSON(ctx, http.MethodPost, instBase, map[string]any{
			"name":               vmName,
			"sourceMachineImage": g.cfg.QAMachineImage,
			"tags":               map[string]any{"items": []string{g.cfg.IsolatedTag}},
			"networkInterfaces": []map[string]any{
				{
					"subnetwork":    g.cfg.Subnet,
					"accessConfigs": []any{}, // Zero external IP
				},
			},
		})
		if err != nil {
			return nil, err
		}
		vmNames = append(vmNames, vmName)
	}

	patchPath := fmt.Sprintf("/osconfig/v1/projects/%s/patchJobs:execute", url.PathEscape(g.cfg.ProjectID))
	rawExec, err := g.doJSON(ctx, http.MethodPost, patchPath, map[string]any{
		"description":  "G1-Warrant 3-Clone Isolated GCE QA Proving Run",
		"rebootConfig": "ALWAYS",
		"instanceFilter": map[string]any{
			"instanceNamePrefixes": []string{prefix},
		},
		"cve_id":           req.CVEID,
		"package_nevra":    req.PackageNEVRA,
		"candidate_digest": req.CandidateDigest,
		"vm_names":         vmNames,
	})
	if err != nil {
		return nil, err
	}
	var execResp struct {
		Clones []vmCloneRawOutcome `json:"clones"`
	}
	if err := json.Unmarshal(rawExec, &execResp); err != nil {
		return nil, fmt.Errorf("VM_TWIN_UNPARSEABLE_RESPONSE (gcp-gce): %w", err)
	}
	return assembleVMProvingManifest(DriverGCPGCE, fmt.Sprintf("gcp-vpc://%s/%s", g.cfg.ProjectID, g.cfg.IsolatedTag), req, execResp.Clones)
}
