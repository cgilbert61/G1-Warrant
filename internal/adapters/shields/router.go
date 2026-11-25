package shields

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// MultiSubstrateShieldRouter routes sub-second Stage 02 Containment Bridge compilation & enforcement
// and Stage 04 symmetric retirement across all 6 execution substrates:
//   - KUBERNETES   -> CiliumNetworkPolicy + K8s NetworkPolicy + Envoy SPIFFE mTLS (CiliumShieldAdapter / LiveKubernetesAdapter)
//   - AWS_EC2      -> AWS EC2 Quarantine Security Group + IMDSv2 HopLimit=1 (SigV4)
//   - AZURE_VM     -> Azure ARM NSG Priority-100 Outbound/Metadata Deny Rule
//   - GCP_GCE      -> GCP Compute Engine VPC Firewall Priority-100 Deny Rule
//   - LINUX_HOST   -> Atomic isolated Linux nftables table (`table inet g1_warrant_<id>`)
//   - WINDOWS_HOST -> Windows Filtering Platform NetFirewallRule group (`G1-Warrant-Bridge-<id>`)
type MultiSubstrateShieldRouter struct {
	k8sShield     adapters.ShieldEnforcer
	awsShield     *AWSEC2ShieldDriver
	azureShield   *AzureNSGShieldDriver
	gcpShield     *GCPFirewallShieldDriver
	linuxShield   *LinuxNftablesShieldDriver
	windowsShield *WindowsWFPShieldDriver
	defaultSub    string

	mu            sync.RWMutex
	bridgeTargets map[string]string // bridgeID -> resolved substrate family
}

func NewMultiSubstrateShieldRouter(
	k8sShield adapters.ShieldEnforcer,
	rt http.RoundTripper,
	rulepacks *adapters.RulepackRegistry,
	getenv func(string) string,
) *MultiSubstrateShieldRouter {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return &MultiSubstrateShieldRouter{
		k8sShield:     k8sShield,
		awsShield:     NewAWSEC2ShieldDriverFromEnv(rt, rulepacks, getenv),
		azureShield:   NewAzureNSGShieldDriverFromEnv(rt, rulepacks, getenv),
		gcpShield:     NewGCPFirewallShieldDriverFromEnv(rt, rulepacks, getenv),
		linuxShield:   NewLinuxNftablesShieldDriverFromEnv(rt, rulepacks, getenv),
		windowsShield: NewWindowsWFPShieldDriverFromEnv(rt, rulepacks, getenv),
		defaultSub:    strings.ToUpper(strings.TrimSpace(getenv("WARRANT_SHIELD_SUBSTRATE_DEFAULT"))),
		bridgeTargets: make(map[string]string),
	}
}

// ResolveSubstrate deterministically maps an incoming BridgeApplyRequest to one of the 6 shield substrates.
func (r *MultiSubstrateShieldRouter) ResolveSubstrate(req adapters.BridgeApplyRequest) string {
	// 1. Explicit caller substrate hint takes precedence
	if sub := normalizeSubstrate(req.SubstrateHint); sub != "" {
		return sub
	}

	// 2. WN-8 Distributor ID hints the target machine/cloud substrate
	switch strings.ToLower(strings.TrimSpace(req.DistributorID)) {
	case "aws-ssm":
		return models.ShieldSubstrateAWSEC2
	case "azure-update-manager":
		return models.ShieldSubstrateAzureVM
	case "gcp-os-config":
		return models.ShieldSubstrateGCPGCE
	case "ms-intune", "ms-mecm", "ms-wsus":
		return models.ShieldSubstrateWindowsHost
	case "ansible-awx", "redhat-satellite":
		return models.ShieldSubstrateLinuxHost
	case "k8s-cilium-native", "argocd", "flux":
		return models.ShieldSubstrateKubernetes
	}

	// 3. Normalized WN-7 AssetIdentity (CloudInstanceID / PlatformFamily / AssetKey prefix)
	if id := req.AssetIdentity; id != nil {
		cid := strings.ToLower(strings.TrimSpace(id.CloudInstanceID))
		switch {
		case strings.HasPrefix(cid, "i-") || strings.Contains(cid, "arn:aws:ec2"):
			return models.ShieldSubstrateAWSEC2
		case strings.Contains(cid, "/subscriptions/") || strings.Contains(cid, "microsoft.compute/virtualmachines"):
			return models.ShieldSubstrateAzureVM
		case strings.HasPrefix(cid, "projects/") || strings.HasPrefix(cid, "gce-"):
			return models.ShieldSubstrateGCPGCE
		}

		pf := strings.ToUpper(strings.TrimSpace(id.PlatformFamily))
		ak := strings.ToLower(strings.TrimSpace(id.AssetKey))
		hn := strings.ToLower(strings.TrimSpace(id.Hostname))
		switch {
		case strings.Contains(pf, "WIN") || strings.HasPrefix(ak, "win-") || strings.HasPrefix(hn, "win-"):
			return models.ShieldSubstrateWindowsHost
		case strings.Contains(pf, "LINUX") || strings.Contains(pf, "RHEL") || strings.Contains(pf, "UBUNTU") || strings.Contains(pf, "DEBIAN") || strings.HasPrefix(ak, "lnx-") || strings.HasPrefix(ak, "rhel-"):
			return models.ShieldSubstrateLinuxHost
		}
	}

	// 4. Optional operator default substrate override, otherwise Kubernetes/Cilium
	if sub := normalizeSubstrate(r.defaultSub); sub != "" {
		return sub
	}
	return models.ShieldSubstrateKubernetes
}

func normalizeSubstrate(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case models.ShieldSubstrateKubernetes, "K8S", "CILIUM", "CONTAINER":
		return models.ShieldSubstrateKubernetes
	case models.ShieldSubstrateAWSEC2, "AWS", "EC2":
		return models.ShieldSubstrateAWSEC2
	case models.ShieldSubstrateAzureVM, "AZURE", "AZURE_NSG":
		return models.ShieldSubstrateAzureVM
	case models.ShieldSubstrateGCPGCE, "GCP", "GCE":
		return models.ShieldSubstrateGCPGCE
	case models.ShieldSubstrateLinuxHost, "LINUX", "NFTABLES":
		return models.ShieldSubstrateLinuxHost
	case models.ShieldSubstrateWindowsHost, "WINDOWS", "WFP":
		return models.ShieldSubstrateWindowsHost
	default:
		return ""
	}
}

func (r *MultiSubstrateShieldRouter) CompileAndApplyBridge(ctx context.Context, req adapters.BridgeApplyRequest) (*models.ContainmentBridge, error) {
	sub := r.ResolveSubstrate(req)
	var (
		bridge *models.ContainmentBridge
		err    error
	)
	switch sub {
	case models.ShieldSubstrateAWSEC2:
		bridge, err = r.awsShield.CompileAndApplyBridge(ctx, req)
	case models.ShieldSubstrateAzureVM:
		bridge, err = r.azureShield.CompileAndApplyBridge(ctx, req)
	case models.ShieldSubstrateGCPGCE:
		bridge, err = r.gcpShield.CompileAndApplyBridge(ctx, req)
	case models.ShieldSubstrateLinuxHost:
		bridge, err = r.linuxShield.CompileAndApplyBridge(ctx, req)
	case models.ShieldSubstrateWindowsHost:
		bridge, err = r.windowsShield.CompileAndApplyBridge(ctx, req)
	default:
		sub = models.ShieldSubstrateKubernetes
		bridge, err = r.k8sShield.CompileAndApplyBridge(ctx, req)
	}
	if err != nil {
		return nil, err
	}
	if bridge != nil && bridge.SubstrateFamily == "" {
		bridge.SubstrateFamily = sub
	}
	r.mu.Lock()
	r.bridgeTargets[req.BridgeID] = sub
	r.mu.Unlock()
	return bridge, nil
}

func (r *MultiSubstrateShieldRouter) RetireBridge(ctx context.Context, bridgeID string) error {
	r.mu.Lock()
	sub, known := r.bridgeTargets[bridgeID]
	delete(r.bridgeTargets, bridgeID)
	r.mu.Unlock()

	if known {
		switch sub {
		case models.ShieldSubstrateAWSEC2:
			return r.awsShield.RetireBridge(ctx, bridgeID)
		case models.ShieldSubstrateAzureVM:
			return r.azureShield.RetireBridge(ctx, bridgeID)
		case models.ShieldSubstrateGCPGCE:
			return r.gcpShield.RetireBridge(ctx, bridgeID)
		case models.ShieldSubstrateLinuxHost:
			return r.linuxShield.RetireBridge(ctx, bridgeID)
		case models.ShieldSubstrateWindowsHost:
			return r.windowsShield.RetireBridge(ctx, bridgeID)
		default:
			return r.k8sShield.RetireBridge(ctx, bridgeID)
		}
	}

	// Restart-resilient fallback: non-K8s drivers no-op safely when bridgeID wasn't armed in memory; delegate K8s last.
	_ = r.awsShield.RetireBridge(ctx, bridgeID)
	_ = r.azureShield.RetireBridge(ctx, bridgeID)
	_ = r.gcpShield.RetireBridge(ctx, bridgeID)
	_ = r.linuxShield.RetireBridge(ctx, bridgeID)
	_ = r.windowsShield.RetireBridge(ctx, bridgeID)
	return r.k8sShield.RetireBridge(ctx, bridgeID)
}
