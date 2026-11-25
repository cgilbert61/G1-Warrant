package shields

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

var reNftIdent = regexp.MustCompile(`[^a-zA-Z0-9_]`)

func nftSafeIdent(raw string, maxLen int) string {
	clean := reNftIdent.ReplaceAllString(strings.TrimSpace(raw), "_")
	clean = strings.Trim(clean, "_")
	if clean == "" {
		clean = "bridge"
	}
	if maxLen > 0 && len(clean) > maxLen {
		clean = clean[:maxLen]
	}
	return clean
}

// ---------------------------------------------------------------------------
// 4. Linux Host Atomic nftables Quarantine Shield (table inet g1_warrant_*)
// ---------------------------------------------------------------------------

type LinuxShieldConfig struct {
	AgentBaseURL string // Optional SSM / AWX / host-agent gateway URL receiving APPLY_NFTABLES_BRIDGE & RETIRE_NFTABLES_BRIDGE
	BearerToken  string
}

type linuxArmedState struct {
	TargetHost string `json:"target_host"`
	TableName  string `json:"table_name"`
	RetireNFT  string `json:"retire_nft"`
}

// LinuxNftablesShieldDriver compiles an isolated atomic `nft -f -` table (`table inet g1_warrant_<id>`)
// so host containment never mutates or flushes existing production iptables/nftables tables, and Stage 04
// retirement executes as a single atomic `nft delete table inet g1_warrant_<id>`.
type LinuxNftablesShieldDriver struct {
	cfg        LinuxShieldConfig
	httpClient *http.Client
	rulepacks  *adapters.RulepackRegistry
	mu         sync.Mutex
	armed      map[string]linuxArmedState
}

func NewLinuxNftablesShieldDriver(cfg LinuxShieldConfig, rt http.RoundTripper, rulepacks *adapters.RulepackRegistry) *LinuxNftablesShieldDriver {
	cli := &http.Client{Timeout: 15 * time.Second}
	if rt != nil {
		cli.Transport = rt
	}
	if rulepacks == nil {
		rulepacks = adapters.NewDefaultRulepackRegistry()
	}
	return &LinuxNftablesShieldDriver{
		cfg:        cfg,
		httpClient: cli,
		rulepacks:  rulepacks,
		armed:      make(map[string]linuxArmedState),
	}
}

func NewLinuxNftablesShieldDriverFromEnv(rt http.RoundTripper, rulepacks *adapters.RulepackRegistry, getenv func(string) string) *LinuxNftablesShieldDriver {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return NewLinuxNftablesShieldDriver(LinuxShieldConfig{
		AgentBaseURL: firstNonEmpty(getenv("WARRANT_LINUX_SHIELD_URL")),
		BearerToken:  firstNonEmpty(getenv("WARRANT_LINUX_SHIELD_TOKEN")),
	}, rt, rulepacks)
}

func (d *LinuxNftablesShieldDriver) EndpointConfigured() bool {
	return strings.TrimSpace(d.cfg.AgentBaseURL) != ""
}

func (d *LinuxNftablesShieldDriver) CompileAndApplyBridge(ctx context.Context, req adapters.BridgeApplyRequest) (*models.ContainmentBridge, error) {
	port := req.AffectedPort
	if port <= 0 || port > 65535 {
		port = 8080
	}
	targetHost := sanitizeID(req.ServiceID, 48)
	if req.AssetIdentity != nil {
		targetHost = sanitizeID(firstNonEmpty(req.AssetIdentity.Hostname, req.AssetIdentity.IPv4, req.AssetIdentity.AssetKey, targetHost), 48)
	}
	tableName := "g1_warrant_" + nftSafeIdent(req.BridgeID, 24)

	matchedRP := d.rulepacks.Lookup(req.CVEID, req.CWEID, req.ExploitVector)
	containmentMode := models.ContainmentModeZeroProseQuarantine
	rulepackID := ""
	inboundGuard := fmt.Sprintf("        # Zero-prose mode: allow established/loopback; hold vulnerable port %d to RFC1918 internal mesh only\n        ip saddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } tcp dport %d drop", port, port)
	if matchedRP != nil {
		containmentMode = models.ContainmentModeSignedRulepackL7
		rulepackID = matchedRP.RulepackID
		inboundGuard = fmt.Sprintf("        # Signed Rulepack (%s): drop untrusted inbound exploit vector (%s) on tcp/%d\n        ip saddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } tcp dport %d drop", sanitizeID(rulepackID, 40), sanitizeID(matchedRP.ExploitVector, 32), port, port)
	}

	nftScript := strings.Join([]string{
		"#!/usr/sbin/nft -f",
		fmt.Sprintf("# G1-Warrant Sub-Second Linux Host Shield (%s | %s | target=%s)", sanitizeID(req.BridgeID, 32), sanitizeID(req.CVEID, 24), targetHost),
		fmt.Sprintf("table inet %s {", tableName),
		"    chain g1_egress_quarantine {",
		"        type filter hook output priority -150; policy accept;",
		"        oifname \"lo\" accept",
		"        ct state established,related accept",
		"        # Block Cloud IMDS / WireServer credential theft (IPv4 + IPv6)",
		"        ip daddr { 169.254.169.254, 169.254.170.2, 168.63.129.16, 100.100.100.200 } drop",
		"        ip6 daddr fd00:ec2::254 drop",
		"        # Permit internal RFC1918 east-west & DNS; sever external C2 / reverse-shell callbacks",
		"        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept",
		"        meta l4proto { tcp, udp } drop",
		"    }",
		"    chain g1_ingress_quarantine {",
		"        type filter hook input priority -150; policy accept;",
		"        iifname \"lo\" accept",
		"        ct state established,related accept",
		inboundGuard,
		"    }",
		"}",
	}, "\n") + "\n"

	retireNFT := fmt.Sprintf("nft delete table inet %s\n", tableName)

	if d.EndpointConfigured() {
		wireBody, _ := json.Marshal(map[string]any{
			"action":      "APPLY_NFTABLES_BRIDGE",
			"bridge_id":   req.BridgeID,
			"service_id":  req.ServiceID,
			"target_host": targetHost,
			"cve_id":      req.CVEID,
			"table_name":  tableName,
			"nft_ruleset": nftScript,
			"retire_cmd":  strings.TrimSpace(retireNFT),
		})
		if err := d.postAgentJSON(ctx, "/v1/shields/nftables/apply", wireBody); err != nil {
			return nil, fmt.Errorf("LINUX_NFTABLES_SHIELD_APPLY_FAILED: %w", err)
		}
	}

	d.mu.Lock()
	d.armed[req.BridgeID] = linuxArmedState{
		TargetHost: targetHost,
		TableName:  tableName,
		RetireNFT:  strings.TrimSpace(retireNFT),
	}
	d.mu.Unlock()

	summaryCanon, _ := crypto.CanonicalizeStruct(map[string]any{
		"substrate":        models.ShieldSubstrateLinuxHost,
		"bridge_id":        req.BridgeID,
		"target_host":      targetHost,
		"nft_table":        tableName,
		"containment_mode": containmentMode,
		"rulepack_id":      rulepackID,
		"metadata_blocked": cloudMetadataIPs,
	})
	status := "ARMED"
	if req.RearmCount > 0 {
		status = "REARMED_DRIFT"
	}
	allowed := req.AllowedEgressServices
	if len(allowed) == 0 {
		allowed = []string{"rfc1918-internal"}
	}
	return &models.ContainmentBridge{
		BridgeID:             req.BridgeID,
		RemediationID:        req.RemediationID,
		ServiceID:            req.ServiceID,
		CVEID:                req.CVEID,
		BridgeType:           models.BridgeTypeLinuxNftables,
		SubstrateFamily:      models.ShieldSubstrateLinuxHost,
		ContainmentMode:      containmentMode,
		RulepackID:           rulepackID,
		MetadataPlaneBlocked: true,
		AllowedEgressPeers:   allowed,
		Status:               status,
		SLABridgeMinutes:     req.SLABridgeMinutes,
		BlockerReasonCode:    req.BlockerReasonCode,
		CiliumManifestYAML:   nftScript,
		K8sNetpolYAML:        retireNFT,
		EnvoyFilterJSON:      string(summaryCanon),
		NativeShieldManifest: nftScript,
		NativeRetireSpec:     retireNFT,
		ArmedAt:              time.Now().UTC(),
		RearmedCount:         req.RearmCount,
	}, nil
}

func (d *LinuxNftablesShieldDriver) RetireBridge(ctx context.Context, bridgeID string) error {
	d.mu.Lock()
	st, ok := d.armed[bridgeID]
	delete(d.armed, bridgeID)
	d.mu.Unlock()
	if !ok || !d.EndpointConfigured() {
		return nil
	}
	wireBody, _ := json.Marshal(map[string]any{
		"action":      "RETIRE_NFTABLES_BRIDGE",
		"bridge_id":   bridgeID,
		"target_host": st.TargetHost,
		"table_name":  st.TableName,
		"retire_cmd":  st.RetireNFT,
	})
	return d.postAgentJSON(ctx, "/v1/shields/nftables/retire", wireBody)
}

func (d *LinuxNftablesShieldDriver) postAgentJSON(ctx context.Context, path string, body []byte) error {
	fullURL := strings.TrimRight(d.cfg.AgentBaseURL, "/") + path
	hReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hReq.Header.Set("Content-Type", "application/json")
	if tok := strings.TrimSpace(d.cfg.BearerToken); tok != "" {
		hReq.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := d.httpClient.Do(hReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// ---------------------------------------------------------------------------
// 5. Windows Host Filtering Platform (WFP) NetFirewallRule Quarantine Shield
// ---------------------------------------------------------------------------

type WindowsShieldConfig struct {
	AgentBaseURL string // Optional WinRM / Intune / host-agent gateway URL receiving APPLY_WFP_BRIDGE & RETIRE_WFP_BRIDGE
	BearerToken  string
}

type windowsArmedState struct {
	TargetHost string `json:"target_host"`
	RuleGroup  string `json:"rule_group"`
	RetirePS1  string `json:"retire_ps1"`
}

// WindowsWFPShieldDriver compiles a deterministic PowerShell NetSecurity rule group
// (`-Group "G1-Warrant-Bridge-<id>"`) blocking cloud IMDS/WireServer credential theft,
// external C2 callbacks, and untrusted inbound exploit traffic, with symmetric 1-line
// removal via `Remove-NetFirewallRule -Group`.
type WindowsWFPShieldDriver struct {
	cfg        WindowsShieldConfig
	httpClient *http.Client
	rulepacks  *adapters.RulepackRegistry
	mu         sync.Mutex
	armed      map[string]windowsArmedState
}

func NewWindowsWFPShieldDriver(cfg WindowsShieldConfig, rt http.RoundTripper, rulepacks *adapters.RulepackRegistry) *WindowsWFPShieldDriver {
	cli := &http.Client{Timeout: 15 * time.Second}
	if rt != nil {
		cli.Transport = rt
	}
	if rulepacks == nil {
		rulepacks = adapters.NewDefaultRulepackRegistry()
	}
	return &WindowsWFPShieldDriver{
		cfg:        cfg,
		httpClient: cli,
		rulepacks:  rulepacks,
		armed:      make(map[string]windowsArmedState),
	}
}

func NewWindowsWFPShieldDriverFromEnv(rt http.RoundTripper, rulepacks *adapters.RulepackRegistry, getenv func(string) string) *WindowsWFPShieldDriver {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return NewWindowsWFPShieldDriver(WindowsShieldConfig{
		AgentBaseURL: firstNonEmpty(getenv("WARRANT_WINDOWS_SHIELD_URL")),
		BearerToken:  firstNonEmpty(getenv("WARRANT_WINDOWS_SHIELD_TOKEN")),
	}, rt, rulepacks)
}

func (d *WindowsWFPShieldDriver) EndpointConfigured() bool {
	return strings.TrimSpace(d.cfg.AgentBaseURL) != ""
}

func (d *WindowsWFPShieldDriver) CompileAndApplyBridge(ctx context.Context, req adapters.BridgeApplyRequest) (*models.ContainmentBridge, error) {
	port := req.AffectedPort
	if port <= 0 || port > 65535 {
		port = 445
	}
	targetHost := sanitizeID(req.ServiceID, 48)
	if req.AssetIdentity != nil {
		targetHost = sanitizeID(firstNonEmpty(req.AssetIdentity.Hostname, req.AssetIdentity.AssetKey, req.AssetIdentity.IPv4, targetHost), 48)
	}
	cleanBridge := sanitizeID(req.BridgeID, 28)
	ruleGroup := "G1-Warrant-Bridge-" + cleanBridge

	matchedRP := d.rulepacks.Lookup(req.CVEID, req.CWEID, req.ExploitVector)
	containmentMode := models.ContainmentModeZeroProseQuarantine
	rulepackID := ""
	if matchedRP != nil {
		containmentMode = models.ContainmentModeSignedRulepackL7
		rulepackID = matchedRP.RulepackID
	}

	psScript := strings.Join([]string{
		"$ErrorActionPreference = 'Stop'",
		fmt.Sprintf("# G1-Warrant Sub-Second Windows WFP NetFirewall Shield (%s | %s | host=%s)", cleanBridge, sanitizeID(req.CVEID, 24), targetHost),
		fmt.Sprintf("Remove-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue", ruleGroup),
		fmt.Sprintf(
			"New-NetFirewallRule -Name 'G1-Block-IMDS-%s' -DisplayName 'G1-Warrant IMDS & WireServer Block (%s)' -Group '%s' -Direction Outbound -Action Block -RemoteAddress @('169.254.169.254','169.254.170.2','168.63.129.16','100.100.100.200','fd00:ec2::254') -Profile Any | Out-Null",
			cleanBridge, sanitizeID(req.CVEID, 24), ruleGroup,
		),
		fmt.Sprintf(
			"New-NetFirewallRule -Name 'G1-Block-PublicC2-%s' -DisplayName 'G1-Warrant Public Egress C2 Clamp (%s)' -Group '%s' -Direction Outbound -Action Block -RemoteAddress Internet -Profile Any | Out-Null",
			cleanBridge, sanitizeID(req.CVEID, 24), ruleGroup,
		),
		fmt.Sprintf(
			"New-NetFirewallRule -Name 'G1-Restrict-Port-%s' -DisplayName 'G1-Warrant Untrusted Inbound Port %d Clamp (%s)' -Group '%s' -Direction Inbound -Action Block -Protocol TCP -LocalPort %d -RemoteAddress Internet -Profile Any | Out-Null",
			cleanBridge, port, sanitizeID(req.CVEID, 24), ruleGroup, port,
		),
	}, "\n") + "\n"

	retirePS1 := fmt.Sprintf("Remove-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue\n", ruleGroup)

	if d.EndpointConfigured() {
		wireBody, _ := json.Marshal(map[string]any{
			"action":      "APPLY_WFP_BRIDGE",
			"bridge_id":   req.BridgeID,
			"service_id":  req.ServiceID,
			"target_host": targetHost,
			"cve_id":      req.CVEID,
			"rule_group":  ruleGroup,
			"ps1_script":  psScript,
			"retire_ps1":  strings.TrimSpace(retirePS1),
		})
		if err := d.postAgentJSON(ctx, "/v1/shields/windows-wfp/apply", wireBody); err != nil {
			return nil, fmt.Errorf("WINDOWS_WFP_SHIELD_APPLY_FAILED: %w", err)
		}
	}

	d.mu.Lock()
	d.armed[req.BridgeID] = windowsArmedState{
		TargetHost: targetHost,
		RuleGroup:  ruleGroup,
		RetirePS1:  strings.TrimSpace(retirePS1),
	}
	d.mu.Unlock()

	summaryCanon, _ := crypto.CanonicalizeStruct(map[string]any{
		"substrate":        models.ShieldSubstrateWindowsHost,
		"bridge_id":        req.BridgeID,
		"target_host":      targetHost,
		"wfp_rule_group":   ruleGroup,
		"containment_mode": containmentMode,
		"rulepack_id":      rulepackID,
		"metadata_blocked": cloudMetadataIPs,
	})
	status := "ARMED"
	if req.RearmCount > 0 {
		status = "REARMED_DRIFT"
	}
	allowed := req.AllowedEgressServices
	if len(allowed) == 0 {
		allowed = []string{"LocalSubnet", "Intranet"}
	}
	return &models.ContainmentBridge{
		BridgeID:             req.BridgeID,
		RemediationID:        req.RemediationID,
		ServiceID:            req.ServiceID,
		CVEID:                req.CVEID,
		BridgeType:           models.BridgeTypeWindowsNetFW,
		SubstrateFamily:      models.ShieldSubstrateWindowsHost,
		ContainmentMode:      containmentMode,
		RulepackID:           rulepackID,
		MetadataPlaneBlocked: true,
		AllowedEgressPeers:   allowed,
		Status:               status,
		SLABridgeMinutes:     req.SLABridgeMinutes,
		BlockerReasonCode:    req.BlockerReasonCode,
		CiliumManifestYAML:   psScript,
		K8sNetpolYAML:        retirePS1,
		EnvoyFilterJSON:      string(summaryCanon),
		NativeShieldManifest: psScript,
		NativeRetireSpec:     retirePS1,
		ArmedAt:              time.Now().UTC(),
		RearmedCount:         req.RearmCount,
	}, nil
}

func (d *WindowsWFPShieldDriver) RetireBridge(ctx context.Context, bridgeID string) error {
	d.mu.Lock()
	st, ok := d.armed[bridgeID]
	delete(d.armed, bridgeID)
	d.mu.Unlock()
	if !ok || !d.EndpointConfigured() {
		return nil
	}
	wireBody, _ := json.Marshal(map[string]any{
		"action":      "RETIRE_WFP_BRIDGE",
		"bridge_id":   bridgeID,
		"target_host": st.TargetHost,
		"rule_group":  st.RuleGroup,
		"retire_ps1":  st.RetirePS1,
	})
	return d.postAgentJSON(ctx, "/v1/shields/windows-wfp/retire", wireBody)
}

func (d *WindowsWFPShieldDriver) postAgentJSON(ctx context.Context, path string, body []byte) error {
	fullURL := strings.TrimRight(d.cfg.AgentBaseURL, "/") + path
	hReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hReq.Header.Set("Content-Type", "application/json")
	if tok := strings.TrimSpace(d.cfg.BearerToken); tok != "" {
		hReq.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := d.httpClient.Do(hReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
