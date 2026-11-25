package shields

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

type stubK8sShield struct {
	mu      sync.Mutex
	applied []string
	retired []string
}

func (s *stubK8sShield) CompileAndApplyBridge(_ context.Context, req adapters.BridgeApplyRequest) (*models.ContainmentBridge, error) {
	s.mu.Lock()
	s.applied = append(s.applied, req.BridgeID)
	s.mu.Unlock()
	return &models.ContainmentBridge{
		BridgeID:        req.BridgeID,
		RemediationID:   req.RemediationID,
		ServiceID:       req.ServiceID,
		CVEID:           req.CVEID,
		BridgeType:      models.BridgeTypeK8sNetpol,
		SubstrateFamily: models.ShieldSubstrateKubernetes,
		Status:          "ARMED",
	}, nil
}

func (s *stubK8sShield) RetireBridge(_ context.Context, bridgeID string) error {
	s.mu.Lock()
	s.retired = append(s.retired, bridgeID)
	s.mu.Unlock()
	return nil
}

func TestMultiSubstrateShieldRouter_AllSixSubstratesWireAndRetire(t *testing.T) {
	ctx := context.Background()

	var (
		mu             sync.Mutex
		ec2Actions     []url.Values
		azureCalls     []string
		gcpCalls       []string
		linuxActions   []string
		windowsActions []string
	)

	wireSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		path := r.URL.Path

		mu.Lock()
		defer mu.Unlock()

		switch {
		case strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256"):
			vals, _ := url.ParseQuery(string(bodyBytes))
			ec2Actions = append(ec2Actions, vals)
			if vals.Get("Action") == "DescribeInstances" {
				w.Header().Set("Content-Type", "text/xml")
				_, _ = w.Write([]byte(`<DescribeInstancesResponse><reservationSet><item><instancesSet><item><groupSet><item><groupId>sg-prod-orig-01</groupId></item><item><groupId>sg-prod-orig-02</groupId></item></groupSet></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`))
				return
			}
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(`<ModifyResponse><return>true</return></ModifyResponse>`))

		case strings.HasPrefix(path, "/subscriptions/"):
			azureCalls = append(azureCalls, r.Method+" "+path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"Succeeded"}`))

		case strings.HasPrefix(path, "/projects/"):
			gcpCalls = append(gcpCalls, r.Method+" "+path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"kind":"compute#operation","status":"DONE"}`))

		case strings.HasPrefix(path, "/v1/shields/nftables/"):
			var p map[string]any
			_ = json.Unmarshal(bodyBytes, &p)
			linuxActions = append(linuxActions, p["action"].(string))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))

		case strings.HasPrefix(path, "/v1/shields/windows-wfp/"):
			var p map[string]any
			_ = json.Unmarshal(bodyBytes, &p)
			windowsActions = append(windowsActions, p["action"].(string))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))

		default:
			t.Errorf("unexpected wire request: %s %s", r.Method, path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer wireSrv.Close()

	env := map[string]string{
		"WARRANT_AWS_REGION":            "us-east-1",
		"WARRANT_AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"WARRANT_AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"WARRANT_AWS_SHIELD_ENDPOINT":   wireSrv.URL,
		"WARRANT_AWS_QUARANTINE_SG_ID":  "sg-quarantine-zero",
		"WARRANT_AZURE_SHIELD_URL":      wireSrv.URL,
		"WARRANT_AZURE_SHIELD_TOKEN":    "az-shield-tok",
		"WARRANT_AZURE_SUBSCRIPTION_ID": "sub-123",
		"WARRANT_GCP_SHIELD_URL":        wireSrv.URL,
		"WARRANT_GCP_SHIELD_TOKEN":      "gcp-shield-tok",
		"WARRANT_GCP_PROJECT_ID":        "proj-g1",
		"WARRANT_LINUX_SHIELD_URL":      wireSrv.URL,
		"WARRANT_LINUX_SHIELD_TOKEN":    "lnx-tok",
		"WARRANT_WINDOWS_SHIELD_URL":    wireSrv.URL,
		"WARRANT_WINDOWS_SHIELD_TOKEN":  "win-tok",
	}
	k8sStub := &stubK8sShield{}
	router := NewMultiSubstrateShieldRouter(k8sStub, nil, adapters.NewDefaultRulepackRegistry(), func(k string) string {
		return env[k]
	})

	// 1. AWS EC2 (inferred from aws-ssm + CloudInstanceID)
	awsBrg, err := router.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
		BridgeID:      "brg-aws-01",
		RemediationID: "rem-aws-01",
		ServiceID:     "payments-ledger-api",
		CVEID:         "CVE-2026-81001",
		AffectedPort:  8443,
		DistributorID: "aws-ssm",
		AssetIdentity: &models.AssetIdentity{AssetKey: "ec2-pay-01", CloudInstanceID: "i-0123456789abcdef0"},
	})
	if err != nil {
		t.Fatalf("AWS shield apply failed: %v", err)
	}
	if awsBrg.BridgeType != models.BridgeTypeAWSEC2SGIMDS || awsBrg.SubstrateFamily != models.ShieldSubstrateAWSEC2 {
		t.Fatalf("unexpected AWS bridge metadata: %+v", awsBrg)
	}
	if err := router.RetireBridge(ctx, "brg-aws-01"); err != nil {
		t.Fatalf("AWS shield retire failed: %v", err)
	}

	// Verify 4 SigV4 EC2 calls: DescribeInstances -> ModifyInstanceAttribute (quarantine) -> ModifyInstanceMetadataOptions (HttpTokens=required) -> ModifyInstanceAttribute (restore original 2 SGs)
	mu.Lock()
	if len(ec2Actions) != 4 {
		t.Fatalf("expected 4 SigV4 EC2 calls, got %d: %+v", len(ec2Actions), ec2Actions)
	}
	if ec2Actions[1].Get("GroupId.1") != "sg-quarantine-zero" {
		t.Fatalf("expected quarantine SG on apply, got %v", ec2Actions[1])
	}
	if ec2Actions[2].Get("HttpTokens") != "required" || ec2Actions[2].Get("HttpPutResponseHopLimit") != "1" {
		t.Fatalf("expected IMDSv2 clamp, got %v", ec2Actions[2])
	}
	if ec2Actions[3].Get("GroupId.1") != "sg-prod-orig-01" || ec2Actions[3].Get("GroupId.2") != "sg-prod-orig-02" {
		t.Fatalf("expected symmetric restore of original SGs on retire, got %v", ec2Actions[3])
	}
	mu.Unlock()

	// 2. Azure VM NSG
	azBrg, err := router.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
		BridgeID:      "brg-az-01",
		RemediationID: "rem-az-01",
		ServiceID:     "identity-sso-gateway",
		CVEID:         "CVE-2026-81002",
		DistributorID: "azure-update-manager",
	})
	if err != nil || azBrg.BridgeType != models.BridgeTypeAzureNSG {
		t.Fatalf("Azure shield apply failed: brg=%+v err=%v", azBrg, err)
	}
	if err := router.RetireBridge(ctx, "brg-az-01"); err != nil {
		t.Fatalf("Azure shield retire failed: %v", err)
	}

	// 3. GCP VPC Firewall
	gcpBrg, err := router.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
		BridgeID:      "brg-gcp-01",
		RemediationID: "rem-gcp-01",
		ServiceID:     "checkout-cart-svc",
		CVEID:         "CVE-2026-81003",
		DistributorID: "gcp-os-config",
	})
	if err != nil || gcpBrg.BridgeType != models.BridgeTypeGCPVPCFirewall {
		t.Fatalf("GCP shield apply failed: brg=%+v err=%v", gcpBrg, err)
	}
	if err := router.RetireBridge(ctx, "brg-gcp-01"); err != nil {
		t.Fatalf("GCP shield retire failed: %v", err)
	}

	// 4. Linux Host atomic nftables (inferred from PlatformFamily=LINUX)
	lnxBrg, err := router.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
		BridgeID:      "brg-lnx-01",
		RemediationID: "rem-lnx-01",
		ServiceID:     "identity-sso-gateway",
		CVEID:         "CVE-2026-81004",
		AffectedPort:  8080,
		AssetIdentity: &models.AssetIdentity{AssetKey: "rhel-01", Hostname: "rhel-sso-01", PlatformFamily: "LINUX"},
	})
	if err != nil || lnxBrg.BridgeType != models.BridgeTypeLinuxNftables || !strings.Contains(lnxBrg.NativeShieldManifest, "table inet g1_warrant_") {
		t.Fatalf("Linux nftables shield failed: brg=%+v err=%v", lnxBrg, err)
	}
	if err := router.RetireBridge(ctx, "brg-lnx-01"); err != nil {
		t.Fatalf("Linux nftables retire failed: %v", err)
	}

	// 5. Windows Host WFP NetFirewallRule (inferred from ms-intune / PlatformFamily=WINDOWS)
	winBrg, err := router.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
		BridgeID:      "brg-win-01",
		RemediationID: "rem-win-01",
		ServiceID:     "payments-ledger-api",
		CVEID:         "CVE-2026-81005",
		AffectedPort:  445,
		DistributorID: "ms-intune",
		AssetIdentity: &models.AssetIdentity{AssetKey: "win-pay-01", PlatformFamily: "WINDOWS"},
	})
	if err != nil || winBrg.BridgeType != models.BridgeTypeWindowsNetFW || !strings.Contains(winBrg.NativeShieldManifest, "New-NetFirewallRule") {
		t.Fatalf("Windows WFP shield failed: brg=%+v err=%v", winBrg, err)
	}
	if err := router.RetireBridge(ctx, "brg-win-01"); err != nil {
		t.Fatalf("Windows WFP retire failed: %v", err)
	}

	// 6. Default Container / Kubernetes fallback
	k8sBrg, err := router.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
		BridgeID:      "brg-k8s-01",
		RemediationID: "rem-k8s-01",
		ServiceID:     "payments-ledger-api",
		CVEID:         "CVE-2026-81006",
	})
	if err != nil || k8sBrg.BridgeType != models.BridgeTypeK8sNetpol {
		t.Fatalf("K8s fallback shield failed: brg=%+v err=%v", k8sBrg, err)
	}
	if err := router.RetireBridge(ctx, "brg-k8s-01"); err != nil {
		t.Fatalf("K8s fallback retire failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(azureCalls) != 2 || !strings.HasPrefix(azureCalls[0], "PUT ") || !strings.HasPrefix(azureCalls[1], "DELETE ") {
		t.Fatalf("expected PUT + DELETE on Azure NSG, got %+v", azureCalls)
	}
	if len(gcpCalls) != 2 || !strings.HasPrefix(gcpCalls[0], "POST ") || !strings.HasPrefix(gcpCalls[1], "DELETE ") {
		t.Fatalf("expected POST + DELETE on GCP Firewall, got %+v", gcpCalls)
	}
	if len(linuxActions) != 2 || linuxActions[0] != "APPLY_NFTABLES_BRIDGE" || linuxActions[1] != "RETIRE_NFTABLES_BRIDGE" {
		t.Fatalf("expected APPLY + RETIRE on Linux nftables, got %+v", linuxActions)
	}
	if len(windowsActions) != 2 || windowsActions[0] != "APPLY_WFP_BRIDGE" || windowsActions[1] != "RETIRE_WFP_BRIDGE" {
		t.Fatalf("expected APPLY + RETIRE on Windows WFP, got %+v", windowsActions)
	}
	if len(k8sStub.applied) != 1 || len(k8sStub.retired) != 1 {
		t.Fatalf("expected 1 apply + 1 retire on K8s stub, got applied=%v retired=%v", k8sStub.applied, k8sStub.retired)
	}
}
