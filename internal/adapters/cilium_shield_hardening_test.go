package adapters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCiliumShieldBlocksExpandedCloudMetadataCIDRs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	reg := NewDefaultRulepackRegistry()
	shield := NewCiliumShieldAdapter(srv.URL, reg)

	bridge, err := shield.CompileAndApplyBridge(context.Background(), BridgeApplyRequest{
		BridgeID:      "brg-meta-1",
		RemediationID: "rem-meta-1",
		ServiceID:     "payments-api",
		Namespace:     "prod",
		CVEID:         "CVE-2026-99999",
		CWEID:         "CWE-918",
		AffectedPort:  8080,
	})
	if err != nil {
		t.Fatalf("CompileAndApplyBridge: %v", err)
	}

	for _, cidr := range []string{
		"169.254.169.254/32",
		"169.254.170.2/32",
		"168.63.129.16/32",
		"100.100.100.200/32",
		"fd00:ec2::254/128",
	} {
		if !strings.Contains(bridge.CiliumManifestYAML, cidr) {
			t.Errorf("expected Cilium manifest to block cloud metadata CIDR %s", cidr)
		}
	}
}
