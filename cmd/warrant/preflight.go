package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/netguard"
	"github.com/cgilbert61/G1-Warrant/pkg/warrantsdk"
)

type preflightCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func handlePreflightCommand(ctx context.Context, cli *warrantsdk.Client, args []string, jsonOutput bool) {
	fs := flag.NewFlagSet("preflight", flag.ExitOnError)
	anchorURL := fs.String("anchor-url", strings.TrimSpace(os.Getenv("WARRANT_EXTERNAL_ANCHOR_URL")), "External transparency anchor URL")
	anchorPath := fs.String("anchor-path", strings.TrimSpace(os.Getenv("WARRANT_EXTERNAL_ANCHOR_PATH")), "Local WORM anchor receipt path")
	kmsURL := fs.String("kms-url", strings.TrimSpace(os.Getenv("WARRANT_KMS_SIGN_URL")), "Remote KMS signing URL")
	kmsPubB64 := fs.String("kms-pubkey-b64", strings.TrimSpace(os.Getenv("WARRANT_KMS_PUBLIC_KEY_B64")), "Expected KMS Ed25519 public key (base64)")
	skipAPI := fs.Bool("skip-api", false, "Skip live warrantd API health check")
	_ = fs.Parse(args)

	checks := make([]preflightCheck, 0, 4)
	allOK := true
	httpClient := netguard.NewSafeHTTPClient(5*time.Second, nil)

	if !*skipAPI && cli != nil {
		if _, err := cli.Health(ctx); err != nil {
			allOK = false
			checks = append(checks, preflightCheck{Name: "warrantd_api", Status: "FAIL", Detail: err.Error()})
		} else {
			checks = append(checks, preflightCheck{Name: "warrantd_api", Status: "PASS", Detail: "warrantd reachable"})
		}
	}

	if u := strings.TrimSpace(*anchorURL); u != "" {
		req, _ := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
		resp, err := httpClient.Do(req)
		if err != nil {
			allOK = false
			checks = append(checks, preflightCheck{Name: "external_anchor_url", Status: "FAIL", Detail: err.Error()})
		} else {
			_ = resp.Body.Close()
			checks = append(checks, preflightCheck{Name: "external_anchor_url", Status: "PASS", Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)})
		}
	}

	if p := strings.TrimSpace(*anchorPath); p != "" {
		if info, err := os.Stat(p); err != nil {
			allOK = false
			checks = append(checks, preflightCheck{Name: "anchor_path", Status: "FAIL", Detail: err.Error()})
		} else {
			checks = append(checks, preflightCheck{Name: "anchor_path", Status: "PASS", Detail: fmt.Sprintf("exists (mode=%s)", info.Mode())})
		}
	}

	if u := strings.TrimSpace(*kmsURL); u != "" {
		pub := strings.TrimSpace(*kmsPubB64)
		if pub == "" {
			allOK = false
			checks = append(checks, preflightCheck{Name: "kms_config", Status: "FAIL", Detail: "kms-url set without kms-pubkey-b64"})
		} else if raw, err := base64.StdEncoding.DecodeString(pub); err != nil || len(raw) != 32 {
			allOK = false
			checks = append(checks, preflightCheck{Name: "kms_config", Status: "FAIL", Detail: "kms-pubkey-b64 must decode to 32-byte Ed25519 public key"})
		} else {
			checks = append(checks, preflightCheck{Name: "kms_config", Status: "PASS", Detail: "KMS URL and 32-byte Ed25519 public key validated"})
		}
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"passed": allOK, "checks": checks})
	} else {
		for _, c := range checks {
			fmt.Printf("[%s] %s: %s\n", c.Status, c.Name, c.Detail)
		}
	}
	if !allOK {
		os.Exit(1)
	}
}
