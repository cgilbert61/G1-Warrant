package vmtwins

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	g1crypto "github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// GCPComputeConfig configures the real Google Cloud Compute Engine v1 VM_TWIN driver.
type GCPComputeConfig struct {
	ComputeEndpoint    string // Defaults to https://compute.googleapis.com
	TokenURL           string // Defaults to https://oauth2.googleapis.com/token
	ServiceAccountJSON string // Inline JSON or file path to GCP Service Account key
	StaticBearerToken  string // Optional pre-minted OAuth2 access token (or GCE metadata server fallback)
	ProjectID          string
	Zone               string // e.g. "us-east4-a"
	QAMachineImage     string // e.g. "projects/my-proj/global/machineImages/qa-rhel9" or sourceDiskImage
	Subnet             string // e.g. "regions/us-east4/subnetworks/isolated-twin"
	MachineType        string // e.g. "e2-standard-2"
	IsolatedTag        string // VPC firewall tag blocking 0.0.0.0/0 egress
	GuestOSFamily      string // "LINUX" (default) | "WINDOWS"
	SmokeCommand       string
	AcceptanceCommand  string
	PollInterval       time.Duration
}

type GCPComputeVMTwinProvider struct {
	cfg        GCPComputeConfig
	httpClient *http.Client

	mu          sync.Mutex
	cachedToken string
	tokenExp    time.Time
}

func NewGCPComputeVMTwinProvider(cfg GCPComputeConfig, rt http.RoundTripper) (*GCPComputeVMTwinProvider, error) {
	if strings.TrimSpace(cfg.ComputeEndpoint) == "" {
		cfg.ComputeEndpoint = "https://compute.googleapis.com"
	}
	if strings.TrimSpace(cfg.TokenURL) == "" {
		cfg.TokenURL = "https://oauth2.googleapis.com/token"
	}
	if strings.TrimSpace(cfg.ProjectID) == "" || strings.TrimSpace(cfg.Zone) == "" ||
		strings.TrimSpace(cfg.QAMachineImage) == "" || strings.TrimSpace(cfg.Subnet) == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (gcp-gce): PROJECT, ZONE, MACHINE_IMAGE, and SUBNET are required")
	}
	if strings.TrimSpace(cfg.MachineType) == "" {
		cfg.MachineType = "e2-standard-2"
	}
	if strings.TrimSpace(cfg.IsolatedTag) == "" {
		cfg.IsolatedTag = "g1-twin-proving-zero-egress"
	}
	if strings.TrimSpace(cfg.GuestOSFamily) == "" {
		cfg.GuestOSFamily = "LINUX"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 3 * time.Second
	}
	cfg.ComputeEndpoint = strings.TrimRight(strings.TrimSpace(cfg.ComputeEndpoint), "/")

	cli := &http.Client{Timeout: 90 * time.Second}
	if rt != nil {
		cli.Transport = rt
	}
	return &GCPComputeVMTwinProvider{cfg: cfg, httpClient: cli}, nil
}

func NewGCPComputeVMTwinProviderFromEnv(rt http.RoundTripper, getenv func(string) string) (*GCPComputeVMTwinProvider, error) {
	poll := 3 * time.Second
	if rawMs := strings.TrimSpace(getenv("WARRANT_VM_TWIN_POLL_MS")); rawMs != "" {
		if ms, err := strconv.Atoi(rawMs); err == nil && ms > 0 {
			poll = time.Duration(ms) * time.Millisecond
		}
	}
	saRaw := strings.TrimSpace(getenv("WARRANT_GCP_SERVICE_ACCOUNT_JSON"))
	if saRaw == "" {
		if credPath := strings.TrimSpace(getenv("GOOGLE_APPLICATION_CREDENTIALS")); credPath != "" {
			if b, err := os.ReadFile(credPath); err == nil {
				saRaw = string(b)
			}
		}
	} else if !strings.HasPrefix(saRaw, "{") {
		if b, err := os.ReadFile(saRaw); err == nil {
			saRaw = string(b)
		}
	}
	return NewGCPComputeVMTwinProvider(GCPComputeConfig{
		ComputeEndpoint:    firstNonEmptyStr(getenv("WARRANT_GCP_COMPUTE_ENDPOINT"), getenv("WARRANT_GCP_TWIN_URL")),
		TokenURL:           getenv("WARRANT_GCP_TOKEN_URL"),
		ServiceAccountJSON: saRaw,
		StaticBearerToken:  getenv("WARRANT_GCP_TWIN_TOKEN"),
		ProjectID:          getenv("WARRANT_GCP_TWIN_PROJECT"),
		Zone:               getenv("WARRANT_GCP_TWIN_ZONE"),
		QAMachineImage:     getenv("WARRANT_GCP_TWIN_MACHINE_IMAGE"),
		Subnet:             getenv("WARRANT_GCP_TWIN_SUBNET"),
		MachineType:        getenv("WARRANT_GCP_TWIN_MACHINE_TYPE"),
		IsolatedTag:        getenv("WARRANT_GCP_TWIN_ISOLATED_TAG"),
		GuestOSFamily:      getenv("WARRANT_GCP_TWIN_OS_FAMILY"),
		SmokeCommand:       getenv("WARRANT_VM_TWIN_SMOKE_CMD"),
		AcceptanceCommand:  getenv("WARRANT_VM_TWIN_ACCEPTANCE_CMD"),
		PollInterval:       poll,
	}, rt)
}

func (g *GCPComputeVMTwinProvider) resolveAccessToken(ctx context.Context) (string, error) {
	if strings.TrimSpace(g.cfg.StaticBearerToken) != "" {
		return strings.TrimSpace(g.cfg.StaticBearerToken), nil
	}
	g.mu.Lock()
	if g.cachedToken != "" && time.Now().Add(60*time.Second).Before(g.tokenExp) {
		tok := g.cachedToken
		g.mu.Unlock()
		return tok, nil
	}
	g.mu.Unlock()

	if strings.TrimSpace(g.cfg.ServiceAccountJSON) != "" {
		var sa struct {
			ClientEmail string `json:"client_email"`
			PrivateKey  string `json:"private_key"`
			TokenURI    string `json:"token_uri"`
		}
		if err := json.Unmarshal([]byte(g.cfg.ServiceAccountJSON), &sa); err != nil {
			return "", fmt.Errorf("GCP_SA_JSON_INVALID: %w", err)
		}
		block, _ := pem.Decode([]byte(sa.PrivateKey))
		if block == nil {
			return "", fmt.Errorf("GCP_SA_PRIVATE_KEY_PEM_INVALID")
		}
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return "", fmt.Errorf("GCP_SA_PRIVATE_KEY_PARSE_FAILED: %w", err)
			}
		}
		rsaKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("GCP_SA_PRIVATE_KEY_NOT_RSA")
		}
		tokURI := firstNonEmptyStr(sa.TokenURI, g.cfg.TokenURL)
		now := time.Now().UTC()
		hdrB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
		claimsJSON, _ := json.Marshal(map[string]any{
			"iss":   sa.ClientEmail,
			"scope": "https://www.googleapis.com/auth/compute",
			"aud":   tokURI,
			"iat":   now.Unix(),
			"exp":   now.Add(55 * time.Minute).Unix(),
		})
		claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
		signingInput := hdrB64 + "." + claimsB64
		digest := sha256.Sum256([]byte(signingInput))
		sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			return "", err
		}
		jwtAssertion := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		form.Set("assertion", jwtAssertion)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokURI, strings.NewReader(form.Encode()))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := g.httpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode >= 300 {
			return "", fmt.Errorf("GCP_OAUTH_TOKEN_ERROR (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		var tokResp struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.Unmarshal(raw, &tokResp); err != nil || tokResp.AccessToken == "" {
			return "", fmt.Errorf("GCP_OAUTH_EMPTY_TOKEN")
		}
		if tokResp.ExpiresIn <= 0 {
			tokResp.ExpiresIn = 3300
		}
		g.mu.Lock()
		g.cachedToken = tokResp.AccessToken
		g.tokenExp = time.Now().Add(time.Duration(tokResp.ExpiresIn) * time.Second)
		g.mu.Unlock()
		return tokResp.AccessToken, nil
	}

	// Fallback: GCE / GKE Workload Identity Metadata Server
	metaReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	metaReq.Header.Set("Metadata-Flavor", "Google")
	resp, err := g.httpClient.Do(metaReq)
	if err != nil {
		return "", fmt.Errorf("GCP_AUTH_UNCONFIGURED: set WARRANT_GCP_SERVICE_ACCOUNT_JSON or WARRANT_GCP_TWIN_TOKEN (%w)", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tokResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if resp.StatusCode >= 300 || json.Unmarshal(raw, &tokResp) != nil || tokResp.AccessToken == "" {
		return "", fmt.Errorf("GCP_METADATA_TOKEN_FAILED (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return tokResp.AccessToken, nil
}

func (g *GCPComputeVMTwinProvider) doComputeJSON(ctx context.Context, method, path string, payload any) ([]byte, error) {
	tok, err := g.resolveAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	fullURL := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		fullURL = g.cfg.ComputeEndpoint + path
	}
	var body io.Reader
	if payload != nil {
		b, mErr := json.Marshal(payload)
		if mErr != nil {
			return nil, mErr
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VM_TWIN_TRANSPORT_ERROR (gcp-gce %s %s): %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("VM_TWIN_REMOTE_ERROR (gcp-gce %s %s -> HTTP %d): %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func (g *GCPComputeVMTwinProvider) waitZoneOperation(ctx context.Context, opNameOrLink string) error {
	if strings.TrimSpace(opNameOrLink) == "" {
		return nil
	}
	opPath := opNameOrLink
	if !strings.HasPrefix(opPath, "http://") && !strings.HasPrefix(opPath, "https://") && !strings.HasPrefix(opPath, "/compute/") {
		opPath = fmt.Sprintf("/compute/v1/projects/%s/zones/%s/operations/%s",
			url.PathEscape(g.cfg.ProjectID), url.PathEscape(g.cfg.Zone), url.PathEscape(opNameOrLink))
	}
	for i := 0; i < 120; i++ {
		raw, err := g.doComputeJSON(ctx, http.MethodGet, opPath, nil)
		if err != nil {
			return err
		}
		var op struct {
			Status string `json:"status"`
			Error  *struct {
				Errors []struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"errors"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &op) == nil {
			if strings.EqualFold(op.Status, "DONE") {
				if op.Error != nil && len(op.Error.Errors) > 0 {
					return fmt.Errorf("GCP_ZONE_OP_FAILED (%s): %s - %s", opNameOrLink, op.Error.Errors[0].Code, op.Error.Errors[0].Message)
				}
				return nil
			}
		}
		if err := sleepWithContext(ctx, g.cfg.PollInterval); err != nil {
			return err
		}
	}
	return fmt.Errorf("GCP_ZONE_OP_TIMEOUT: %s", opNameOrLink)
}

func buildGCPStartupProvingScript(req adapters.CloneTwinProvingRequest, smokeCmd, acceptCmd string, isWin bool) (string, string) {
	if isWin {
		ps := fmt.Sprintf(`$Stage = 'C:\ProgramData\g1-gce-rebooted.flag'
if (-not (Test-Path $Stage)) {
  $kb = '%s'
  if ($kb -ne '') {
    $m = Get-ChildItem -Path 'C:\Stage','C:\Windows\Temp' -Filter "*$kb*.msu" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($m) { Start-Process wusa.exe -ArgumentList "`+"`\"$($m.FullName)`\" /quiet /norestart"+`" -Wait }
  }
  New-Item -ItemType File -Force -Path $Stage | Out-Null
  Restart-Computer -Force
  exit 0
}
`+buildWindowsGuestProvingPowerShell(req, smokeCmd, acceptCmd, false), strings.ReplaceAll(req.KBArticleID, "'", ""))
		return "windows-startup-script-ps1", ps
	}

	sh := fmt.Sprintf(`#!/usr/bin/env bash
STAGE_FILE="/var/lib/g1-gce-proving-rebooted"
if [ ! -f "$STAGE_FILE" ]; then
  PKG=%q
  if [ -n "$PKG" ]; then
    if command -v dnf >/dev/null 2>&1; then dnf install -y "$PKG" || dnf upgrade -y "$PKG";
    elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y "$PKG"; fi
  fi
  mkdir -p /var/lib
  date -u +%%s > "$STAGE_FILE"
  sync
  systemctl reboot || reboot
  exit 0
fi
{
%s
} | tee /dev/ttyS0
`, req.PackageNEVRA, buildLinuxGuestProvingScript(req, smokeCmd, acceptCmd, false))
	return "startup-script", sh
}

func (g *GCPComputeVMTwinProvider) RunVMTwinProving(ctx context.Context, req adapters.CloneTwinProvingRequest) (*models.CloneTwinProvingManifest, error) {
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	runSlug := g1crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%d", req.ServiceID, req.CVEID, time.Now().UnixNano())))[:8]
	instBase := fmt.Sprintf("/compute/v1/projects/%s/zones/%s/instances",
		url.PathEscape(g.cfg.ProjectID), url.PathEscape(g.cfg.Zone))

	isWin := strings.EqualFold(g.cfg.GuestOSFamily, "WINDOWS") || strings.TrimSpace(req.KBArticleID) != ""
	metaKey, metaScript := buildGCPStartupProvingScript(req, g.cfg.SmokeCommand, g.cfg.AcceptanceCommand, isWin)

	vmNames := make([]string, 0, cloneCount)
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		for _, vm := range vmNames {
			_, _ = g.doComputeJSON(cleanCtx, http.MethodDelete, instBase+"/"+url.PathEscape(vm), nil)
		}
	}()

	// 1. Insert 3 isolated GCE QA Machine Image clones (zero accessConfigs -> no external IP, isolated firewall tag, two-phase reboot startup script)
	for i := 0; i < cloneCount; i++ {
		vmName := fmt.Sprintf("g1-gcp-%s-%d", runSlug, i)
		instBody := map[string]any{
			"name":        vmName,
			"machineType": fmt.Sprintf("zones/%s/machineTypes/%s", g.cfg.Zone, g.cfg.MachineType),
			"tags":        map[string]any{"items": []string{g.cfg.IsolatedTag}},
			"labels": map[string]string{
				"g1-warrant-proving": "true",
				"g1-zero-egress":     "true",
			},
			"networkInterfaces": []map[string]any{{
				"subnetwork":    g.cfg.Subnet,
				"accessConfigs": []any{}, // Strictly zero public IP
			}},
			"metadata": map[string]any{
				"items": []map[string]string{
					{"key": "serial-port-enable", "value": "TRUE"},
					{"key": metaKey, "value": metaScript},
				},
			},
		}
		gcpImg := firstNonEmptyStr(req.BaseCloneImageIdentity, g.cfg.QAMachineImage)
		if strings.Contains(gcpImg, "/machineImages/") {
			instBody["sourceMachineImage"] = gcpImg
		} else {
			instBody["disks"] = []map[string]any{{
				"boot":       true,
				"autoDelete": true,
				"initializeParams": map[string]any{
					"sourceImage": gcpImg,
				},
			}}
		}

		rawOp, err := g.doComputeJSON(ctx, http.MethodPost, instBase, instBody)
		if err != nil {
			return nil, err
		}
		vmNames = append(vmNames, vmName)

		var opDoc struct {
			Name     string `json:"name"`
			SelfLink string `json:"selfLink"`
		}
		_ = json.Unmarshal(rawOp, &opDoc)
		if err := g.waitZoneOperation(ctx, firstNonEmptyStr(opDoc.SelfLink, opDoc.Name)); err != nil {
			return nil, err
		}
	}

	// 2. Poll GCE Serial Port 1 output (zero inbound firewall ports required) across VM reboot until G1_CLONE_RESULT={...} appears
	outcomes := make([]vmCloneRawOutcome, cloneCount)
	doneSet := make([]bool, cloneCount)
	for attempt := 0; attempt < 120; attempt++ {
		allDone := true
		for i, vmName := range vmNames {
			if doneSet[i] {
				continue
			}
			allDone = false
			spRaw, sErr := g.doComputeJSON(ctx, http.MethodGet, fmt.Sprintf("%s/%s/serialPort?port=1", instBase, url.PathEscape(vmName)), nil)
			if sErr != nil {
				continue
			}
			var spDoc struct {
				Contents string `json:"contents"`
			}
			if json.Unmarshal(spRaw, &spDoc) != nil || spDoc.Contents == "" {
				continue
			}
			if parsed, ok := parseCloneResultMarker(spDoc.Contents); ok {
				parsed.CloneIndex = i
				parsed.CloneName = vmName
				parsed.HostOrZone = g.cfg.Zone
				parsed.PrivateIP = "gce-serial://ttyS0"
				outcomes[i] = *parsed
				doneSet[i] = true
			}
		}
		if allDone {
			break
		}
		if err := sleepWithContext(ctx, g.cfg.PollInterval); err != nil {
			return nil, err
		}
	}
	for i, d := range doneSet {
		if !d {
			return nil, fmt.Errorf("VM_TWIN_GCE_SERIAL_TIMEOUT: instance %s did not emit post-reboot G1_CLONE_RESULT marker", vmNames[i])
		}
	}

	return assembleVMProvingManifest(DriverGCPGCE, fmt.Sprintf("gcp-vpc://%s/%s", g.cfg.ProjectID, g.cfg.IsolatedTag), req, outcomes)
}
