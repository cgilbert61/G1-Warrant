package vmtwins

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// AzureComputeConfig configures the real Azure Resource Manager (ARM) Compute + Network VM_TWIN driver.
type AzureComputeConfig struct {
	ARMEndpoint       string // Defaults to https://management.azure.com (or https://management.usgovcloudapi.net)
	AuthEndpoint      string // Defaults to https://login.microsoftonline.com (or https://login.microsoftonline.us)
	TenantID          string
	ClientID          string
	ClientSecret      string
	StaticBearerToken string // Optional pre-minted Managed Identity / bearer token
	SubscriptionID    string
	ResourceGroup     string
	Location          string // e.g. "eastus" or "usgovvirginia"
	QAImageID         string // Shared Image Gallery / Managed Image / Snapshot resource ID
	SubnetID          string // Full ARM Subnet ID
	DenyEgressNSGID   string // Full ARM NSG ID blocking 0.0.0.0/0 outbound
	VMSize            string // e.g. "Standard_D2s_v5"
	GuestOSFamily     string // "LINUX" (default) | "WINDOWS"
	AdminUsername     string
	SmokeCommand      string
	AcceptanceCommand string
	PollInterval      time.Duration
}

type AzureComputeVMTwinProvider struct {
	cfg        AzureComputeConfig
	httpClient *http.Client

	mu          sync.Mutex
	cachedToken string
	tokenExp    time.Time
}

func NewAzureComputeVMTwinProvider(cfg AzureComputeConfig, rt http.RoundTripper) (*AzureComputeVMTwinProvider, error) {
	if strings.TrimSpace(cfg.ARMEndpoint) == "" {
		cfg.ARMEndpoint = "https://management.azure.com"
	}
	if strings.TrimSpace(cfg.AuthEndpoint) == "" {
		cfg.AuthEndpoint = "https://login.microsoftonline.com"
	}
	if strings.TrimSpace(cfg.StaticBearerToken) == "" &&
		(strings.TrimSpace(cfg.TenantID) == "" || strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ClientSecret) == "") {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (azure-vm): provide WARRANT_AZURE_TENANT_ID + CLIENT_ID + CLIENT_SECRET or WARRANT_AZURE_TWIN_TOKEN")
	}
	if strings.TrimSpace(cfg.SubscriptionID) == "" || strings.TrimSpace(cfg.ResourceGroup) == "" ||
		strings.TrimSpace(cfg.QAImageID) == "" || strings.TrimSpace(cfg.SubnetID) == "" || strings.TrimSpace(cfg.DenyEgressNSGID) == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (azure-vm): SUBSCRIPTION_ID, RESOURCE_GROUP, IMAGE_ID, SUBNET_ID, and NSG_ID are required")
	}
	if strings.TrimSpace(cfg.Location) == "" {
		cfg.Location = "eastus"
	}
	if strings.TrimSpace(cfg.VMSize) == "" {
		cfg.VMSize = "Standard_D2s_v5"
	}
	if strings.TrimSpace(cfg.GuestOSFamily) == "" {
		cfg.GuestOSFamily = "LINUX"
	}
	if strings.TrimSpace(cfg.AdminUsername) == "" {
		cfg.AdminUsername = "g1twinadmin"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 3 * time.Second
	}
	cfg.ARMEndpoint = strings.TrimRight(strings.TrimSpace(cfg.ARMEndpoint), "/")
	cfg.AuthEndpoint = strings.TrimRight(strings.TrimSpace(cfg.AuthEndpoint), "/")

	cli := &http.Client{Timeout: 90 * time.Second}
	if rt != nil {
		cli.Transport = rt
	}
	return &AzureComputeVMTwinProvider{cfg: cfg, httpClient: cli}, nil
}

func NewAzureComputeVMTwinProviderFromEnv(rt http.RoundTripper, getenv func(string) string) (*AzureComputeVMTwinProvider, error) {
	poll := 3 * time.Second
	if rawMs := strings.TrimSpace(getenv("WARRANT_VM_TWIN_POLL_MS")); rawMs != "" {
		if ms, err := strconv.Atoi(rawMs); err == nil && ms > 0 {
			poll = time.Duration(ms) * time.Millisecond
		}
	}
	return NewAzureComputeVMTwinProvider(AzureComputeConfig{
		ARMEndpoint:       firstNonEmptyStr(getenv("WARRANT_AZURE_ARM_ENDPOINT"), getenv("WARRANT_AZURE_TWIN_URL")),
		AuthEndpoint:      getenv("WARRANT_AZURE_AUTH_ENDPOINT"),
		TenantID:          firstNonEmptyStr(getenv("WARRANT_AZURE_TENANT_ID"), getenv("AZURE_TENANT_ID")),
		ClientID:          firstNonEmptyStr(getenv("WARRANT_AZURE_CLIENT_ID"), getenv("AZURE_CLIENT_ID")),
		ClientSecret:      firstNonEmptyStr(getenv("WARRANT_AZURE_CLIENT_SECRET"), getenv("AZURE_CLIENT_SECRET")),
		StaticBearerToken: getenv("WARRANT_AZURE_TWIN_TOKEN"),
		SubscriptionID:    getenv("WARRANT_AZURE_TWIN_SUBSCRIPTION_ID"),
		ResourceGroup:     getenv("WARRANT_AZURE_TWIN_RESOURCE_GROUP"),
		Location:          getenv("WARRANT_AZURE_TWIN_LOCATION"),
		QAImageID:         getenv("WARRANT_AZURE_TWIN_IMAGE_ID"),
		SubnetID:          getenv("WARRANT_AZURE_TWIN_SUBNET_ID"),
		DenyEgressNSGID:   getenv("WARRANT_AZURE_TWIN_NSG_ID"),
		VMSize:            getenv("WARRANT_AZURE_TWIN_VM_SIZE"),
		GuestOSFamily:     getenv("WARRANT_AZURE_TWIN_OS_FAMILY"),
		AdminUsername:     getenv("WARRANT_AZURE_TWIN_ADMIN_USER"),
		SmokeCommand:      getenv("WARRANT_VM_TWIN_SMOKE_CMD"),
		AcceptanceCommand: getenv("WARRANT_VM_TWIN_ACCEPTANCE_CMD"),
		PollInterval:      poll,
	}, rt)
}

func (az *AzureComputeVMTwinProvider) resolveBearerToken(ctx context.Context) (string, error) {
	if strings.TrimSpace(az.cfg.StaticBearerToken) != "" {
		return strings.TrimSpace(az.cfg.StaticBearerToken), nil
	}
	az.mu.Lock()
	if az.cachedToken != "" && time.Now().Add(60*time.Second).Before(az.tokenExp) {
		tok := az.cachedToken
		az.mu.Unlock()
		return tok, nil
	}
	az.mu.Unlock()

	scope := az.cfg.ARMEndpoint + "/.default"
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", az.cfg.ClientID)
	form.Set("client_secret", az.cfg.ClientSecret)
	form.Set("scope", scope)

	tokURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", az.cfg.AuthEndpoint, url.PathEscape(az.cfg.TenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := az.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("AZURE_OAUTH_TOKEN_ERROR: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("AZURE_OAUTH_TOKEN_REJECTED (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var tokDoc struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &tokDoc); err != nil || tokDoc.AccessToken == "" {
		return "", fmt.Errorf("AZURE_OAUTH_TOKEN_INVALID: %v", err)
	}
	if tokDoc.ExpiresIn <= 0 {
		tokDoc.ExpiresIn = 3600
	}
	az.mu.Lock()
	az.cachedToken = tokDoc.AccessToken
	az.tokenExp = time.Now().Add(time.Duration(tokDoc.ExpiresIn) * time.Second)
	az.mu.Unlock()
	return tokDoc.AccessToken, nil
}

// doARM executes an Azure Resource Manager REST call and transparently polls 201/202 Long-Running Operations (LRO)
// via Azure-AsyncOperation or Location headers until terminal completion.
func (az *AzureComputeVMTwinProvider) doARM(ctx context.Context, method, pathOrFullURL string, payload any) ([]byte, error) {
	tok, err := az.resolveBearerToken(ctx)
	if err != nil {
		return nil, err
	}
	fullURL := pathOrFullURL
	if !strings.HasPrefix(pathOrFullURL, "http://") && !strings.HasPrefix(pathOrFullURL, "https://") {
		fullURL = az.cfg.ARMEndpoint + pathOrFullURL
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

	resp, err := az.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VM_TWIN_TRANSPORT_ERROR (azure-vm %s %s): %w", method, fullURL, err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	asyncURL := strings.TrimSpace(resp.Header.Get("Azure-AsyncOperation"))
	locURL := strings.TrimSpace(resp.Header.Get("Location"))
	status := resp.StatusCode
	_ = resp.Body.Close()

	if status >= 300 {
		return nil, fmt.Errorf("VM_TWIN_REMOTE_ERROR (azure-vm %s %s -> HTTP %d): %s", method, fullURL, status, strings.TrimSpace(string(raw)))
	}

	// Poll Azure Long-Running Operation (LRO) when Azure-AsyncOperation or 202 Location is returned
	if asyncURL != "" {
		for i := 0; i < 120; i++ {
			if err := sleepWithContext(ctx, az.cfg.PollInterval); err != nil {
				return nil, err
			}
			opBytes, oErr := az.doSimpleGET(ctx, asyncURL, tok)
			if oErr != nil {
				return nil, oErr
			}
			var opDoc struct {
				Status string `json:"status"`
				Error  *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(opBytes, &opDoc) == nil {
				switch strings.ToLower(opDoc.Status) {
				case "succeeded":
					if locURL != "" && method == http.MethodPost {
						if finalRes, lErr := az.doSimpleGET(ctx, locURL, tok); lErr == nil && len(finalRes) > 0 {
							return finalRes, nil
						}
					}
					return opBytes, nil
				case "failed", "canceled", "cancelled":
					msg := opDoc.Status
					if opDoc.Error != nil {
						msg = opDoc.Error.Code + ": " + opDoc.Error.Message
					}
					return nil, fmt.Errorf("AZURE_LRO_FAILED (%s): %s", fullURL, msg)
				}
			}
		}
		return nil, fmt.Errorf("AZURE_LRO_TIMEOUT: %s", asyncURL)
	}

	if status == http.StatusAccepted && locURL != "" {
		for i := 0; i < 120; i++ {
			if err := sleepWithContext(ctx, az.cfg.PollInterval); err != nil {
				return nil, err
			}
			lRaw, lCode, lErr := az.doGETWithStatus(ctx, locURL, tok)
			if lErr != nil {
				return nil, lErr
			}
			if lCode == http.StatusAccepted {
				continue
			}
			return lRaw, nil
		}
		return nil, fmt.Errorf("AZURE_LOCATION_LRO_TIMEOUT: %s", locURL)
	}
	return raw, nil
}

func (az *AzureComputeVMTwinProvider) doSimpleGET(ctx context.Context, fullURL, tok string) ([]byte, error) {
	raw, _, err := az.doGETWithStatus(ctx, fullURL, tok)
	return raw, err
}

func (az *AzureComputeVMTwinProvider) doGETWithStatus(ctx context.Context, fullURL, tok string) ([]byte, int, error) {
	if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
		fullURL = az.cfg.ARMEndpoint + fullURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := az.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("AZURE_LRO_POLL_ERROR (%s -> HTTP %d): %s", fullURL, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, resp.StatusCode, nil
}

func randomEphemeralPassword() string {
	var b [18]byte
	_, _ = rand.Read(b[:])
	return "G1w!" + hex.EncodeToString(b[:]) + "Aa9#"
}

func (az *AzureComputeVMTwinProvider) RunVMTwinProving(ctx context.Context, req adapters.CloneTwinProvingRequest) (*models.CloneTwinProvingManifest, error) {
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	runSlug := crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%d", req.ServiceID, req.CVEID, time.Now().UnixNano())))[:8]
	rgPrefix := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s",
		url.PathEscape(az.cfg.SubscriptionID), url.PathEscape(az.cfg.ResourceGroup))
	nicBase := rgPrefix + "/providers/Microsoft.Network/networkInterfaces"
	vmBase := rgPrefix + "/providers/Microsoft.Compute/virtualMachines"

	isWin := strings.EqualFold(az.cfg.GuestOSFamily, "WINDOWS") || strings.TrimSpace(req.KBArticleID) != ""
	cmdID := "RunShellScript"
	var preScript, postScript []string
	if isWin {
		cmdID = "RunPowerShellScript"
		preScript = []string{fmt.Sprintf("$kb='%s'; if ($kb -ne '') { $m = Get-ChildItem -Path 'C:\\Stage','C:\\Windows\\Temp' -Filter \"*$kb*.msu\" -ErrorAction SilentlyContinue | Select-Object -First 1; if ($m) { Start-Process wusa.exe -ArgumentList \"`\"$($m.FullName)`\" /quiet /norestart\" -Wait } }", strings.ReplaceAll(req.KBArticleID, "'", ""))}
		postScript = strings.Split(buildWindowsGuestProvingPowerShell(req, az.cfg.SmokeCommand, az.cfg.AcceptanceCommand, false), "\n")
	} else {
		preScript = []string{fmt.Sprintf("PKG=%q; if [ -n \"$PKG\" ]; then if command -v dnf >/dev/null 2>&1; then dnf install -y \"$PKG\" || dnf upgrade -y \"$PKG\"; elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y \"$PKG\"; fi; fi", req.PackageNEVRA)}
		postScript = strings.Split(buildLinuxGuestProvingScript(req, az.cfg.SmokeCommand, az.cfg.AcceptanceCommand, false), "\n")
	}

	var createdVMs, createdNICs []string
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		for _, vm := range createdVMs {
			_, _ = az.doARM(cleanCtx, http.MethodDelete, fmt.Sprintf("%s/%s?forceDeletion=true&api-version=2024-03-01", vmBase, url.PathEscape(vm)), nil)
		}
		for _, nic := range createdNICs {
			_, _ = az.doARM(cleanCtx, http.MethodDelete, fmt.Sprintf("%s/%s?api-version=2023-11-01", nicBase, url.PathEscape(nic)), nil)
		}
	}()

	outcomes := make([]vmCloneRawOutcome, 0, cloneCount)
	for i := 0; i < cloneCount; i++ {
		vmName := fmt.Sprintf("g1-az-%s-%d", runSlug, i)
		nicName := vmName + "-nic"
		nicID := fmt.Sprintf("%s/%s", nicBase, nicName)

		// 1. Create zero-public-IP NetworkInterface bound to isolated Subnet + Deny-Egress NSG
		_, err := az.doARM(ctx, http.MethodPut, fmt.Sprintf("%s/%s?api-version=2023-11-01", nicBase, url.PathEscape(nicName)), map[string]any{
			"location": az.cfg.Location,
			"properties": map[string]any{
				"networkSecurityGroup": map[string]string{"id": az.cfg.DenyEgressNSGID},
				"ipConfigurations": []map[string]any{{
					"name": "ipconfig1",
					"properties": map[string]any{
						"privateIPAllocationMethod": "Dynamic",
						"subnet":                    map[string]string{"id": az.cfg.SubnetID},
					},
				}},
			},
		})
		if err != nil {
			return nil, err
		}
		createdNICs = append(createdNICs, nicName)

		// 2. Create VirtualMachine from QA Image/Snapshot with deleteOption="Delete" on OS disk & NIC
		_, err = az.doARM(ctx, http.MethodPut, fmt.Sprintf("%s/%s?api-version=2024-03-01", vmBase, url.PathEscape(vmName)), map[string]any{
			"location": az.cfg.Location,
			"tags": map[string]string{
				"g1.warrant/proving-ground":         "true",
				"g1.warrant/zero-production-egress": "true",
				"g1.warrant/service-id":             req.ServiceID,
				"g1.warrant/cve-id":                 req.CVEID,
			},
			"properties": map[string]any{
				"hardwareProfile": map[string]string{"vmSize": az.cfg.VMSize},
				"osProfile": map[string]any{
					"computerName":  vmName,
					"adminUsername": az.cfg.AdminUsername,
					"adminPassword": randomEphemeralPassword(),
				},
				"storageProfile": map[string]any{
					"imageReference": map[string]string{"id": firstNonEmptyStr(req.BaseCloneImageIdentity, az.cfg.QAImageID)},
					"osDisk": map[string]any{
						"createOption": "FromImage",
						"deleteOption": "Delete",
					},
				},
				"networkProfile": map[string]any{
					"networkInterfaces": []map[string]any{{
						"id":         nicID,
						"properties": map[string]any{"primary": true, "deleteOption": "Delete"},
					}},
				},
			},
		})
		if err != nil {
			return nil, err
		}
		createdVMs = append(createdVMs, vmName)

		// 3. Stage/Apply candidate patch via Azure VM RunCommand (control-plane channel, zero inbound network)
		_, err = az.doARM(ctx, http.MethodPost, fmt.Sprintf("%s/%s/runCommand?api-version=2024-03-01", vmBase, url.PathEscape(vmName)), map[string]any{
			"commandId": cmdID,
			"script":    preScript,
		})
		if err != nil {
			return nil, err
		}

		// 4. Perform real Azure VM reboot (POST .../restart)
		_, err = az.doARM(ctx, http.MethodPost, fmt.Sprintf("%s/%s/restart?api-version=2024-03-01", vmBase, url.PathEscape(vmName)), nil)
		if err != nil {
			return nil, err
		}

		// 5. Execute post-reboot readiness, smoke, and class acceptance checks via RunCommand
		rawPost, err := az.doARM(ctx, http.MethodPost, fmt.Sprintf("%s/%s/runCommand?api-version=2024-03-01", vmBase, url.PathEscape(vmName)), map[string]any{
			"commandId": cmdID,
			"script":    postScript,
		})
		if err != nil {
			return nil, err
		}

		var rcResp struct {
			Value []struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"value"`
		}
		_ = json.Unmarshal(rawPost, &rcResp)
		var combinedMsg strings.Builder
		for _, v := range rcResp.Value {
			combinedMsg.WriteString(v.Message + "\n")
		}
		msgStr := combinedMsg.String()

		if parsed, ok := parseCloneResultMarker(msgStr); ok {
			parsed.CloneIndex = i
			parsed.CloneName = vmName
			parsed.HostOrZone = az.cfg.Location
			parsed.PrivateIP = "azure-arm://runCommand"
			outcomes = append(outcomes, *parsed)
		} else {
			return nil, fmt.Errorf("VM_TWIN_UNPARSEABLE_RESPONSE (azure-vm %s): missing G1_CLONE_RESULT marker in runCommand output %q", vmName, strings.TrimSpace(msgStr))
		}
	}

	return assembleVMProvingManifest(DriverAzureVM, "azure-nsg://"+az.cfg.DenyEgressNSGID, req, outcomes)
}
