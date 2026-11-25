package shields

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

var (
	reSafeIdentifier = regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	cloudMetadataIPs = []string{
		"169.254.169.254/32",
		"169.254.170.2/32",
		"168.63.129.16/32",
		"100.100.100.200/32",
		"fd00:ec2::254/128",
	}
)

func sanitizeID(raw string, maxLen int) string {
	clean := reSafeIdentifier.ReplaceAllString(strings.TrimSpace(raw), "-")
	clean = strings.Trim(clean, "-")
	if clean == "" {
		clean = "workload"
	}
	if maxLen > 0 && len(clean) > maxLen {
		clean = clean[:maxLen]
	}
	return clean
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// 1. AWS EC2 Security Group Quarantine + IMDSv2 Hop-Limit Clamp (SigV4)
// ---------------------------------------------------------------------------

// AWSShieldConfig configures the sub-second AWS EC2 Quarantine SG + IMDSv2 Shield driver.
type AWSShieldConfig struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	EC2Endpoint     string // Optional VPC/GovCloud/test-double override; defaults to https://ec2.<region>.amazonaws.com
	QuarantineSGID  string // e.g., "sg-0quarantine999" (0.0.0.0/0 egress denied; internal DNS/mgmt only)
}

type awsArmedBridgeState struct {
	InstanceID     string   `json:"instance_id"`
	QuarantineSGID string   `json:"quarantine_sg_id"`
	OriginalSGIDs  []string `json:"original_sg_ids"`
}

// AWSEC2ShieldDriver enforces sub-second cloud VM containment on AWS EC2 via:
//  1. DescribeInstances (records pre-quarantine SecurityGroupIds for symmetric Stage 04 restoration),
//  2. ModifyInstanceAttribute (attaches isolated Quarantine Security Group),
//  3. ModifyInstanceMetadataOptions (forces HttpTokens=required & HttpPutResponseHopLimit=1, blocking 169.254.169.254 IMDSv1 credential theft).
type AWSEC2ShieldDriver struct {
	cfg        AWSShieldConfig
	httpClient *http.Client
	rulepacks  *adapters.RulepackRegistry
	mu         sync.Mutex
	armed      map[string]awsArmedBridgeState
}

func NewAWSEC2ShieldDriver(cfg AWSShieldConfig, rt http.RoundTripper, rulepacks *adapters.RulepackRegistry) *AWSEC2ShieldDriver {
	if strings.TrimSpace(cfg.Region) == "" {
		cfg.Region = "us-east-1"
	}
	cli := &http.Client{Timeout: 15 * time.Second}
	if rt != nil {
		cli.Transport = rt
	}
	if rulepacks == nil {
		rulepacks = adapters.NewDefaultRulepackRegistry()
	}
	return &AWSEC2ShieldDriver{
		cfg:        cfg,
		httpClient: cli,
		rulepacks:  rulepacks,
		armed:      make(map[string]awsArmedBridgeState),
	}
}

func NewAWSEC2ShieldDriverFromEnv(rt http.RoundTripper, rulepacks *adapters.RulepackRegistry, getenv func(string) string) *AWSEC2ShieldDriver {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return NewAWSEC2ShieldDriver(AWSShieldConfig{
		Region:          firstNonEmpty(getenv("WARRANT_AWS_SHIELD_REGION"), getenv("WARRANT_AWS_REGION"), "us-east-1"),
		AccessKeyID:     firstNonEmpty(getenv("WARRANT_AWS_SHIELD_ACCESS_KEY_ID"), getenv("WARRANT_AWS_ACCESS_KEY_ID")),
		SecretAccessKey: firstNonEmpty(getenv("WARRANT_AWS_SHIELD_SECRET_ACCESS_KEY"), getenv("WARRANT_AWS_SECRET_ACCESS_KEY")),
		SessionToken:    firstNonEmpty(getenv("WARRANT_AWS_SHIELD_SESSION_TOKEN"), getenv("WARRANT_AWS_SESSION_TOKEN")),
		EC2Endpoint:     firstNonEmpty(getenv("WARRANT_AWS_SHIELD_ENDPOINT"), getenv("WARRANT_AWS_EC2_ENDPOINT")),
		QuarantineSGID:  firstNonEmpty(getenv("WARRANT_AWS_QUARANTINE_SG_ID"), getenv("WARRANT_AWS_TWIN_ISOLATED_SG_ID")),
	}, rt, rulepacks)
}

func (d *AWSEC2ShieldDriver) EndpointConfigured() bool {
	return strings.TrimSpace(d.cfg.AccessKeyID) != "" &&
		strings.TrimSpace(d.cfg.SecretAccessKey) != "" &&
		strings.TrimSpace(d.cfg.QuarantineSGID) != ""
}

func (d *AWSEC2ShieldDriver) ec2BaseURL() string {
	if ep := strings.TrimSpace(d.cfg.EC2Endpoint); ep != "" {
		return strings.TrimRight(ep, "/")
	}
	return fmt.Sprintf("https://ec2.%s.amazonaws.com", d.cfg.Region)
}

func (d *AWSEC2ShieldDriver) CompileAndApplyBridge(ctx context.Context, req adapters.BridgeApplyRequest) (*models.ContainmentBridge, error) {
	port := req.AffectedPort
	if port <= 0 {
		port = 443
	}
	instanceID := "i-unassigned-" + sanitizeID(req.ServiceID, 16)
	if req.AssetIdentity != nil {
		instanceID = firstNonEmpty(req.AssetIdentity.CloudInstanceID, req.AssetIdentity.AssetKey, instanceID)
	}
	qSG := firstNonEmpty(d.cfg.QuarantineSGID, "sg-g1-quarantine-zero-egress")

	matchedRP := d.rulepacks.Lookup(req.CVEID, req.CWEID, req.ExploitVector)
	containmentMode := models.ContainmentModeZeroProseQuarantine
	rulepackID := ""
	var blockedPaths []string
	if matchedRP != nil {
		containmentMode = models.ContainmentModeSignedRulepackL7
		rulepackID = matchedRP.RulepackID
		blockedPaths = matchedRP.BlockedPaths
	}

	origSGs := []string{"sg-baseline-" + sanitizeID(req.ServiceID, 16)}
	execMode := "DECLARATIVE_SANDBOX"

	if d.EndpointConfigured() {
		execMode = "LIVE_SIGV4_EC2_API"
		// 1. Snapshot original SecurityGroupIds on the target EC2 instance
		descVals := url.Values{
			"Action":       {"DescribeInstances"},
			"Version":      {"2016-11-15"},
			"InstanceId.1": {instanceID},
		}
		descXML, err := d.doEC2FormSigV4(ctx, descVals)
		if err != nil {
			return nil, fmt.Errorf("AWS_SHIELD_DESCRIBE_FAILED: %w", err)
		}
		if parsedSGs := parseEC2SecurityGroupIDs(descXML); len(parsedSGs) > 0 {
			origSGs = parsedSGs
		}

		// 2. Swap EC2 instance into Quarantine Security Group (<1s VPC ENI enforcement)
		modSGVals := url.Values{
			"Action":     {"ModifyInstanceAttribute"},
			"Version":    {"2016-11-15"},
			"InstanceId": {instanceID},
			"GroupId.1":  {qSG},
		}
		if _, err := d.doEC2FormSigV4(ctx, modSGVals); err != nil {
			return nil, fmt.Errorf("AWS_SHIELD_QUARANTINE_SG_FAILED: %w", err)
		}

		// 3. Clamp IMDSv2 (HttpTokens=required, HopLimit=1) to block SSRF / 169.254.169.254 IAM role theft
		imdsVals := url.Values{
			"Action":                  {"ModifyInstanceMetadataOptions"},
			"Version":                 {"2016-11-15"},
			"InstanceId":              {instanceID},
			"HttpTokens":              {"required"},
			"HttpEndpoint":            {"enabled"},
			"HttpPutResponseHopLimit": {"1"},
		}
		if _, err := d.doEC2FormSigV4(ctx, imdsVals); err != nil {
			return nil, fmt.Errorf("AWS_SHIELD_IMDSV2_CLAMP_FAILED: %w", err)
		}
	}

	d.mu.Lock()
	d.armed[req.BridgeID] = awsArmedBridgeState{
		InstanceID:     instanceID,
		QuarantineSGID: qSG,
		OriginalSGIDs:  origSGs,
	}
	d.mu.Unlock()

	applyManifest := map[string]any{
		"substrate":        models.ShieldSubstrateAWSEC2,
		"bridge_id":        req.BridgeID,
		"execution_mode":   execMode,
		"region":           d.cfg.Region,
		"instance_id":      instanceID,
		"quarantine_sg_id": qSG,
		"original_sg_ids":  origSGs,
		"ec2_actions": []map[string]any{
			{
				"api":         "ec2:ModifyInstanceAttribute",
				"instance_id": instanceID,
				"group_ids":   []string{qSG},
			},
			{
				"api":                         "ec2:ModifyInstanceMetadataOptions",
				"instance_id":                 instanceID,
				"http_tokens":                 "required",
				"http_put_response_hop_limit": 1,
				"blocked_metadata_cidrs":      cloudMetadataIPs,
			},
		},
		"affected_port":    port,
		"containment_mode": containmentMode,
		"rulepack_id":      rulepackID,
		"waf_deny_paths":   blockedPaths,
	}
	retireSpec := map[string]any{
		"substrate":          models.ShieldSubstrateAWSEC2,
		"bridge_id":          req.BridgeID,
		"api":                "ec2:ModifyInstanceAttribute",
		"instance_id":        instanceID,
		"restore_group_ids":  origSGs,
		"keep_imdsv2_tokens": "required",
	}
	manifestBytes, _ := json.MarshalIndent(applyManifest, "", "  ")
	retireBytes, _ := json.MarshalIndent(retireSpec, "", "  ")
	envoyCanon, _ := crypto.CanonicalizeStruct(applyManifest)

	status := "ARMED"
	if req.RearmCount > 0 {
		status = "REARMED_DRIFT"
	}
	allowed := req.AllowedEgressServices
	if len(allowed) == 0 {
		allowed = []string{"vpc-dns:169.254.169.253"}
	}

	return &models.ContainmentBridge{
		BridgeID:             req.BridgeID,
		RemediationID:        req.RemediationID,
		ServiceID:            req.ServiceID,
		CVEID:                req.CVEID,
		BridgeType:           models.BridgeTypeAWSEC2SGIMDS,
		SubstrateFamily:      models.ShieldSubstrateAWSEC2,
		ContainmentMode:      containmentMode,
		RulepackID:           rulepackID,
		MetadataPlaneBlocked: true,
		AllowedEgressPeers:   allowed,
		Status:               status,
		SLABridgeMinutes:     req.SLABridgeMinutes,
		BlockerReasonCode:    req.BlockerReasonCode,
		CiliumManifestYAML:   string(manifestBytes),
		K8sNetpolYAML:        string(retireBytes),
		EnvoyFilterJSON:      string(envoyCanon),
		NativeShieldManifest: string(manifestBytes),
		NativeRetireSpec:     string(retireBytes),
		ArmedAt:              time.Now().UTC(),
		RearmedCount:         req.RearmCount,
	}, nil
}

func (d *AWSEC2ShieldDriver) RetireBridge(ctx context.Context, bridgeID string) error {
	d.mu.Lock()
	st, ok := d.armed[bridgeID]
	delete(d.armed, bridgeID)
	d.mu.Unlock()

	if !ok || !d.EndpointConfigured() || len(st.OriginalSGIDs) == 0 {
		return nil
	}
	vals := url.Values{
		"Action":     {"ModifyInstanceAttribute"},
		"Version":    {"2016-11-15"},
		"InstanceId": {st.InstanceID},
	}
	for i, sg := range st.OriginalSGIDs {
		vals.Set(fmt.Sprintf("GroupId.%d", i+1), sg)
	}
	_, err := d.doEC2FormSigV4(ctx, vals)
	return err
}

func (d *AWSEC2ShieldDriver) doEC2FormSigV4(ctx context.Context, vals url.Values) ([]byte, error) {
	body := vals.Encode()
	endpoint := d.ec2BaseURL() + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	signAWSRequestSigV4(req, []byte(body), d.cfg.Region, "ec2", d.cfg.AccessKeyID, d.cfg.SecretAccessKey, d.cfg.SessionToken, time.Now().UTC())
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("EC2 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	return respBytes, nil
}

func parseEC2SecurityGroupIDs(rawXML []byte) []string {
	type groupItem struct {
		GroupID string `xml:"groupId"`
	}
	var doc struct {
		Groups []groupItem `xml:"reservationSet>item>instancesSet>item>groupSet>item"`
	}
	if err := xml.Unmarshal(rawXML, &doc); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range doc.Groups {
		id := strings.TrimSpace(g.GroupID)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func hmacSHA256Bytes(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

func signAWSRequestSigV4(req *http.Request, payload []byte, region, service, accessKey, secretKey, sessionToken string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")
	payloadHash := crypto.SHA256Hex(payload)

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	host := req.URL.Host
	req.Header.Set("Host", host)

	signedHeadersList := []string{"content-type", "host", "x-amz-content-sha256", "x-amz-date"}
	if sessionToken != "" {
		signedHeadersList = append(signedHeadersList, "x-amz-security-token")
	}
	sort.Strings(signedHeadersList)

	var canonHeaders strings.Builder
	for _, h := range signedHeadersList {
		canonHeaders.WriteString(h + ":" + strings.TrimSpace(req.Header.Get(h)) + "\n")
	}
	signedHeaders := strings.Join(signedHeadersList, ";")
	canonURI := req.URL.EscapedPath()
	if canonURI == "" {
		canonURI = "/"
	}
	canonReq := strings.Join([]string{
		req.Method,
		canonURI,
		req.URL.RawQuery,
		canonHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		crypto.SHA256Hex([]byte(canonReq)),
	}, "\n")

	kDate := hmacSHA256Bytes([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256Bytes(kDate, region)
	kService := hmacSHA256Bytes(kRegion, service)
	kSigning := hmacSHA256Bytes(kService, "aws4_request")
	sigHex := hex.EncodeToString(hmacSHA256Bytes(kSigning, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credScope, signedHeaders, sigHex,
	))
}

// ---------------------------------------------------------------------------
// 2. Azure ARM Network Security Group (NSG) Priority-100 Quarantine Shield
// ---------------------------------------------------------------------------

type AzureShieldConfig struct {
	ARMBaseURL     string // e.g., "https://management.azure.com" or test-double override
	SubscriptionID string
	ResourceGroup  string
	NSGName        string
	BearerToken    string
}

type AzureNSGShieldDriver struct {
	cfg        AzureShieldConfig
	httpClient *http.Client
	rulepacks  *adapters.RulepackRegistry
	mu         sync.Mutex
	armedRules map[string]string // bridgeID -> ARM rule URL
}

func NewAzureNSGShieldDriver(cfg AzureShieldConfig, rt http.RoundTripper, rulepacks *adapters.RulepackRegistry) *AzureNSGShieldDriver {
	cli := &http.Client{Timeout: 15 * time.Second}
	if rt != nil {
		cli.Transport = rt
	}
	if rulepacks == nil {
		rulepacks = adapters.NewDefaultRulepackRegistry()
	}
	return &AzureNSGShieldDriver{
		cfg:        cfg,
		httpClient: cli,
		rulepacks:  rulepacks,
		armedRules: make(map[string]string),
	}
}

func NewAzureNSGShieldDriverFromEnv(rt http.RoundTripper, rulepacks *adapters.RulepackRegistry, getenv func(string) string) *AzureNSGShieldDriver {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return NewAzureNSGShieldDriver(AzureShieldConfig{
		ARMBaseURL:     firstNonEmpty(getenv("WARRANT_AZURE_SHIELD_URL"), getenv("WARRANT_AZURE_ARM_URL")),
		SubscriptionID: firstNonEmpty(getenv("WARRANT_AZURE_SUBSCRIPTION_ID"), "sub-sandbox"),
		ResourceGroup:  firstNonEmpty(getenv("WARRANT_AZURE_SHIELD_RG"), getenv("WARRANT_AZURE_RESOURCE_GROUP"), "rg-g1-warrant"),
		NSGName:        firstNonEmpty(getenv("WARRANT_AZURE_QUARANTINE_NSG"), "nsg-g1-quarantine"),
		BearerToken:    firstNonEmpty(getenv("WARRANT_AZURE_SHIELD_TOKEN"), getenv("WARRANT_AZURE_UPDATE_TOKEN")),
	}, rt, rulepacks)
}

func (d *AzureNSGShieldDriver) EndpointConfigured() bool {
	return strings.TrimSpace(d.cfg.ARMBaseURL) != "" && strings.TrimSpace(d.cfg.BearerToken) != ""
}

func (d *AzureNSGShieldDriver) CompileAndApplyBridge(ctx context.Context, req adapters.BridgeApplyRequest) (*models.ContainmentBridge, error) {
	port := req.AffectedPort
	if port <= 0 {
		port = 443
	}
	ruleName := "g1-quarantine-" + sanitizeID(req.BridgeID, 32)
	armPath := fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups/%s/securityRules/%s?api-version=2023-11-01",
		url.PathEscape(d.cfg.SubscriptionID),
		url.PathEscape(d.cfg.ResourceGroup),
		url.PathEscape(d.cfg.NSGName),
		url.PathEscape(ruleName),
	)

	armPayload := map[string]any{
		"properties": map[string]any{
			"description":              fmt.Sprintf("G1-Warrant sub-second quarantine for %s (%s)", req.ServiceID, req.CVEID),
			"protocol":                 "*",
			"sourcePortRange":          "*",
			"destinationPortRanges":    []string{"80", "443", strconv.Itoa(port)},
			"sourceAddressPrefix":      "*",
			"destinationAddressPrefixes": []string{"169.254.169.254/32", "168.63.129.16/32", "Internet"},
			"access":                   "Deny",
			"priority":                 100,
			"direction":                "Outbound",
		},
	}
	manifestBytes, _ := json.MarshalIndent(armPayload, "", "  ")
	retireDoc := map[string]any{
		"substrate": models.ShieldSubstrateAzureVM,
		"method":    "DELETE",
		"arm_path":  armPath,
	}
	retireBytes, _ := json.MarshalIndent(retireDoc, "", "  ")

	if d.EndpointConfigured() {
		fullURL := strings.TrimRight(d.cfg.ARMBaseURL, "/") + armPath
		hReq, err := http.NewRequestWithContext(ctx, http.MethodPut, fullURL, bytes.NewReader(manifestBytes))
		if err != nil {
			return nil, err
		}
		hReq.Header.Set("Content-Type", "application/json")
		hReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(d.cfg.BearerToken))
		resp, err := d.httpClient.Do(hReq)
		if err != nil {
			return nil, fmt.Errorf("AZURE_NSG_SHIELD_PUT_FAILED: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			return nil, fmt.Errorf("AZURE_NSG_SHIELD_HTTP_%d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
		}
		d.mu.Lock()
		d.armedRules[req.BridgeID] = fullURL
		d.mu.Unlock()
	}

	envoyCanon, _ := crypto.CanonicalizeStruct(armPayload)
	status := "ARMED"
	if req.RearmCount > 0 {
		status = "REARMED_DRIFT"
	}
	return &models.ContainmentBridge{
		BridgeID:             req.BridgeID,
		RemediationID:        req.RemediationID,
		ServiceID:            req.ServiceID,
		CVEID:                req.CVEID,
		BridgeType:           models.BridgeTypeAzureNSG,
		SubstrateFamily:      models.ShieldSubstrateAzureVM,
		ContainmentMode:      models.ContainmentModeZeroProseQuarantine,
		MetadataPlaneBlocked: true,
		AllowedEgressPeers:   []string{"VirtualNetwork"},
		Status:               status,
		SLABridgeMinutes:     req.SLABridgeMinutes,
		BlockerReasonCode:    req.BlockerReasonCode,
		CiliumManifestYAML:   string(manifestBytes),
		K8sNetpolYAML:        string(retireBytes),
		EnvoyFilterJSON:      string(envoyCanon),
		NativeShieldManifest: string(manifestBytes),
		NativeRetireSpec:     string(retireBytes),
		ArmedAt:              time.Now().UTC(),
		RearmedCount:         req.RearmCount,
	}, nil
}

func (d *AzureNSGShieldDriver) RetireBridge(ctx context.Context, bridgeID string) error {
	d.mu.Lock()
	fullURL, ok := d.armedRules[bridgeID]
	delete(d.armedRules, bridgeID)
	d.mu.Unlock()
	if !ok || !d.EndpointConfigured() {
		return nil
	}
	hReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, fullURL, nil)
	if err != nil {
		return err
	}
	hReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(d.cfg.BearerToken))
	resp, err := d.httpClient.Do(hReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("AZURE_NSG_RETIRE_HTTP_%d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// 3. GCP Compute Engine VPC Firewall Priority-100 Quarantine Shield
// ---------------------------------------------------------------------------

type GCPShieldConfig struct {
	ComputeBaseURL string // e.g., "https://compute.googleapis.com/compute/v1" or test-double override
	ProjectID      string
	Network        string
	BearerToken    string
}

type GCPFirewallShieldDriver struct {
	cfg        GCPShieldConfig
	httpClient *http.Client
	rulepacks  *adapters.RulepackRegistry
	mu         sync.Mutex
	armedRules map[string]string // bridgeID -> rule DELETE URL
}

func NewGCPFirewallShieldDriver(cfg GCPShieldConfig, rt http.RoundTripper, rulepacks *adapters.RulepackRegistry) *GCPFirewallShieldDriver {
	cli := &http.Client{Timeout: 15 * time.Second}
	if rt != nil {
		cli.Transport = rt
	}
	if rulepacks == nil {
		rulepacks = adapters.NewDefaultRulepackRegistry()
	}
	return &GCPFirewallShieldDriver{
		cfg:        cfg,
		httpClient: cli,
		rulepacks:  rulepacks,
		armedRules: make(map[string]string),
	}
}

func NewGCPFirewallShieldDriverFromEnv(rt http.RoundTripper, rulepacks *adapters.RulepackRegistry, getenv func(string) string) *GCPFirewallShieldDriver {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return NewGCPFirewallShieldDriver(GCPShieldConfig{
		ComputeBaseURL: firstNonEmpty(getenv("WARRANT_GCP_SHIELD_URL"), getenv("WARRANT_GCP_COMPUTE_URL")),
		ProjectID:      firstNonEmpty(getenv("WARRANT_GCP_PROJECT_ID"), "gcp-g1-sandbox"),
		Network:        firstNonEmpty(getenv("WARRANT_GCP_VPC_NETWORK"), "global/networks/default"),
		BearerToken:    firstNonEmpty(getenv("WARRANT_GCP_SHIELD_TOKEN"), getenv("WARRANT_GCP_OSCONFIG_TOKEN")),
	}, rt, rulepacks)
}

func (d *GCPFirewallShieldDriver) EndpointConfigured() bool {
	return strings.TrimSpace(d.cfg.ComputeBaseURL) != "" && strings.TrimSpace(d.cfg.BearerToken) != ""
}

func (d *GCPFirewallShieldDriver) CompileAndApplyBridge(ctx context.Context, req adapters.BridgeApplyRequest) (*models.ContainmentBridge, error) {
	port := req.AffectedPort
	if port <= 0 {
		port = 443
	}
	fwName := strings.ToLower("g1-fw-" + sanitizeID(req.BridgeID, 36))
	targetTag := strings.ToLower("svc-" + sanitizeID(req.ServiceID, 32))

	fwDoc := map[string]any{
		"kind":               "compute#firewall",
		"name":               fwName,
		"network":            d.cfg.Network,
		"direction":          "EGRESS",
		"priority":           100,
		"targetTags":         []string{targetTag},
		"destinationRanges":  []string{"169.254.169.254/32", "0.0.0.0/0"},
		"denied": []map[string]any{
			{"IPProtocol": "tcp", "ports": []string{"80", "443", strconv.Itoa(port)}},
			{"IPProtocol": "udp", "ports": []string{"53"}},
		},
	}
	manifestBytes, _ := json.MarshalIndent(fwDoc, "", "  ")
	delPath := fmt.Sprintf("/projects/%s/global/firewalls/%s", url.PathEscape(d.cfg.ProjectID), url.PathEscape(fwName))
	retireBytes, _ := json.MarshalIndent(map[string]any{
		"substrate":   models.ShieldSubstrateGCPGCE,
		"method":      "DELETE",
		"delete_path": delPath,
	}, "", "  ")

	if d.EndpointConfigured() {
		postURL := fmt.Sprintf("%s/projects/%s/global/firewalls", strings.TrimRight(d.cfg.ComputeBaseURL, "/"), url.PathEscape(d.cfg.ProjectID))
		hReq, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(manifestBytes))
		if err != nil {
			return nil, err
		}
		hReq.Header.Set("Content-Type", "application/json")
		hReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(d.cfg.BearerToken))
		resp, err := d.httpClient.Do(hReq)
		if err != nil {
			return nil, fmt.Errorf("GCP_FIREWALL_SHIELD_POST_FAILED: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			return nil, fmt.Errorf("GCP_FIREWALL_SHIELD_HTTP_%d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
		}
		d.mu.Lock()
		d.armedRules[req.BridgeID] = strings.TrimRight(d.cfg.ComputeBaseURL, "/") + delPath
		d.mu.Unlock()
	}

	envoyCanon, _ := crypto.CanonicalizeStruct(fwDoc)
	status := "ARMED"
	if req.RearmCount > 0 {
		status = "REARMED_DRIFT"
	}
	return &models.ContainmentBridge{
		BridgeID:             req.BridgeID,
		RemediationID:        req.RemediationID,
		ServiceID:            req.ServiceID,
		CVEID:                req.CVEID,
		BridgeType:           models.BridgeTypeGCPVPCFirewall,
		SubstrateFamily:      models.ShieldSubstrateGCPGCE,
		ContainmentMode:      models.ContainmentModeZeroProseQuarantine,
		MetadataPlaneBlocked: true,
		AllowedEgressPeers:   []string{"internal-vpc-rfc1918"},
		Status:               status,
		SLABridgeMinutes:     req.SLABridgeMinutes,
		BlockerReasonCode:    req.BlockerReasonCode,
		CiliumManifestYAML:   string(manifestBytes),
		K8sNetpolYAML:        string(retireBytes),
		EnvoyFilterJSON:      string(envoyCanon),
		NativeShieldManifest: string(manifestBytes),
		NativeRetireSpec:     string(retireBytes),
		ArmedAt:              time.Now().UTC(),
		RearmedCount:         req.RearmCount,
	}, nil
}

func (d *GCPFirewallShieldDriver) RetireBridge(ctx context.Context, bridgeID string) error {
	d.mu.Lock()
	delURL, ok := d.armedRules[bridgeID]
	delete(d.armedRules, bridgeID)
	d.mu.Unlock()
	if !ok || !d.EndpointConfigured() {
		return nil
	}
	hReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, delURL, nil)
	if err != nil {
		return err
	}
	hReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(d.cfg.BearerToken))
	resp, err := d.httpClient.Do(hReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("GCP_FIREWALL_RETIRE_HTTP_%d", resp.StatusCode)
	}
	return nil
}
