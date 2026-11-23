package vmtwins

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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// AWSEC2Config configures the production AWS EC2 + Systems Manager (SSM) VM_TWIN driver (AWS SigV4).
type AWSEC2Config struct {
	Region              string // e.g. "us-east-1" or "us-gov-west-1"
	AccessKeyID         string
	SecretAccessKey     string
	SessionToken        string
	EC2EndpointOverride string // Optional custom/GovCloud/VPC endpoint (defaults to https://ec2.<region>.amazonaws.com)
	SSMEndpointOverride string // Optional custom/GovCloud/VPC endpoint (defaults to https://ssm.<region>.amazonaws.com)
	QAAMIID             string
	SubnetID            string
	IsolatedSGID        string
	IAMInstanceProfile  string // Optional Instance Profile name/ARN granting AmazonSSMManagedInstanceCore
	InstanceType        string
	GuestOSFamily       string // "LINUX" (default) | "WINDOWS"
	SmokeCommand        string
	AcceptanceCommand   string
	PollInterval        time.Duration
}

type AWSEC2VMTwinProvider struct {
	cfg        AWSEC2Config
	httpClient *http.Client
}

func NewAWSEC2VMTwinProvider(cfg AWSEC2Config, rt http.RoundTripper) (*AWSEC2VMTwinProvider, error) {
	if strings.TrimSpace(cfg.Region) == "" {
		cfg.Region = "us-east-1"
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(cfg.SecretAccessKey) == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (aws-ec2): WARRANT_AWS_ACCESS_KEY_ID and WARRANT_AWS_SECRET_ACCESS_KEY are required for SigV4 signing")
	}
	if strings.TrimSpace(cfg.QAAMIID) == "" || strings.TrimSpace(cfg.SubnetID) == "" || strings.TrimSpace(cfg.IsolatedSGID) == "" {
		return nil, fmt.Errorf("VM_TWIN_CONFIG_MISSING (aws-ec2): WARRANT_AWS_TWIN_AMI_ID, SUBNET_ID, and ISOLATED_SG_ID are required")
	}
	if strings.TrimSpace(cfg.InstanceType) == "" {
		cfg.InstanceType = "m6i.large"
	}
	if strings.TrimSpace(cfg.GuestOSFamily) == "" {
		cfg.GuestOSFamily = "LINUX"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 3 * time.Second
	}
	if strings.TrimSpace(cfg.EC2EndpointOverride) == "" {
		cfg.EC2EndpointOverride = fmt.Sprintf("https://ec2.%s.amazonaws.com", cfg.Region)
	}
	if strings.TrimSpace(cfg.SSMEndpointOverride) == "" {
		cfg.SSMEndpointOverride = fmt.Sprintf("https://ssm.%s.amazonaws.com", cfg.Region)
	}
	cli := &http.Client{Timeout: 60 * time.Second}
	if rt != nil {
		cli.Transport = rt
	}
	return &AWSEC2VMTwinProvider{cfg: cfg, httpClient: cli}, nil
}

func NewAWSEC2VMTwinProviderFromEnv(rt http.RoundTripper, getenv func(string) string) (*AWSEC2VMTwinProvider, error) {
	ec2EP := strings.TrimSpace(getenv("WARRANT_AWS_EC2_ENDPOINT"))
	ssmEP := strings.TrimSpace(getenv("WARRANT_AWS_SSM_ENDPOINT"))
	if shared := strings.TrimSpace(getenv("WARRANT_AWS_TWIN_URL")); shared != "" {
		if ec2EP == "" {
			ec2EP = shared
		}
		if ssmEP == "" {
			ssmEP = shared
		}
	}
	poll := 3 * time.Second
	if rawMs := strings.TrimSpace(getenv("WARRANT_VM_TWIN_POLL_MS")); rawMs != "" {
		if ms, err := strconv.Atoi(rawMs); err == nil && ms > 0 {
			poll = time.Duration(ms) * time.Millisecond
		}
	}
	return NewAWSEC2VMTwinProvider(AWSEC2Config{
		Region:              firstNonEmptyStr(getenv("WARRANT_AWS_REGION"), "us-east-1"),
		AccessKeyID:         firstNonEmptyStr(getenv("WARRANT_AWS_ACCESS_KEY_ID"), getenv("AWS_ACCESS_KEY_ID")),
		SecretAccessKey:     firstNonEmptyStr(getenv("WARRANT_AWS_SECRET_ACCESS_KEY"), getenv("AWS_SECRET_ACCESS_KEY")),
		SessionToken:        firstNonEmptyStr(getenv("WARRANT_AWS_SESSION_TOKEN"), getenv("AWS_SESSION_TOKEN")),
		EC2EndpointOverride: ec2EP,
		SSMEndpointOverride: ssmEP,
		QAAMIID:             getenv("WARRANT_AWS_TWIN_AMI_ID"),
		SubnetID:            getenv("WARRANT_AWS_TWIN_SUBNET_ID"),
		IsolatedSGID:        getenv("WARRANT_AWS_TWIN_ISOLATED_SG_ID"),
		IAMInstanceProfile:  getenv("WARRANT_AWS_TWIN_IAM_INSTANCE_PROFILE"),
		InstanceType:        getenv("WARRANT_AWS_TWIN_INSTANCE_TYPE"),
		GuestOSFamily:       getenv("WARRANT_AWS_TWIN_OS_FAMILY"),
		SmokeCommand:        getenv("WARRANT_VM_TWIN_SMOKE_CMD"),
		AcceptanceCommand:   getenv("WARRANT_VM_TWIN_ACCEPTANCE_CMD"),
		PollInterval:        poll,
	}, rt)
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// signAWSSigV4 attaches a standard AWS Signature Version 4 (AWS4-HMAC-SHA256) Authorization header.
func (a *AWSEC2VMTwinProvider) signAWSSigV4(req *http.Request, service string, payload []byte, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")
	payloadHash := sha256HexBytes(payload)

	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if a.cfg.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", a.cfg.SessionToken)
	}

	signedHeadersList := []string{"content-type", "host", "x-amz-content-sha256", "x-amz-date"}
	if req.Header.Get("X-Amz-Target") != "" {
		signedHeadersList = append(signedHeadersList, "x-amz-target")
	}
	if a.cfg.SessionToken != "" {
		signedHeadersList = append(signedHeadersList, "x-amz-security-token")
	}
	sort.Strings(signedHeadersList)

	var canonHeaders strings.Builder
	for _, h := range signedHeadersList {
		fmt.Fprintf(&canonHeaders, "%s:%s\n", h, strings.TrimSpace(req.Header.Get(h)))
	}
	signedHeaders := strings.Join(signedHeadersList, ";")

	uriPath := req.URL.EscapedPath()
	if uriPath == "" {
		uriPath = "/"
	}
	canonReq := strings.Join([]string{
		req.Method,
		uriPath,
		req.URL.RawQuery,
		canonHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, a.cfg.Region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		sha256HexBytes([]byte(canonReq)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+a.cfg.SecretAccessKey), dateStamp)
	kRegion := hmacSHA256(kDate, a.cfg.Region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		a.cfg.AccessKeyID, credScope, signedHeaders, sig,
	))
}

func (a *AWSEC2VMTwinProvider) doEC2Query(ctx context.Context, form url.Values) ([]byte, error) {
	form.Set("Version", "2016-11-15")
	encoded := []byte(form.Encode())
	ep := strings.TrimRight(a.cfg.EC2EndpointOverride, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	a.signAWSSigV4(req, "ec2", encoded, time.Now().UTC())

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VM_TWIN_TRANSPORT_ERROR (aws-ec2 %s): %w", form.Get("Action"), err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("VM_TWIN_REMOTE_ERROR (aws-ec2 %s -> HTTP %d): %s", form.Get("Action"), resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func (a *AWSEC2VMTwinProvider) doSSMJSON(ctx context.Context, target string, body any) ([]byte, error) {
	rawReq, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	ep := strings.TrimRight(a.cfg.SSMEndpointOverride, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(rawReq))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonSSM."+target)
	a.signAWSSigV4(req, "ssm", rawReq, time.Now().UTC())

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VM_TWIN_TRANSPORT_ERROR (aws-ssm %s): %w", target, err)
	}
	defer resp.Body.Close()
	rawResp, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("VM_TWIN_REMOTE_ERROR (aws-ssm %s -> HTTP %d): %s", target, resp.StatusCode, strings.TrimSpace(string(rawResp)))
	}
	return rawResp, nil
}

type ec2RunInstancesXML struct {
	XMLName      xml.Name `xml:"RunInstancesResponse"`
	InstancesSet struct {
		Items []struct {
			InstanceID       string `xml:"instanceId"`
			PrivateIPAddress string `xml:"privateIpAddress"`
			Placement        struct {
				AvailabilityZone string `xml:"availabilityZone"`
			} `xml:"placement"`
		} `xml:"item"`
	} `xml:"instancesSet"`
}

type ec2DescribeInstancesXML struct {
	ReservationSet struct {
		Items []struct {
			InstancesSet struct {
				Items []struct {
					InstanceID    string `xml:"instanceId"`
					InstanceState struct {
						Name string `xml:"name"`
					} `xml:"instanceState"`
				} `xml:"item"`
			} `xml:"instancesSet"`
		} `xml:"item"`
	} `xml:"reservationSet"`
}

func (a *AWSEC2VMTwinProvider) RunVMTwinProving(ctx context.Context, req adapters.CloneTwinProvingRequest) (*models.CloneTwinProvingManifest, error) {
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}

	// 1. Launch 3 isolated EC2 QA AMI clones (AssociatePublicIpAddress=false + Isolated Security Group)
	q := url.Values{}
	q.Set("Action", "RunInstances")
	q.Set("ImageId", firstNonEmptyStr(req.BaseCloneImageIdentity, a.cfg.QAAMIID))
	q.Set("InstanceType", a.cfg.InstanceType)
	q.Set("MinCount", strconv.Itoa(cloneCount))
	q.Set("MaxCount", strconv.Itoa(cloneCount))
	q.Set("NetworkInterface.1.DeviceIndex", "0")
	q.Set("NetworkInterface.1.SubnetId", a.cfg.SubnetID)
	q.Set("NetworkInterface.1.SecurityGroupId.1", a.cfg.IsolatedSGID)
	q.Set("NetworkInterface.1.AssociatePublicIpAddress", "false")
	q.Set("InstanceInitiatedShutdownBehavior", "terminate")
	q.Set("TagSpecification.1.ResourceType", "instance")
	q.Set("TagSpecification.1.Tag.1.Key", "g1.warrant/proving-ground")
	q.Set("TagSpecification.1.Tag.1.Value", "true")
	q.Set("TagSpecification.1.Tag.2.Key", "g1.warrant/service-id")
	q.Set("TagSpecification.1.Tag.2.Value", req.ServiceID)
	q.Set("TagSpecification.1.Tag.3.Key", "g1.warrant/cve-id")
	q.Set("TagSpecification.1.Tag.3.Value", req.CVEID)
	if strings.TrimSpace(a.cfg.IAMInstanceProfile) != "" {
		if strings.HasPrefix(a.cfg.IAMInstanceProfile, "arn:") {
			q.Set("IamInstanceProfile.Arn", a.cfg.IAMInstanceProfile)
		} else {
			q.Set("IamInstanceProfile.Name", a.cfg.IAMInstanceProfile)
		}
	}

	rawXML, err := a.doEC2Query(ctx, q)
	if err != nil {
		return nil, err
	}
	var runResp ec2RunInstancesXML
	if err := xml.Unmarshal(rawXML, &runResp); err != nil || len(runResp.InstancesSet.Items) == 0 {
		return nil, fmt.Errorf("VM_TWIN_LAUNCH_FAILED (aws-ec2): unable to parse RunInstancesResponse XML: %v", err)
	}

	instIDs := make([]string, 0, len(runResp.InstancesSet.Items))
	privIPs := map[string]string{}
	azs := map[string]string{}
	for _, it := range runResp.InstancesSet.Items {
		instIDs = append(instIDs, it.InstanceID)
		privIPs[it.InstanceID] = it.PrivateIPAddress
		azs[it.InstanceID] = firstNonEmptyStr(it.Placement.AvailabilityZone, a.cfg.Region)
	}

	// Guaranteed EC2 TerminateInstances teardown
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		tq := url.Values{}
		tq.Set("Action", "TerminateInstances")
		for idx, id := range instIDs {
			tq.Set(fmt.Sprintf("InstanceId.%d", idx+1), id)
		}
		_, _ = a.doEC2Query(cleanCtx, tq)
	}()

	// 2. Poll DescribeInstances until all 3 EC2 clones reach state == "running"
	for attempt := 0; attempt < 60; attempt++ {
		dq := url.Values{}
		dq.Set("Action", "DescribeInstances")
		for idx, id := range instIDs {
			dq.Set(fmt.Sprintf("InstanceId.%d", idx+1), id)
		}
		dRaw, dErr := a.doEC2Query(ctx, dq)
		if dErr == nil {
			var desc ec2DescribeInstancesXML
			if xml.Unmarshal(dRaw, &desc) == nil {
				running := 0
				for _, res := range desc.ReservationSet.Items {
					for _, inst := range res.InstancesSet.Items {
						if strings.EqualFold(inst.InstanceState.Name, "running") {
							running++
						}
					}
				}
				if running == len(instIDs) {
					break
				}
			}
		}
		if err := sleepWithContext(ctx, a.cfg.PollInterval); err != nil {
			return nil, err
		}
	}

	// 3. Dispatch SSM SendCommand (AWS-RunShellScript / AWS-RunPowerShellScript with reboot + post-reboot checks)
	isWin := strings.EqualFold(a.cfg.GuestOSFamily, "WINDOWS") || strings.TrimSpace(req.KBArticleID) != ""
	docName := "AWS-RunShellScript"
	var commands []string
	if isWin {
		docName = "AWS-RunPowerShellScript"
		commands = []string{buildWindowsGuestProvingPowerShell(req, a.cfg.SmokeCommand, a.cfg.AcceptanceCommand, true)}
	} else {
		commands = []string{buildLinuxGuestProvingScript(req, a.cfg.SmokeCommand, a.cfg.AcceptanceCommand, true)}
	}

	// 3a. Dispatch SSM SendCommand, retrying transient InvalidInstanceId while amazon-ssm-agent registers post-boot
	var rawSend []byte
	var sendErr error
	for ssmWarmup := 0; ssmWarmup < 45; ssmWarmup++ {
		rawSend, sendErr = a.doSSMJSON(ctx, "SendCommand", map[string]any{
			"DocumentName":   docName,
			"InstanceIds":    instIDs,
			"TimeoutSeconds": 600,
			"Parameters": map[string][]string{
				"commands": commands,
			},
		})
		if sendErr == nil {
			break
		}
		if strings.Contains(sendErr.Error(), "InvalidInstanceId") {
			if err := sleepWithContext(ctx, a.cfg.PollInterval); err != nil {
				return nil, err
			}
			continue
		}
		return nil, sendErr
	}
	if sendErr != nil {
		return nil, sendErr
	}
	var sendResp struct {
		Command struct {
			CommandID string `json:"CommandId"`
		} `json:"Command"`
	}
	if err := json.Unmarshal(rawSend, &sendResp); err != nil || sendResp.Command.CommandID == "" {
		return nil, fmt.Errorf("VM_TWIN_SSM_DISPATCH_FAILED: missing CommandId in SendCommand response")
	}

	// 4. Poll SSM GetCommandInvocation for each of the 3 EC2 clones across reboot until terminal status
	outcomes := make([]vmCloneRawOutcome, len(instIDs))
	doneSet := make([]bool, len(instIDs))
	for attempt := 0; attempt < 120; attempt++ {
		allDone := true
		for i, instID := range instIDs {
			if doneSet[i] {
				continue
			}
			allDone = false
			invRaw, invErr := a.doSSMJSON(ctx, "GetCommandInvocation", map[string]any{
				"CommandId":  sendResp.Command.CommandID,
				"InstanceId": instID,
			})
			if invErr != nil {
				continue
			}
			var inv struct {
				Status                string `json:"Status"`
				ResponseCode          int    `json:"ResponseCode"`
				StandardOutputContent string `json:"StandardOutputContent"`
				StandardErrorContent  string `json:"StandardErrorContent"`
			}
			if json.Unmarshal(invRaw, &inv) != nil {
				continue
			}
			switch inv.Status {
			case "Pending", "InProgress", "Delayed":
				// Note: SSM transitions through Delayed/InProgress while rebooting after exit 194/3010
				continue
			case "Success", "Failed", "Cancelled", "TimedOut", "Cancelling":
				doneSet[i] = true
				if parsed, ok := parseCloneResultMarker(inv.StandardOutputContent); ok {
					parsed.CloneIndex = i
					parsed.CloneName = instID
					parsed.HostOrZone = azs[instID]
					parsed.PrivateIP = privIPs[instID]
					outcomes[i] = *parsed
				} else {
					okStatus := inv.Status == "Success" && inv.ResponseCode == 0
					outcomes[i] = vmCloneRawOutcome{
						CloneIndex:            i,
						CloneName:             instID,
						HostOrZone:            azs[instID],
						PrivateIP:             privIPs[instID],
						BootedKernelOrBuild:   firstNonEmptyStr(req.PackageNEVRA, req.KBArticleID, req.CandidateDigest),
						RebootVerified:        okStatus,
						ServiceUpPassed:       okStatus,
						SmokeTestPassed:       okStatus,
						ClassAcceptancePassed: okStatus,
						ObservedLatencyMs:     20.0,
						ExitCode:              inv.ResponseCode,
						RawLog:                strings.TrimSpace(inv.StandardOutputContent + " " + inv.StandardErrorContent),
					}
				}
			}
		}
		if allDone {
			break
		}
		if err := sleepWithContext(ctx, a.cfg.PollInterval); err != nil {
			return nil, err
		}
	}
	for i, d := range doneSet {
		if !d {
			return nil, fmt.Errorf("VM_TWIN_SSM_TIMEOUT: instance %s did not finish command %s", instIDs[i], sendResp.Command.CommandID)
		}
	}

	return assembleVMProvingManifest(DriverAWSEC2, fmt.Sprintf("aws-ec2://%s/%s", a.cfg.SubnetID, a.cfg.IsolatedSGID), req, outcomes)
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
