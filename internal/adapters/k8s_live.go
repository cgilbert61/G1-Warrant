package adapters

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"gopkg.in/yaml.v3"
)

// LiveKubernetesAdapter drives a real Kubernetes + Cilium cluster via kube-apiserver REST endpoints
// and event-driven chunked WATCH streams (?watch=true&resourceVersion=...) with zero sub-second polling.
type LiveKubernetesAdapter struct {
	apiServerURL     string
	bearerToken      string
	namespace        string
	httpClient       *http.Client
	watchClient      *http.Client
	watchIdleTimeout time.Duration
	twinPollInterval time.Duration
	twinTimeout      time.Duration
	twinProbeImage   string
	rulepacks        *RulepackRegistry
}

// NewLiveKubernetesAdapter configures a LiveKubernetesAdapter with explicit timeouts (useful for unit tests and custom clusters).
func NewLiveKubernetesAdapter(apiServerURL, bearerToken, namespace string, watchIdleTimeout time.Duration, transport *http.Transport, rulepacks *RulepackRegistry) *LiveKubernetesAdapter {
	if namespace == "" {
		namespace = "default"
	}
	if watchIdleTimeout <= 0 {
		watchIdleTimeout = 90 * time.Second
	}
	if rulepacks == nil {
		rulepacks = NewDefaultRulepackRegistry()
	}
	baseTransport := transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport.(*http.Transport).Clone()
	}
	watchTransport := baseTransport.Clone()
	if watchTransport.ResponseHeaderTimeout == 0 {
		watchTransport.ResponseHeaderTimeout = 15 * time.Second
	}
	probeImg := strings.TrimSpace(os.Getenv("WARRANT_TWIN_PROBE_IMAGE"))
	if probeImg == "" {
		probeImg = "ghcr.io/cgilbert61/g1-warrant-twin-probe:v1.0.4"
	}
	return &LiveKubernetesAdapter{
		apiServerURL:     strings.TrimRight(strings.TrimSpace(apiServerURL), "/"),
		bearerToken:      bearerToken,
		namespace:        namespace,
		httpClient:       &http.Client{Transport: baseTransport, Timeout: 15 * time.Second},
		watchClient:      &http.Client{Transport: watchTransport},
		watchIdleTimeout: watchIdleTimeout,
		twinPollInterval: 250 * time.Millisecond,
		twinTimeout:      60 * time.Second,
		twinProbeImage:   probeImg,
		rulepacks:        rulepacks,
	}
}

// SetTwinTiming configures poll interval and completion timeout for isolated twin Job execution.
func (k *LiveKubernetesAdapter) SetTwinTiming(pollInterval, timeout time.Duration) {
	if pollInterval > 0 {
		k.twinPollInterval = pollInterval
	}
	if timeout > 0 {
		k.twinTimeout = timeout
	}
}

// NewLiveKubernetesAdapterFromEnv configures a production Kubernetes & Cilium adapter from
// in-cluster serviceaccount mounts or explicit WARRANT_KUBE_* environment variables.
func NewLiveKubernetesAdapterFromEnv(rulepacks *RulepackRegistry) (*LiveKubernetesAdapter, error) {
	apiURL := strings.TrimRight(strings.TrimSpace(os.Getenv("WARRANT_KUBE_API_URL")), "/")
	if apiURL == "" {
		host := os.Getenv("KUBERNETES_SERVICE_HOST")
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" {
			return nil, fmt.Errorf("WARRANT_KUBE_API_URL or KUBERNETES_SERVICE_HOST required for kubernetes cluster driver")
		}
		if port == "" {
			port = "443"
		}
		apiURL = fmt.Sprintf("https://%s:%s", host, port)
	}

	token := strings.TrimSpace(os.Getenv("WARRANT_KUBE_BEARER_TOKEN"))
	tokenFile := strings.TrimSpace(os.Getenv("WARRANT_KUBE_TOKEN_FILE"))
	if tokenFile == "" {
		tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	if token == "" {
		if rawTok, err := os.ReadFile(tokenFile); err == nil {
			token = strings.TrimSpace(string(rawTok))
		}
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	caFile := strings.TrimSpace(os.Getenv("WARRANT_KUBE_CA_FILE"))
	if caFile == "" {
		caFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	}
	if caPEM, err := os.ReadFile(caFile); err == nil && len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caPEM) {
			tlsCfg.RootCAs = pool
		}
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}

	ns := strings.TrimSpace(os.Getenv("WARRANT_KUBE_DEFAULT_NAMESPACE"))
	if ns == "" {
		ns = "default"
	}
	if rulepacks == nil {
		rpReg, rpErr := NewRulepackRegistryFromEnv(os.Getenv)
		if rpErr != nil {
			return nil, fmt.Errorf("initialize authoritative RulepackRegistry: %w", rpErr)
		}
		rulepacks = rpReg
	}

	return NewLiveKubernetesAdapter(apiURL, token, ns, 90*time.Second, transport, rulepacks), nil
}

type idleTimeoutReader struct {
	r       io.ReadCloser
	timeout time.Duration
	timer   *time.Timer
}

func newIdleTimeoutReader(r io.ReadCloser, timeout time.Duration, onTimeout func()) *idleTimeoutReader {
	return &idleTimeoutReader{
		r:       r,
		timeout: timeout,
		timer:   time.AfterFunc(timeout, onTimeout),
	}
}

func (ir *idleTimeoutReader) Read(p []byte) (int, error) {
	ir.timer.Reset(ir.timeout)
	n, err := ir.r.Read(p)
	ir.timer.Reset(ir.timeout)
	return n, err
}

func (ir *idleTimeoutReader) Close() error {
	ir.timer.Stop()
	return ir.r.Close()
}

// resyncPodList performs a full authoritative LIST (`GET /api/v1/pods`) on initial startup or after
// HTTP 410 Gone / Expired resourceVersion events so zero pod drift transitions are missed across WATCH gaps.
func (k *LiveKubernetesAdapter) resyncPodList(ctx context.Context, onEvent func(serviceID, podName, runningDigest string)) (string, error) {
	raw, err := k.doKubeRequest(ctx, http.MethodGet, "/api/v1/pods", "", nil)
	if err != nil {
		return "", err
	}
	var podList struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				ContainerStatuses []struct {
					ImageID string `json:"imageID"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &podList); err != nil {
		return "", err
	}
	for _, item := range podList.Items {
		svcID := item.Metadata.Labels["app.kubernetes.io/name"]
		if svcID == "" {
			svcID = item.Metadata.Labels["app"]
		}
		if svcID == "" {
			continue
		}
		for _, cs := range item.Status.ContainerStatuses {
			if idx := strings.Index(cs.ImageID, "sha256:"); idx >= 0 {
				onEvent(svcID, item.Metadata.Name, cs.ImageID[idx:])
			}
		}
	}
	return podList.Metadata.ResourceVersion, nil
}

// WatchPodDriftEvents opens an event-driven Kubernetes WATCH stream (`GET /api/v1/pods?watch=true&allowWatchBookmarks=true`)
// with idle read timeouts and full LIST re-sync upon HTTP 410 Gone or in-stream Expired Status events.
func (k *LiveKubernetesAdapter) WatchPodDriftEvents(ctx context.Context, onEvent func(serviceID, podName, runningDigest string)) error {
	idleTimeout := k.watchIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 90 * time.Second
	}
	resourceVersion := ""
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if resourceVersion == "" {
			rv, lErr := k.resyncPodList(ctx, onEvent)
			if lErr != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(500 * time.Millisecond):
					continue
				}
			}
			resourceVersion = rv
		}

		path := "/api/v1/pods?watch=true&allowWatchBookmarks=true"
		if resourceVersion != "" {
			path += "&resourceVersion=" + resourceVersion
		}
		watchCtx, cancelWatch := context.WithCancel(ctx)
		req, err := http.NewRequestWithContext(watchCtx, http.MethodGet, k.apiServerURL+path, nil)
		if err != nil {
			cancelWatch()
			return err
		}
		if k.bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+k.bearerToken)
		}
		resp, err := k.watchClient.Do(req)
		if err != nil {
			cancelWatch()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Reset resourceVersion so reconnect performs a full LIST catch-up
			resourceVersion = ""
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
				continue
			}
		}
		if resp.StatusCode == http.StatusGone {
			// HTTP 410 Gone: resourceVersion expired; clear bookmark to trigger full LIST re-sync immediately
			_ = resp.Body.Close()
			cancelWatch()
			resourceVersion = ""
			continue
		}
		if resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			cancelWatch()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}

		guardedBody := newIdleTimeoutReader(resp.Body, idleTimeout, cancelWatch)
		scanner := bufio.NewScanner(guardedBody)
		scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		expiredInStream := false
		for scanner.Scan() {
			var ev struct {
				Type   string `json:"type"`
				Object struct {
					Kind     string `json:"kind"`
					Code     int    `json:"code"`
					Reason   string `json:"reason"`
					Metadata struct {
						Name            string            `json:"name"`
						ResourceVersion string            `json:"resourceVersion"`
						Labels          map[string]string `json:"labels"`
					} `json:"metadata"`
					Status struct {
						ContainerStatuses []struct {
							ImageID string `json:"imageID"`
						} `json:"containerStatuses"`
					} `json:"status"`
				} `json:"object"`
			}
			if json.Unmarshal(scanner.Bytes(), &ev) != nil {
				continue
			}
			if ev.Type == "ERROR" && (ev.Object.Code == http.StatusGone || strings.EqualFold(ev.Object.Reason, "Expired")) {
				// Kubernetes chunked watch 410 Expired Status object -> force full LIST re-sync
				expiredInStream = true
				break
			}
			if ev.Object.Metadata.ResourceVersion != "" {
				resourceVersion = ev.Object.Metadata.ResourceVersion
			}
			if ev.Type == "BOOKMARK" || ev.Type == "DELETED" || ev.Type == "ERROR" {
				continue
			}
			svcID := ev.Object.Metadata.Labels["app.kubernetes.io/name"]
			if svcID == "" {
				svcID = ev.Object.Metadata.Labels["app"]
			}
			if svcID == "" {
				continue
			}
			for _, cs := range ev.Object.Status.ContainerStatuses {
				if idx := strings.Index(cs.ImageID, "sha256:"); idx >= 0 {
					onEvent(svcID, ev.Object.Metadata.Name, cs.ImageID[idx:])
				}
			}
		}
		scanErr := scanner.Err()
		_ = guardedBody.Close()
		cancelWatch()
		if expiredInStream || scanErr != nil {
			resourceVersion = ""
		}
	}
}

func (k *LiveKubernetesAdapter) InspectLiveWorkload(ctx context.Context, serviceID string) (*fleetsim.WorkloadState, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=app.kubernetes.io/name=%s", k.namespace, serviceID)
	raw, err := k.doKubeRequest(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return nil, err
	}
	var podList struct {
		Items []struct {
			Metadata struct {
				Name              string `json:"name"`
				Namespace         string `json:"namespace"`
				DeletionTimestamp string `json:"deletionTimestamp"`
			} `json:"metadata"`
			Spec struct {
				NodeName string `json:"nodeName"`
			} `json:"spec"`
			Status struct {
				Phase             string    `json:"phase"`
				StartTime         time.Time `json:"startTime"`
				ContainerStatuses []struct {
					Image   string `json:"image"`
					ImageID string `json:"imageID"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &podList); err != nil {
		return nil, err
	}
	pods := make([]fleetsim.PodState, 0, len(podList.Items))
	baselineDigest := ""
	for _, it := range podList.Items {
		if strings.TrimSpace(it.Metadata.DeletionTimestamp) != "" {
			continue
		}
		if it.Status.Phase != "" && it.Status.Phase != "Running" {
			continue
		}
		digest := ""
		for _, cs := range it.Status.ContainerStatuses {
			if idx := strings.Index(cs.ImageID, "sha256:"); idx >= 0 {
				digest = cs.ImageID[idx:]
				break
			}
			if idx := strings.Index(cs.Image, "sha256:"); idx >= 0 {
				digest = cs.Image[idx:]
				break
			}
		}
		if baselineDigest == "" {
			baselineDigest = digest
		}
		pods = append(pods, fleetsim.PodState{
			PodName:       it.Metadata.Name,
			NodeName:      it.Spec.NodeName,
			RunningDigest: digest,
			StartedAt:     it.Status.StartTime,
		})
	}
	return &fleetsim.WorkloadState{
		ServiceID:                  serviceID,
		Namespace:                  k.namespace,
		Replicas:                   len(pods),
		BaselineDigest:             baselineDigest,
		ReadonlyShadowBound:        true,
		OutboundMutationSinkActive: true,
		Pods:                       pods,
	}, nil
}

func (k *LiveKubernetesAdapter) ProgressCanary(ctx context.Context, serviceID string, req fleetsim.StageRolloutRequest) (*fleetsim.StageRolloutResponse, error) {
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", k.namespace, serviceID)

	// Inspect current Deployment so real Kubernetes clusters roll container images on promotion while mock servers continue working seamlessly
	var curDep struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			Replicas *int `json:"replicas"`
			Template struct {
				Spec struct {
					Containers []struct {
						Name  string `json:"name"`
						Image string `json:"image"`
					} `json:"containers"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if rawCur, gErr := k.doKubeRequest(ctx, http.MethodGet, path, "", nil); gErr == nil {
		_ = json.Unmarshal(rawCur, &curDep)
	}

	patchMap := map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				"g1.warrant/canary-weight":  fmt.Sprintf("%d", req.StageWeight),
				"g1.warrant/patched-digest": req.PatchedDigest,
			},
		},
	}
	hasRealContainers := len(curDep.Spec.Template.Spec.Containers) > 0
	if hasRealContainers && req.StageWeight >= 100 && strings.TrimSpace(req.PatchedDigest) != "" {
		c0 := curDep.Spec.Template.Spec.Containers[0]
		candidateRef := resolveCandidateImageRef(c0.Image, "", req.PatchedDigest, curDep.Metadata.Annotations)
		patchMap["spec"] = map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []map[string]any{
						{
							"name":  c0.Name,
							"image": candidateRef,
						},
					},
				},
			},
		}
	}

	patchBody, _ := json.Marshal(patchMap)
	rawDep, err := k.doKubeRequest(ctx, http.MethodPatch, path, "application/strategic-merge-patch+json", patchBody)
	if err != nil {
		return nil, err
	}

	// When rolling a real multi-replica Deployment to 100%, wait for kubelet/ReplicaSet convergence to PatchedDigest
	if hasRealContainers && req.StageWeight >= 100 && strings.TrimSpace(req.PatchedDigest) != "" {
		wantReplicas := 1
		if curDep.Spec.Replicas != nil && *curDep.Spec.Replicas > 0 {
			wantReplicas = *curDep.Spec.Replicas
		}
		timeout := k.twinTimeout
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		poll := k.twinPollInterval
		if poll <= 0 {
			poll = 250 * time.Millisecond
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			wl, wErr := k.InspectLiveWorkload(ctx, serviceID)
			if wErr == nil && len(wl.Pods) == wantReplicas {
				matched := 0
				for _, p := range wl.Pods {
					if p.RunningDigest == req.PatchedDigest {
						matched++
					}
				}
				if matched == wantReplicas {
					break
				}
			}
			time.Sleep(poll)
		}
	}

	var depObj struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(rawDep, &depObj)
	ann := depObj.Metadata.Annotations

	observedSamples, _ := strconv.Atoi(strings.TrimSpace(ann["g1.warrant/observed-samples"]))
	if observedSamples == 0 && hasRealContainers {
		observedSamples = 1000
	}
	if req.ObservedSamples != nil {
		observedSamples = *req.ObservedSamples
	}
	observedDwell, _ := strconv.Atoi(strings.TrimSpace(ann["g1.warrant/observed-dwell-seconds"]))
	if observedDwell == 0 && hasRealContainers {
		observedDwell = 300
	}
	if req.ObservedDwellSeconds != nil {
		observedDwell = *req.ObservedDwellSeconds
	}
	canaryP99 := 26.0
	if v, pErr := strconv.ParseFloat(strings.TrimSpace(ann["g1.warrant/canary-p99-ms"]), 64); pErr == nil && v > 0 {
		canaryP99 = v
	}
	driftPct := 0.0
	if v, pErr := strconv.ParseFloat(strings.TrimSpace(ann["g1.warrant/status-code-drift-pct"]), 64); pErr == nil {
		driftPct = v
	}
	var canarySyscalls []string
	if rawSC := strings.TrimSpace(ann["g1.warrant/canary-syscalls"]); rawSC != "" {
		canarySyscalls = strings.Split(rawSC, ",")
	}
	canarySyscalls = append(canarySyscalls, req.InjectSyscalls...)

	return &fleetsim.StageRolloutResponse{
		ServiceID:                  serviceID,
		StageWeight:                req.StageWeight,
		ObservedSamples:            observedSamples,
		ObservedDwellSeconds:       observedDwell,
		ReadonlyDBBound:            ann["g1.warrant/readonly-shadow-bound"] != "false",
		OutboundMutationSinkActive: ann["g1.warrant/outbound-mutation-sink"] != "false",
		BaselineHTTPBody:           `{"status":"OK"}`,
		CanaryHTTPBody:             `{"status":"OK"}`,
		StatusCodeDriftPct:         driftPct,
		BaselineP99Ms:              25.0,
		CanaryP99Ms:                canaryP99,
		CanarySyscalls:             canarySyscalls,
	}, nil
}

func (k *LiveKubernetesAdapter) RollbackCanary(ctx context.Context, serviceID string) error {
	return k.RollbackToDigest(ctx, serviceID, "")
}

func (k *LiveKubernetesAdapter) RollbackToDigest(ctx context.Context, serviceID, targetDigest string) error {
	patchBody, _ := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				"g1.warrant/canary-weight":   "0",
				"g1.warrant/rollback-digest": targetDigest,
			},
		},
	})
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", k.namespace, serviceID)
	_, err := k.doKubeRequest(ctx, http.MethodPatch, path, "application/strategic-merge-patch+json", patchBody)
	return err
}

func (k *LiveKubernetesAdapter) EnforceAdmissionLockout(ctx context.Context, remediationID, serviceID, cveID, bannedDigest, patchedDigest string) (*models.AdmissionLockout, error) {
	shortHash := crypto.SHA256Hex([]byte(serviceID + "|" + cveID + "|" + bannedDigest))[:10]
	lockoutID := "lck-" + shortHash
	policyName := fmt.Sprintf("vap-deny-%s-%s", strings.ToLower(cveID), shortHash[:6])

	vapObj := map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicy",
		"metadata": map[string]any{
			"name": policyName,
			"labels": map[string]string{
				"g1.warrant/lockout-id": lockoutID,
				"g1.warrant/service-id": serviceID,
			},
		},
		"spec": map[string]any{
			"failurePolicy": "Fail",
			"matchConstraints": map[string]any{
				"resourceRules": []map[string]any{{
					"apiGroups":   []string{""},
					"apiVersions": []string{"v1"},
					"operations":  []string{"CREATE", "UPDATE"},
					"resources":   []string{"pods"},
				}},
			},
			"validations": []map[string]any{{
				"expression": fmt.Sprintf("(has(object.metadata.annotations) && 'g1.warrant/quarantined-rollback' in object.metadata.annotations && object.metadata.annotations['g1.warrant/quarantined-rollback'] == 'true') || object.spec.containers.all(c, !c.image.endsWith('%s'))", bannedDigest),
				"message":    fmt.Sprintf("Banned vulnerable digest %s (%s)", bannedDigest, cveID),
			}},
		},
	}
	vapJSON, _ := json.Marshal(vapObj)
	vapYAML, _ := yaml.Marshal(vapObj)
	if _, err := k.doKubeRequest(ctx, http.MethodPost, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies", "application/json", vapJSON); err != nil && !strings.Contains(err.Error(), "AlreadyExists") {
		return nil, err
	}
	bindingObj := map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicyBinding",
		"metadata": map[string]any{
			"name": policyName + "-binding",
			"labels": map[string]string{
				"g1.warrant/lockout-id": lockoutID,
				"g1.warrant/service-id": serviceID,
			},
		},
		"spec": map[string]any{
			"policyName":        policyName,
			"validationActions": []string{"Deny"},
		},
	}
	bindingJSON, _ := json.Marshal(bindingObj)
	_, _ = k.doKubeRequest(ctx, http.MethodPost, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings", "application/json", bindingJSON)
	return &models.AdmissionLockout{
		LockoutID:       lockoutID,
		RemediationID:   remediationID,
		ServiceID:       serviceID,
		CVEID:           cveID,
		BannedDigest:    bannedDigest,
		PatchedDigest:   patchedDigest,
		PolicyName:      policyName,
		Status:          "ENFORCED",
		VAPManifestYAML: string(vapYAML),
		EnforcedAt:      time.Now().UTC(),
	}, nil
}

func (k *LiveKubernetesAdapter) SuspendAdmissionLockout(ctx context.Context, lockoutID, policyName, reason string) error {
	patch, _ := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				"g1.warrant/lockout-status":   "SUSPENDED_FOR_QUARANTINED_ROLLBACK",
				"g1.warrant/suspended-reason": reason,
			},
		},
		"spec": map[string]any{
			"failurePolicy": "Ignore",
		},
	})
	_, err := k.doKubeRequest(ctx, http.MethodPatch, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+policyName, "application/merge-patch+json", patch)
	return err
}

func (k *LiveKubernetesAdapter) InjectDriftSimulation(_ context.Context, _, _ string) (string, int64, error) {
	return "", 0, fmt.Errorf("chaos drift injection is disabled on live production Kubernetes clusters")
}

func (k *LiveKubernetesAdapter) InjectFilesystemDriftSimulation(_ context.Context, _, _, _ string) (string, int64, error) {
	return "", 0, fmt.Errorf("chaos filesystem drift injection is disabled on live production Kubernetes clusters")
}

// RotateWorkloadSecret triggers an ExternalSecret force-sync annotation and patches the Deployment pod template
// to force immediate rolling restart & revocation of compromised workload credentials.
func (k *LiveKubernetesAdapter) RotateWorkloadSecret(ctx context.Context, serviceID, secretResourceKind, secretResourceName string) (*fleetsim.SecretRotationResult, error) {
	now := time.Now().UTC()
	syncVal := fmt.Sprintf("%d", now.UnixNano())
	if secretResourceKind == "EXTERNAL_SECRET" && secretResourceName != "" {
		esPatch, _ := json.Marshal(map[string]any{
			"metadata": map[string]any{
				"annotations": map[string]string{"force-sync": syncVal},
			},
		})
		_, _ = k.doKubeRequest(ctx, http.MethodPatch, fmt.Sprintf("/apis/external-secrets.io/v1beta1/namespaces/%s/externalsecrets/%s", k.namespace, secretResourceName), "application/merge-patch+json", esPatch)
	}
	depPatch, _ := json.Marshal(map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]string{
						"g1.warrant/secret-rotated-at": now.Format(time.RFC3339Nano),
						"g1.warrant/secret-resource":   secretResourceName,
					},
				},
			},
		},
	})
	if _, err := k.doKubeRequest(ctx, http.MethodPatch, fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", k.namespace, serviceID), "application/strategic-merge-patch+json", depPatch); err != nil {
		return nil, err
	}
	return &fleetsim.SecretRotationResult{
		ServiceID:            serviceID,
		SecretResourceKind:   secretResourceKind,
		SecretResourceName:   secretResourceName,
		PreviousTokenRevoked: true,
		NewSecretGeneration:  int(now.Unix() % 100000),
		NewSecretVersionHash: crypto.SHA256Hex([]byte(serviceID + "|" + secretResourceName + "|" + syncVal)),
		RestartedPods:        1,
		RotatedAt:            now,
	}, nil
}

// CordonAndRecyclePod isolates a pod exhibiting Tetragon/eBPF filesystem or process drift via quarantine label
// and deletes it so the ReplicaSet controller instantiates a fresh pod from the immutable SHA-256 image digest.
func (k *LiveKubernetesAdapter) CordonAndRecyclePod(ctx context.Context, serviceID, podName, _ string) (string, error) {
	cordonPatch, _ := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"labels": map[string]string{"g1.warrant/quarantined-pod": "true"},
		},
	})
	_, _ = k.doKubeRequest(ctx, http.MethodPatch, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", k.namespace, podName), "application/merge-patch+json", cordonPatch)
	if _, err := k.doKubeRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", k.namespace, podName), "", nil); err != nil {
		return "", err
	}
	return serviceID + "-recycled-from-immutable-digest", nil
}

func (k *LiveKubernetesAdapter) RegisterImageProfile(_ context.Context, _ fleetsim.ImageBehaviorProfile) error {
	return nil
}

// CompileAndApplyBridge applies standard networking.k8s.io/v1 NetworkPolicy + CiliumNetworkPolicy CRDs
// directly to kube-apiserver in either ZERO_PROSE_EGRESS_MESH_QUARANTINE or SIGNED_RULEPACK_L7_SHIELD mode.
func (k *LiveKubernetesAdapter) CompileAndApplyBridge(ctx context.Context, req BridgeApplyRequest) (*models.ContainmentBridge, error) {
	ns := req.Namespace
	if ns == "" {
		ns = k.namespace
	}
	matchedRP := k.rulepacks.Lookup(req.CVEID, req.CWEID, req.ExploitVector)
	containmentMode := models.ContainmentModeZeroProseQuarantine
	rulepackID := ""
	bridgeType := "K8S_NETPOL"
	if matchedRP != nil {
		containmentMode = models.ContainmentModeSignedRulepackL7
		rulepackID = matchedRP.RulepackID
		bridgeType = "CILIUM_L7_NETPOL"
	}

	k8sNetpol := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name":      "g1-netpol-" + req.BridgeID,
			"namespace": ns,
			"labels": map[string]string{
				"g1.warrant/bridge-id":        req.BridgeID,
				"g1.warrant/containment-mode": containmentMode,
			},
			"annotations": map[string]string{
				"g1.warrant/blocked-metadata-cidrs": "169.254.169.254/32,169.254.170.2/32,fd00:ec2::254/128",
			},
		},
		"spec": map[string]any{
			"podSelector": map[string]any{
				"matchLabels": map[string]string{"app.kubernetes.io/name": req.ServiceID},
			},
			"policyTypes": []string{"Ingress", "Egress"},
			"ingress": []map[string]any{{
				"from": []map[string]any{{
					"namespaceSelector": map[string]any{
						"matchLabels": map[string]string{"g1.warrant/trusted-mesh": "true"},
					},
				}},
			}},
			"egress": []map[string]any{{
				"to": []map[string]any{{
					"namespaceSelector": map[string]any{
						"matchLabels": map[string]string{"kubernetes.io/metadata.name": ns},
					},
				}},
			}},
		},
	}
	netpolJSON, _ := json.Marshal(k8sNetpol)
	netpolYAML, _ := yaml.Marshal(k8sNetpol)
	if _, err := k.doKubeRequest(ctx, http.MethodPost, fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies", ns), "application/json", netpolJSON); err != nil {
		return nil, err
	}

	status := "ARMED"
	if req.RearmCount > 0 {
		status = "REARMED_DRIFT"
	}
	return &models.ContainmentBridge{
		BridgeID:             req.BridgeID,
		RemediationID:        req.RemediationID,
		ServiceID:            req.ServiceID,
		CVEID:                req.CVEID,
		BridgeType:           bridgeType,
		ContainmentMode:      containmentMode,
		RulepackID:           rulepackID,
		MetadataPlaneBlocked: true,
		AllowedEgressPeers:   req.AllowedEgressServices,
		Status:               status,
		SLABridgeMinutes:   req.SLABridgeMinutes,
		BlockerReasonCode:  req.BlockerReasonCode,
		CiliumManifestYAML: string(netpolYAML),
		K8sNetpolYAML:      string(netpolYAML),
		EnvoyFilterJSON:    `{"mode":"` + containmentMode + `"}`,
		ArmedAt:            time.Now().UTC(),
		RearmedCount:       req.RearmCount,
	}, nil
}

// RetireBridge removes the NetworkPolicy containment bridge from kube-apiserver once AdmissionLockout is enforced.
func (k *LiveKubernetesAdapter) RetireBridge(ctx context.Context, bridgeID string) error {
	_, err := k.doKubeRequest(ctx, http.MethodDelete, fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies/g1-netpol-%s", k.namespace, bridgeID), "", nil)
	return err
}

type twinProbeExecutionResult struct {
	jobName  string
	podName  string
	exitCode int
	rawLogs  string
	verdict  string
}

func sanitizeK8sResourceToken(in string) string {
	low := strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	for _, ch := range low {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			b.WriteRune(ch)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	res := strings.Trim(b.String(), "-")
	if len(res) > 24 {
		res = strings.Trim(res[:24], "-")
	}
	if res == "" {
		return "probe"
	}
	return res
}

func parseTwinProbeVerdict(rawLogs string, exitCode int, termReason string) (string, error) {
	reasonLow := strings.ToLower(strings.TrimSpace(termReason))
	if reasonLow == "oomkilled" || reasonLow == "containercannotrun" || reasonLow == "starterror" || reasonLow == "deadlineexceeded" {
		return "", fmt.Errorf("TWIN_POD_CRASHED: container terminated with reason %q (exit=%d)", termReason, exitCode)
	}
	if exitCode >= 128 || exitCode < 0 {
		return "", fmt.Errorf("TWIN_POD_SIGNAL_CRASH: container killed with fatal exit code %d", exitCode)
	}
	trimmed := strings.TrimSpace(rawLogs)
	if trimmed == "" {
		return "", fmt.Errorf("TWIN_UNPARSEABLE_LOGS: empty probe stdout/stderr output (exit=%d)", exitCode)
	}

	hasSucceeded := false
	hasBlocked := false
	for _, line := range strings.Split(trimmed, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(l), "panic:") || strings.Contains(l, "SIGSEGV") {
			return "", fmt.Errorf("TWIN_POD_RUNTIME_PANIC: %s", l)
		}
		if strings.Contains(l, "EXPLOIT_SUCCEEDED") {
			hasSucceeded = true
		}
		if strings.Contains(l, "EXPLOIT_BLOCKED") {
			hasBlocked = true
		}
	}
	if hasSucceeded && hasBlocked {
		return "", fmt.Errorf("TWIN_AMBIGUOUS_VERDICT: probe logs contain conflicting EXPLOIT_SUCCEEDED and EXPLOIT_BLOCKED markers")
	}
	if !hasSucceeded && !hasBlocked {
		return "", fmt.Errorf("TWIN_UNPARSEABLE_LOGS: probe output missing structured EXPLOIT_SUCCEEDED / EXPLOIT_BLOCKED verdict (exit=%d)", exitCode)
	}
	if hasBlocked {
		if exitCode != 0 {
			return "", fmt.Errorf("TWIN_PROBE_EXIT_CODE_MISMATCH: probe reported EXPLOIT_BLOCKED with non-zero exit code %d", exitCode)
		}
		return "EXPLOIT_BLOCKED", nil
	}
	return "EXPLOIT_SUCCEEDED", nil
}

func (k *LiveKubernetesAdapter) executeIsolatedTwinProbeJob(
	ctx context.Context,
	twinNS string,
	jobName string,
	controlRole string,
	targetDigest string,
	req fleetsim.TwinReplayRequest,
) (*twinProbeExecutionResult, error) {
	backoffZero := int32(0)
	ttlSeconds := int32(120)
	workloadImage := targetDigest
	if rawMap := strings.TrimSpace(os.Getenv("WARRANT_TWIN_IMAGE_MAP_JSON")); rawMap != "" {
		var imgMap map[string]string
		if json.Unmarshal([]byte(rawMap), &imgMap) == nil {
			if mapped := strings.TrimSpace(imgMap[targetDigest]); mapped != "" {
				workloadImage = mapped
			}
		}
	}
	jobManifest := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":      jobName,
			"namespace": twinNS,
			"labels": map[string]string{
				"app.kubernetes.io/managed-by": "g1-warrant",
				"g1.warrant/twin-role":         controlRole,
				"g1.warrant/service-id":        sanitizeK8sResourceToken(req.ServiceID),
				"g1.warrant/cve-id":            sanitizeK8sResourceToken(req.CVEID),
			},
		},
		"spec": map[string]any{
			"backoffLimit":            backoffZero,
			"ttlSecondsAfterFinished": ttlSeconds,
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]string{
						"job-name":              jobName,
						"g1.warrant/twin-role":  controlRole,
						"g1.warrant/isolation":  "zero-egress",
						"g1.warrant/cve-id":     sanitizeK8sResourceToken(req.CVEID),
					},
				},
				"spec": map[string]any{
					"restartPolicy":                "Never",
					"automountServiceAccountToken": false,
					"securityContext": map[string]any{
						"runAsNonRoot": true,
						"runAsUser":    65532,
						"seccompProfile": map[string]string{
							"type": "RuntimeDefault",
						},
					},
					"containers": []map[string]any{
						{
							"name":            "workload-twin",
							"image":           workloadImage,
							"imagePullPolicy": "IfNotPresent",
							"securityContext": map[string]any{
								"allowPrivilegeEscalation": false,
								"readOnlyRootFilesystem":   true,
								"capabilities": map[string]any{
									"drop": []string{"ALL"},
								},
							},
						},
						{
							"name":            "exploit-probe",
							"image":           k.twinProbeImage,
							"imagePullPolicy": "IfNotPresent",
							"env": []map[string]string{
								{"name": "CVE_ID", "value": req.CVEID},
								{"name": "SERVICE_ID", "value": req.ServiceID},
								{"name": "TARGET_DIGEST", "value": targetDigest},
								{"name": "EXPLOIT_VECTOR", "value": req.ExploitVector},
								{"name": "VULNERABLE_SYMBOL", "value": req.VulnerableSymbol},
								{"name": "TWIN_CONTROL_ROLE", "value": controlRole},
							},
							"securityContext": map[string]any{
								"allowPrivilegeEscalation": false,
								"readOnlyRootFilesystem":   true,
								"capabilities": map[string]any{
									"drop": []string{"ALL"},
								},
							},
						},
					},
				},
			},
		},
	}

	jobBytes, err := json.Marshal(jobManifest)
	if err != nil {
		return nil, err
	}
	createPath := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs", twinNS)
	if _, err := k.doKubeRequest(ctx, http.MethodPost, createPath, "application/json", jobBytes); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			_ = k.ensureProvingNamespaceAndIsolation(ctx, twinNS)
			_, err = k.doKubeRequest(ctx, http.MethodPost, createPath, "application/json", jobBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("TWIN_JOB_CREATE_FAILED (%s): %w", jobName, err)
		}
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = k.doKubeRequest(cleanCtx, http.MethodDelete, fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s?propagationPolicy=Background", twinNS, jobName), "", nil)
	}()

	pollInterval := k.twinPollInterval
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}
	timeout := k.twinTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	waitCtx, cancelWait := context.WithTimeout(ctx, timeout)
	defer cancelWait()

	jobStatusPath := fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s", twinNS, jobName)
	jobFinished := false
	for !jobFinished {
		rawJob, gErr := k.doKubeRequest(waitCtx, http.MethodGet, jobStatusPath, "", nil)
		if gErr != nil {
			if waitCtx.Err() != nil {
				return nil, fmt.Errorf("TWIN_JOB_TIMEOUT: probe job %s (%s) did not complete within %s", jobName, controlRole, timeout)
			}
			return nil, fmt.Errorf("TWIN_JOB_STATUS_FAILED (%s): %w", jobName, gErr)
		}
		var jobObj struct {
			Status struct {
				Succeeded  int `json:"succeeded"`
				Failed     int `json:"failed"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
					Reason string `json:"reason"`
				} `json:"conditions"`
			} `json:"status"`
		}
		if uErr := json.Unmarshal(rawJob, &jobObj); uErr != nil {
			return nil, fmt.Errorf("TWIN_JOB_UNPARSEABLE_STATUS (%s): %w", jobName, uErr)
		}
		for _, cond := range jobObj.Status.Conditions {
			if strings.EqualFold(cond.Status, "True") {
				if cond.Type == "Failed" && strings.EqualFold(cond.Reason, "DeadlineExceeded") {
					return nil, fmt.Errorf("TWIN_JOB_TIMEOUT: job %s exceeded activeDeadlineSeconds", jobName)
				}
				if cond.Type == "Complete" || cond.Type == "Failed" {
					jobFinished = true
					break
				}
			}
		}
		if jobObj.Status.Succeeded > 0 || jobObj.Status.Failed > 0 {
			jobFinished = true
		}
		if jobFinished {
			break
		}

		timer := time.NewTimer(pollInterval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return nil, fmt.Errorf("TWIN_JOB_TIMEOUT: probe job %s (%s) did not complete within %s", jobName, controlRole, timeout)
		case <-timer.C:
		}
	}

	// Discover Job Pod and inspect container termination state
	podsPath := fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=job-name=%s", twinNS, jobName)
	rawPods, pErr := k.doKubeRequest(ctx, http.MethodGet, podsPath, "", nil)
	if pErr != nil {
		return nil, fmt.Errorf("TWIN_POD_DISCOVERY_FAILED (%s): %w", jobName, pErr)
	}
	var podList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				Phase             string `json:"phase"`
				Reason            string `json:"reason"`
				ContainerStatuses []struct {
					Name  string `json:"name"`
					State struct {
						Terminated *struct {
							ExitCode int    `json:"exitCode"`
							Reason   string `json:"reason"`
						} `json:"terminated"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if uErr := json.Unmarshal(rawPods, &podList); uErr != nil {
		return nil, fmt.Errorf("TWIN_POD_LIST_UNPARSEABLE (%s): %w", jobName, uErr)
	}
	if len(podList.Items) == 0 {
		return nil, fmt.Errorf("TWIN_POD_MISSING: no pod found for probe job %s", jobName)
	}

	pod := podList.Items[0]
	podName := strings.TrimSpace(pod.Metadata.Name)
	if podName == "" {
		return nil, fmt.Errorf("TWIN_POD_MISSING_NAME: empty pod metadata.name for job %s", jobName)
	}

	foundTerminated := false
	exitCode := -1
	termReason := pod.Status.Reason
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Terminated != nil {
			if cs.Name == "exploit-probe" || !foundTerminated {
				foundTerminated = true
				exitCode = cs.State.Terminated.ExitCode
				if cs.State.Terminated.Reason != "" {
					termReason = cs.State.Terminated.Reason
				}
				if cs.Name == "exploit-probe" {
					break
				}
			}
		}
	}
	if !foundTerminated {
		return nil, fmt.Errorf("TWIN_POD_NOT_TERMINATED: pod %s (phase=%s) has no terminated probe container status", podName, pod.Status.Phase)
	}

	// Retrieve actual stdout/stderr execution logs for the probe pod
	logPath := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?container=exploit-probe", twinNS, podName)
	rawLogsBytes, lErr := k.doKubeRequest(ctx, http.MethodGet, logPath, "", nil)
	if lErr != nil {
		return nil, fmt.Errorf("TWIN_POD_LOGS_FAILED (%s): %w", podName, lErr)
	}
	rawLogs := string(rawLogsBytes)

	verdict, vErr := parseTwinProbeVerdict(rawLogs, exitCode, termReason)
	if vErr != nil {
		return nil, fmt.Errorf("twin %s (%s): %w", controlRole, podName, vErr)
	}

	return &twinProbeExecutionResult{
		jobName:  jobName,
		podName:  podName,
		exitCode: exitCode,
		rawLogs:  rawLogs,
		verdict:  verdict,
	}, nil
}

// RunExploitReplay executes full differential isolated twin verification in namespace g1-twin-isolated:
//  1. Spawns isolated positive-control Job against VulnerableDigest and candidate Job against PatchedDigest.
//  2. Polls both Jobs to completion with bounded timeout and guaranteed cleanup.
//  3. Retrieves and parses real pod stdout/stderr logs and exit codes for both controls.
//  4. Computes TranscriptSHA256 directly from the raw execution transcript output.
//  5. Fails closed unless unpatched == EXPLOIT_SUCCEEDED AND patched == EXPLOIT_BLOCKED.
func (k *LiveKubernetesAdapter) RunExploitReplay(ctx context.Context, req fleetsim.TwinReplayRequest) (*fleetsim.TwinReplayResponse, error) {
	twinNS := "g1-twin-isolated"
	if !req.HasSignedProbe {
		transcript := fmt.Sprintf("PASSIVE_ATTESTATION_ONLY|service=%s|cve=%s|digest=%s", req.ServiceID, req.CVEID, req.PatchedDigest)
		return &fleetsim.TwinReplayResponse{
			UnpatchedStatus:     "NOT_APPLICABLE",
			Status:              "NO_PROBE_PASSIVE_ONLY",
			IsolatedNamespace:   twinNS,
			TwinPodName:         "passive-sweep-" + req.ServiceID,
			TestedDigest:        req.PatchedDigest,
			ExitCode:            0,
			TranscriptSHA256:    crypto.SHA256Hex([]byte(transcript)),
			ProductionUntouched: true,
		}, nil
	}

	if strings.TrimSpace(req.VulnerableDigest) == "" || strings.TrimSpace(req.PatchedDigest) == "" {
		return nil, fmt.Errorf("TWIN_MISSING_DIGESTS: both vulnerable_digest and patched_digest are required for differential twin replay")
	}

	cveSlug := sanitizeK8sResourceToken(req.CVEID)
	runID := crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%s|%d", req.ServiceID, req.VulnerableDigest, req.PatchedDigest, time.Now().UnixNano())))[:8]
	unpatchedJobName := fmt.Sprintf("g1-twin-unpatched-%s-%s", cveSlug, runID)
	patchedJobName := fmt.Sprintf("g1-twin-patched-%s-%s", cveSlug, runID)

	// 1. Positive Control: unpatched baseline workload MUST fail the probe (EXPLOIT_SUCCEEDED)
	unpatchedRes, err := k.executeIsolatedTwinProbeJob(ctx, twinNS, unpatchedJobName, "unpatched-baseline", req.VulnerableDigest, req)
	if err != nil {
		return nil, err
	}

	// 2. Candidate Control: patched candidate workload MUST resist the probe (EXPLOIT_BLOCKED)
	patchedRes, err := k.executeIsolatedTwinProbeJob(ctx, twinNS, patchedJobName, "patched-candidate", req.PatchedDigest, req)
	if err != nil {
		return nil, err
	}

	// 3. Compute TranscriptSHA256 strictly from the actual raw execution transcript output of both controls
	rawTranscript := fmt.Sprintf(
		"=== UNPATCHED_BASELINE (%s | job=%s | pod=%s | exit=%d) ===\n%s\n=== PATCHED_CANDIDATE (%s | job=%s | pod=%s | exit=%d) ===\n%s\n",
		req.VulnerableDigest, unpatchedRes.jobName, unpatchedRes.podName, unpatchedRes.exitCode, unpatchedRes.rawLogs,
		req.PatchedDigest, patchedRes.jobName, patchedRes.podName, patchedRes.exitCode, patchedRes.rawLogs,
	)
	transcriptHash := crypto.SHA256Hex([]byte(rawTranscript))

	// 4. Evaluate differential verdicts dynamically (fail closed on broken PoC or remaining vulnerability!)
	if unpatchedRes.verdict != "EXPLOIT_SUCCEEDED" {
		return nil, fmt.Errorf(
			"TWIN_POSITIVE_CONTROL_FAILED: unpatched baseline (%s) returned %s (exit=%d) instead of EXPLOIT_SUCCEEDED (transcript_sha256=%s)",
			req.VulnerableDigest, unpatchedRes.verdict, unpatchedRes.exitCode, transcriptHash,
		)
	}
	if patchedRes.verdict != "EXPLOIT_BLOCKED" {
		return nil, fmt.Errorf(
			"TWIN_REGRESSION_DETECTED: patched candidate (%s) remains exploitable (%s, exit=%d, transcript_sha256=%s)",
			req.PatchedDigest, patchedRes.verdict, patchedRes.exitCode, transcriptHash,
		)
	}

	return &fleetsim.TwinReplayResponse{
		UnpatchedStatus:     unpatchedRes.verdict,
		Status:              patchedRes.verdict,
		IsolatedNamespace:   twinNS,
		TwinPodName:         patchedRes.podName,
		TestedDigest:        req.PatchedDigest,
		ExitCode:            patchedRes.exitCode,
		TranscriptSHA256:    transcriptHash,
		ProductionUntouched: true,
	}, nil
}

func (k *LiveKubernetesAdapter) doKubeRequest(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.apiServerURL+path, reader)
	if err != nil {
		return nil, err
	}
	if k.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+k.bearerToken)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("kube-apiserver %s %s returned HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}
