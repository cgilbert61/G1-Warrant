package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"gopkg.in/yaml.v3"
)

// K8sRolloutAdapter implements DeploymentTarget and TwinRunner against the Kubernetes/Cilium cluster API.
type K8sRolloutAdapter struct {
	fleetBaseURL string
	httpClient   *http.Client
}

// NewK8sRolloutAdapter creates a K8sRolloutAdapter targeting fleetBaseURL.
func NewK8sRolloutAdapter(fleetBaseURL string) *K8sRolloutAdapter {
	return &K8sRolloutAdapter{
		fleetBaseURL: strings.TrimRight(fleetBaseURL, "/"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetHTTPTransport configures a governed RoundTripper attaching X-Warrant-Task-DSSE + X-Warrant-Agent-PoP.
func (k *K8sRolloutAdapter) SetHTTPTransport(rt http.RoundTripper) {
	if k != nil && k.httpClient != nil && rt != nil {
		k.httpClient.Transport = rt
	}
}

func (k *K8sRolloutAdapter) ProgressCanary(ctx context.Context, serviceID string, req fleetsim.StageRolloutRequest) (*fleetsim.StageRolloutResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/rollouts/%s/stage", k.fleetBaseURL, serviceID), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("k8s canary rollout HTTP error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var errDoc map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errDoc)
		return nil, fmt.Errorf("k8s rollout rejected (HTTP %d): %s", resp.StatusCode, errDoc["error"])
	}
	var out fleetsim.StageRolloutResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (k *K8sRolloutAdapter) RollbackCanary(ctx context.Context, serviceID string) error {
	return k.RollbackToDigest(ctx, serviceID, "")
}

func (k *K8sRolloutAdapter) RollbackToDigest(ctx context.Context, serviceID, targetDigest string) error {
	reqBody, _ := json.Marshal(map[string]string{
		"target_digest": targetDigest,
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/rollouts/%s/rollback", k.fleetBaseURL, serviceID), bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("k8s rollback HTTP error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("k8s rollback failed with HTTP %d", resp.StatusCode)
	}
	return nil
}

func (k *K8sRolloutAdapter) InspectLiveWorkload(ctx context.Context, serviceID string) (*fleetsim.WorkloadState, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v1/workloads/%s", k.fleetBaseURL, serviceID), nil)
	if err != nil {
		return nil, err
	}
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("inspect workload %s returned HTTP %d", serviceID, resp.StatusCode)
	}
	var wl fleetsim.WorkloadState
	if err := json.NewDecoder(resp.Body).Decode(&wl); err != nil {
		return nil, err
	}
	return &wl, nil
}

func (k *K8sRolloutAdapter) EnforceAdmissionLockout(ctx context.Context, remediationID, serviceID, cveID, bannedDigest, patchedDigest string) (*models.AdmissionLockout, error) {
	shortHash := crypto.SHA256Hex([]byte(serviceID + "|" + cveID + "|" + bannedDigest))[:10]
	lockoutID := fmt.Sprintf("lck-%s", shortHash)
	policyName := fmt.Sprintf("vap-deny-%s-%s", strings.ToLower(cveID), shortHash[:6])

	vapDoc := map[string]any{
		"apiVersion": "admissionregistration.k8s.io/v1",
		"kind":       "ValidatingAdmissionPolicy",
		"metadata": map[string]any{
			"name": policyName,
			"labels": map[string]string{
				"g1.warrant/lockout-id":     lockoutID,
				"g1.warrant/remediation-id": remediationID,
				"g1.warrant/cve":            cveID,
			},
		},
		"spec": map[string]any{
			"failurePolicy": "Fail",
			"matchConstraints": map[string]any{
				"resourceRules": []map[string]any{
					{
						"apiGroups":   []string{"apps", ""},
						"apiVersions": []string{"v1"},
						"operations":  []string{"CREATE", "UPDATE"},
						"resources":   []string{"deployments", "replicasets", "pods"},
					},
				},
			},
			"validations": []map[string]any{
				{
					"expression": fmt.Sprintf("object.spec.containers.all(c, !c.image.endsWith('%s'))", bannedDigest),
					"message":    fmt.Sprintf("G1-Warrant Admission Lockout (%s): container digest %s is permanently banned due to %s", policyName, bannedDigest, cveID),
				},
			},
		},
	}
	vapYAML, err := yaml.Marshal(vapDoc)
	if err != nil {
		return nil, err
	}

	gatekeeperRego := fmt.Sprintf(`package k8sdigests.lockout_%s
import rego.v1

violation contains {"msg": msg} if {
    some container in input.review.object.spec.containers
    endswith(container.image, %q)
    msg := %q
}
`, shortHash[:6], bannedDigest, fmt.Sprintf("G1-Warrant Lockout %s: digest %s banned (%s)", policyName, bannedDigest, cveID))

	now := time.Now().UTC()
	clusterPayload := fleetsim.LockoutPolicyState{
		LockoutID:       lockoutID,
		PolicyName:      policyName,
		ServiceID:       serviceID,
		BannedDigest:    bannedDigest,
		VAPManifestYAML: string(vapYAML),
		EnforcedAt:      now,
	}
	body, _ := json.Marshal(clusterPayload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, k.fleetBaseURL+"/v1/admission/lockouts", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enforce admission lockout on cluster: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cluster rejected admission lockout: HTTP %d", resp.StatusCode)
	}

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
		GatekeeperRego:  gatekeeperRego,
		EnforcedAt:      now,
	}, nil
}

func (k *K8sRolloutAdapter) SuspendAdmissionLockout(ctx context.Context, lockoutID, policyName, reason string) error {
	body, _ := json.Marshal(map[string]string{
		"policy_name": policyName,
		"reason":      reason,
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/admission/lockouts/%s/suspend", k.fleetBaseURL, lockoutID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("suspend admission lockout %s: %w", lockoutID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("cluster failed suspending lockout %s: HTTP %d", lockoutID, resp.StatusCode)
	}
	return nil
}

func (k *K8sRolloutAdapter) RunExploitReplay(ctx context.Context, req fleetsim.TwinReplayRequest) (*fleetsim.TwinReplayResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, k.fleetBaseURL+"/v1/twins/replay", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("twin exploit replay HTTP error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("twin exploit replay returned HTTP %d", resp.StatusCode)
	}
	var out fleetsim.TwinReplayResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (k *K8sRolloutAdapter) InjectDriftSimulation(ctx context.Context, serviceID, bannedDigest string) (string, int64, error) {
	body, _ := json.Marshal(map[string]string{
		"service_id":    serviceID,
		"banned_digest": bannedDigest,
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, k.fleetBaseURL+"/v1/chaos/drift", bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("drift simulation failed with HTTP %d", resp.StatusCode)
	}
	var out struct {
		RoguePodName   string `json:"rogue_pod_name"`
		InjectedUnixMs int64  `json:"injected_unix_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, err
	}
	return out.RoguePodName, out.InjectedUnixMs, nil
}

func (k *K8sRolloutAdapter) RegisterImageProfile(ctx context.Context, prof fleetsim.ImageBehaviorProfile) error {
	body, _ := json.Marshal(prof)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, k.fleetBaseURL+"/v1/profiles", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("register profile HTTP %d", resp.StatusCode)
	}
	return nil
}

func (k *K8sRolloutAdapter) RotateWorkloadSecret(ctx context.Context, serviceID, secretResourceKind, secretResourceName string) (*fleetsim.SecretRotationResult, error) {
	body, _ := json.Marshal(map[string]string{
		"secret_resource_kind": secretResourceKind,
		"secret_resource_name": secretResourceName,
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/secrets/%s/rotate", k.fleetBaseURL, serviceID), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rotate workload secret HTTP error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rotate workload secret returned HTTP %d", resp.StatusCode)
	}
	var out fleetsim.SecretRotationResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (k *K8sRolloutAdapter) CordonAndRecyclePod(ctx context.Context, serviceID, podName, cleanDigest string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"pod_name":     podName,
		"clean_digest": cleanDigest,
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/workloads/%s/cordon-recycle", k.fleetBaseURL, serviceID), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("cordon and recycle pod HTTP error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("cordon and recycle pod returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		RecycledPod string `json:"recycled_pod"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.RecycledPod, nil
}

func (k *K8sRolloutAdapter) InjectFilesystemDriftSimulation(ctx context.Context, serviceID, filePath, processName string) (string, int64, error) {
	body, _ := json.Marshal(map[string]string{
		"file_path": filePath,
		"process":   processName,
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/drift/%s/inject-webshell", k.fleetBaseURL, serviceID), bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := k.httpClient.Do(httpReq)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("filesystem drift simulation failed with HTTP %d", resp.StatusCode)
	}
	var out struct {
		PodName        string `json:"pod_name"`
		InjectedUnixMs int64  `json:"injected_unix_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, err
	}
	return out.PodName, out.InjectedUnixMs, nil
}
