package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

func resolveCandidateImageRef(currentImage, explicitRef, candidateDigest string, annotations map[string]string) string {
	if strings.TrimSpace(explicitRef) != "" {
		return strings.TrimSpace(explicitRef)
	}
	if annotations != nil {
		if v := strings.TrimSpace(annotations["g1.warrant/candidate-image-ref"]); v != "" {
			return v
		}
		if strings.HasPrefix(candidateDigest, "sha256:") && len(candidateDigest) >= 19 {
			key := "g1.warrant/image-" + candidateDigest[7:19]
			if v := strings.TrimSpace(annotations[key]); v != "" {
				return v
			}
		}
	}
	if envRef := strings.TrimSpace(os.Getenv("WARRANT_CANDIDATE_IMAGE_REF")); envRef != "" {
		return envRef
	}
	trimmedDigest := strings.TrimSpace(candidateDigest)
	if trimmedDigest == "" {
		return currentImage
	}
	if !strings.HasPrefix(trimmedDigest, "sha256:") {
		return trimmedDigest
	}
	repo := strings.TrimSpace(currentImage)
	if repo == "" {
		return trimmedDigest
	}
	if idx := strings.Index(repo, "@"); idx > 0 {
		repo = repo[:idx]
	} else {
		lastSlash := strings.LastIndex(repo, "/")
		lastColon := strings.LastIndex(repo, ":")
		if lastColon > lastSlash {
			repo = repo[:lastColon]
		}
	}
	return repo + "@" + trimmedDigest
}

func (k *LiveKubernetesAdapter) ensureProvingNamespaceAndIsolation(ctx context.Context, provingNS string) error {
	if _, err := k.doKubeRequest(ctx, http.MethodGet, "/api/v1/namespaces/"+provingNS, "", nil); err != nil {
		nsObj := map[string]any{
			"apiVersion": "v1",
			"kind":       "Namespace",
			"metadata": map[string]any{
				"name": provingNS,
				"labels": map[string]string{
					"kubernetes.io/metadata.name":       provingNS,
					"app.kubernetes.io/managed-by":      "g1-warrant",
					"g1.warrant/proving-ground":         "true",
					"g1.warrant/zero-production-egress": "true",
				},
			},
		}
		nsBytes, _ := json.Marshal(nsObj)
		if _, cErr := k.doKubeRequest(ctx, http.MethodPost, "/api/v1/namespaces", "application/json", nsBytes); cErr != nil && !strings.Contains(cErr.Error(), "AlreadyExists") {
			return fmt.Errorf("CLONE_TWIN_NAMESPACE_CREATE_FAILED: %w", cErr)
		}
	}

	npName := "g1-twin-proving-zero-egress"
	npObj := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name":      npName,
			"namespace": provingNS,
			"labels": map[string]string{
				"app.kubernetes.io/managed-by":      "g1-warrant",
				"g1.warrant/zero-production-egress": "true",
			},
		},
		"spec": map[string]any{
			"podSelector": map[string]any{},
			"policyTypes": []string{"Ingress", "Egress"},
			"ingress": []map[string]any{
				{
					"from": []map[string]any{
						{"podSelector": map[string]any{}},
					},
				},
			},
			"egress": []map[string]any{
				{
					"to": []map[string]any{
						{"podSelector": map[string]any{}},
					},
				},
			},
		},
	}
	npBytes, _ := json.Marshal(npObj)
	if _, err := k.doKubeRequest(ctx, http.MethodGet, fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies/%s", provingNS, npName), "", nil); err != nil {
		if _, cErr := k.doKubeRequest(ctx, http.MethodPost, fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies", provingNS), "application/json", npBytes); cErr != nil && !strings.Contains(cErr.Error(), "AlreadyExists") {
			return fmt.Errorf("CLONE_TWIN_NETPOL_FAILED: %w", cErr)
		}
	}
	return nil
}

// RunCloneTwinProving clones a representative subset (default 3) of the production Kubernetes workload
// into isolated namespace g1-twin-proving (with zero production egress), applies the candidate patched image,
// and executes (a) services-up readiness checks, (b) workload smoke tests, and (c) authorization-class acceptance checks.
func (k *LiveKubernetesAdapter) RunCloneTwinProving(ctx context.Context, req CloneTwinProvingRequest) (*models.CloneTwinProvingManifest, error) {
	if req.PatchTargetLayer == models.PatchTargetLayerKernel || req.PatchTargetLayer == models.PatchTargetLayerBoot {
		return nil, fmt.Errorf("KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME: LiveKubernetesAdapter is a CONTAINER_TWIN runtime and cannot boot or prove %s patches", req.PatchTargetLayer)
	}

	provingNS := "g1-twin-proving"
	prodNS := strings.TrimSpace(req.Namespace)
	if prodNS == "" {
		prodNS = k.namespace
	}
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	maxP99 := req.MaxP99LatencyMs
	if maxP99 <= 0 {
		maxP99 = 250.0
	}

	if err := k.ensureProvingNamespaceAndIsolation(ctx, provingNS); err != nil {
		return nil, err
	}

	// Read production Deployment to clone real container config, ports, env, probes, and ConfigMaps
	depPath := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", prodNS, req.ServiceID)
	rawDep, err := k.doKubeRequest(ctx, http.MethodGet, depPath, "", nil)
	if err != nil {
		return nil, fmt.Errorf("CLONE_TWIN_SOURCE_DEPLOYMENT_NOT_FOUND (%s/%s): %w", prodNS, req.ServiceID, err)
	}

	var dep struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			Template struct {
				Spec struct {
					Containers []map[string]any `json:"containers"`
					Volumes    []map[string]any `json:"volumes"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(rawDep, &dep); err != nil {
		return nil, fmt.Errorf("CLONE_TWIN_SOURCE_UNPARSEABLE: %w", err)
	}
	if len(dep.Spec.Template.Spec.Containers) == 0 {
		return nil, fmt.Errorf("CLONE_TWIN_SOURCE_EMPTY_CONTAINERS: deployment %s/%s has zero containers", prodNS, req.ServiceID)
	}

	// Copy any referenced ConfigMaps from prodNS into provingNS
	for _, vol := range dep.Spec.Template.Spec.Volumes {
		if cmRef, ok := vol["configMap"].(map[string]any); ok {
			cmName, _ := cmRef["name"].(string)
			if cmName != "" {
				if rawCM, cmErr := k.doKubeRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", prodNS, cmName), "", nil); cmErr == nil {
					var cmDoc struct {
						Data       map[string]string `json:"data"`
						BinaryData map[string][]byte `json:"binaryData"`
					}
					if json.Unmarshal(rawCM, &cmDoc) == nil {
						cloneCM, _ := json.Marshal(map[string]any{
							"apiVersion": "v1",
							"kind":       "ConfigMap",
							"metadata": map[string]any{
								"name":      cmName,
								"namespace": provingNS,
							},
							"data":       cmDoc.Data,
							"binaryData": cmDoc.BinaryData,
						})
						_, _ = k.doKubeRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", provingNS, cmName), "", nil)
						_, _ = k.doKubeRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/namespaces/%s/configmaps", provingNS), "application/json", cloneCM)
					}
				}
			}
		}
	}

	primaryOrig := dep.Spec.Template.Spec.Containers[0]
	origImage, _ := primaryOrig["image"].(string)
	candidateImage := resolveCandidateImageRef(origImage, req.CandidateImageRef, req.CandidateDigest, dep.Metadata.Annotations)

	targetPort := 8080
	if portsRaw, ok := primaryOrig["ports"].([]any); ok && len(portsRaw) > 0 {
		if p0, ok := portsRaw[0].(map[string]any); ok {
			if cp, ok := p0["containerPort"].(float64); ok && cp > 0 {
				targetPort = int(cp)
			}
		}
	}

	svcSlug := sanitizeK8sResourceToken(req.ServiceID)
	runHash := crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%s|%d", req.ServiceID, req.CVEID, candidateImage, time.Now().UnixNano())))[:8]
	provingRunID := "prv-" + runHash

	clonePodNames := make([]string, 0, cloneCount)
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, podName := range clonePodNames {
			_, _ = k.doKubeRequest(cleanCtx, http.MethodDelete, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s?gracePeriodSeconds=0", provingNS, podName), "", nil)
		}
	}()

	// 1. Create all 3 (cloneCount) isolated ephemeral Clone Pods in g1-twin-proving
	for i := 0; i < cloneCount; i++ {
		podName := fmt.Sprintf("g1-clone-%s-%s-%d", svcSlug, runHash, i)
		cloneContainersBytes, _ := json.Marshal(dep.Spec.Template.Spec.Containers)
		var cloneContainers []map[string]any
		_ = json.Unmarshal(cloneContainersBytes, &cloneContainers)
		cloneContainers[0]["image"] = candidateImage
		if _, hasPull := cloneContainers[0]["imagePullPolicy"]; !hasPull {
			cloneContainers[0]["imagePullPolicy"] = "IfNotPresent"
		}

		podManifest := map[string]any{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]any{
				"name":      podName,
				"namespace": provingNS,
				"labels": map[string]string{
					"app.kubernetes.io/managed-by": "g1-warrant",
					"g1.warrant/proving-run":       provingRunID,
					"g1.warrant/proving-clone":     "true",
					"g1.warrant/service-id":        svcSlug,
					"g1.warrant/clone-index":       strconv.Itoa(i),
				},
			},
			"spec": map[string]any{
				"restartPolicy":                "Never",
				"automountServiceAccountToken": false,
				"containers":                   cloneContainers,
				"volumes":                      dep.Spec.Template.Spec.Volumes,
			},
		}
		podBytes, _ := json.Marshal(podManifest)
		if _, cErr := k.doKubeRequest(ctx, http.MethodPost, fmt.Sprintf("/api/v1/namespaces/%s/pods", provingNS), "application/json", podBytes); cErr != nil {
			return nil, fmt.Errorf("CLONE_TWIN_POD_CREATE_FAILED (%s): %w", podName, cErr)
		}
		clonePodNames = append(clonePodNames, podName)
	}

	// 2. Wait for all 3 clones to reach Running + Ready (Check A: Services Up & Readiness Probes)
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

	type readyCloneMeta struct {
		index         int
		podName       string
		nodeName      string
		podIP         string
		runningDigest string
	}
	readyClones := make([]readyCloneMeta, cloneCount)
	readySet := make([]bool, cloneCount)

	for {
		allReady := true
		for i, podName := range clonePodNames {
			if readySet[i] {
				continue
			}
			allReady = false
			rawPod, pErr := k.doKubeRequest(waitCtx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", provingNS, podName), "", nil)
			if pErr != nil {
				continue
			}
			var podObj struct {
				Spec struct {
					NodeName string `json:"nodeName"`
				} `json:"spec"`
				Status struct {
					Phase      string `json:"phase"`
					PodIP      string `json:"podIP"`
					Conditions []struct {
						Type   string `json:"type"`
						Status string `json:"status"`
					} `json:"conditions"`
					ContainerStatuses []struct {
						Ready   bool   `json:"ready"`
						Image   string `json:"image"`
						ImageID string `json:"imageID"`
						State   struct {
							Waiting *struct {
								Reason  string `json:"reason"`
								Message string `json:"message"`
							} `json:"waiting"`
							Terminated *struct {
								ExitCode int    `json:"exitCode"`
								Reason   string `json:"reason"`
							} `json:"terminated"`
						} `json:"state"`
					} `json:"containerStatuses"`
				} `json:"status"`
			}
			if json.Unmarshal(rawPod, &podObj) != nil {
				continue
			}
			for _, cs := range podObj.Status.ContainerStatuses {
				if cs.State.Terminated != nil && cs.State.Terminated.ExitCode != 0 {
					return nil, fmt.Errorf("CLONE_SERVICE_READINESS_FAILED: clone %s crashed on boot (exit=%d reason=%s)",
						podName, cs.State.Terminated.ExitCode, cs.State.Terminated.Reason)
				}
				if cs.State.Waiting != nil && (cs.State.Waiting.Reason == "ImagePullBackOff" || cs.State.Waiting.Reason == "ErrImagePull" || cs.State.Waiting.Reason == "CrashLoopBackOff") {
					return nil, fmt.Errorf("CLONE_SERVICE_READINESS_FAILED: clone %s failed (%s: %s)",
						podName, cs.State.Waiting.Reason, cs.State.Waiting.Message)
				}
			}
			podReady := false
			for _, cond := range podObj.Status.Conditions {
				if cond.Type == "Ready" && strings.EqualFold(cond.Status, "True") {
					podReady = true
					break
				}
			}
			if podObj.Status.Phase == "Running" && podReady && podObj.Status.PodIP != "" {
				digest := req.CandidateDigest
				for _, cs := range podObj.Status.ContainerStatuses {
					if idx := strings.Index(cs.ImageID, "sha256:"); idx >= 0 {
						digest = cs.ImageID[idx:]
						break
					}
				}
				readyClones[i] = readyCloneMeta{
					index:         i,
					podName:       podName,
					nodeName:      podObj.Spec.NodeName,
					podIP:         podObj.Status.PodIP,
					runningDigest: digest,
				}
				readySet[i] = true
			}
		}
		if allReady {
			break
		}
		if waitCtx.Err() != nil {
			return nil, fmt.Errorf("CLONE_SERVICE_READINESS_TIMEOUT: clones in %s did not all reach Ready within %s", provingNS, timeout)
		}
		time.Sleep(pollInterval)
	}

	// 3. Spawn in-cluster Proving Runner Job inside g1-twin-proving to execute Smoke + Class Acceptance checks over PodIPs
	runnerImg := strings.TrimSpace(os.Getenv("WARRANT_PROVING_RUNNER_IMAGE"))
	if runnerImg == "" {
		runnerImg = candidateImage
	}
	var targetSpecs []string
	for _, rc := range readyClones {
		targetSpecs = append(targetSpecs, fmt.Sprintf("%d|%s|%s", rc.index, rc.podName, rc.podIP))
	}
	provingScript := `
import json, os, sys, time, urllib.request, urllib.error

targets = os.environ["CLONE_TARGETS"].split(",")
port = int(os.environ.get("TARGET_PORT", "8080"))
max_p99 = float(os.environ.get("MAX_P99_MS", "250.0"))
all_ok = True

def get_url(url):
    t0 = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": "g1-warrant-clone-prover/1.3.0"})
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, (time.monotonic() - t0) * 1000.0
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body, (time.monotonic() - t0) * 1000.0

for item in targets:
    idx_s, name, ip = item.split("|", 2)
    base = f"http://{ip}:{port}"
    st_up, body_up, lat_up = get_url(base + "/healthz")
    svc_up = (st_up == 200)

    st_sm, body_sm, lat_sm = get_url(base + "/smoke")
    if st_sm == 404:
        st_sm, body_sm, lat_sm = get_url(base + "/")
    smoke_ok = svc_up and (200 <= st_sm < 300) and len(body_sm.strip()) > 0

    st_ac, body_ac, lat_ac = get_url(base + "/acceptance")
    if st_ac == 404:
        st_ac, body_ac, lat_ac = get_url(base + "/healthz")
    st_neg, body_neg, _ = get_url(base + "/exploit-probe-check")
    vuln_exposed = ("EXPLOIT_SUCCEEDED" in body_neg) or ("VULNERABLE_BUILD" in body_ac)
    max_lat = max(lat_up, lat_sm, lat_ac)
    acc_ok = smoke_ok and (200 <= st_ac < 300) and (not vuln_exposed) and (max_lat <= max_p99)

    if not (svc_up and smoke_ok and acc_ok):
        all_ok = False
    rec = {
        "clone_index": int(idx_s),
        "clone_name": name,
        "pod_ip": ip,
        "service_up": svc_up,
        "smoke_passed": smoke_ok,
        "acceptance_passed": acc_ok,
        "latency_ms": round(max_lat, 2),
        "detail": f"healthz={st_up} smoke={st_sm} acceptance={st_ac} neg_probe={st_neg}",
    }
    print("CLONE_PROVING_JSON " + json.dumps(rec, sort_keys=True), flush=True)

sys.exit(0 if all_ok else 1)
`
	runnerJobName := fmt.Sprintf("g1-prover-%s-%s", svcSlug, runHash)
	backoffZero := int32(0)
	jobManifest := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":      runnerJobName,
			"namespace": provingNS,
			"labels": map[string]string{
				"app.kubernetes.io/managed-by": "g1-warrant",
				"g1.warrant/proving-run":       provingRunID,
			},
		},
		"spec": map[string]any{
			"backoffLimit": backoffZero,
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]string{
						"job-name":                  runnerJobName,
						"g1.warrant/proving-runner": "true",
						"g1.warrant/proving-run":    provingRunID,
					},
				},
				"spec": map[string]any{
					"restartPolicy":                "Never",
					"automountServiceAccountToken": false,
					"containers": []map[string]any{
						{
							"name":            "proving-runner",
							"image":           runnerImg,
							"imagePullPolicy": "IfNotPresent",
							"command":         []string{"python3", "-c", provingScript},
							"env": []map[string]string{
								{"name": "CLONE_TARGETS", "value": strings.Join(targetSpecs, ",")},
								{"name": "TARGET_PORT", "value": strconv.Itoa(targetPort)},
								{"name": "MAX_P99_MS", "value": fmt.Sprintf("%.2f", maxP99)},
							},
						},
					},
				},
			},
		},
	}
	jobBytes, _ := json.Marshal(jobManifest)
	if _, err := k.doKubeRequest(ctx, http.MethodPost, fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs", provingNS), "application/json", jobBytes); err != nil {
		return nil, fmt.Errorf("CLONE_TWIN_RUNNER_CREATE_FAILED: %w", err)
	}
	defer func() {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = k.doKubeRequest(cleanCtx, http.MethodDelete, fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s?propagationPolicy=Background", provingNS, runnerJobName), "", nil)
	}()

	jobWaitCtx, cancelJobWait := context.WithTimeout(ctx, timeout)
	defer cancelJobWait()
	for {
		rawJob, gErr := k.doKubeRequest(jobWaitCtx, http.MethodGet, fmt.Sprintf("/apis/batch/v1/namespaces/%s/jobs/%s", provingNS, runnerJobName), "", nil)
		if gErr == nil {
			var jStatus struct {
				Status struct {
					Succeeded int `json:"succeeded"`
					Failed    int `json:"failed"`
				} `json:"status"`
			}
			if json.Unmarshal(rawJob, &jStatus) == nil && (jStatus.Status.Succeeded > 0 || jStatus.Status.Failed > 0) {
				break
			}
		}
		if jobWaitCtx.Err() != nil {
			return nil, fmt.Errorf("CLONE_TWIN_RUNNER_TIMEOUT: job %s timed out after %s", runnerJobName, timeout)
		}
		time.Sleep(pollInterval)
	}

	rawJobPods, err := k.doKubeRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=job-name=%s", provingNS, runnerJobName), "", nil)
	if err != nil {
		return nil, fmt.Errorf("CLONE_TWIN_RUNNER_POD_LOOKUP_FAILED: %w", err)
	}
	var jPods struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				ContainerStatuses []struct {
					State struct {
						Terminated *struct {
							ExitCode int `json:"exitCode"`
						} `json:"terminated"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rawJobPods, &jPods); err != nil || len(jPods.Items) == 0 {
		return nil, fmt.Errorf("CLONE_TWIN_RUNNER_POD_MISSING: %v", err)
	}
	runnerPodName := jPods.Items[0].Metadata.Name
	runnerExit := -1
	for _, cs := range jPods.Items[0].Status.ContainerStatuses {
		if cs.State.Terminated != nil {
			runnerExit = cs.State.Terminated.ExitCode
		}
	}
	runnerLogsBytes, err := k.doKubeRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log", provingNS, runnerPodName), "", nil)
	if err != nil {
		return nil, fmt.Errorf("CLONE_TWIN_RUNNER_LOGS_FAILED: %w", err)
	}
	runnerLogs := string(runnerLogsBytes)

	type parsedCloneLine struct {
		CloneIndex       int     `json:"clone_index"`
		CloneName        string  `json:"clone_name"`
		PodIP            string  `json:"pod_ip"`
		ServiceUp        bool    `json:"service_up"`
		SmokePassed      bool    `json:"smoke_passed"`
		AcceptancePassed bool    `json:"acceptance_passed"`
		LatencyMs        float64 `json:"latency_ms"`
		Detail           string  `json:"detail"`
	}
	byIdx := map[int]parsedCloneLine{}
	for _, line := range strings.Split(runnerLogs, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "CLONE_PROVING_JSON ") {
			var pl parsedCloneLine
			if json.Unmarshal([]byte(strings.TrimPrefix(l, "CLONE_PROVING_JSON ")), &pl) == nil {
				byIdx[pl.CloneIndex] = pl
			}
		}
	}

	var transcript strings.Builder
	transcript.WriteString(fmt.Sprintf("=== PROVING_RUNNER (%s | pod=%s | exit=%d) ===\n%s\n", runnerJobName, runnerPodName, runnerExit, runnerLogs))

	cloneResults := make([]models.CloneTwinInstanceResult, 0, cloneCount)
	upCount, smokeCount, accCount := 0, 0, 0
	failureReason := ""
	for _, rc := range readyClones {
		cLogBytes, _ := k.doKubeRequest(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log", provingNS, rc.podName), "", nil)
		cLogStr := strings.TrimSpace(string(cLogBytes))
		transcript.WriteString(fmt.Sprintf("=== CLONE_%d (%s | ip=%s | digest=%s) ===\n%s\n", rc.index, rc.podName, rc.podIP, rc.runningDigest, cLogStr))

		pl, ok := byIdx[rc.index]
		exitCode := 0
		if !ok || !pl.ServiceUp || !pl.SmokePassed || !pl.AcceptancePassed || runnerExit != 0 {
			exitCode = max(1, runnerExit)
			if failureReason == "" {
				failureReason = "CLONE_PROVING_SUITE_FAILED"
			}
		}
		if pl.ServiceUp {
			upCount++
		}
		if pl.SmokePassed {
			smokeCount++
		}
		if pl.AcceptancePassed {
			accCount++
		}
		summary := pl.Detail
		if summary == "" {
			summary = "missing structured runner verdict"
		}
		evMaterial := fmt.Sprintf("%s|%s|%s|%t|%t|%t|%.2f|%s", rc.podName, rc.podIP, rc.runningDigest, pl.ServiceUp, pl.SmokePassed, pl.AcceptancePassed, pl.LatencyMs, cLogStr)
		cloneResults = append(cloneResults, models.CloneTwinInstanceResult{
			CloneIndex:            rc.index,
			CloneName:             rc.podName,
			NodeOrHost:            rc.nodeName,
			PodIP:                 rc.podIP,
			RunningDigest:         rc.runningDigest,
			ServiceUpPassed:       pl.ServiceUp,
			SmokeTestPassed:       pl.SmokePassed,
			ClassAcceptancePassed: pl.AcceptancePassed,
			ObservedLatencyMs:     pl.LatencyMs,
			ExitCode:              exitCode,
			EvidenceSHA256:        crypto.SHA256Hex([]byte(evMaterial)),
			LogSummary:            summary,
		})
	}

	allPassed := runnerExit == 0 && upCount == cloneCount && smokeCount == cloneCount && accCount == cloneCount
	return &models.CloneTwinProvingManifest{
		ProvingRunID:          provingRunID,
		RemediationID:         req.RemediationID,
		ServiceID:             req.ServiceID,
		WarrantID:             req.WarrantID,
		WarrantClass:          req.WarrantClass,
		CVEID:                 req.CVEID,
		CandidateDigest:       req.CandidateDigest,
		PatchTargetLayer:      models.PatchTargetLayerUserspace,
		TwinRuntime:           models.TwinRuntimeContainer,
		ProvingNamespace:      provingNS,
		ZeroProductionEgress:  true,
		CloneCount:            cloneCount,
		ServicesUpCount:       upCount,
		SmokePassedCount:      smokeCount,
		AcceptancePassedCount: accCount,
		AllPassed:             allPassed,
		FailureReasonCode:     failureReason,
		Clones:                cloneResults,
		TranscriptSHA256:      crypto.SHA256Hex([]byte(transcript.String())),
		ProvedAt:              time.Now().UTC(),
	}, nil
}
