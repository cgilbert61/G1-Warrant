package estatereader

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// LocalK8sWorkloadReader allows the unified Kubernetes handler family to inspect local cluster/simulator EstateServices
// when no remote WARRANT_KUBE_READ_URL is configured (preserving fail-closed semantics if the local reader errors).
type LocalK8sWorkloadReader func(ctx context.Context, scopeServices []string) ([]models.EstateService, error)

// KubernetesFamilyEstateReader is ONE unified handler serving all 3 Kubernetes-native systems (Family c — TIER_B_WORKLOAD):
//   - k8s-cilium-native (Kubernetes API Deployments/Pods + staging namespace OCI digests)
//   - argocd (Argo CD Application controller + K8s workload imageID digests)
//   - flux (Flux Kustomization/HelmRelease OCI repository digests + K8s workloads)
type KubernetesFamilyEstateReader struct {
	baseEstateHTTPClient
	variant        string // "k8s-cilium-native" | "argocd" | "flux"
	localInspector LocalK8sWorkloadReader
}

func NewKubernetesFamilyEstateReader(
	variant, displayName, envPrefix, readURL, readToken, dispatchToken string,
	localInspector LocalK8sWorkloadReader,
	rt http.RoundTripper,
) *KubernetesFamilyEstateReader {
	return &KubernetesFamilyEstateReader{
		baseEstateHTTPClient: newBaseEstateHTTPClient(
			variant,
			displayName,
			models.EstateSourceTierBWorkload,
			models.EstateHandlerFamilyKubernetes,
			envPrefix,
			readURL,
			readToken,
			dispatchToken,
			rt,
		),
		variant:        variant,
		localInspector: localInspector,
	}
}

func (k *KubernetesFamilyEstateReader) ReadConfigured() bool {
	return k.readURL != "" || (k.variant == "k8s-cilium-native" && k.localInspector != nil)
}

func (k *KubernetesFamilyEstateReader) WithTransport(rt http.RoundTripper) EstateReader {
	cp := *k
	cp.baseEstateHTTPClient = k.baseEstateHTTPClient.cloneWithTransport(rt)
	return &cp
}

type k8sInventoryWirePayload struct {
	TotalPods      int                     `json:"total_pods"`
	FreshnessAt    string                  `json:"freshness_at"`
	RuntimeBuckets []microsoftOSWireRow    `json:"runtime_buckets"`
	ImageDigests   []microsoftSWWireRow    `json:"image_digests"`
	StagingSources []microsoftImageWireRow `json:"staging_clone_sources"`
	Items          []struct {
		Metadata struct {
			Name              string `json:"name"`
			Namespace         string `json:"namespace"`
			CreationTimestamp string `json:"creationTimestamp"`
		} `json:"metadata"`
		Spec struct {
			Replicas int `json:"replicas"`
		} `json:"spec"`
		Status struct {
			ReadyReplicas int    `json:"readyReplicas"`
			ImageID       string `json:"imageID"`
			StagingDigest string `json:"stagingDigest"`
			NodeKernel    string `json:"nodeKernel"`
		} `json:"status"`
	} `json:"items"`
}

func (k *KubernetesFamilyEstateReader) ReadEstateSnapshot(ctx context.Context, q EstateReadQuery) (*models.EstateSnapshot, error) {
	if err := k.ValidateReadCredentialSeparation(""); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	queryID := ComputeCanonicalQueryIdentity(k.sourceSystem, q)

	// Path 1: Remote HTTP Kubernetes / Argo CD / Flux read-only API endpoint
	if k.readURL != "" {
		scopeParam := url.QueryEscape(strings.Join(q.ScopeServices, ","))
		var route string
		switch k.variant {
		case "k8s-cilium-native":
			route = fmt.Sprintf("/apis/apps/v1/deployments?labelSelector=warrant-class%%3D%s&scope=%s", url.QueryEscape(q.WarrantClass), scopeParam)
		case "argocd":
			route = fmt.Sprintf("/api/v1/applications?selector=warrant-class%%3D%s&scope=%s", url.QueryEscape(q.WarrantClass), scopeParam)
		case "flux":
			route = fmt.Sprintf("/v1/flux/inventory?warrant_class=%s&scope=%s", url.QueryEscape(q.WarrantClass), scopeParam)
		default:
			return nil, fmt.Errorf("UNSUPPORTED_K8S_ESTATE_VARIANT: %s", k.variant)
		}
		raw, err := k.doReadRequest(ctx, http.MethodGet, route, nil)
		if err != nil {
			return nil, err
		}
		var wire k8sInventoryWirePayload
		if err := json.Unmarshal(raw, &wire); err != nil {
			return nil, fmt.Errorf("ESTATE_READ_PARSE_ERROR (%s): %w", k.sourceSystem, err)
		}

		snap := &models.EstateSnapshot{
			SourceSystem:         k.sourceSystem,
			SourceTier:           models.EstateSourceTierBWorkload,
			HandlerFamily:        models.EstateHandlerFamilyKubernetes,
			QueryIdentity:        queryID,
			ClassScope:           q.ScopeServices,
			ClassMembershipCount: wire.TotalPods,
		}
		for _, rb := range wire.RuntimeBuckets {
			snap.OSBuildKernelDistribution = append(snap.OSBuildKernelDistribution, models.OSKernelBucket{
				OSFamily:         firstStr(rb.OSFamily, "CONTAINER_LINUX"),
				OSVersionOrBuild: rb.OSBuild,
				KernelRelease:    rb.Kernel,
				CPE23:            rb.CPE23,
				Count:            rb.Count,
			})
		}
		for _, im := range wire.ImageDigests {
			snap.SoftwareVersionDistribution = append(snap.SoftwareVersionDistribution, models.SoftwareBucket{
				ComponentName: im.Name,
				Version:       im.Version,
				CPE23:         im.CPE23,
				SWIDTagID:     im.SWIDTagID,
				PURL:          im.PURL,
				Count:         im.Count,
			})
		}
		for _, st := range wire.StagingSources {
			if strings.TrimSpace(st.ImageID) == "" {
				continue
			}
			snap.CandidateCloneSources = append(snap.CandidateCloneSources, models.CloneSourceCandidate{
				SourceSystem:      k.sourceSystem,
				ImageIdentity:     st.ImageID,
				PlatformFamily:    firstStr(st.PlatformFamily, "CONTAINER_LINUX"),
				PatchTargetLayers: []string{models.PatchTargetLayerUserspace},
				CreatedAt:         firstStr(st.CreatedAt, now.Add(-12*time.Hour).Format(time.RFC3339)),
				Tags:              st.Tags,
			})
		}
		for _, item := range wire.Items {
			reps := item.Status.ReadyReplicas
			if reps <= 0 {
				reps = maxInt(item.Spec.Replicas, 1)
			}
			snap.ClassMembershipCount += reps
			snap.OSBuildKernelDistribution = append(snap.OSBuildKernelDistribution, models.OSKernelBucket{
				OSFamily:         "CONTAINER_LINUX",
				OSVersionOrBuild: "distroless-static-debian12",
				KernelRelease:    firstStr(item.Status.NodeKernel, "6.6.32-k8s"),
				CPE23:            "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*",
				Count:            reps,
			})
			if item.Status.ImageID != "" {
				snap.SoftwareVersionDistribution = append(snap.SoftwareVersionDistribution, models.SoftwareBucket{
					ComponentName: item.Metadata.Name,
					Version:       item.Status.ImageID,
					PURL:          fmt.Sprintf("pkg:oci/%s@%s", item.Metadata.Name, item.Status.ImageID),
					Count:         reps,
				})
			}
			candDigest := firstStr(item.Status.StagingDigest, item.Status.ImageID)
			if candDigest != "" {
				snap.CandidateCloneSources = append(snap.CandidateCloneSources, models.CloneSourceCandidate{
					SourceSystem:      k.sourceSystem,
					ImageIdentity:     candDigest,
					PlatformFamily:    "CONTAINER_LINUX",
					PatchTargetLayers: []string{models.PatchTargetLayerUserspace},
					CreatedAt:         firstStr(item.Metadata.CreationTimestamp, now.Add(-6*time.Hour).Format(time.RFC3339)),
					Tags:              map[string]string{"namespace": item.Metadata.Namespace, "deployment": item.Metadata.Name},
				})
			}
		}
		snap.SourceInventoryFreshnessAt = parseFlexibleTimestamp(wire.FreshnessAt, now)
		if err := FinalizeEstateSnapshot(snap, now); err != nil {
			return nil, err
		}
		return snap, nil
	}

	// Path 2: Local cluster/simulator workload state reader (only for k8s-cilium-native when wired)
	if k.variant == "k8s-cilium-native" && k.localInspector != nil {
		svcs, err := k.localInspector(ctx, q.ScopeServices)
		if err != nil {
			return nil, fmt.Errorf("ESTATE_READ_UNAVAILABLE (%s): %w", k.sourceSystem, err)
		}
		if len(svcs) == 0 {
			return nil, fmt.Errorf("ESTATE_READ_UNAVAILABLE (%s): zero matching workloads in scope", k.sourceSystem)
		}
		snap := &models.EstateSnapshot{
			SourceSystem:  k.sourceSystem,
			SourceTier:    models.EstateSourceTierBWorkload,
			HandlerFamily: models.EstateHandlerFamilyKubernetes,
			QueryIdentity: queryID,
			ClassScope:    q.ScopeServices,
		}
		var latestUpdate time.Time
		totalReplicas := 0
		for _, svc := range svcs {
			reps := maxInt(svc.Replicas, 1)
			totalReplicas += reps
			snap.SoftwareVersionDistribution = append(snap.SoftwareVersionDistribution, models.SoftwareBucket{
				ComponentName: svc.ServiceID,
				Version:       svc.CurrentDigest,
				PURL:          firstStr(svc.CurrentPURL, fmt.Sprintf("pkg:oci/%s@%s", svc.ServiceID, svc.CurrentDigest)),
				Count:         reps,
			})
			createdTs := svc.UpdatedAt
			if createdTs.IsZero() {
				createdTs = now.Add(-2 * time.Hour)
			}
			if createdTs.After(latestUpdate) {
				latestUpdate = createdTs
			}
			snap.CandidateCloneSources = append(snap.CandidateCloneSources, models.CloneSourceCandidate{
				SourceSystem:      k.sourceSystem,
				ImageIdentity:     svc.CurrentDigest,
				PlatformFamily:    "CONTAINER_LINUX",
				PatchTargetLayers: []string{models.PatchTargetLayerUserspace},
				CreatedAt:         createdTs.UTC().Format(time.RFC3339),
				Tags:              map[string]string{"namespace": svc.Namespace, "service_id": svc.ServiceID},
			})
		}
		snap.ClassMembershipCount = totalReplicas
		snap.OSBuildKernelDistribution = []models.OSKernelBucket{
			{
				OSFamily:         "CONTAINER_LINUX",
				OSVersionOrBuild: "distroless-debian12",
				KernelRelease:    "6.6.32-k8s",
				CPE23:            "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*",
				Count:            totalReplicas,
			},
		}
		if latestUpdate.IsZero() {
			latestUpdate = now
		}
		snap.SourceInventoryFreshnessAt = latestUpdate
		if err := FinalizeEstateSnapshot(snap, now); err != nil {
			return nil, err
		}
		return snap, nil
	}

	return nil, fmt.Errorf("ESTATE_READ_UNAVAILABLE (%s): %s_READ_URL is not configured", k.sourceSystem, k.readEnvPrefix)
}
