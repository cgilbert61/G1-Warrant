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

// CloudFamilyEstateReader serves both Cloud Inventory systems (Family b — TIER_A_MACHINE):
//   - aws-ssm (AWS SSM Inventory GetInventory + EC2 QA AMI catalog)
//   - gcp-os-config (GCP Cloud Asset / OS Config instanceOSPoliciesCompliance + GCE Machine Images)
type CloudFamilyEstateReader struct {
	baseEstateHTTPClient
	variant string // "aws-ssm" | "gcp-os-config"
}

func NewCloudFamilyEstateReader(
	variant, displayName, envPrefix, readURL, readToken, dispatchToken string,
	rt http.RoundTripper,
) *CloudFamilyEstateReader {
	return &CloudFamilyEstateReader{
		baseEstateHTTPClient: newBaseEstateHTTPClient(
			variant,
			displayName,
			models.EstateSourceTierAMachine,
			models.EstateHandlerFamilyCloud,
			envPrefix,
			readURL,
			readToken,
			dispatchToken,
			rt,
		),
		variant: variant,
	}
}

func (c *CloudFamilyEstateReader) WithTransport(rt http.RoundTripper) EstateReader {
	cp := *c
	cp.baseEstateHTTPClient = c.baseEstateHTTPClient.cloneWithTransport(rt)
	return &cp
}

type cloudInventoryWirePayload struct {
	TotalInstances int                     `json:"total_instances"`
	CaptureTime    string                  `json:"capture_time"`
	UpdateTime     string                  `json:"updateTime"`
	OSBuckets      []microsoftOSWireRow    `json:"os_buckets"`
	Packages       []microsoftSWWireRow    `json:"packages"`
	CandidateAMIs  []microsoftImageWireRow `json:"candidate_images"`
	Entities       []map[string]any        `json:"Entities"`
	Items          []map[string]any        `json:"instanceOSPoliciesCompliances"`
}

func (c *CloudFamilyEstateReader) ReadEstateSnapshot(ctx context.Context, q EstateReadQuery) (*models.EstateSnapshot, error) {
	now := time.Now().UTC()
	queryID := ComputeCanonicalQueryIdentity(c.sourceSystem, q)

	var raw []byte
	var err error
	switch c.variant {
	case "aws-ssm":
		raw, err = c.doReadRequest(ctx, http.MethodPost, "/ssm/GetInventory", map[string]any{
			"Filters": []map[string]any{
				{"Key": "AWS:InstanceInformation.InstanceStatus", "Values": []string{"Active"}, "Type": "Equal"},
			},
			"WarrantClass":  q.WarrantClass,
			"ScopeServices": q.ScopeServices,
		})
	case "gcp-os-config":
		scopeParam := url.QueryEscape(strings.Join(q.ScopeServices, ","))
		raw, err = c.doReadRequest(ctx, http.MethodGet,
			fmt.Sprintf("/v1/projects/default/locations/global/instanceOSPoliciesCompliances?warrant_class=%s&scope=%s",
				url.QueryEscape(q.WarrantClass), scopeParam), nil)
	default:
		return nil, fmt.Errorf("UNSUPPORTED_CLOUD_ESTATE_VARIANT: %s", c.variant)
	}
	if err != nil {
		return nil, err
	}

	var wire cloudInventoryWirePayload
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("ESTATE_READ_PARSE_ERROR (%s): %w", c.sourceSystem, err)
	}

	snap := &models.EstateSnapshot{
		SourceSystem:         c.sourceSystem,
		SourceTier:           models.EstateSourceTierAMachine,
		HandlerFamily:        models.EstateHandlerFamilyCloud,
		QueryIdentity:        queryID,
		ClassScope:           q.ScopeServices,
		ClassMembershipCount: wire.TotalInstances,
	}

	defaultPlat := "LINUX_RPM"
	if c.variant == "gcp-os-config" {
		defaultPlat = "LINUX_DEB"
	}

	for _, o := range wire.OSBuckets {
		snap.OSBuildKernelDistribution = append(snap.OSBuildKernelDistribution, models.OSKernelBucket{
			OSFamily:         firstStr(o.OSFamily, "LINUX"),
			OSVersionOrBuild: o.OSBuild,
			KernelRelease:    o.Kernel,
			CPE23:            o.CPE23,
			Count:            o.Count,
		})
	}
	for _, p := range wire.Packages {
		snap.SoftwareVersionDistribution = append(snap.SoftwareVersionDistribution, models.SoftwareBucket{
			ComponentName: p.Name,
			Version:       p.Version,
			CPE23:         p.CPE23,
			SWIDTagID:     p.SWIDTagID,
			PURL:          p.PURL,
			Count:         p.Count,
		})
	}
	for _, im := range wire.CandidateAMIs {
		if strings.TrimSpace(im.ImageID) == "" {
			continue
		}
		snap.CandidateCloneSources = append(snap.CandidateCloneSources, models.CloneSourceCandidate{
			SourceSystem:      c.sourceSystem,
			ImageIdentity:     im.ImageID,
			PlatformFamily:    firstStr(im.PlatformFamily, defaultPlat),
			PatchTargetLayers: []string{models.PatchTargetLayerUserspace, models.PatchTargetLayerKernel, models.PatchTargetLayerBoot},
			CreatedAt:         firstStr(im.CreatedAt, now.Add(-36*time.Hour).Format(time.RFC3339)),
			Tags:              im.Tags,
		})
	}

	// Native AWS SSM `Entities` or GCP `instanceOSPoliciesCompliances` fallback normalization
	rows := wire.Entities
	if len(rows) == 0 {
		rows = wire.Items
	}
	freshStr := firstStr(wire.CaptureTime, wire.UpdateTime)
	if len(rows) > 0 {
		osMap := map[string]*models.OSKernelBucket{}
		for _, r := range rows {
			cnt := intFromMap(r, "count", 1)
			snap.ClassMembershipCount += cnt
			osFam := strFromMap(r, "PlatformType", "osLongName", "LINUX")
			osVer := strFromMap(r, "PlatformVersion", "osVersion", "2023")
			kern := strFromMap(r, "KernelRelease", "kernelVersion", "6.1.92")
			k := osFam + "|" + osVer + "|" + kern
			if b, ok := osMap[k]; ok {
				b.Count += cnt
			} else {
				osMap[k] = &models.OSKernelBucket{
					OSFamily: osFam, OSVersionOrBuild: osVer, KernelRelease: kern,
					CPE23: strFromMap(r, "cpe23", ""), Count: cnt,
				}
			}
			if img := strFromMap(r, "qaImageId", "sourceMachineImage", ""); img != "" {
				snap.CandidateCloneSources = append(snap.CandidateCloneSources, models.CloneSourceCandidate{
					SourceSystem:      c.sourceSystem,
					ImageIdentity:     img,
					PlatformFamily:    defaultPlat,
					PatchTargetLayers: []string{models.PatchTargetLayerUserspace, models.PatchTargetLayerKernel, models.PatchTargetLayerBoot},
					CreatedAt:         firstStr(strFromMap(r, "imageCreatedAt", ""), now.Add(-24*time.Hour).Format(time.RFC3339)),
				})
			}
			if freshStr == "" {
				freshStr = strFromMap(r, "CaptureTime", "updateTime", "")
			}
		}
		if len(snap.OSBuildKernelDistribution) == 0 {
			for _, b := range osMap {
				snap.OSBuildKernelDistribution = append(snap.OSBuildKernelDistribution, *b)
			}
		}
	}

	if snap.ClassMembershipCount == 0 {
		for _, b := range snap.OSBuildKernelDistribution {
			snap.ClassMembershipCount += b.Count
		}
	}
	snap.SourceInventoryFreshnessAt = parseFlexibleTimestamp(freshStr, now)
	if err := FinalizeEstateSnapshot(snap, now); err != nil {
		return nil, err
	}
	return snap, nil
}
