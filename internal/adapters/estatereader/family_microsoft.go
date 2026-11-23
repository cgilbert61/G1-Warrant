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

// MicrosoftFamilyEstateReader serves all 4 Microsoft Estate systems (Family a — TIER_A_MACHINE):
//   - ms-intune (Microsoft Graph managedDevices + golden Autopilot/Windows image profiles)
//   - azure-update-manager (Azure Resource Graph patchinstallationresources + Compute Managed Images)
//   - ms-mecm (ConfigMgr AdminService CIM SMS_G_System_* hardware/OS/software inventory + SMS_ImagePackage)
//   - ms-wsus (WSUS computer target group summaries + baseline QA VHDX images)
type MicrosoftFamilyEstateReader struct {
	baseEstateHTTPClient
	variant string // "ms-intune" | "azure-update-manager" | "ms-mecm" | "ms-wsus"
}

func NewMicrosoftFamilyEstateReader(
	variant, displayName, envPrefix, readURL, readToken, dispatchToken string,
	rt http.RoundTripper,
) *MicrosoftFamilyEstateReader {
	return &MicrosoftFamilyEstateReader{
		baseEstateHTTPClient: newBaseEstateHTTPClient(
			variant,
			displayName,
			models.EstateSourceTierAMachine,
			models.EstateHandlerFamilyMicrosoft,
			envPrefix,
			readURL,
			readToken,
			dispatchToken,
			rt,
		),
		variant: variant,
	}
}

func (m *MicrosoftFamilyEstateReader) WithTransport(rt http.RoundTripper) EstateReader {
	cp := *m
	cp.baseEstateHTTPClient = m.baseEstateHTTPClient.cloneWithTransport(rt)
	return &cp
}

type microsoftEstateWirePayload struct {
	// Shared/normalized fields + Graph (`value`) + AdminService (`value`) + Azure Resource Graph (`data`)
	TotalCount       int                      `json:"total_count"`
	FreshnessAt      string                   `json:"freshness_at"`
	LastSyncDateTime string                   `json:"lastSyncDateTime"`
	OSDistribution   []microsoftOSWireRow     `json:"os_distribution"`
	Software         []microsoftSWWireRow     `json:"software_distribution"`
	Images           []microsoftImageWireRow  `json:"images"`
	Value            []map[string]any         `json:"value"`
	Data             []map[string]any         `json:"data"`
}

type microsoftOSWireRow struct {
	OSFamily  string `json:"os_family"`
	OSBuild   string `json:"os_build"`
	Kernel    string `json:"kernel_release"`
	CPE23     string `json:"cpe23"`
	Count     int    `json:"count"`
}

type microsoftSWWireRow struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	CPE23     string `json:"cpe23"`
	SWIDTagID string `json:"swid_tag_id"`
	PURL      string `json:"purl"`
	Count     int    `json:"count"`
}

type microsoftImageWireRow struct {
	ImageID        string            `json:"image_id"`
	PlatformFamily string            `json:"platform_family"`
	CreatedAt      string            `json:"created_at"`
	Tags           map[string]string `json:"tags"`
}

func (m *MicrosoftFamilyEstateReader) ReadEstateSnapshot(ctx context.Context, q EstateReadQuery) (*models.EstateSnapshot, error) {
	now := time.Now().UTC()
	queryID := ComputeCanonicalQueryIdentity(m.sourceSystem, q)
	scopeParam := url.QueryEscape(strings.Join(q.ScopeServices, ","))
	clsParam := url.QueryEscape(q.WarrantClass)

	var raw []byte
	var err error
	switch m.variant {
	case "ms-intune":
		raw, err = m.doReadRequest(ctx, http.MethodGet,
			fmt.Sprintf("/v1.0/deviceManagement/managedDevices?$select=operatingSystem,osVersion,lastSyncDateTime&warrantClass=%s&scope=%s", clsParam, scopeParam), nil)
	case "azure-update-manager":
		raw, err = m.doReadRequest(ctx, http.MethodPost,
			"/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01",
			map[string]any{
				"query":        fmt.Sprintf("patchinstallationresources | where properties.warrantClass == '%s'", q.WarrantClass),
				"scope_filter": q.ScopeServices,
			})
	case "ms-mecm":
		raw, err = m.doReadRequest(ctx, http.MethodGet,
			fmt.Sprintf("/AdminService/v1.0/SMS_G_System_OPERATING_SYSTEM?$filter=WarrantClass%%20eq%%20'%s'&scope=%s", clsParam, scopeParam), nil)
	case "ms-wsus":
		raw, err = m.doReadRequest(ctx, http.MethodGet,
			fmt.Sprintf("/wsus/v1/computers/summary?warrant_class=%s&scope=%s", clsParam, scopeParam), nil)
	default:
		return nil, fmt.Errorf("UNSUPPORTED_MICROSOFT_ESTATE_VARIANT: %s", m.variant)
	}
	if err != nil {
		return nil, err
	}

	var wire microsoftEstateWirePayload
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("ESTATE_READ_PARSE_ERROR (%s): %w", m.sourceSystem, err)
	}

	snap := &models.EstateSnapshot{
		SourceSystem:         m.sourceSystem,
		SourceTier:           models.EstateSourceTierAMachine,
		HandlerFamily:        models.EstateHandlerFamilyMicrosoft,
		QueryIdentity:        queryID,
		ClassScope:           q.ScopeServices,
		ClassMembershipCount: wire.TotalCount,
	}

	freshStr := wire.FreshnessAt
	if freshStr == "" {
		freshStr = wire.LastSyncDateTime
	}

	for _, o := range wire.OSDistribution {
		snap.OSBuildKernelDistribution = append(snap.OSBuildKernelDistribution, models.OSKernelBucket{
			OSFamily:         firstStr(o.OSFamily, "WINDOWS"),
			OSVersionOrBuild: o.OSBuild,
			KernelRelease:    o.Kernel,
			CPE23:            o.CPE23,
			Count:            o.Count,
		})
	}
	for _, sw := range wire.Software {
		snap.SoftwareVersionDistribution = append(snap.SoftwareVersionDistribution, models.SoftwareBucket{
			ComponentName: sw.Name,
			Version:       sw.Version,
			CPE23:         sw.CPE23,
			SWIDTagID:     sw.SWIDTagID,
			PURL:          sw.PURL,
			Count:         sw.Count,
		})
	}
	for _, im := range wire.Images {
		if strings.TrimSpace(im.ImageID) == "" {
			continue
		}
		snap.CandidateCloneSources = append(snap.CandidateCloneSources, models.CloneSourceCandidate{
			SourceSystem:      m.sourceSystem,
			ImageIdentity:     im.ImageID,
			PlatformFamily:    firstStr(im.PlatformFamily, "WINDOWS_SERVER"),
			PatchTargetLayers: []string{models.PatchTargetLayerUserspace, models.PatchTargetLayerKernel, models.PatchTargetLayerBoot},
			CreatedAt:         firstStr(im.CreatedAt, now.Add(-24*time.Hour).Format(time.RFC3339)),
			Tags:              im.Tags,
		})
	}
	seenImages := map[string]bool{}
	for _, c := range snap.CandidateCloneSources {
		seenImages[c.ImageIdentity] = true
	}

	// Also support native OData `value` (Graph / ConfigMgr AdminService) and Resource Graph `data` arrays
	rows := wire.Value
	if len(rows) == 0 {
		rows = wire.Data
	}
	if len(rows) > 0 {
		osCounts := map[string]*models.OSKernelBucket{}
		swCounts := map[string]*models.SoftwareBucket{}
		total := 0
		for rowIdx, r := range rows {
			cnt := intFromMap(r, "count", 1)
			total += cnt
			osFam := strFromMap(r, "operatingSystem", "Caption0", "osName", "os_family", "WINDOWS")
			osVer := strFromMap(r, "osVersion", "BuildNumber0", "osBuild", "os_version", "10.0.20348")
			kern := strFromMap(r, "kernelRelease", "CSDVersion0", "kernel_release", "")
			cpe := strFromMap(r, "cpe23", "osCpe23", "")
			key := osFam + "|" + osVer + "|" + kern
			if b, ok := osCounts[key]; ok {
				b.Count += cnt
			} else {
				osCounts[key] = &models.OSKernelBucket{
					OSFamily: osFam, OSVersionOrBuild: osVer, KernelRelease: kern, CPE23: cpe, Count: cnt,
				}
			}
			swName := strFromMap(r, "softwareName", "ProductName0", "kbPackage", "")
			swVer := strFromMap(r, "softwareVersion", "ProductVersion0", "version", "1.0")
			if swName != "" {
				swKey := swName + "|" + swVer
				if sb, ok := swCounts[swKey]; ok {
					sb.Count += cnt
				} else {
					swCounts[swKey] = &models.SoftwareBucket{
						ComponentName: swName,
						Version:       swVer,
						CPE23:         strFromMap(r, "softwareCpe23", ""),
						SWIDTagID:     strFromMap(r, "swidTagId", "SoftwareCode0", ""),
						PURL:          strFromMap(r, "purl", ""),
						Count:         cnt,
					}
				}
			}
			imgID := strFromMap(r, "qaImageId", "ImagePackageID", "sourceImageId", "baselineVhdx", "")
			imgCreated := firstStr(strFromMap(r, "imageCreatedAt", ""), now.Add(-48*time.Hour).Format(time.RFC3339))
			platFam := firstStr(strFromMap(r, "platformFamily", ""), "WINDOWS_SERVER")
			if imgID != "" && !seenImages[imgID] {
				seenImages[imgID] = true
				snap.CandidateCloneSources = append(snap.CandidateCloneSources, models.CloneSourceCandidate{
					SourceSystem:      m.sourceSystem,
					ImageIdentity:     imgID,
					PlatformFamily:    platFam,
					PatchTargetLayers: []string{models.PatchTargetLayerUserspace, models.PatchTargetLayerKernel, models.PatchTargetLayerBoot},
					CreatedAt:         imgCreated,
				})
			}
			host := strFromMap(r, "deviceName", "Name0", "FullDomainName", "hostname", "name", "")
			srvID := strFromMap(r, "id", "ResourceID", "computerTargetId", "server_id", "")
			if host != "" || srvID != "" {
				twinImg := imgID
				if twinImg == "" && len(snap.CandidateCloneSources) > 0 {
					twinImg = snap.CandidateCloneSources[0].ImageIdentity
				}
				if twinImg != "" {
					if srvID == "" {
						srvID = fmt.Sprintf("%s-srv-%02d", m.sourceSystem, rowIdx+1)
					}
					if host == "" {
						host = srvID
					}
					pkgSummary := swName
					if swName != "" && swVer != "" {
						pkgSummary = swName + " " + swVer
					}
					snap.EphemeralServers = append(snap.EphemeralServers, models.EstateSelectableServer{
						ServerID:          srvID,
						Hostname:          host,
						ServiceID:         strFromMap(r, "serviceId", "service_id", ""),
						SourceSystem:      m.sourceSystem,
						OSFamily:          osFam,
						OSVersionOrBuild:  osVer,
						KernelRelease:     kern,
						PrimaryPackage:    pkgSummary,
						TwinImageIdentity: twinImg,
						PlatformFamily:    platFam,
						ImageCreatedAt:    imgCreated,
					})
				}
			}
			if freshStr == "" {
				freshStr = strFromMap(r, "lastSyncDateTime", "LastHWScan", "lastReportedStatusTime", "lastModifiedDateTime", "")
			}
		}
		if snap.ClassMembershipCount == 0 {
			snap.ClassMembershipCount = total
		}
		if len(snap.OSBuildKernelDistribution) == 0 {
			for _, b := range osCounts {
				snap.OSBuildKernelDistribution = append(snap.OSBuildKernelDistribution, *b)
			}
		}
		if len(snap.SoftwareVersionDistribution) == 0 {
			for _, sb := range swCounts {
				snap.SoftwareVersionDistribution = append(snap.SoftwareVersionDistribution, *sb)
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

func firstStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func strFromMap(m map[string]any, keysAndDefault ...string) string {
	if len(keysAndDefault) == 0 {
		return ""
	}
	def := keysAndDefault[len(keysAndDefault)-1]
	for _, k := range keysAndDefault[:len(keysAndDefault)-1] {
		if v, ok := m[k]; ok && v != nil {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return def
}

func intFromMap(m map[string]any, key string, def int) int {
	if v, ok := m[key]; ok && v != nil {
		switch tv := v.(type) {
		case float64:
			return int(tv)
		case int:
			return tv
		case int64:
			return int(tv)
		}
	}
	return def
}
