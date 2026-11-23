package estatereader

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/extractor/finders"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// ScannerCensusEstateReader serves all 3 WN-7 Vulnerability Scanners (Family e — TIER_C_CENSUS):
//   - qualys_vmdr (Qualys VMDR Host Detection XML / JSON v2)
//   - tenable (Tenable.io / Tenable.sc Vulnerability Export JSON)
//   - rapid7_insightvm (Rapid7 InsightVM v3 Asset-Vulnerability JSON)
//
// Rides the existing WN-7 zero-egress FinderTranslator layer to extract corroborating asset-inventory
// census counts ONLY. CandidateCloneSources is unconditionally empty ([]): scanners never propose clone sources.
type ScannerCensusEstateReader struct {
	baseEstateHTTPClient
	vendorSlug string
}

func NewScannerCensusEstateReader(
	sourceSystem, displayName, envPrefix, readURL, readToken, intakeOrDispatchToken string,
	rt http.RoundTripper,
) *ScannerCensusEstateReader {
	return &ScannerCensusEstateReader{
		baseEstateHTTPClient: newBaseEstateHTTPClient(
			sourceSystem,
			displayName,
			models.EstateSourceTierCCensus,
			models.EstateHandlerFamilyScanners,
			envPrefix,
			readURL,
			readToken,
			intakeOrDispatchToken,
			rt,
		),
		vendorSlug: sourceSystem,
	}
}

func (s *ScannerCensusEstateReader) WithTransport(rt http.RoundTripper) EstateReader {
	cp := *s
	cp.baseEstateHTTPClient = s.baseEstateHTTPClient.cloneWithTransport(rt)
	return &cp
}

func (s *ScannerCensusEstateReader) ReadEstateSnapshot(ctx context.Context, q EstateReadQuery) (*models.EstateSnapshot, error) {
	now := time.Now().UTC()
	queryID := ComputeCanonicalQueryIdentity(s.sourceSystem, q)

	translator, err := finders.LookupTranslator(s.vendorSlug)
	if err != nil {
		return nil, err
	}

	var route string
	scopeParam := url.QueryEscape(strings.Join(q.ScopeServices, ","))
	clsParam := url.QueryEscape(q.WarrantClass)
	switch s.sourceSystem {
	case "qualys_vmdr":
		route = fmt.Sprintf("/api/2.0/fo/asset/host/vm/detection/?action=list&warrant_class=%s&scope=%s", clsParam, scopeParam)
	case "tenable":
		route = fmt.Sprintf("/vulns/export/census?warrant_class=%s&scope=%s", clsParam, scopeParam)
	case "rapid7_insightvm":
		route = fmt.Sprintf("/api/3/assets?warrant_class=%s&scope=%s", clsParam, scopeParam)
	default:
		route = fmt.Sprintf("/census?warrant_class=%s&scope=%s", clsParam, scopeParam)
	}

	raw, err := s.doReadRequest(ctx, http.MethodGet, route, nil)
	if err != nil {
		return nil, err
	}

	defSvc := "estate-census"
	if len(q.ScopeServices) > 0 && strings.TrimSpace(q.ScopeServices[0]) != "" {
		defSvc = strings.TrimSpace(q.ScopeServices[0])
	}
	extracted, err := translator.Translate(raw, "sha256:estate-census-reader", finders.FinderTranslateOptions{
		DefaultServiceID: defSvc,
		MaxFindings:      5000,
	})
	if err != nil {
		return nil, fmt.Errorf("ESTATE_READ_PARSE_ERROR (%s via WN-7 FinderTranslator): %w", s.sourceSystem, err)
	}

	uniqueAssets := map[string]bool{}
	osCounts := map[string]int{}
	swCounts := map[string]*models.SoftwareBucket{}
	var latestSeen time.Time

	for _, f := range extracted.Findings {
		assetKey := f.TargetServiceID
		plat := "LINUX"
		if f.AssetIdentity != nil {
			if f.AssetIdentity.AssetKey != "" {
				assetKey = f.AssetIdentity.AssetKey
			}
			if f.AssetIdentity.PlatformFamily != "" {
				plat = f.AssetIdentity.PlatformFamily
			}
		}
		if !uniqueAssets[assetKey] {
			uniqueAssets[assetKey] = true
			osCounts[plat]++
		}
		if f.PackagePURL != "" {
			if sb, ok := swCounts[f.PackagePURL]; ok {
				sb.Count++
			} else {
				swCounts[f.PackagePURL] = &models.SoftwareBucket{
					ComponentName: f.PackagePURL,
					Version:       firstStr(f.PackageNEVRA, f.KBArticleID, "detected"),
					PURL:          f.PackagePURL,
					Count:         1,
				}
			}
		}
		if strings.TrimSpace(f.LastSeenAt) != "" {
			if ts := parseFlexibleTimestamp(f.LastSeenAt, time.Time{}); !ts.IsZero() && ts.After(latestSeen) {
				latestSeen = ts
			}
		}
	}

	snap := &models.EstateSnapshot{
		SourceSystem:          s.sourceSystem,
		SourceTier:            models.EstateSourceTierCCensus,
		HandlerFamily:         models.EstateHandlerFamilyScanners,
		QueryIdentity:         queryID,
		ClassScope:            q.ScopeServices,
		ClassMembershipCount:  len(uniqueAssets),
		CandidateCloneSources: []models.CloneSourceCandidate{}, // Tier C NEVER proposes clone sources
	}
	for plat, cnt := range osCounts {
		snap.OSBuildKernelDistribution = append(snap.OSBuildKernelDistribution, models.OSKernelBucket{
			OSFamily:         plat,
			OSVersionOrBuild: "scanner-observed",
			Count:            cnt,
		})
	}
	for _, sb := range swCounts {
		snap.SoftwareVersionDistribution = append(snap.SoftwareVersionDistribution, *sb)
	}
	if latestSeen.IsZero() {
		latestSeen = now
	}
	snap.SourceInventoryFreshnessAt = latestSeen
	if err := FinalizeEstateSnapshot(snap, now); err != nil {
		return nil, err
	}
	return snap, nil
}
