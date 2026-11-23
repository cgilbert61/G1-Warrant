package finders

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

var reTenablePluginID = regexp.MustCompile(`^\d{1,10}$`)

// TenableTranslator implements zero-egress, prose-free translation for Tenable.io Vulnerability Export JSON & Tenable.sc analysis payloads.
type TenableTranslator struct{}

func NewTenableTranslator() *TenableTranslator {
	return &TenableTranslator{}
}

func (t *TenableTranslator) VendorID() string {
	return models.FinderVendorTenableIOSC
}

// Tenable.io / Tenable.sc minimal JSON projection — output, description, synopsis, solution, see_also prose omitted!
type tenableFindingJSON struct {
	State      string `json:"state"`
	Severity   string `json:"severity"`
	SeverityID int    `json:"severity_id"`
	FirstFound string `json:"first_found"`
	LastFound  string `json:"last_found"`
	Port       struct {
		Port int `json:"port"`
	} `json:"port"`
	Asset struct {
		UUID            string   `json:"uuid"`
		AssetKey        string   `json:"asset_key"`
		ServiceID       string   `json:"service_id"`
		Hostname        string   `json:"hostname"`
		FQDN            string   `json:"fqdn"`
		IPv4            string   `json:"ipv4"`
		IPv6            string   `json:"ipv6"`
		OperatingSystem []string `json:"operating_system"`
		AWSInstanceID   string   `json:"aws_ec2_instance_id"`
	} `json:"asset"`
	Plugin struct {
		ID             any      `json:"id"`
		CVE            []string `json:"cve"`
		CWE            []string `json:"cwe"`
		CVSS3BaseScore float64  `json:"cvss3_base_score"`
		ExploitKEV     bool     `json:"cisa_known_exploited"`
		KBArticleID    string   `json:"kb_article_id"`
		PackageNEVRA   string   `json:"package_nevra"`
		VulnDigest     string   `json:"vulnerable_digest"`
		PatchedDigest  string   `json:"patched_digest"`
		VPR            struct {
			Score float64 `json:"score"`
		} `json:"vpr"`
	} `json:"plugin"`
	// Tenable.sc flat record compatibility fields (still prose-free!)
	SCPluginID   any    `json:"pluginID"`
	SCCVE        string `json:"cve"`
	SCIP         string `json:"ip"`
	SCDNSName    string `json:"dnsName"`
	SCOS         string `json:"os"`
	SCFirstSeen  string `json:"firstSeen"`
	SCLastSeen   string `json:"lastSeen"`
	SCCVSSv3     string `json:"cvssV3BaseScore"`
	SCSeverityID string `json:"severityID"`
}

func (t *TenableTranslator) Translate(raw []byte, extractorDigest string, opts FinderTranslateOptions) (*models.ExtractedFindingSet, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("empty Tenable payload")
	}

	var items []tenableFindingJSON
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("invalid Tenable JSON array: %w", err)
		}
	} else {
		var wrapper struct {
			Findings        []tenableFindingJSON `json:"findings"`
			Vulnerabilities []tenableFindingJSON `json:"vulnerabilities"`
			Response        struct {
				Results []tenableFindingJSON `json:"results"`
			} `json:"response"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err != nil {
			return nil, fmt.Errorf("invalid Tenable JSON object: %w", err)
		}
		switch {
		case len(wrapper.Findings) > 0:
			items = wrapper.Findings
		case len(wrapper.Vulnerabilities) > 0:
			items = wrapper.Vulnerabilities
		default:
			items = wrapper.Response.Results
		}
	}

	var out []models.ExtractedFinding
	seen := map[string]bool{}
	for _, it := range items {
		pluginID := stringifyAnyID(it.Plugin.ID)
		if pluginID == "" {
			pluginID = stringifyAnyID(it.SCPluginID)
		}
		pluginID = strings.TrimPrefix(strings.ToUpper(pluginID), "PLUGIN-")
		if !reTenablePluginID.MatchString(pluginID) {
			continue
		}

		normState := normalizeTenableState(it.State)
		if normState == models.DetectionStateFixedReported {
			continue
		}

		itemOpts := opts
		if reServiceID.MatchString(strings.ToLower(strings.TrimSpace(it.Asset.ServiceID))) {
			itemOpts.DefaultServiceID = strings.ToLower(strings.TrimSpace(it.Asset.ServiceID))
		}
		host := it.Asset.Hostname
		if host == "" {
			host = it.Asset.FQDN
		}
		if host == "" {
			host = it.SCDNSName
		}
		ipv4 := it.Asset.IPv4
		if ipv4 == "" {
			ipv4 = it.SCIP
		}
		osStr := strings.Join(it.Asset.OperatingSystem, " ")
		if osStr == "" {
			osStr = it.SCOS
		}
		assetIdent, svcID := NormalizeAssetIdentity(
			it.Asset.AssetKey, host, ipv4, it.Asset.IPv6, it.Asset.UUID, it.Asset.AWSInstanceID, osStr, itemOpts,
		)

		score := it.Plugin.CVSS3BaseScore
		if score <= 0 && it.Plugin.VPR.Score > 0 && it.Plugin.VPR.Score <= 10.0 {
			score = it.Plugin.VPR.Score
		}
		if score <= 0 {
			score = tenableSeverityToCVSS(it.Severity, it.SeverityID)
		}

		var cveInputs []string
		cveInputs = append(cveInputs, it.Plugin.CVE...)
		if it.SCCVE != "" {
			cveInputs = append(cveInputs, it.SCCVE)
		}
		cves := extractUniqueCVEs(cveInputs...)
		cwe := extractFirstCWE(it.Plugin.CWE...)

		firstTS := NormalizeTimestampRFC3339(it.FirstFound)
		if firstTS == "" {
			firstTS = NormalizeTimestampRFC3339(it.SCFirstSeen)
		}
		lastTS := NormalizeTimestampRFC3339(it.LastFound)
		if lastTS == "" {
			lastTS = NormalizeTimestampRFC3339(it.SCLastSeen)
		}

		vendorDetID := "PLUGIN-" + pluginID
		vDig := defaultDigestOrPlaceholder(it.Plugin.VulnDigest, itemOpts.DefaultVulnerableDigest, svcID+":vuln:"+vendorDetID)
		pDig := defaultDigestOrPlaceholder(it.Plugin.PatchedDigest, itemOpts.DefaultPatchedDigest, svcID+":patch:"+vendorDetID)
		port := it.Port.Port
		if port < 0 || port > 65535 {
			port = 0
		}

		if len(cves) == 0 {
			idCopy := assetIdent
			f := models.ExtractedFinding{
				RuleID:                   vendorDetID,
				CVEID:                    "UNMAPPED-" + vendorDetID,
				CWEID:                    cwe,
				CVSSScore:                score,
				IsKEV:                    it.Plugin.ExploitKEV,
				TargetServiceID:          svcID,
				PackagePURL:              fmt.Sprintf("pkg:generic/%s@0.0.0", svcID),
				VulnerableDigest:         vDig,
				PatchedDigest:            pDig,
				ExploitVector:            "GENERIC_RCE",
				AffectedPort:             port,
				BlockedPaths:             []string{},
				ArtifactPaths:            []string{},
				ChainedExploitEnabler:    reChainedExploitID[cwe],
				FinderVendor:             models.FinderVendorTenableIOSC,
				AssetIdentity:            &idCopy,
				VendorDetectionID:        vendorDetID,
				CVEMappingStatus:         models.CVEMappingStatusUnmappedVendor,
				NormalizedDetectionState: normState,
				FirstSeenAt:              firstTS,
				LastSeenAt:               lastTS,
				KBArticleID:              sanitizeKB(it.Plugin.KBArticleID),
				PackageNEVRA:             sanitizeNEVRA(it.Plugin.PackageNEVRA),
			}
			dedup := fmt.Sprintf("%s|%s|%s", f.TargetServiceID, f.AssetIdentity.AssetKey, f.CVEID)
			if !seen[dedup] {
				seen[dedup] = true
				out = append(out, f)
			}
			continue
		}

		for _, cve := range cves {
			idCopy := assetIdent
			f := models.ExtractedFinding{
				RuleID:                   vendorDetID,
				CVEID:                    cve,
				CWEID:                    cwe,
				CVSSScore:                score,
				IsKEV:                    it.Plugin.ExploitKEV,
				TargetServiceID:          svcID,
				PackagePURL:              fmt.Sprintf("pkg:generic/%s@0.0.0", svcID),
				VulnerableDigest:         vDig,
				PatchedDigest:            pDig,
				ExploitVector:            "GENERIC_RCE",
				AffectedPort:             port,
				BlockedPaths:             []string{},
				ArtifactPaths:            []string{},
				ChainedExploitEnabler:    reChainedExploitID[cwe],
				FinderVendor:             models.FinderVendorTenableIOSC,
				AssetIdentity:            &idCopy,
				VendorDetectionID:        vendorDetID,
				CVEMappingStatus:         models.CVEMappingStatusMapped,
				NormalizedDetectionState: normState,
				FirstSeenAt:              firstTS,
				LastSeenAt:               lastTS,
				KBArticleID:              sanitizeKB(it.Plugin.KBArticleID),
				PackageNEVRA:             sanitizeNEVRA(it.Plugin.PackageNEVRA),
			}
			dedup := fmt.Sprintf("%s|%s|%s", f.TargetServiceID, f.AssetIdentity.AssetKey, f.CVEID)
			if !seen[dedup] {
				seen[dedup] = true
				out = append(out, f)
			}
		}
	}

	return finalizeFindingSet(models.FinderVendorTenableIOSC, raw, extractorDigest, out, opts.MaxFindings)
}

func normalizeTenableState(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "NEW":
		return models.DetectionStateNew
	case "REOPENED", "RESURFACED":
		return models.DetectionStateReopened
	case "FIXED":
		return models.DetectionStateFixedReported
	default:
		return models.DetectionStateActive
	}
}

func tenableSeverityToCVSS(sev string, sevID int) float64 {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 9.8
	case "high":
		return 8.1
	case "medium":
		return 5.8
	case "low":
		return 3.3
	}
	switch sevID {
	case 4:
		return 9.8
	case 3:
		return 8.1
	case 2:
		return 5.8
	case 1:
		return 3.3
	default:
		return 7.0
	}
}
