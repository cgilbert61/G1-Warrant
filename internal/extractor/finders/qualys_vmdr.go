package finders

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

var reQualysQID = regexp.MustCompile(`^\d{1,10}$`)

// QualysVMDRTranslator implements zero-egress, prose-free translation for Qualys VMDR Host Detection XML & JSON v2 exports.
type QualysVMDRTranslator struct{}

func NewQualysVMDRTranslator() *QualysVMDRTranslator {
	return &QualysVMDRTranslator{}
}

func (q *QualysVMDRTranslator) VendorID() string {
	return models.FinderVendorQualysVMDR
}

// XML projection — RESULTS, SOLUTION, DIAGNOSIS, CONSEQUENCE, and THREAT prose elements are intentionally omitted!
type qualysHostListXML struct {
	XMLName xml.Name `xml:"HOST_LIST_VM_DETECTION_OUTPUT"`
	Response struct {
		HostList struct {
			Hosts []qualysHostXML `xml:"HOST"`
		} `xml:"HOST_LIST"`
	} `xml:"RESPONSE"`
}

type qualysHostXML struct {
	ID              string `xml:"ID"`
	IP              string `xml:"IP"`
	IPv6            string `xml:"IPV6"`
	DNS             string `xml:"DNS"`
	NetBIOS         string `xml:"NETBIOS"`
	OS              string `xml:"OS"`
	CloudInstanceID string `xml:"CLOUD_RESOURCE_ID"`
	DetectionList   struct {
		Detections []qualysDetectionXML `xml:"DETECTION"`
	} `xml:"DETECTION_LIST"`
}

type qualysDetectionXML struct {
	QID           string  `xml:"QID"`
	Type          string  `xml:"TYPE"`
	Severity      int     `xml:"SEVERITY"`
	Port          int     `xml:"PORT"`
	Status        string  `xml:"STATUS"`
	FirstFound    string  `xml:"FIRST_FOUND_DATETIME"`
	LastFound     string  `xml:"LAST_FOUND_DATETIME"`
	CVSS3Base     float64 `xml:"CVSS_V3>BASE"`
	CWE           string  `xml:"CWE"`
	KBArticle     string  `xml:"KB_ARTICLE"`
	PackageNEVRA  string  `xml:"PACKAGE"`
	PatchedDigest string  `xml:"PATCHED_DIGEST"`
	VulnDigest    string  `xml:"VULNERABLE_DIGEST"`
	ExploitKEV    bool    `xml:"CISA_KEV"`
	CVEList       struct {
		CVEs []struct {
			ID string `xml:"ID"`
		} `xml:"CVE"`
	} `xml:"CVE_LIST"`
}

// JSON v2 projection — results/solution/diagnosis/consequence prose keys intentionally omitted!
type qualysHostJSON struct {
	ID              any                   `json:"id"`
	AssetKey        string                `json:"asset_key"`
	ServiceID       string                `json:"service_id"`
	IP              string                `json:"ip"`
	IPv6            string                `json:"ipv6"`
	DNS             string                `json:"dns"`
	Hostname        string                `json:"hostname"`
	OS              string                `json:"os"`
	CloudInstanceID string                `json:"cloud_instance_id"`
	Detections      []qualysDetectionJSON `json:"detections"`
}

type qualysDetectionJSON struct {
	QID           any      `json:"qid"`
	Severity      int      `json:"severity"`
	CVSS3Base     float64  `json:"cvss3_base"`
	Port          int      `json:"port"`
	Status        string   `json:"status"`
	FirstFound    string   `json:"first_found_datetime"`
	LastFound     string   `json:"last_found_datetime"`
	CVEs          []string `json:"cves"`
	CWE           string   `json:"cwe"`
	IsKEV         bool     `json:"cisa_kev"`
	KBArticleID   string   `json:"kb_article_id"`
	PackageNEVRA  string   `json:"package_nevra"`
	VulnDigest    string   `json:"vulnerable_digest"`
	PatchedDigest string   `json:"patched_digest"`
}

func (q *QualysVMDRTranslator) Translate(raw []byte, extractorDigest string, opts FinderTranslateOptions) (*models.ExtractedFindingSet, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("empty Qualys VMDR payload")
	}

	if trimmed[0] == '<' {
		return q.translateXML(trimmed, raw, extractorDigest, opts)
	}
	return q.translateJSON(trimmed, raw, extractorDigest, opts)
}

func (q *QualysVMDRTranslator) translateXML(trimmed, raw []byte, extractorDigest string, opts FinderTranslateOptions) (*models.ExtractedFindingSet, error) {
	dec := xml.NewDecoder(bytes.NewReader(trimmed))
	dec.Strict = true
	dec.Entity = map[string]string{} // Fail-closed against external/custom XML entities (XXE defense)
	var doc qualysHostListXML
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid Qualys VMDR XML: %w", err)
	}

	var out []models.ExtractedFinding
	seen := map[string]bool{}
	for _, h := range doc.Response.HostList.Hosts {
		hostName := h.DNS
		if hostName == "" {
			hostName = h.NetBIOS
		}
		assetIdent, svcID := NormalizeAssetIdentity("", hostName, h.IP, h.IPv6, h.ID, h.CloudInstanceID, h.OS, opts)
		for _, det := range h.DetectionList.Detections {
			var cveStrs []string
			for _, c := range det.CVEList.CVEs {
				cveStrs = append(cveStrs, c.ID)
			}
			emitted := buildQualysFindings(
				svcID, assetIdent, strings.TrimSpace(det.QID), det.Status, det.Severity, det.CVSS3Base,
				det.Port, det.FirstFound, det.LastFound, cveStrs, det.CWE, det.ExploitKEV,
				det.KBArticle, det.PackageNEVRA, det.VulnDigest, det.PatchedDigest, opts,
			)
			for _, f := range emitted {
				dedup := fmt.Sprintf("%s|%s|%s", f.TargetServiceID, f.AssetIdentity.AssetKey, f.CVEID)
				if !seen[dedup] {
					seen[dedup] = true
					out = append(out, f)
				}
			}
		}
	}
	return finalizeFindingSet(models.FinderVendorQualysVMDR, raw, extractorDigest, out, opts.MaxFindings)
}

func (q *QualysVMDRTranslator) translateJSON(trimmed, raw []byte, extractorDigest string, opts FinderTranslateOptions) (*models.ExtractedFindingSet, error) {
	var hosts []qualysHostJSON
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &hosts); err != nil {
			return nil, fmt.Errorf("invalid Qualys VMDR JSON array: %w", err)
		}
	} else {
		var wrapper struct {
			Hosts []qualysHostJSON `json:"hosts"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err != nil {
			return nil, fmt.Errorf("invalid Qualys VMDR JSON object: %w", err)
		}
		hosts = wrapper.Hosts
	}

	var out []models.ExtractedFinding
	seen := map[string]bool{}
	for _, h := range hosts {
		hostOpts := opts
		if reServiceID.MatchString(strings.ToLower(strings.TrimSpace(h.ServiceID))) {
			hostOpts.DefaultServiceID = strings.ToLower(strings.TrimSpace(h.ServiceID))
		}
		hostName := h.DNS
		if hostName == "" {
			hostName = h.Hostname
		}
		assetIdent, svcID := NormalizeAssetIdentity(h.AssetKey, hostName, h.IP, h.IPv6, stringifyAnyID(h.ID), h.CloudInstanceID, h.OS, hostOpts)
		for _, det := range h.Detections {
			emitted := buildQualysFindings(
				svcID, assetIdent, stringifyAnyID(det.QID), det.Status, det.Severity, det.CVSS3Base,
				det.Port, det.FirstFound, det.LastFound, det.CVEs, det.CWE, det.IsKEV,
				det.KBArticleID, det.PackageNEVRA, det.VulnDigest, det.PatchedDigest, hostOpts,
			)
			for _, f := range emitted {
				dedup := fmt.Sprintf("%s|%s|%s", f.TargetServiceID, f.AssetIdentity.AssetKey, f.CVEID)
				if !seen[dedup] {
					seen[dedup] = true
					out = append(out, f)
				}
			}
		}
	}
	return finalizeFindingSet(models.FinderVendorQualysVMDR, raw, extractorDigest, out, opts.MaxFindings)
}

func buildQualysFindings(
	svcID string,
	assetIdent models.AssetIdentity,
	rawQID string,
	rawStatus string,
	severity int,
	cvss3 float64,
	port int,
	firstFound string,
	lastFound string,
	rawCVEs []string,
	rawCWE string,
	isKEV bool,
	kbArticle string,
	pkgNEVRA string,
	vulnDigest string,
	patchedDigest string,
	opts FinderTranslateOptions,
) []models.ExtractedFinding {
	qidClean := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(rawQID)), "QID-")
	if !reQualysQID.MatchString(qidClean) {
		return nil
	}
	normState := normalizeQualysStatus(rawStatus)
	if normState == models.DetectionStateFixedReported {
		return nil
	}

	score := cvss3
	if score <= 0 || score > 10.0 {
		score = qualysSeverityToCVSS(severity)
	}
	if port < 0 || port > 65535 {
		port = 0
	}

	vendorDetID := "QID-" + qidClean
	cves := extractUniqueCVEs(rawCVEs...)
	cwe := extractFirstCWE(rawCWE)
	firstTS := NormalizeTimestampRFC3339(firstFound)
	lastTS := NormalizeTimestampRFC3339(lastFound)
	vDig := defaultDigestOrPlaceholder(vulnDigest, opts.DefaultVulnerableDigest, svcID+":vuln:"+vendorDetID)
	pDig := defaultDigestOrPlaceholder(patchedDigest, opts.DefaultPatchedDigest, svcID+":patch:"+vendorDetID)
	identCopy := assetIdent

	if len(cves) == 0 {
		return []models.ExtractedFinding{
			{
				RuleID:                   vendorDetID,
				CVEID:                    "UNMAPPED-" + vendorDetID,
				CWEID:                    cwe,
				CVSSScore:                score,
				IsKEV:                    isKEV,
				TargetServiceID:          svcID,
				PackagePURL:              fmt.Sprintf("pkg:generic/%s@0.0.0", svcID),
				VulnerableDigest:         vDig,
				PatchedDigest:            pDig,
				ExploitVector:            "GENERIC_RCE",
				AffectedPort:             port,
				BlockedPaths:             []string{},
				ArtifactPaths:            []string{},
				ChainedExploitEnabler:    reChainedExploitID[cwe],
				FinderVendor:             models.FinderVendorQualysVMDR,
				AssetIdentity:            &identCopy,
				VendorDetectionID:        vendorDetID,
				CVEMappingStatus:         models.CVEMappingStatusUnmappedVendor,
				NormalizedDetectionState: normState,
				FirstSeenAt:              firstTS,
				LastSeenAt:               lastTS,
				KBArticleID:              sanitizeKB(kbArticle),
				PackageNEVRA:             sanitizeNEVRA(pkgNEVRA),
			},
		}
	}

	out := make([]models.ExtractedFinding, 0, len(cves))
	for _, cve := range cves {
		idCopy := assetIdent
		out = append(out, models.ExtractedFinding{
			RuleID:                   vendorDetID,
			CVEID:                    cve,
			CWEID:                    cwe,
			CVSSScore:                score,
			IsKEV:                    isKEV,
			TargetServiceID:          svcID,
			PackagePURL:              fmt.Sprintf("pkg:generic/%s@0.0.0", svcID),
			VulnerableDigest:         vDig,
			PatchedDigest:            pDig,
			ExploitVector:            "GENERIC_RCE",
			AffectedPort:             port,
			BlockedPaths:             []string{},
			ArtifactPaths:            []string{},
			ChainedExploitEnabler:    reChainedExploitID[cwe],
			FinderVendor:             models.FinderVendorQualysVMDR,
			AssetIdentity:            &idCopy,
			VendorDetectionID:        vendorDetID,
			CVEMappingStatus:         models.CVEMappingStatusMapped,
			NormalizedDetectionState: normState,
			FirstSeenAt:              firstTS,
			LastSeenAt:               lastTS,
			KBArticleID:              sanitizeKB(kbArticle),
			PackageNEVRA:             sanitizeNEVRA(pkgNEVRA),
		})
	}
	return out
}

func normalizeQualysStatus(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "NEW":
		return models.DetectionStateNew
	case "RE-OPENED", "REOPENED":
		return models.DetectionStateReopened
	case "FIXED":
		return models.DetectionStateFixedReported
	default:
		return models.DetectionStateActive
	}
}

func qualysSeverityToCVSS(sev int) float64 {
	switch sev {
	case 5:
		return 9.8
	case 4:
		return 8.2
	case 3:
		return 6.5
	case 2:
		return 4.3
	case 1:
		return 2.5
	default:
		return 7.0
	}
}

func stringifyAnyID(v any) string {
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case float64:
		return strconv.FormatInt(int64(val), 10)
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	default:
		return ""
	}
}
