package finders

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

var reRapid7VulnToken = regexp.MustCompile(`^[A-Z0-9][A-Z0-9._-]{1,64}$`)

// Rapid7InsightVMTranslator implements zero-egress, prose-free translation for Rapid7 InsightVM v3 Asset-Vulnerability JSON payloads.
type Rapid7InsightVMTranslator struct{}

func NewRapid7InsightVMTranslator() *Rapid7InsightVMTranslator {
	return &Rapid7InsightVMTranslator{}
}

func (r *Rapid7InsightVMTranslator) VendorID() string {
	return models.FinderVendorRapid7InsightVM
}

// Rapid7 InsightVM v3 minimal JSON projection — proof, description, html, fix prose fields intentionally omitted!
type rapid7AssetJSON struct {
	ID              any              `json:"id"`
	AssetKey        string           `json:"assetKey"`
	ServiceID       string           `json:"serviceId"`
	IP              string           `json:"ip"`
	IPv6            string           `json:"ipv6"`
	HostName        string           `json:"hostName"`
	OS              string           `json:"os"`
	CloudInstanceID string           `json:"cloudInstanceId"`
	Vulnerabilities []rapid7VulnJSON `json:"vulnerabilities"`
}

type rapid7VulnJSON struct {
	ID                     string   `json:"id"`
	Status                 string   `json:"status"`
	CVEs                   []string `json:"cves"`
	CWE                    string   `json:"cwe"`
	RiskScore              float64  `json:"riskScore"`
	Since                  string   `json:"since"`
	MostRecentlyDiscovered string   `json:"mostRecentlyDiscovered"`
	Port                   int      `json:"port"`
	IsKEV                  bool     `json:"cisaKev"`
	KBArticleID            string   `json:"kbArticleId"`
	PackageNEVRA           string   `json:"packageNevra"`
	VulnDigest             string   `json:"vulnerableDigest"`
	PatchedDigest          string   `json:"patchedDigest"`
	CVSS                   struct {
		V3 struct {
			Score float64 `json:"score"`
		} `json:"v3"`
		V2 struct {
			Score float64 `json:"score"`
		} `json:"v2"`
	} `json:"cvss"`
}

func (r *Rapid7InsightVMTranslator) Translate(raw []byte, extractorDigest string, opts FinderTranslateOptions) (*models.ExtractedFindingSet, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("empty Rapid7 InsightVM payload")
	}

	var assets []rapid7AssetJSON
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &assets); err != nil {
			return nil, fmt.Errorf("invalid Rapid7 InsightVM JSON array: %w", err)
		}
	} else {
		var wrapper struct {
			Resources []rapid7AssetJSON `json:"resources"`
			Assets    []rapid7AssetJSON `json:"assets"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err != nil {
			return nil, fmt.Errorf("invalid Rapid7 InsightVM JSON object: %w", err)
		}
		if len(wrapper.Resources) > 0 {
			assets = wrapper.Resources
		} else {
			assets = wrapper.Assets
		}
	}

	var out []models.ExtractedFinding
	seen := map[string]bool{}
	for _, a := range assets {
		assetOpts := opts
		if reServiceID.MatchString(strings.ToLower(strings.TrimSpace(a.ServiceID))) {
			assetOpts.DefaultServiceID = strings.ToLower(strings.TrimSpace(a.ServiceID))
		}
		assetIdent, svcID := NormalizeAssetIdentity(
			a.AssetKey, a.HostName, a.IP, a.IPv6, stringifyAnyID(a.ID), a.CloudInstanceID, a.OS, assetOpts,
		)

		for _, v := range a.Vulnerabilities {
			normState := normalizeRapid7Status(v.Status)
			if normState == models.DetectionStateFixedReported {
				continue
			}
			cleanID := sanitizeRapid7ID(v.ID)
			if cleanID == "" {
				continue
			}
			vendorDetID := "R7-" + cleanID

			score := v.CVSS.V3.Score
			if score <= 0 && v.CVSS.V2.Score > 0 {
				score = v.CVSS.V2.Score
			}
			if score <= 0 && v.RiskScore > 0 {
				// Rapid7 riskScore typically spans 0..1000
				norm := v.RiskScore
				if norm > 10.0 {
					norm = norm / 100.0
				}
				score = math.Min(10.0, math.Max(1.0, math.Round(norm*10)/10))
			}
			if score <= 0 || score > 10.0 {
				score = 7.5
			}

			cves := extractUniqueCVEs(v.CVEs...)
			cwe := extractFirstCWE(v.CWE)
			firstTS := NormalizeTimestampRFC3339(v.Since)
			lastTS := NormalizeTimestampRFC3339(v.MostRecentlyDiscovered)
			if lastTS == "" {
				lastTS = firstTS
			}
			vDig := defaultDigestOrPlaceholder(v.VulnDigest, assetOpts.DefaultVulnerableDigest, svcID+":vuln:"+vendorDetID)
			pDig := defaultDigestOrPlaceholder(v.PatchedDigest, assetOpts.DefaultPatchedDigest, svcID+":patch:"+vendorDetID)
			port := v.Port
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
					IsKEV:                    v.IsKEV,
					TargetServiceID:          svcID,
					PackagePURL:              fmt.Sprintf("pkg:generic/%s@0.0.0", svcID),
					VulnerableDigest:         vDig,
					PatchedDigest:            pDig,
					ExploitVector:            "GENERIC_RCE",
					AffectedPort:             port,
					BlockedPaths:             []string{},
					ArtifactPaths:            []string{},
					ChainedExploitEnabler:    reChainedExploitID[cwe],
					FinderVendor:             models.FinderVendorRapid7InsightVM,
					AssetIdentity:            &idCopy,
					VendorDetectionID:        vendorDetID,
					CVEMappingStatus:         models.CVEMappingStatusUnmappedVendor,
					NormalizedDetectionState: normState,
					FirstSeenAt:              firstTS,
					LastSeenAt:               lastTS,
					KBArticleID:              sanitizeKB(v.KBArticleID),
					PackageNEVRA:             sanitizeNEVRA(v.PackageNEVRA),
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
					IsKEV:                    v.IsKEV,
					TargetServiceID:          svcID,
					PackagePURL:              fmt.Sprintf("pkg:generic/%s@0.0.0", svcID),
					VulnerableDigest:         vDig,
					PatchedDigest:            pDig,
					ExploitVector:            "GENERIC_RCE",
					AffectedPort:             port,
					BlockedPaths:             []string{},
					ArtifactPaths:            []string{},
					ChainedExploitEnabler:    reChainedExploitID[cwe],
					FinderVendor:             models.FinderVendorRapid7InsightVM,
					AssetIdentity:            &idCopy,
					VendorDetectionID:        vendorDetID,
					CVEMappingStatus:         models.CVEMappingStatusMapped,
					NormalizedDetectionState: normState,
					FirstSeenAt:              firstTS,
					LastSeenAt:               lastTS,
					KBArticleID:              sanitizeKB(v.KBArticleID),
					PackageNEVRA:             sanitizeNEVRA(v.PackageNEVRA),
				}
				dedup := fmt.Sprintf("%s|%s|%s", f.TargetServiceID, f.AssetIdentity.AssetKey, f.CVEID)
				if !seen[dedup] {
					seen[dedup] = true
					out = append(out, f)
				}
			}
		}
	}

	return finalizeFindingSet(models.FinderVendorRapid7InsightVM, raw, extractorDigest, out, opts.MaxFindings)
}

func sanitizeRapid7ID(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "R7-")
	var b strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		case r == ':' || r == '/':
			b.WriteRune('-')
		}
		if b.Len() >= 48 {
			break
		}
	}
	res := strings.Trim(b.String(), "-_.")
	if !reRapid7VulnToken.MatchString(res) {
		return ""
	}
	return res
}

func normalizeRapid7Status(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "invulnerable", "not-vulnerable", "remediated", "fixed":
		return models.DetectionStateFixedReported
	case "reopened":
		return models.DetectionStateReopened
	case "new":
		return models.DetectionStateNew
	default:
		return models.DetectionStateActive
	}
}
