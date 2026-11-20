package extractor

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

var (
	reISODate    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reCatalogVer = regexp.MustCompile(`^[0-9A-Za-z._:-]{1,40}$`)
	reOSVID      = regexp.MustCompile(`^[A-Z0-9][A-Z0-9._:-]{2,64}$`)
	reSemverSafe = regexp.MustCompile(`^[0-9A-Za-z._+~:-]{1,64}$`)
)

// ParseUntrustedCISAKEV parses the official CISA Known Exploited Vulnerabilities JSON feed,
// drops all prose fields (vendorProject, product, vulnerabilityName, shortDescription, requiredAction, notes),
// validates strict regex bounds on CVE IDs, CWE IDs, and YYYY-MM-DD dates, and computes a JCS hash.
func ParseUntrustedCISAKEV(raw []byte, extractorDigest string) (*models.ExtractedKEVCatalog, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty CISA KEV input")
	}
	rawSHA := crypto.SHA256Hex(raw)

	var doc struct {
		CatalogVersion  string `json:"catalogVersion"`
		DateReleased    string `json:"dateReleased"`
		Vulnerabilities []struct {
			CVEID                      string   `json:"cveID"`
			DateAdded                  string   `json:"dateAdded"`
			DueDate                    string   `json:"dueDate"`
			KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
			CWEs                       []string `json:"cwes"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("invalid CISA KEV JSON: %w", err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return nil, errors.New("CISA KEV payload contains zero vulnerabilities")
	}

	catVer := sanitizeToken(doc.CatalogVersion, 40)
	if !reCatalogVer.MatchString(catVer) {
		catVer = "UNKNOWN"
	}
	dateRel := sanitizeToken(doc.DateReleased, 30)

	seen := make(map[string]bool, len(doc.Vulnerabilities))
	entries := make([]models.ExtractedKEVEntry, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		cve := reCVE.FindString(strings.ToUpper(strings.TrimSpace(v.CVEID)))
		if cve == "" || seen[cve] {
			continue
		}
		seen[cve] = true

		cwe := "CWE-20"
		for _, cand := range v.CWEs {
			if matched := reCWE.FindString(strings.ToUpper(cand)); matched != "" {
				cwe = matched
				break
			}
		}

		dateAdded := strings.TrimSpace(v.DateAdded)
		if !reISODate.MatchString(dateAdded) {
			dateAdded = "1970-01-01"
		}
		dueDate := strings.TrimSpace(v.DueDate)
		if !reISODate.MatchString(dueDate) {
			dueDate = "1970-01-01"
		}

		ransomware := "Unknown"
		if strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "Known") {
			ransomware = "Known"
		}

		entries = append(entries, models.ExtractedKEVEntry{
			CVEID:              cve,
			CWEID:              cwe,
			DateAdded:          dateAdded,
			DueDate:            dueDate,
			RansomwareCampaign: ransomware,
		})
	}

	if len(entries) == 0 {
		return nil, errors.New("zero valid CVE entries extracted from CISA KEV feed")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CVEID < entries[j].CVEID })

	out := &models.ExtractedKEVCatalog{
		SchemaVersion:   "g1.extractor.cisa-kev.v1",
		CatalogVersion:  catVer,
		DateReleased:    dateRel,
		Entries:         entries,
		RawInputSHA256:  rawSHA,
		ExtractorDigest: extractorDigest,
	}
	typedHash, _, err := crypto.CanonicalSHA256Hex(out)
	if err != nil {
		return nil, err
	}
	out.TypedOutputSHA256 = typedHash
	return out, nil
}

// UntrustedOSVInputItem pairs a target service + package PURL with an untrusted OSV vulnerability JSON object.
type UntrustedOSVInputItem struct {
	ServiceID   string          `json:"service_id"`
	PackagePURL string          `json:"package_purl"`
	Vuln        json.RawMessage `json:"vuln"`
}

// ParseUntrustedOSVBundle parses a batch of untrusted Google OSV.dev vulnerability records,
// strips all prose (summary, details, references), extracts strictly validated IDs/CVEs/scores/fixed versions,
// and computes a canonical JCS digest.
func ParseUntrustedOSVBundle(raw []byte, extractorDigest string) (*models.ExtractedOSVReport, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty OSV bundle input")
	}
	rawSHA := crypto.SHA256Hex(raw)

	var wrapper struct {
		Items []UntrustedOSVInputItem `json:"items"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, fmt.Errorf("invalid OSV bundle JSON: %w", err)
	}

	advisories := make([]models.ExtractedOSVEntry, 0, len(wrapper.Items))
	seen := map[string]bool{}

	for _, item := range wrapper.Items {
		svcID := strings.ToLower(strings.TrimSpace(item.ServiceID))
		if !reServiceID.MatchString(svcID) {
			continue
		}
		purl := strings.TrimSpace(item.PackagePURL)
		if !rePURL.MatchString(purl) {
			continue
		}

		var v struct {
			ID       string   `json:"id"`
			Aliases  []string `json:"aliases"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			DatabaseSpecific struct {
				Severity string   `json:"severity"`
				CWEIDs   []string `json:"cwe_ids"`
			} `json:"database_specific"`
			Affected []struct {
				Ranges []struct {
					Events []struct {
						Fixed string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		}
		if err := json.Unmarshal(item.Vuln, &v); err != nil {
			continue
		}

		osvID := strings.ToUpper(strings.TrimSpace(v.ID))
		if !reOSVID.MatchString(osvID) {
			continue
		}

		cve := reCVE.FindString(osvID)
		if cve == "" {
			for _, al := range v.Aliases {
				if m := reCVE.FindString(strings.ToUpper(al)); m != "" {
					cve = m
					break
				}
			}
		}
		if cve == "" {
			cve = "CVE-0000-0000"
		}

		cwe := "CWE-20"
		for _, cid := range v.DatabaseSpecific.CWEIDs {
			if m := reCWE.FindString(strings.ToUpper(cid)); m != "" {
				cwe = m
				break
			}
		}

		cvss := inferOSVCVSS(v.DatabaseSpecific.Severity, v.Severity)

		fixedVer := ""
		for _, aff := range v.Affected {
			for _, rng := range aff.Ranges {
				for _, ev := range rng.Events {
					cand := strings.TrimSpace(ev.Fixed)
					if cand != "" && reSemverSafe.MatchString(cand) {
						fixedVer = cand
						break
					}
				}
				if fixedVer != "" {
					break
				}
			}
			if fixedVer != "" {
				break
			}
		}
		if fixedVer == "" {
			fixedVer = "UPSTREAM_PATCH_AVAILABLE"
		}

		key := osvID + "|" + svcID + "|" + purl
		if seen[key] {
			continue
		}
		seen[key] = true

		advisories = append(advisories, models.ExtractedOSVEntry{
			OSVID:        osvID,
			CVEID:        cve,
			CWEID:        cwe,
			ServiceID:    svcID,
			PackagePURL:  purl,
			CVSSScore:    cvss,
			FixedVersion: fixedVer,
		})
	}

	sort.Slice(advisories, func(i, j int) bool {
		if advisories[i].CVSSScore != advisories[j].CVSSScore {
			return advisories[i].CVSSScore > advisories[j].CVSSScore
		}
		return advisories[i].OSVID < advisories[j].OSVID
	})

	out := &models.ExtractedOSVReport{
		SchemaVersion:   "g1.extractor.osv.v1",
		Advisories:      advisories,
		RawInputSHA256:  rawSHA,
		ExtractorDigest: extractorDigest,
	}
	typedHash, _, err := crypto.CanonicalSHA256Hex(out)
	if err != nil {
		return nil, err
	}
	out.TypedOutputSHA256 = typedHash
	return out, nil
}

func inferOSVCVSS(dbSeverity string, sevList []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) float64 {
	for _, s := range sevList {
		if val, err := strconv.ParseFloat(strings.TrimSpace(s.Score), 64); err == nil && val > 0 && val <= 10.0 {
			return val
		}
		// Estimate from CVSS:3.1 vector string impact metrics if present
		u := strings.ToUpper(s.Score)
		if strings.HasPrefix(u, "CVSS:3.") {
			if strings.Contains(u, "/AV:N/") && strings.Contains(u, "/C:H/I:H/A:H") {
				return 9.8
			}
			if strings.Contains(u, "/C:H/") || strings.Contains(u, "/I:H/") || strings.Contains(u, "/A:H") {
				return 7.8
			}
			return 6.5
		}
	}
	switch strings.ToUpper(strings.TrimSpace(dbSeverity)) {
	case "CRITICAL":
		return 9.4
	case "HIGH":
		return 7.8
	case "MODERATE", "MEDIUM":
		return 5.6
	case "LOW":
		return 3.3
	default:
		return 7.5
	}
}
