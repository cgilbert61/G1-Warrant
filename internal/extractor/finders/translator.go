package finders

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

var (
	reCVE              = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)
	reCWE              = regexp.MustCompile(`(?i)CWE-\d{1,5}`)
	reDigest           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	rePURL             = regexp.MustCompile(`^pkg:[a-z0-9+.-]+/[a-zA-Z0-9._/:%?=&@-]+$`)
	reServiceID        = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	reAssetToken       = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,120}$`)
	reKBArticle        = regexp.MustCompile(`(?i)^KB\d{4,9}$`)
	reSafeNEVRA        = regexp.MustCompile(`^[a-zA-Z0-9._+:-]{1,140}$`)
	reChainedExploitID = map[string]bool{
		"CWE-209": true,
		"CWE-918": true,
		"CWE-434": true,
	}
)

// FinderTranslateOptions provides bounded, prose-free asset-alias and service defaults to zero-egress Finder translators.
type FinderTranslateOptions struct {
	DefaultServiceID        string
	DefaultVulnerableDigest string
	DefaultPatchedDigest    string
	MaxFindings             int
	// AliasToService maps lowercase alias tokens (hostname, IPv4, IPv6, scanner asset ID, cloud instance ID, asset key) -> ServiceID.
	AliasToService map[string]string
	// AliasToAssetKey maps lowercase alias tokens -> canonical AssetKey.
	AliasToAssetKey map[string]string
}

// FinderTranslator is the single internal interface implemented by every WN-7 estate vulnerability scanner translator.
// Raw vendor inputs terminate here inside zero-egress warrant-extractor; all prose/HTML/markdown is stripped.
type FinderTranslator interface {
	VendorID() string
	Translate(raw []byte, extractorDigest string, opts FinderTranslateOptions) (*models.ExtractedFindingSet, error)
}

// Registry returns the canonical WN-7 FinderTranslator for a vendor slug ("qualys", "tenable", "rapid7").
func LookupTranslator(vendor string) (FinderTranslator, error) {
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "qualys", "qualys_vmdr", "qualys-vmdr":
		return NewQualysVMDRTranslator(), nil
	case "tenable", "tenable_io", "tenable_sc", "tenable_io_sc", "tenable-io-sc":
		return NewTenableTranslator(), nil
	case "rapid7", "insightvm", "rapid7_insightvm", "rapid7-insightvm":
		return NewRapid7InsightVMTranslator(), nil
	default:
		return nil, fmt.Errorf("UNSUPPORTED_FINDER_VENDOR: %q", vendor)
	}
}

// NormalizeAssetIdentity sanitizes raw host/IP/cloud/scanner identifiers (dropping any arbitrary prose or invalid tokens)
// and deterministically resolves canonical AssetKey and TargetServiceID using opts.
func NormalizeAssetIdentity(
	rawAssetKey, rawHostname, rawIPv4, rawIPv6, rawScannerID, rawCloudID, rawOS string,
	opts FinderTranslateOptions,
) (models.AssetIdentity, string) {
	hostname := sanitizeDNSName(rawHostname)
	ipv4 := sanitizeIP(rawIPv4, false)
	ipv6 := sanitizeIP(rawIPv6, true)
	scannerID := sanitizeBoundedToken(rawScannerID, 80)
	cloudID := sanitizeBoundedToken(rawCloudID, 80)
	platform := inferPlatformFamily(rawOS)

	candidates := []string{
		strings.ToLower(strings.TrimSpace(rawAssetKey)),
		strings.ToLower(hostname),
		strings.ToLower(shortHost(hostname)),
		strings.ToLower(ipv4),
		strings.ToLower(ipv6),
		strings.ToLower(scannerID),
		strings.ToLower(cloudID),
	}

	resolvedSvc := ""
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if opts.AliasToService != nil {
			if svc, ok := opts.AliasToService[c]; ok && reServiceID.MatchString(svc) {
				resolvedSvc = svc
				break
			}
		}
	}
	if resolvedSvc == "" {
		sh := strings.ToLower(shortHost(hostname))
		if reServiceID.MatchString(sh) {
			resolvedSvc = sh
		} else if reServiceID.MatchString(strings.ToLower(strings.TrimSpace(opts.DefaultServiceID))) {
			resolvedSvc = strings.ToLower(strings.TrimSpace(opts.DefaultServiceID))
		} else {
			resolvedSvc = "unmapped-estate-asset"
		}
	}

	resolvedAssetKey := ""
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if opts.AliasToAssetKey != nil {
			if ak, ok := opts.AliasToAssetKey[c]; ok && reAssetToken.MatchString(ak) {
				resolvedAssetKey = ak
				break
			}
		}
	}
	if resolvedAssetKey == "" {
		switch {
		case sanitizeBoundedToken(rawAssetKey, 96) != "":
			resolvedAssetKey = strings.ToLower(sanitizeBoundedToken(rawAssetKey, 96))
		case hostname != "":
			resolvedAssetKey = strings.ToLower(hostname)
		case cloudID != "":
			resolvedAssetKey = strings.ToLower(cloudID)
		case ipv4 != "":
			resolvedAssetKey = "ip-" + strings.ReplaceAll(ipv4, ".", "-")
		case scannerID != "":
			resolvedAssetKey = "scan-" + strings.ToLower(scannerID)
		default:
			resolvedAssetKey = resolvedSvc
		}
	}

	return models.AssetIdentity{
		AssetKey:        resolvedAssetKey,
		Hostname:        hostname,
		IPv4:            ipv4,
		IPv6:            ipv6,
		ScannerAssetID:  scannerID,
		CloudInstanceID: cloudID,
		PlatformFamily:  platform,
	}, resolvedSvc
}

func inferPlatformFamily(rawOS string) string {
	low := strings.ToLower(strings.TrimSpace(rawOS))
	switch {
	case strings.Contains(low, "windows"):
		return "WINDOWS"
	case strings.Contains(low, "mac") || strings.Contains(low, "darwin") || strings.Contains(low, "os x"):
		return "MACOS"
	case strings.Contains(low, "rhel") || strings.Contains(low, "red hat") || strings.Contains(low, "centos") || strings.Contains(low, "rocky") || strings.Contains(low, "alma"):
		return "LINUX_RPM"
	case strings.Contains(low, "ubuntu") || strings.Contains(low, "debian"):
		return "LINUX_DEB"
	case strings.Contains(low, "amzn") || strings.Contains(low, "amazon linux"):
		return "LINUX_RPM"
	case strings.Contains(low, "k8s") || strings.Contains(low, "container") || strings.Contains(low, "alpine") || strings.Contains(low, "distroless"):
		return "CONTAINER_LINUX"
	case strings.Contains(low, "linux"):
		return "LINUX_GENERIC"
	default:
		return "ESTATE_HOST"
	}
}

func shortHost(h string) string {
	if idx := strings.IndexByte(h, '.'); idx > 0 {
		return h[:idx]
	}
	return h
}

func sanitizeDNSName(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 180 {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' {
			b.WriteRune(r)
		} else {
			return ""
		}
	}
	return b.String()
}

func sanitizeIP(raw string, wantV6 bool) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return ""
	}
	if wantV6 {
		if ip.To4() != nil {
			return ""
		}
		return ip.String()
	}
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return v4.String()
}

func sanitizeBoundedToken(raw string, maxLen int) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			b.WriteRune(r)
			if b.Len() >= maxLen {
				break
			}
		}
	}
	return b.String()
}

// NormalizeTimestampRFC3339 parses common Qualys, Tenable, and Rapid7 timestamps into strict UTC RFC 3339 strings.
func NormalizeTimestampRFC3339(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	layouts := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

func extractUniqueCVEs(inputs ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, in := range inputs {
		matches := reCVE.FindAllString(strings.ToUpper(in), -1)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

func extractFirstCWE(inputs ...string) string {
	for _, in := range inputs {
		if m := reCWE.FindString(strings.ToUpper(in)); m != "" {
			return m
		}
	}
	return "CWE-000"
}

func sanitizeKB(raw string) string {
	up := strings.ToUpper(strings.TrimSpace(raw))
	if reKBArticle.MatchString(up) {
		return up
	}
	return ""
}

func sanitizeNEVRA(raw string) string {
	s := strings.TrimSpace(raw)
	if reSafeNEVRA.MatchString(s) {
		return s
	}
	return ""
}

func finalizeFindingSet(
	scannerToolID string,
	raw []byte,
	extractorDigest string,
	findings []models.ExtractedFinding,
	maxFindings int,
) (*models.ExtractedFindingSet, error) {
	if len(findings) == 0 {
		return nil, fmt.Errorf("%s payload contained zero active extractable findings", scannerToolID)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].IsKEV != findings[j].IsKEV {
			return findings[i].IsKEV
		}
		if findings[i].CVSSScore != findings[j].CVSSScore {
			return findings[i].CVSSScore > findings[j].CVSSScore
		}
		if findings[i].TargetServiceID != findings[j].TargetServiceID {
			return findings[i].TargetServiceID < findings[j].TargetServiceID
		}
		return findings[i].CVEID < findings[j].CVEID
	})
	if maxFindings > 0 && len(findings) > maxFindings {
		findings = findings[:maxFindings]
	}
	out := &models.ExtractedFindingSet{
		SchemaVersion:   "g1.extractor.finder.v1.2",
		ScannerToolID:   scannerToolID,
		Findings:        findings,
		RawInputSHA256:  crypto.SHA256Hex(raw),
		ExtractorDigest: extractorDigest,
	}
	typedHash, _, err := crypto.CanonicalSHA256Hex(out)
	if err != nil {
		return nil, err
	}
	out.TypedOutputSHA256 = typedHash
	return out, nil
}

func defaultDigestOrPlaceholder(candidate, fallback, seed string) string {
	if reDigest.MatchString(strings.ToLower(strings.TrimSpace(candidate))) {
		return strings.ToLower(strings.TrimSpace(candidate))
	}
	if reDigest.MatchString(strings.ToLower(strings.TrimSpace(fallback))) {
		return strings.ToLower(strings.TrimSpace(fallback))
	}
	return "sha256:" + crypto.SHA256Hex([]byte("estate-artifact:"+seed))
}
