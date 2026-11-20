package extractor

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
)

var (
	reCVE       = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	reCWE       = regexp.MustCompile(`CWE-\d{1,5}`)
	reDigest    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	rePURL      = regexp.MustCompile(`^pkg:[a-z0-9+.-]+/[a-zA-Z0-9._/:%?=&@-]+$`)
	reServiceID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	reSafePath  = regexp.MustCompile(`^[a-zA-Z0-9._/-]{1,180}$`)
	reRuleID    = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,80}$`)

	reDDLStatements = map[string]*regexp.Regexp{
		"ALTER_TABLE":    regexp.MustCompile(`(?i)\bALTER\s+TABLE\b`),
		"DROP_TABLE":     regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`),
		"DROP_COLUMN":    regexp.MustCompile(`(?i)\bDROP\s+COLUMN\b`),
		"ADD_COLUMN":     regexp.MustCompile(`(?i)\bADD\s+COLUMN\b`),
		"CREATE_TABLE":   regexp.MustCompile(`(?i)\bCREATE\s+TABLE\b`),
		"TRUNCATE_TABLE": regexp.MustCompile(`(?i)\bTRUNCATE\s+(TABLE\s+)?[a-zA-Z0-9_]+`),
		"CREATE_INDEX":   regexp.MustCompile(`(?i)\bCREATE\s+(UNIQUE\s+)?INDEX\b`),
	}

	reORMTokens = map[string]*regexp.Regexp{
		"GORM_COLUMN_TAG":    regexp.MustCompile(`gorm:"[^"]*column:`),
		"SQL_DB_STRUCT_TAG":  regexp.MustCompile("`[^`]*db:\"[^\"]+\""),
		"JPA_COLUMN_ANNOT":   regexp.MustCompile(`@Column\s*\(`),
		"PRISMA_MODEL_FIELD": regexp.MustCompile(`@map\(|@@index\(`),
		"ALEMBIC_OP_ALTER":   regexp.MustCompile(`\bop\.(add_column|drop_column|alter_column)\b`),
	}

	reSerializationBreak = regexp.MustCompile(`(?m)^-\s*.*(json:"[a-zA-Z0-9_]+"|protobuf:"[^"]+"|required\s+[a-zA-Z0-9_]+)`)
	reWireBreaking       = regexp.MustCompile(`(?i)(BREAKING_WIRE_CHANGE|x-breaking-change:\s*true|^-\s*rpc\s+[A-Z]|^-\s*/api/v[0-9]+/)`)
	reDangerousSyscalls  = map[string]*regexp.Regexp{
		"execve":   regexp.MustCompile(`\b(syscall\.Exec|exec\.Command|execve\s*\()`),
		"execveat": regexp.MustCompile(`\bexecveat\s*\(`),
		"ptrace":   regexp.MustCompile(`\b(syscall\.Ptrace|ptrace\s*\()`),
		"mount":    regexp.MustCompile(`\b(syscall\.Mount|mount\s*\()`),
		"connect":  regexp.MustCompile(`\b(net\.Dial|syscall\.Connect)\b`),
	}
)

var allowedVectors = map[string]bool{
	"HTTP_PATH_TRAVERSAL": true,
	"JNDI_LOOKUP":         true,
	"PROTO_DESERIALIZE":   true,
	"TLS_HEARTBEAT":       true,
	"HTTP2_RAPID_RESET":   true,
	"SSRF_METADATA":       true,
	"UNRESTRICTED_UPLOAD": true,
	"ERROR_STACK_TRACE":   true,
	"GENERIC_RCE":         true,
}

// chainedExploitCWEs are "medium" / non-RCE CWE classes actively weaponized by autonomous LLM intrusion
// frameworks (ARTEX / GTIG / Phoenix findings) for compiler/SQL feedback, metadata pivoting, and webshell drops.
var chainedExploitCWEs = map[string]bool{
	"CWE-209": true, // Generation of Error Message Containing Sensitive Information (stack traces)
	"CWE-918": true, // Server-Side Request Forgery (SSRF -> 169.254.169.254 / internal APIs)
	"CWE-434": true, // Unrestricted Upload of File with Dangerous Type (JSP/PHP webshell drop)
}

// SelfBinaryDigest computes the SHA-256 hex digest of the running extractor binary.
func SelfBinaryDigest() string {
	exe, err := os.Executable()
	if err != nil {
		return crypto.SHA256Hex([]byte("warrant-extractor-static-v1"))
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		return crypto.SHA256Hex([]byte("warrant-extractor-static-v1"))
	}
	return crypto.SHA256Hex(b)
}

// untrusted SARIF 2.1.0 minimal projection (prose fields intentionally omitted from struct decoding!)
type sarifEnvelope struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name  string      `json:"name"`
			Rules []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifRule struct {
	ID         string          `json:"id"`
	Properties sarifProperties `json:"properties"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Locations  []sarifLocation `json:"locations"`
	Properties sarifProperties `json:"properties"`
}

// SARIFExtractOptions supplies optional bounded target defaults when ingesting unmodified
// OSS scanner reports (such as aquasec/trivy --format sarif) that lack custom workload tags.
type SARIFExtractOptions struct {
	DefaultServiceID        string
	DefaultVulnerableDigest string
	MaxFindings             int
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

type sarifProperties struct {
	CVE              string   `json:"cve"`
	CWE              string   `json:"cwe"`
	SecuritySeverity string   `json:"security-severity"`
	CVSS             float64  `json:"cvss"`
	KEV              bool     `json:"cisa_kev"`
	ServiceID        string   `json:"service_id"`
	PURL             string   `json:"purl"`
	VulnerableDigest string   `json:"vulnerable_digest"`
	PatchedDigest    string   `json:"patched_digest"`
	VulnerableSymbol string   `json:"vulnerable_symbol"`
	ExploitVector    string   `json:"exploit_vector"`
	AffectedPort     int      `json:"affected_port"`
	BlockedPaths     []string `json:"blocked_paths"`
	Tags             []string `json:"tags"`
}

type sarifRunProperties struct {
	ImageName   string   `json:"imageName"`
	RepoDigests []string `json:"repoDigests"`
}

// ParseUntrustedSARIF parses untrusted SARIF 2.1.0 bytes using strict default options.
func ParseUntrustedSARIF(raw []byte, extractorDigest string) (*models.ExtractedFindingSet, error) {
	return ParseUntrustedSARIFWithOptions(raw, extractorDigest, SARIFExtractOptions{})
}

// ParseUntrustedSARIFWithOptions parses untrusted Wiz/Tenable/GitHub/Trivy SARIF 2.1.0 bytes,
// drops all prose/messages/markdown, validates strict regex bounds, deduplicates by (service, CVE),
// and produces a JCS-hashed ExtractedFindingSet.
func ParseUntrustedSARIFWithOptions(raw []byte, extractorDigest string, opts SARIFExtractOptions) (*models.ExtractedFindingSet, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty SARIF input")
	}
	rawSHA := crypto.SHA256Hex(raw)

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string      `json:"name"`
					Rules []sarifRule `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Properties sarifRunProperties `json:"properties"`
			Results    []sarifResult      `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("invalid SARIF JSON: %w", err)
	}
	if doc.Version != "2.1.0" {
		return nil, fmt.Errorf("unsupported SARIF version %q (expected 2.1.0)", doc.Version)
	}
	if len(doc.Runs) == 0 {
		return nil, errors.New("SARIF contains zero runs")
	}

	findings := make([]models.ExtractedFinding, 0)
	seen := map[string]bool{}
	scannerID := "UNKNOWN_SCANNER"

	for _, run := range doc.Runs {
		name := sanitizeToken(run.Tool.Driver.Name, 40)
		if name != "" {
			scannerID = name
		}
		ruleMap := map[string]sarifRule{}
		for _, r := range run.Tool.Driver.Rules {
			ruleMap[r.ID] = r
		}

		// Extract optional OCI sha256 digest from Trivy repoDigests if present
		runDigest := ""
		for _, rd := range run.Properties.RepoDigests {
			if idx := strings.Index(rd, "sha256:"); idx >= 0 {
				cand := strings.ToLower(strings.TrimSpace(rd[idx:]))
				if reDigest.MatchString(cand) {
					runDigest = cand
					break
				}
			}
		}

		for _, res := range run.Results {
			rule := ruleMap[res.RuleID]
			props := mergeProps(rule.Properties, res.Properties)

			cve := reCVE.FindString(strings.ToUpper(props.CVE + " " + res.RuleID + " " + strings.Join(props.Tags, " ")))
			if cve == "" {
				// In multi-result OSS scans (e.g., Trivy GHSA-only or misconfig rules), skip non-CVE entries
				if len(run.Results) > 1 {
					continue
				}
				return nil, fmt.Errorf("SARIF finding missing valid CVE identifier (ruleId=%q)", sanitizeToken(res.RuleID, 40))
			}
			cwe := reCWE.FindString(strings.ToUpper(props.CWE + " " + strings.Join(props.Tags, " ")))
			if cwe == "" {
				cwe = "CWE-000"
			}

			cvss := props.CVSS
			if cvss <= 0 && props.SecuritySeverity != "" {
				if parsed, err := strconv.ParseFloat(props.SecuritySeverity, 64); err == nil {
					cvss = parsed
				}
			}
			if cvss <= 0 {
				cvss = inferCVSSFromTagsAndLevel(props.Tags, res.Level)
			}
			if cvss < 0 || cvss > 10.0 {
				return nil, fmt.Errorf("CVSS score %.2f out of bounds [0, 10]", cvss)
			}

			isKEV := props.KEV
			for _, tag := range props.Tags {
				if strings.EqualFold(tag, "CISA-KEV") || strings.EqualFold(tag, "KEV") {
					isKEV = true
				}
			}

			svcID := strings.ToLower(strings.TrimSpace(props.ServiceID))
			if svcID == "" {
				svcID = strings.ToLower(strings.TrimSpace(opts.DefaultServiceID))
			}
			if !reServiceID.MatchString(svcID) {
				return nil, fmt.Errorf("invalid target service_id %q", sanitizeToken(svcID, 40))
			}

			vulnDigest := strings.ToLower(strings.TrimSpace(props.VulnerableDigest))
			if vulnDigest == "" {
				if opts.DefaultVulnerableDigest != "" {
					vulnDigest = strings.ToLower(strings.TrimSpace(opts.DefaultVulnerableDigest))
				} else if runDigest != "" {
					vulnDigest = runDigest
				} else if run.Properties.ImageName != "" {
					vulnDigest = "sha256:" + crypto.SHA256Hex([]byte("trivy-image:"+run.Properties.ImageName))
				}
			}
			if !reDigest.MatchString(vulnDigest) {
				return nil, fmt.Errorf("invalid vulnerable_digest format for %s", cve)
			}

			patchedDigest := strings.ToLower(strings.TrimSpace(props.PatchedDigest))
			if patchedDigest != "" && !reDigest.MatchString(patchedDigest) {
				return nil, fmt.Errorf("invalid patched_digest format for %s", cve)
			}

			purl := strings.TrimSpace(props.PURL)
			if purl == "" {
				purl = "pkg:oci/" + svcID + "@" + vulnDigest
			}
			if !rePURL.MatchString(purl) {
				return nil, fmt.Errorf("invalid package PURL format for %s", cve)
			}

			vec := strings.ToUpper(strings.TrimSpace(props.ExploitVector))
			if vec == "" || !allowedVectors[vec] {
				vec = "GENERIC_RCE"
			}

			port := props.AffectedPort
			if port <= 0 || port > 65535 {
				port = 8080
			}

			blockedPaths := []string{}
			for _, bp := range props.BlockedPaths {
				if reSafePath.MatchString(bp) {
					blockedPaths = append(blockedPaths, bp)
				}
			}
			sort.Strings(blockedPaths)

			var artPaths []string
			for _, loc := range res.Locations {
				uri := loc.PhysicalLocation.ArtifactLocation.URI
				if reSafePath.MatchString(uri) {
					artPaths = append(artPaths, uri)
				}
			}
			sort.Strings(artPaths)

			ruleID := res.RuleID
			if !reRuleID.MatchString(ruleID) {
				ruleID = cve
			}

			vulnSym := sanitizeToken(props.VulnerableSymbol, 80)

			dedupKey := svcID + "|" + cve
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true

			findings = append(findings, models.ExtractedFinding{
				RuleID:                ruleID,
				CVEID:                 cve,
				CWEID:                 cwe,
				CVSSScore:             cvss,
				IsKEV:                 isKEV,
				TargetServiceID:       svcID,
				PackagePURL:           purl,
				VulnerableDigest:      vulnDigest,
				PatchedDigest:         patchedDigest,
				VulnerableSymbol:      vulnSym,
				ExploitVector:         vec,
				AffectedPort:          port,
				BlockedPaths:          blockedPaths,
				ArtifactPaths:         artPaths,
				ChainedExploitEnabler: chainedExploitCWEs[strings.ToUpper(cwe)],
			})
		}
	}

	if len(findings) == 0 {
		return nil, errors.New("SARIF contained zero extractable CVE findings")
	}

	// Sort deterministically: KEV first, then CVSS descending, then CVE ascending
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].IsKEV != findings[j].IsKEV {
			return findings[i].IsKEV
		}
		if findings[i].CVSSScore != findings[j].CVSSScore {
			return findings[i].CVSSScore > findings[j].CVSSScore
		}
		return findings[i].CVEID < findings[j].CVEID
	})

	if opts.MaxFindings > 0 && len(findings) > opts.MaxFindings {
		findings = findings[:opts.MaxFindings]
	}

	out := &models.ExtractedFindingSet{
		SchemaVersion:   "g1.extractor.sarif.v1",
		ScannerToolID:   scannerID,
		Findings:        findings,
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

func inferCVSSFromTagsAndLevel(tags []string, level string) float64 {
	for _, t := range tags {
		switch strings.ToUpper(strings.TrimSpace(t)) {
		case "CRITICAL":
			return 9.4
		case "HIGH":
			return 7.8
		case "MEDIUM":
			return 5.5
		case "LOW":
			return 3.1
		}
	}
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return 8.5
	case "warning":
		return 5.5
	default:
		return 7.0
	}
}

// IsProtectedBuildOrAgentPath checks normalized repository paths at ANY directory depth
// (checking both directory segments and basenames) to block CI/CD, container build, Makefile,
// and coding-agent instruction mutations in nested monorepo/multi-service layouts.
func IsProtectedBuildOrAgentPath(cleanPath string) bool {
	norm := strings.ReplaceAll(strings.TrimSpace(cleanPath), `\`, "/")
	for _, seg := range strings.Split(norm, "/") {
		sLow := strings.ToLower(strings.TrimSpace(seg))
		if sLow == ".." {
			return true
		}
		switch sLow {
		case ".github", ".cursor", ".gemini", ".windsurf", ".copilot", ".vscode", ".git":
			return true
		}
		if strings.HasPrefix(sLow, ".gitlab-ci") || strings.HasPrefix(sLow, ".cursor") {
			return true
		}
	}
	base := strings.ToLower(path.Base(norm))
	if strings.HasPrefix(base, "dockerfile") || strings.HasSuffix(base, ".dockerfile") {
		return true
	}
	switch base {
	case "makefile", "gnumakefile", "agents.md", "claude.md":
		return true
	}
	if strings.HasPrefix(base, ".gitlab-ci") || strings.HasPrefix(base, ".cursor") {
		return true
	}
	return false
}

// DiffExtractRequest wraps an untrusted unified git diff and target patched OCI digest.
type DiffExtractRequest struct {
	PatchedDigest string `json:"patched_digest"`
	UnifiedDiff   string `json:"unified_diff"`
}

// ParseUntrustedDiff parses a unified git diff, strips all commit messages and comments,
// and deterministically computes Patch Statelessness (SQL DDL, ORM deltas, serialization breaks, syscalls).
func ParseUntrustedDiff(raw []byte, extractorDigest string) (*models.ExtractedPatchMetadata, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty diff payload")
	}
	rawSHA := crypto.SHA256Hex(raw)
	var req DiffExtractRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		// Also accept raw text unified diff directly
		req.UnifiedDiff = string(raw)
	}
	patchedDigest := strings.ToLower(strings.TrimSpace(req.PatchedDigest))
	if patchedDigest != "" && !reDigest.MatchString(patchedDigest) {
		return nil, errors.New("invalid patched_digest in diff request")
	}

	lines := strings.Split(req.UnifiedDiff, "\n")
	filesChanged := 0
	touchedSet := map[string]bool{}
	forbiddenSet := map[string]bool{}
	ddlSet := map[string]bool{}
	ddlCount := 0
	ormSet := map[string]bool{}
	ormCount := 0
	serialBreaks := 0
	apiCompatible := true
	syscallSet := map[string]bool{}
	inDockerfile := false

	currentFile := ""
	checkTouchedPath := func(rawPath string) {
		trimmed := strings.Trim(strings.TrimSpace(rawPath), `"`)
		trimmed = strings.ReplaceAll(trimmed, `\`, "/")
		if trimmed == "" || trimmed == "/dev/null" || trimmed == "dev/null" {
			inDockerfile = false
			currentFile = ""
			return
		}
		// Reject raw '..' traversal segments BEFORE path.Clean collapses them
		for _, rawSeg := range strings.Split(trimmed, "/") {
			if rawSeg == ".." {
				forbiddenSet["PATH_TRAVERSAL:"+trimmed] = true
				touchedSet[trimmed] = true
				currentFile = trimmed
				return
			}
		}
		clean := path.Clean(strings.TrimPrefix(strings.TrimPrefix(trimmed, "./"), "/"))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean == "dev/null" {
			if clean == ".." || strings.HasPrefix(clean, "../") {
				forbiddenSet["PATH_TRAVERSAL:"+trimmed] = true
			}
			inDockerfile = false
			currentFile = ""
			return
		}
		currentFile = clean
		touchedSet[clean] = true

		baseLower := strings.ToLower(path.Base(clean))
		inDockerfile = strings.HasPrefix(baseLower, "dockerfile") || strings.HasSuffix(baseLower, ".dockerfile")

		if IsProtectedBuildOrAgentPath(clean) {
			forbiddenSet[clean] = true
		}
	}

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "new file mode 120000") ||
			strings.HasPrefix(trimmedLine, "old mode 120000") ||
			strings.HasPrefix(trimmedLine, "new mode 120000") ||
			(strings.HasPrefix(trimmedLine, "index ") && strings.HasSuffix(trimmedLine, " 120000")) {
			lbl := currentFile
			if lbl == "" {
				lbl = "git-symlink"
			}
			forbiddenSet["SYMLINK_MODE_120000:"+lbl] = true
			continue
		}
		if strings.HasPrefix(line, "diff --git ") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				checkTouchedPath(strings.TrimPrefix(parts[2], "a/"))
				checkTouchedPath(strings.TrimPrefix(parts[3], "b/"))
			}
			continue
		}
		if strings.HasPrefix(line, "--- ") {
			src := strings.TrimSpace(strings.TrimPrefix(line, "--- "))
			src = strings.TrimPrefix(src, "a/")
			if src != "/dev/null" && src != "dev/null" {
				checkTouchedPath(src)
			}
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			target := strings.TrimSpace(strings.TrimPrefix(line, "+++ "))
			target = strings.TrimPrefix(target, "b/")
			if target != "/dev/null" {
				filesChanged++
				checkTouchedPath(target)
			}
			continue
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			added := line[1:]
			if inDockerfile && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(added)), "RUN ") {
				forbiddenSet["DOCKERFILE_RUN_HOOK"] = true
			}
			for code, rx := range reDDLStatements {
				if rx.MatchString(added) {
					ddlSet[code] = true
					ddlCount++
				}
			}
			for code, rx := range reORMTokens {
				if rx.MatchString(added) {
					ormSet[code] = true
					ormCount++
				}
			}
			for sc, rx := range reDangerousSyscalls {
				if rx.MatchString(added) {
					syscallSet[sc] = true
				}
			}
		}
		if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			if reSerializationBreak.MatchString(line) {
				serialBreaks++
			}
			for code, rx := range reORMTokens {
				if rx.MatchString(line) {
					ormSet[code] = true
					ormCount++
				}
			}
		}
		if reWireBreaking.MatchString(line) {
			apiCompatible = false
		}
	}
	if serialBreaks > 0 {
		apiCompatible = false
	}
	if filesChanged == 0 && len(strings.TrimSpace(req.UnifiedDiff)) > 0 {
		filesChanged = 1
	}

	ddlList := sortedKeys(ddlSet)
	ormList := sortedKeys(ormSet)
	sysList := sortedKeys(syscallSet)
	touchedList := sortedKeys(touchedSet)
	forbiddenList := sortedKeys(forbiddenSet)
	stateless := ddlCount == 0 && ormCount == 0 && serialBreaks == 0 && apiCompatible && len(forbiddenList) == 0

	out := &models.ExtractedPatchMetadata{
		SchemaVersion:          "g1.extractor.diff.v1",
		PatchedDigest:          patchedDigest,
		FilesChanged:           filesChanged,
		TouchedFiles:           touchedList,
		ForbiddenConfigTouches: forbiddenList,
		DDLMigrations:          ddlCount,
		DetectedDDLKeywords:    ddlList,
		ORMModelMutations:      ormCount,
		DetectedORMTokens:      ormList,
		SerializationBreaks:    serialBreaks,
		APIBackwardCompatible:  apiCompatible,
		DeclaredSyscallDelta:   sysList,
		StatelessEligible:      stateless,
		RawInputSHA256:         rawSHA,
		ExtractorDigest:        extractorDigest,
	}
	typedHash, _, err := crypto.CanonicalSHA256Hex(out)
	if err != nil {
		return nil, err
	}
	out.TypedOutputSHA256 = typedHash
	return out, nil
}

// ParseUntrustedAdvisory parses CycloneDX/VEX or KEV JSON into a bounded prose-free struct.
func ParseUntrustedAdvisory(raw []byte, extractorDigest string) (*models.ExtractedAdvisory, error) {
	rawSHA := crypto.SHA256Hex(raw)
	var doc struct {
		ID            string   `json:"id"`
		CVE           string   `json:"cve"`
		State         string   `json:"state"`
		IsKEV         bool     `json:"is_kev"`
		CVSS          float64  `json:"cvss"`
		AffectedPURLs []string `json:"affected_purls"`
		FixedDigest   string   `json:"fixed_digest"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("invalid advisory JSON: %w", err)
	}
	cve := reCVE.FindString(strings.ToUpper(doc.CVE + " " + doc.ID))
	if cve == "" {
		return nil, errors.New("advisory missing valid CVE ID")
	}
	state := strings.ToUpper(strings.TrimSpace(doc.State))
	switch state {
	case "AFFECTED", "EXPLOITABLE", "":
		state = "AFFECTED"
	case "FIXED", "RESOLVED":
		state = "FIXED"
	case "NOT_AFFECTED":
		state = "NOT_AFFECTED"
	default:
		state = "AFFECTED"
	}
	var purls []string
	for _, p := range doc.AffectedPURLs {
		if rePURL.MatchString(p) {
			purls = append(purls, p)
		}
	}
	sort.Strings(purls)
	fixed := strings.ToLower(strings.TrimSpace(doc.FixedDigest))
	if fixed != "" && !reDigest.MatchString(fixed) {
		return nil, errors.New("invalid fixed_digest in advisory")
	}
	out := &models.ExtractedAdvisory{
		SchemaVersion:   "g1.extractor.advisory.v1",
		CVEID:           cve,
		VEXStatus:       state,
		IsKEV:           doc.IsKEV,
		CVSSScore:       doc.CVSS,
		AffectedPURLs:   purls,
		FixedDigest:     fixed,
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

// NewHTTPHandler constructs the stateless HTTP mux for /cmd/warrant-extractor.
func NewHTTPHandler(extractorDigest string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":           "OK",
			"service":          "warrant-extractor",
			"egress_profile":   "ZERO_EGRESS_ISOLATED",
			"extractor_digest": extractorDigest,
		})
	})
	mux.HandleFunc("POST /extract/sarif", func(w http.ResponseWriter, r *http.Request) {
		body, err := readBounded(w, r, 8<<20)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		maxFindings := 0
		if mf := r.URL.Query().Get("max_findings"); mf != "" {
			if parsed, pErr := strconv.Atoi(mf); pErr == nil && parsed > 0 {
				maxFindings = parsed
			}
		}
		opts := SARIFExtractOptions{
			DefaultServiceID:        r.URL.Query().Get("target_service"),
			DefaultVulnerableDigest: r.URL.Query().Get("vulnerable_digest"),
			MaxFindings:             maxFindings,
		}
		res, err := ParseUntrustedSARIFWithOptions(body, extractorDigest, opts)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /extract/cisa-kev", func(w http.ResponseWriter, r *http.Request) {
		body, err := readBounded(w, r, 16<<20)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		res, err := ParseUntrustedCISAKEV(body, extractorDigest)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /extract/osv", func(w http.ResponseWriter, r *http.Request) {
		body, err := readBounded(w, r, 8<<20)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		res, err := ParseUntrustedOSVBundle(body, extractorDigest)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /extract/diff", func(w http.ResponseWriter, r *http.Request) {
		body, err := readBounded(w, r, 4<<20)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		res, err := ParseUntrustedDiff(body, extractorDigest)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /extract/advisory", func(w http.ResponseWriter, r *http.Request) {
		body, err := readBounded(w, r, 2<<20)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		res, err := ParseUntrustedAdvisory(body, extractorDigest)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /extract/secrets", func(w http.ResponseWriter, r *http.Request) {
		body, err := readBounded(w, r, 4<<20)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		defaultSvc := r.URL.Query().Get("target_service")
		res, err := ParseUntrustedSecretFindings(body, extractorDigest, defaultSvc)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})
	return mux
}

// ParseUntrustedSecretFindings parses Gitleaks (JSON array or SARIF 2.1.0), GitGuardian, or cloud secret-exposure
// scan outputs, irreversibly hashes raw secret tokens into SHA-256 fingerprints, strips all commit prose/raw secrets,
// and emits bounded ExtractedSecretFindingSet records for SECRET-ROTATION-STATELESS warrant execution.
func ParseUntrustedSecretFindings(raw []byte, extractorDigest, defaultServiceID string) (*models.ExtractedSecretFindingSet, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, errors.New("empty secret scan input")
	}
	rawSHA := crypto.SHA256Hex(raw)
	defaultSvc := strings.ToLower(strings.TrimSpace(defaultServiceID))

	type rawSecretItem struct {
		RuleID       string `json:"RuleID"`
		RuleIDAlt    string `json:"rule_id"`
		Detector     string `json:"detector_name"`
		Secret       string `json:"Secret"`
		Match        string `json:"Match"`
		Fingerprint  string `json:"Fingerprint"`
		File         string `json:"File"`
		FileAlt      string `json:"file_path"`
		ServiceID    string `json:"service_id"`
		ResourceKind string `json:"secret_resource_kind"`
		ResourceName string `json:"secret_resource_name"`
	}

	var items []rawSecretItem
	detector := "Gitleaks"

	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("invalid Gitleaks JSON array: %w", err)
		}
	} else {
		// Check if SARIF 2.1.0 (e.g. gitleaks detect --report-format sarif) or GitGuardian/wrapper JSON
		var wrapper struct {
			Version   string          `json:"version"`
			Detector  string          `json:"detector_tool"`
			Findings  []rawSecretItem `json:"findings"`
			Incidents []rawSecretItem `json:"incidents"`
			Runs      []struct {
				Tool struct {
					Driver struct {
						Name string `json:"name"`
					} `json:"driver"`
				} `json:"tool"`
				Results []struct {
					RuleID       string            `json:"ruleId"`
					Fingerprints map[string]string `json:"partialFingerprints"`
					Locations    []sarifLocation   `json:"locations"`
					Properties   struct {
						ServiceID    string `json:"service_id"`
						ResourceKind string `json:"secret_resource_kind"`
						ResourceName string `json:"secret_resource_name"`
					} `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			return nil, fmt.Errorf("invalid secret scan JSON: %w", err)
		}
		if wrapper.Detector != "" {
			detector = sanitizeToken(wrapper.Detector, 40)
		}
		switch {
		case len(wrapper.Runs) > 0:
			if n := sanitizeToken(wrapper.Runs[0].Tool.Driver.Name, 40); n != "" {
				detector = n
			}
			for _, run := range wrapper.Runs {
				for _, r := range run.Results {
					fp := ""
					for _, v := range r.Fingerprints {
						fp = v
						break
					}
					uri := ""
					if len(r.Locations) > 0 {
						uri = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
					}
					items = append(items, rawSecretItem{
						RuleID:       r.RuleID,
						Fingerprint:  fp,
						File:         uri,
						ServiceID:    r.Properties.ServiceID,
						ResourceKind: r.Properties.ResourceKind,
						ResourceName: r.Properties.ResourceName,
					})
				}
			}
		case len(wrapper.Findings) > 0:
			items = wrapper.Findings
		case len(wrapper.Incidents) > 0:
			detector = "GitGuardian"
			items = wrapper.Incidents
		}
	}

	if len(items) == 0 {
		return nil, errors.New("secret scan contains zero actionable findings")
	}

	outFindings := make([]models.ExtractedSecretFinding, 0, len(items))
	seen := map[string]bool{}
	for idx, it := range items {
		rule := sanitizeToken(nonEmptyStr(it.RuleID, nonEmptyStr(it.RuleIDAlt, it.Detector)), 64)
		if rule == "" {
			rule = "generic-credential-leak"
		}
		svcID := strings.ToLower(strings.TrimSpace(nonEmptyStr(it.ServiceID, defaultSvc)))
		if !reServiceID.MatchString(svcID) {
			return nil, fmt.Errorf("invalid or missing target service_id %q for secret finding", sanitizeToken(svcID, 40))
		}
		fileClean := ""
		rawFile := nonEmptyStr(it.File, it.FileAlt)
		if reSafePath.MatchString(rawFile) {
			fileClean = rawFile
		}

		// Compute irreversible SHA-256 fingerprint over secret material without retaining plaintext
		fpSeed := nonEmptyStr(it.Secret, nonEmptyStr(it.Match, nonEmptyStr(it.Fingerprint, fmt.Sprintf("%s|%s|%d", svcID, rule, idx))))
		secretFP := crypto.SHA256Hex([]byte("g1-secret-fp:" + fpSeed))

		resKind := strings.ToUpper(strings.TrimSpace(it.ResourceKind))
		switch resKind {
		case "EXTERNAL_SECRET", "WORKLOAD_SA_TOKEN", "K8S_SECRET":
		default:
			if strings.Contains(strings.ToLower(rule), "jwt") || strings.Contains(strings.ToLower(rule), "k8s") || strings.Contains(strings.ToLower(rule), "service-account") {
				resKind = "WORKLOAD_SA_TOKEN"
			} else {
				resKind = "EXTERNAL_SECRET"
			}
		}

		resName := sanitizeToken(it.ResourceName, 63)
		if resName == "" {
			resName = fmt.Sprintf("extsec-%s-%s", svcID, strings.ToLower(sanitizeToken(rule, 24)))
		}

		dedup := svcID + "|" + resName + "|" + secretFP
		if seen[dedup] {
			continue
		}
		seen[dedup] = true

		outFindings = append(outFindings, models.ExtractedSecretFinding{
			FindingID:               "SEC-" + strings.ToUpper(secretFP[:10]),
			DetectorTool:            detector,
			RuleID:                  rule,
			TargetServiceID:         svcID,
			SecretResourceKind:      resKind,
			SecretResourceName:      resName,
			SecretFingerprintSHA256: secretFP,
			FilePath:                fileClean,
		})
	}

	out := &models.ExtractedSecretFindingSet{
		SchemaVersion:   "g1.extractor.secrets.v1",
		DetectorTool:    detector,
		Findings:        outFindings,
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

func nonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(b)
}

func readBounded(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer r.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}
	}
	return buf, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func mergeProps(base, override sarifProperties) sarifProperties {
	out := base
	if override.CVE != "" {
		out.CVE = override.CVE
	}
	if override.CWE != "" {
		out.CWE = override.CWE
	}
	if override.SecuritySeverity != "" {
		out.SecuritySeverity = override.SecuritySeverity
	}
	if override.CVSS > 0 {
		out.CVSS = override.CVSS
	}
	if override.KEV {
		out.KEV = true
	}
	if override.ServiceID != "" {
		out.ServiceID = override.ServiceID
	}
	if override.PURL != "" {
		out.PURL = override.PURL
	}
	if override.VulnerableDigest != "" {
		out.VulnerableDigest = override.VulnerableDigest
	}
	if override.PatchedDigest != "" {
		out.PatchedDigest = override.PatchedDigest
	}
	if override.VulnerableSymbol != "" {
		out.VulnerableSymbol = override.VulnerableSymbol
	}
	if override.ExploitVector != "" {
		out.ExploitVector = override.ExploitVector
	}
	if override.AffectedPort > 0 {
		out.AffectedPort = override.AffectedPort
	}
	if len(override.BlockedPaths) > 0 {
		out.BlockedPaths = override.BlockedPaths
	}
	if len(override.Tags) > 0 {
		out.Tags = append(out.Tags, override.Tags...)
	}
	return out
}

func sanitizeToken(s string, maxLen int) string {
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

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
