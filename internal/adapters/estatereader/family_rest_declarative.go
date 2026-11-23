package estatereader

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

//go:embed mappings/*.json
var embeddedMappingsFS embed.FS

// RESTMappingSpec is a purely declarative data specification (data, not code) describing how to query
// and extract bounded EstateSnapshot summaries from any proprietary REST endpoint manager.
// Adding a 19th REST endpoint manager requires ONLY a RESTMappingSpec JSON sheet and zero new Go handler code.
type RESTMappingSpec struct {
	SourceSystem         string            `json:"source_system"`
	DisplayName          string            `json:"display_name"`
	SourceTier           string            `json:"source_tier"` // defaults to TIER_A_MACHINE
	ReadEnvPrefix        string            `json:"read_env_prefix"`
	DispatchEnvPrefix    string            `json:"dispatch_env_prefix"`
	InventoryMethod      string            `json:"inventory_method"` // GET (default) | POST
	InventoryPath        string            `json:"inventory_path"`
	ClassQueryParam      string            `json:"class_query_param,omitempty"`
	ScopeQueryParam      string            `json:"scope_query_param,omitempty"`
	DefaultPlatform      string            `json:"default_platform"`
	DefaultOSFamily      string            `json:"default_os_family"`
	RecordsArrayPath     string            `json:"records_array_path"`
	TotalCountPath       string            `json:"total_count_path,omitempty"`
	FreshnessPath        string            `json:"freshness_path,omitempty"`
	RecordCountField     string            `json:"record_count_field,omitempty"`
	OSFamilyField        string            `json:"os_family_field"`
	OSVersionField       string            `json:"os_version_field"`
	KernelReleaseField   string            `json:"kernel_release_field,omitempty"`
	OSCPE23Field         string            `json:"os_cpe23_field,omitempty"`
	SoftwareArrayField   string            `json:"software_array_field,omitempty"`
	SoftwareNameField    string            `json:"software_name_field"`
	SoftwareVersionField string            `json:"software_version_field"`
	SoftwareCPE23Field   string            `json:"software_cpe23_field,omitempty"`
	SoftwareSWIDField    string            `json:"software_swid_field,omitempty"`
	SoftwarePURLField    string            `json:"software_purl_field,omitempty"`
	CandidatesArrayPath  string            `json:"candidates_array_path,omitempty"`
	CandidateIDField     string            `json:"candidate_id_field"`
	CandidatePlatField   string            `json:"candidate_platform_field,omitempty"`
	CandidateCreatedField string           `json:"candidate_created_field,omitempty"`
	StaticQueryParams    map[string]string `json:"static_query_params,omitempty"`
}

// LoadEmbeddedRESTMappingSpecs loads all declarative JSON vendor mapping sheets bundled in mappings/*.json.
func LoadEmbeddedRESTMappingSpecs() ([]RESTMappingSpec, error) {
	entries, err := fs.ReadDir(embeddedMappingsFS, "mappings")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	specs := make([]RESTMappingSpec, 0, len(names))
	for _, name := range names {
		raw, err := fs.ReadFile(embeddedMappingsFS, "mappings/"+name)
		if err != nil {
			return nil, err
		}
		var spec RESTMappingSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			return nil, fmt.Errorf("parse mapping %s: %w", name, err)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

// ParseRESTMappingSpecJSON parses a declarative RESTMappingSpec from raw JSON bytes (enabling zero-code registration).
func ParseRESTMappingSpecJSON(rawJSON []byte) (RESTMappingSpec, error) {
	var spec RESTMappingSpec
	if err := json.Unmarshal(rawJSON, &spec); err != nil {
		return RESTMappingSpec{}, fmt.Errorf("invalid RESTMappingSpec JSON: %w", err)
	}
	if strings.TrimSpace(spec.SourceSystem) == "" || strings.TrimSpace(spec.InventoryPath) == "" {
		return RESTMappingSpec{}, fmt.Errorf("RESTMappingSpec requires source_system and inventory_path")
	}
	return spec, nil
}

// DeclarativeRESTEstateReader executes bounded decision-time estate queries driven strictly by a RESTMappingSpec.
type DeclarativeRESTEstateReader struct {
	baseEstateHTTPClient
	spec RESTMappingSpec
}

func NewDeclarativeRESTEstateReader(
	spec RESTMappingSpec,
	readURL, readToken, dispatchToken string,
	rt http.RoundTripper,
) *DeclarativeRESTEstateReader {
	tier := strings.TrimSpace(spec.SourceTier)
	if tier == "" {
		tier = models.EstateSourceTierAMachine
	}
	return &DeclarativeRESTEstateReader{
		baseEstateHTTPClient: newBaseEstateHTTPClient(
			spec.SourceSystem,
			firstStr(spec.DisplayName, spec.SourceSystem),
			tier,
			models.EstateHandlerFamilyRESTDeclarative,
			firstStr(spec.ReadEnvPrefix, "WARRANT_"+strings.ToUpper(strings.ReplaceAll(spec.SourceSystem, "-", "_"))),
			readURL,
			readToken,
			dispatchToken,
			rt,
		),
		spec: spec,
	}
}

func (d *DeclarativeRESTEstateReader) MappingSpec() RESTMappingSpec { return d.spec }

func (d *DeclarativeRESTEstateReader) WithTransport(rt http.RoundTripper) EstateReader {
	cp := *d
	cp.baseEstateHTTPClient = d.baseEstateHTTPClient.cloneWithTransport(rt)
	return &cp
}

func (d *DeclarativeRESTEstateReader) ReadEstateSnapshot(ctx context.Context, q EstateReadQuery) (*models.EstateSnapshot, error) {
	now := time.Now().UTC()
	queryID := ComputeCanonicalQueryIdentity(d.sourceSystem, q)

	method := strings.ToUpper(strings.TrimSpace(d.spec.InventoryMethod))
	if method == "" {
		method = http.MethodGet
	}

	u := url.Values{}
	for k, v := range d.spec.StaticQueryParams {
		u.Set(k, v)
	}
	if d.spec.ClassQueryParam != "" && q.WarrantClass != "" {
		u.Set(d.spec.ClassQueryParam, q.WarrantClass)
	}
	if d.spec.ScopeQueryParam != "" && len(q.ScopeServices) > 0 {
		u.Set(d.spec.ScopeQueryParam, strings.Join(q.ScopeServices, ","))
	}

	reqPath := d.spec.InventoryPath
	if enc := u.Encode(); enc != "" {
		if strings.Contains(reqPath, "?") {
			reqPath += "&" + enc
		} else {
			reqPath += "?" + enc
		}
	}

	var reqBody any
	if method == http.MethodPost {
		reqBody = map[string]any{
			"warrant_class":  q.WarrantClass,
			"scope_services": q.ScopeServices,
			"scope_filter":   q.ScopeFilter,
		}
	}

	raw, err := d.doReadRequest(ctx, method, reqPath, reqBody)
	if err != nil {
		return nil, err
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("ESTATE_READ_PARSE_ERROR (%s): %w", d.sourceSystem, err)
	}

	snap := &models.EstateSnapshot{
		SourceSystem:  d.sourceSystem,
		SourceTier:    d.sourceTier,
		HandlerFamily: models.EstateHandlerFamilyRESTDeclarative,
		QueryIdentity: queryID,
		ClassScope:    q.ScopeServices,
	}

	if d.spec.TotalCountPath != "" {
		if v, ok := lookupDotPath(doc, d.spec.TotalCountPath); ok {
			snap.ClassMembershipCount = toInt(v, 0)
		}
	}

	freshStr := ""
	if d.spec.FreshnessPath != "" {
		if v, ok := lookupDotPath(doc, d.spec.FreshnessPath); ok {
			freshStr = toStr(v)
		}
	}

	records := extractObjectSlice(doc, d.spec.RecordsArrayPath)
	osBuckets := map[string]*models.OSKernelBucket{}
	swBuckets := map[string]*models.SoftwareBucket{}
	seenCands := map[string]bool{}
	sumMembers := 0

	for _, rec := range records {
		cnt := 1
		if d.spec.RecordCountField != "" {
			if v, ok := lookupDotPath(rec, d.spec.RecordCountField); ok {
				cnt = maxInt(toInt(v, 1), 1)
			}
		}
		sumMembers += cnt

		osFam := firstStr(lookupStr(rec, d.spec.OSFamilyField), d.spec.DefaultOSFamily, "LINUX")
		osVer := firstStr(lookupStr(rec, d.spec.OSVersionField), "unknown")
		kern := lookupStr(rec, d.spec.KernelReleaseField)
		osCPE := lookupStr(rec, d.spec.OSCPE23Field)
		osKey := osFam + "|" + osVer + "|" + kern
		if b, ok := osBuckets[osKey]; ok {
			b.Count += cnt
		} else {
			osBuckets[osKey] = &models.OSKernelBucket{
				OSFamily:         osFam,
				OSVersionOrBuild: osVer,
				KernelRelease:    kern,
				CPE23:            osCPE,
				Count:            cnt,
			}
		}

		if d.spec.SoftwareArrayField != "" {
			for _, swRec := range extractObjectSlice(rec, d.spec.SoftwareArrayField) {
				name := lookupStr(swRec, d.spec.SoftwareNameField)
				if name == "" {
					continue
				}
				ver := firstStr(lookupStr(swRec, d.spec.SoftwareVersionField), "1.0")
				swKey := name + "|" + ver
				if sb, ok := swBuckets[swKey]; ok {
					sb.Count += cnt
				} else {
					swBuckets[swKey] = &models.SoftwareBucket{
						ComponentName: name,
						Version:       ver,
						CPE23:         lookupStr(swRec, d.spec.SoftwareCPE23Field),
						SWIDTagID:     lookupStr(swRec, d.spec.SoftwareSWIDField),
						PURL:          lookupStr(swRec, d.spec.SoftwarePURLField),
						Count:         cnt,
					}
				}
			}
		} else if name := lookupStr(rec, d.spec.SoftwareNameField); name != "" {
			ver := firstStr(lookupStr(rec, d.spec.SoftwareVersionField), "1.0")
			swKey := name + "|" + ver
			if sb, ok := swBuckets[swKey]; ok {
				sb.Count += cnt
			} else {
				swBuckets[swKey] = &models.SoftwareBucket{
					ComponentName: name,
					Version:       ver,
					CPE23:         lookupStr(rec, d.spec.SoftwareCPE23Field),
					SWIDTagID:     lookupStr(rec, d.spec.SoftwareSWIDField),
					PURL:          lookupStr(rec, d.spec.SoftwarePURLField),
					Count:         cnt,
				}
			}
		}

		if d.spec.CandidatesArrayPath == "" && d.spec.CandidateIDField != "" {
			if cid := lookupStr(rec, d.spec.CandidateIDField); cid != "" && !seenCands[cid] {
				seenCands[cid] = true
				snap.CandidateCloneSources = append(snap.CandidateCloneSources, models.CloneSourceCandidate{
					SourceSystem:   d.sourceSystem,
					ImageIdentity:  cid,
					PlatformFamily: firstStr(lookupStr(rec, d.spec.CandidatePlatField), d.spec.DefaultPlatform, "LINUX_RPM"),
					CreatedAt:      firstStr(lookupStr(rec, d.spec.CandidateCreatedField), now.Add(-24*time.Hour).Format(time.RFC3339)),
				})
			}
		}
		if freshStr == "" && d.spec.FreshnessPath != "" {
			freshStr = lookupStr(rec, d.spec.FreshnessPath)
		}
	}

	if d.spec.CandidatesArrayPath != "" {
		for _, cRec := range extractObjectSlice(doc, d.spec.CandidatesArrayPath) {
			cid := lookupStr(cRec, d.spec.CandidateIDField)
			if cid == "" || seenCands[cid] {
				continue
			}
			seenCands[cid] = true
			snap.CandidateCloneSources = append(snap.CandidateCloneSources, models.CloneSourceCandidate{
				SourceSystem:   d.sourceSystem,
				ImageIdentity:  cid,
				PlatformFamily: firstStr(lookupStr(cRec, d.spec.CandidatePlatField), d.spec.DefaultPlatform, "LINUX_RPM"),
				CreatedAt:      firstStr(lookupStr(cRec, d.spec.CandidateCreatedField), now.Add(-24*time.Hour).Format(time.RFC3339)),
			})
		}
	}

	for recIdx, rec := range records {
		host := firstStr(lookupStr(rec, "hostname"), lookupStr(rec, "computer_name"), lookupStr(rec, "name"), lookupStr(rec, "fqdn"))
		srvID := firstStr(lookupStr(rec, "server_id"), lookupStr(rec, "id"), lookupStr(rec, "uuid"))
		if host == "" && srvID == "" {
			continue
		}
		twinImg := firstStr(lookupStr(rec, "twin_image_identity"), lookupStr(rec, d.spec.CandidateIDField))
		if twinImg == "" && len(snap.CandidateCloneSources) > 0 {
			twinImg = snap.CandidateCloneSources[recIdx%len(snap.CandidateCloneSources)].ImageIdentity
		}
		if twinImg == "" {
			continue
		}
		if !seenCands[twinImg] {
			seenCands[twinImg] = true
			snap.CandidateCloneSources = append(snap.CandidateCloneSources, models.CloneSourceCandidate{
				SourceSystem:   d.sourceSystem,
				ImageIdentity:  twinImg,
				PlatformFamily: firstStr(lookupStr(rec, "platform_family"), d.spec.DefaultPlatform, "LINUX_RPM"),
				CreatedAt:      now.Add(-24 * time.Hour).Format(time.RFC3339),
			})
		}
		if srvID == "" {
			srvID = fmt.Sprintf("%s-host-%02d", d.sourceSystem, recIdx+1)
		}
		if host == "" {
			host = srvID
		}
		osFam := firstStr(lookupStr(rec, d.spec.OSFamilyField), d.spec.DefaultOSFamily, "LINUX")
		osVer := firstStr(lookupStr(rec, d.spec.OSVersionField), "unknown")
		kern := lookupStr(rec, d.spec.KernelReleaseField)
		primaryPkg := ""
		if d.spec.SoftwareArrayField != "" {
			if swArr := extractObjectSlice(rec, d.spec.SoftwareArrayField); len(swArr) > 0 {
				pName := lookupStr(swArr[0], d.spec.SoftwareNameField)
				pVer := lookupStr(swArr[0], d.spec.SoftwareVersionField)
				primaryPkg = strings.TrimSpace(pName + " " + pVer)
			}
		} else {
			pName := lookupStr(rec, d.spec.SoftwareNameField)
			pVer := lookupStr(rec, d.spec.SoftwareVersionField)
			primaryPkg = strings.TrimSpace(pName + " " + pVer)
		}
		snap.EphemeralServers = append(snap.EphemeralServers, models.EstateSelectableServer{
			ServerID:          srvID,
			Hostname:          host,
			ServiceID:         lookupStr(rec, "service_id"),
			SourceSystem:      d.sourceSystem,
			OSFamily:          osFam,
			OSVersionOrBuild:  osVer,
			KernelRelease:     kern,
			PrimaryPackage:    primaryPkg,
			TwinImageIdentity: twinImg,
			PlatformFamily:    firstStr(lookupStr(rec, "platform_family"), d.spec.DefaultPlatform, "LINUX_RPM"),
			ImageCreatedAt:    now.Add(-24 * time.Hour).Format(time.RFC3339),
		})
	}

	if snap.ClassMembershipCount == 0 {
		snap.ClassMembershipCount = sumMembers
	}
	for _, b := range osBuckets {
		snap.OSBuildKernelDistribution = append(snap.OSBuildKernelDistribution, *b)
	}
	for _, sb := range swBuckets {
		snap.SoftwareVersionDistribution = append(snap.SoftwareVersionDistribution, *sb)
	}

	snap.SourceInventoryFreshnessAt = parseFlexibleTimestamp(freshStr, now)
	if err := FinalizeEstateSnapshot(snap, now); err != nil {
		return nil, err
	}
	return snap, nil
}

func lookupDotPath(m map[string]any, dotPath string) (any, bool) {
	p := strings.TrimSpace(dotPath)
	if p == "" || m == nil {
		return nil, false
	}
	parts := strings.Split(p, ".")
	var cur any = m
	for _, seg := range parts {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		val, exists := obj[seg]
		if !exists {
			return nil, false
		}
		cur = val
	}
	return cur, true
}

func lookupStr(m map[string]any, dotPath string) string {
	v, ok := lookupDotPath(m, dotPath)
	if !ok || v == nil {
		return ""
	}
	return toStr(v)
}

func toStr(v any) string {
	if v == nil {
		return ""
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	if s == "<nil>" {
		return ""
	}
	return s
}

func toInt(v any, def int) int {
	switch tv := v.(type) {
	case float64:
		return int(tv)
	case int:
		return tv
	case int64:
		return int(tv)
	default:
		return def
	}
}

func extractObjectSlice(m map[string]any, dotPath string) []map[string]any {
	v, ok := lookupDotPath(m, dotPath)
	if !ok || v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if obj, ok := item.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}
