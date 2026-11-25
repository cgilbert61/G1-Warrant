package estatereader

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/netguard"
	"github.com/google/uuid"
)

// EstateReadQuery defines a bounded decision-time question posed to a connected estate system.
// Warrant never performs bulk sync or standing replication.
type EstateReadQuery struct {
	WarrantClass  string   `json:"warrant_class"`
	ScopeServices []string `json:"scope_services"`
	ScopeFilter   string   `json:"scope_filter,omitempty"`
	MaxCandidates int      `json:"max_candidates,omitempty"`
}

// EstateReader is the unified read-only capability interface implemented across all 5 handler families (18 connected systems).
type EstateReader interface {
	SourceSystem() string
	DisplayName() string
	SourceTier() string    // TIER_A_MACHINE | TIER_B_WORKLOAD | TIER_C_CENSUS
	HandlerFamily() string // FAMILY_MICROSOFT | FAMILY_CLOUD | FAMILY_KUBERNETES | FAMILY_REST_DECLARATIVE | FAMILY_SCANNERS
	ReadEnvPrefix() string
	ReadConfigured() bool
	ValidateReadCredentialSeparation(presentedToken string) error
	WithTransport(rt http.RoundTripper) EstateReader
	ReadEstateSnapshot(ctx context.Context, q EstateReadQuery) (*models.EstateSnapshot, error)
}

// baseEstateHTTPClient provides read-only HTTP transport with strict Read != Dispatch credential separation.
type baseEstateHTTPClient struct {
	sourceSystem  string
	displayName   string
	sourceTier    string
	handlerFamily string
	readEnvPrefix string
	readURL       string
	readToken     string
	dispatchToken string
	httpClient    *http.Client
}

func newBaseEstateHTTPClient(
	sourceSystem, displayName, sourceTier, handlerFamily, readEnvPrefix, readURL, readToken, dispatchToken string,
	rt http.RoundTripper,
) baseEstateHTTPClient {
	rt = netguard.NewGovernedRoundTripper(rt)
	return baseEstateHTTPClient{
		sourceSystem:  strings.TrimSpace(sourceSystem),
		displayName:   strings.TrimSpace(displayName),
		sourceTier:    strings.TrimSpace(sourceTier),
		handlerFamily: strings.TrimSpace(handlerFamily),
		readEnvPrefix: strings.TrimSpace(readEnvPrefix),
		readURL:       strings.TrimRight(strings.TrimSpace(readURL), "/"),
		readToken:     strings.TrimSpace(readToken),
		dispatchToken: strings.TrimSpace(dispatchToken),
		httpClient:    netguard.NewSafeHTTPClient(15*time.Second, rt),
	}
}

func (b *baseEstateHTTPClient) cloneWithTransport(rt http.RoundTripper) baseEstateHTTPClient {
	cp := *b
	rt = netguard.NewGovernedRoundTripper(rt)
	cp.httpClient = netguard.NewSafeHTTPClient(15*time.Second, rt)
	return cp
}

func (b *baseEstateHTTPClient) SourceSystem() string  { return b.sourceSystem }
func (b *baseEstateHTTPClient) DisplayName() string   { return b.displayName }
func (b *baseEstateHTTPClient) SourceTier() string    { return b.sourceTier }
func (b *baseEstateHTTPClient) HandlerFamily() string { return b.handlerFamily }
func (b *baseEstateHTTPClient) ReadEnvPrefix() string { return b.readEnvPrefix }
func (b *baseEstateHTTPClient) ReadConfigured() bool  { return b.readURL != "" }
func (b *baseEstateHTTPClient) ReadURL() string       { return b.readURL }
func (b *baseEstateHTTPClient) HasReadToken() bool    { return b.readToken != "" }
func (b *baseEstateHTTPClient) MaskedReadToken() string {
	return MaskConnectorSecret(b.readToken)
}

// MaskConnectorSecret returns a non-reversible masked preview (e.g. "••••v1") or "" if empty.
func MaskConnectorSecret(secret string) string {
	s := strings.TrimSpace(secret)
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "••••"
	}
	return "••••" + s[len(s)-4:]
}

// ValidateReadCredentialSeparation enforces Rule 2: read credentials and WN-8 dispatch credentials must be strictly distinct.
func (b *baseEstateHTTPClient) ValidateReadCredentialSeparation(presentedToken string) error {
	if b.readToken != "" && b.dispatchToken != "" &&
		subtle.ConstantTimeCompare([]byte(b.readToken), []byte(b.dispatchToken)) == 1 {
		return fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION (%s): %s_READ_TOKEN must be distinct from WN-8 dispatch token", b.sourceSystem, b.readEnvPrefix)
	}
	pt := strings.TrimSpace(presentedToken)
	if pt != "" && b.dispatchToken != "" &&
		subtle.ConstantTimeCompare([]byte(pt), []byte(b.dispatchToken)) == 1 {
		return fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION (%s): WN-8 dispatch credential rejected on EstateReader read path", b.sourceSystem)
	}
	return nil
}

func (b *baseEstateHTTPClient) IsMatchingReadToken(tok string) bool {
	t := strings.TrimSpace(tok)
	return t != "" && b.readToken != "" && subtle.ConstantTimeCompare([]byte(t), []byte(b.readToken)) == 1
}

func (b *baseEstateHTTPClient) IsMatchingDispatchToken(tok string) bool {
	t := strings.TrimSpace(tok)
	return t != "" && b.dispatchToken != "" && subtle.ConstantTimeCompare([]byte(t), []byte(b.dispatchToken)) == 1
}

func (b *baseEstateHTTPClient) doReadRequest(ctx context.Context, method, path string, reqPayload any) ([]byte, error) {
	if err := b.ValidateReadCredentialSeparation(""); err != nil {
		return nil, err
	}
	if b.readURL == "" {
		return nil, fmt.Errorf("ESTATE_READ_UNAVAILABLE (%s): %s_READ_URL is not configured", b.sourceSystem, b.readEnvPrefix)
	}
	var bodyReader io.Reader
	if reqPayload != nil {
		raw, err := json.Marshal(reqPayload)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.readURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Warrant-Read-Role", models.AgentActionReadEstateSnapshot)
	if reqPayload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.readToken != "" {
		req.Header.Set("Authorization", "Bearer "+b.readToken)
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ESTATE_READ_UNAVAILABLE (%s %s %s): %w", b.sourceSystem, method, path, err)
	}
	defer resp.Body.Close()
	rawResp, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("ESTATE_READ_AUTH_DENIED (%s %s -> HTTP %d): %s", b.sourceSystem, path, resp.StatusCode, strings.TrimSpace(string(rawResp)))
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ESTATE_READ_UNAVAILABLE (%s %s -> HTTP %d): %s", b.sourceSystem, path, resp.StatusCode, strings.TrimSpace(string(rawResp)))
	}
	return rawResp, nil
}

// ComputeCanonicalQueryIdentity produces a deterministic bounded query descriptor + short SHA-256 suffix.
func ComputeCanonicalQueryIdentity(sourceSystem string, q EstateReadQuery) string {
	svcs := make([]string, 0, len(q.ScopeServices))
	for _, s := range q.ScopeServices {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			svcs = append(svcs, trimmed)
		}
	}
	sort.Strings(svcs)
	cls := strings.TrimSpace(q.WarrantClass)
	if cls == "" {
		cls = "*"
	}
	flt := strings.TrimSpace(q.ScopeFilter)
	desc := fmt.Sprintf("estate-query:v1:src=%s|class=%s|services=%s|filter=%s",
		strings.ToLower(strings.TrimSpace(sourceSystem)),
		cls,
		strings.Join(svcs, ","),
		flt,
	)
	sum := crypto.SHA256Hex([]byte(desc))[:12]
	return fmt.Sprintf("%s#sha256:%s", desc, sum)
}

type canonicalSnapshotDigestPayload struct {
	OCSFClassUID              int                           `json:"ocsf_class_uid"`
	SourceSystem              string                        `json:"source_system"`
	SourceTier                string                        `json:"source_tier"`
	HandlerFamily             string                        `json:"handler_family"`
	QueryIdentity             string                        `json:"query_identity"`
	ClassScope                []string                      `json:"class_scope"`
	ClassMembershipCount      int                           `json:"class_membership_count"`
	OSBuildKernelDistribution []models.OSKernelBucket       `json:"os_build_kernel_distribution"`
	SoftwareVersionDist       []models.SoftwareBucket       `json:"software_version_distribution"`
	CandidateCloneSources     []canonicalCandidateDigestRow `json:"candidate_clone_sources"`
	SourceFreshnessUTC        string                        `json:"source_inventory_freshness_at"`
}

type canonicalCandidateDigestRow struct {
	SourceSystem      string   `json:"source_system"`
	ImageIdentity     string   `json:"image_identity"`
	PlatformFamily    string   `json:"platform_family"`
	PatchTargetLayers []string `json:"patch_target_layers"`
	CreatedAt         string   `json:"created_at"`
}

// FinalizeEstateSnapshot enforces tier boundaries (0 clone sources for TIER_C_CENSUS), deterministic ordering,
// freshness/image age calculation, and RFC 8785 JCS SnapshotSHA256 computation.
func FinalizeEstateSnapshot(snap *models.EstateSnapshot, now time.Time) error {
	if snap == nil {
		return fmt.Errorf("nil EstateSnapshot")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC().Truncate(time.Second)
	snap.ObservedAt = now
	if snap.SnapshotID == "" {
		snap.SnapshotID = "esn-" + uuid.NewString()[:8]
	}
	snap.OCSFClassUID = models.OCSFInventoryInfoClassUID

	if snap.SourceInventoryFreshnessAt.IsZero() {
		snap.SourceInventoryFreshnessAt = now
	}
	snap.SourceInventoryFreshnessAt = snap.SourceInventoryFreshnessAt.UTC().Truncate(time.Second)
	ageSec := int64(now.Sub(snap.SourceInventoryFreshnessAt).Seconds())
	if ageSec < 0 {
		ageSec = 0
	}
	snap.SourceFreshnessAgeSeconds = ageSec

	svcs := make([]string, 0, len(snap.ClassScope))
	for _, s := range snap.ClassScope {
		if ts := strings.TrimSpace(s); ts != "" {
			svcs = append(svcs, ts)
		}
	}
	sort.Strings(svcs)
	snap.ClassScope = svcs

	if snap.OSBuildKernelDistribution == nil {
		snap.OSBuildKernelDistribution = []models.OSKernelBucket{}
	}
	sort.Slice(snap.OSBuildKernelDistribution, func(i, j int) bool {
		a, b := snap.OSBuildKernelDistribution[i], snap.OSBuildKernelDistribution[j]
		if a.OSFamily != b.OSFamily {
			return a.OSFamily < b.OSFamily
		}
		if a.OSVersionOrBuild != b.OSVersionOrBuild {
			return a.OSVersionOrBuild < b.OSVersionOrBuild
		}
		return a.KernelRelease < b.KernelRelease
	})

	if snap.SoftwareVersionDistribution == nil {
		snap.SoftwareVersionDistribution = []models.SoftwareBucket{}
	}
	sort.Slice(snap.SoftwareVersionDistribution, func(i, j int) bool {
		a, b := snap.SoftwareVersionDistribution[i], snap.SoftwareVersionDistribution[j]
		if a.ComponentName != b.ComponentName {
			return a.ComponentName < b.ComponentName
		}
		return a.Version < b.Version
	})

	// Tier C Scanners NEVER propose clone sources under any circumstance.
	if snap.SourceTier == models.EstateSourceTierCCensus {
		snap.CandidateCloneSources = []models.CloneSourceCandidate{}
		snap.EphemeralServers = nil
	} else {
		if snap.CandidateCloneSources == nil {
			snap.CandidateCloneSources = []models.CloneSourceCandidate{}
		}
		for idx := range snap.CandidateCloneSources {
			c := &snap.CandidateCloneSources[idx]
			c.SourceSystem = snap.SourceSystem
			if len(c.PatchTargetLayers) == 0 {
				if snap.SourceTier == models.EstateSourceTierBWorkload {
					c.PatchTargetLayers = []string{models.PatchTargetLayerUserspace}
				} else {
					c.PatchTargetLayers = []string{models.PatchTargetLayerUserspace, models.PatchTargetLayerKernel, models.PatchTargetLayerBoot}
				}
			}
			sort.Strings(c.PatchTargetLayers)
			if c.CreatedAt != "" {
				if ts, err := time.Parse(time.RFC3339, c.CreatedAt); err == nil {
					imgAge := int64(now.Sub(ts.UTC()).Seconds())
					if imgAge < 0 {
						imgAge = 0
					}
					c.ImageAgeSeconds = imgAge
				}
			}
		}
		sort.Slice(snap.CandidateCloneSources, func(i, j int) bool {
			return snap.CandidateCloneSources[i].ImageIdentity < snap.CandidateCloneSources[j].ImageIdentity
		})

		for idx := range snap.EphemeralServers {
			sv := &snap.EphemeralServers[idx]
			sv.SourceSystem = snap.SourceSystem
			if len(sv.PatchTargetLayers) == 0 {
				if snap.SourceTier == models.EstateSourceTierBWorkload {
					sv.PatchTargetLayers = []string{models.PatchTargetLayerUserspace}
				} else {
					sv.PatchTargetLayers = []string{models.PatchTargetLayerUserspace, models.PatchTargetLayerKernel, models.PatchTargetLayerBoot}
				}
			}
			sort.Strings(sv.PatchTargetLayers)
			if sv.ImageCreatedAt != "" {
				if ts, err := time.Parse(time.RFC3339, sv.ImageCreatedAt); err == nil {
					age := int64(now.Sub(ts.UTC()).Seconds())
					if age < 0 {
						age = 0
					}
					sv.ImageAgeSeconds = age
				}
			}
		}
		sort.Slice(snap.EphemeralServers, func(i, j int) bool {
			a, b := snap.EphemeralServers[i], snap.EphemeralServers[j]
			if a.ServiceID != b.ServiceID {
				return a.ServiceID < b.ServiceID
			}
			if a.Hostname != b.Hostname {
				return a.Hostname < b.Hostname
			}
			return a.ServerID < b.ServerID
		})
	}

	canonCands := make([]canonicalCandidateDigestRow, 0, len(snap.CandidateCloneSources))
	for _, c := range snap.CandidateCloneSources {
		canonCands = append(canonCands, canonicalCandidateDigestRow{
			SourceSystem:      c.SourceSystem,
			ImageIdentity:     c.ImageIdentity,
			PlatformFamily:    c.PlatformFamily,
			PatchTargetLayers: c.PatchTargetLayers,
			CreatedAt:         c.CreatedAt,
		})
	}

	digestObj := canonicalSnapshotDigestPayload{
		OCSFClassUID:              snap.OCSFClassUID,
		SourceSystem:              snap.SourceSystem,
		SourceTier:                snap.SourceTier,
		HandlerFamily:             snap.HandlerFamily,
		QueryIdentity:             snap.QueryIdentity,
		ClassScope:                snap.ClassScope,
		ClassMembershipCount:      snap.ClassMembershipCount,
		OSBuildKernelDistribution: snap.OSBuildKernelDistribution,
		SoftwareVersionDist:       snap.SoftwareVersionDistribution,
		CandidateCloneSources:     canonCands,
		SourceFreshnessUTC:        snap.SourceInventoryFreshnessAt.UTC().Format(time.RFC3339),
	}
	shaHex, _, err := crypto.CanonicalSHA256Hex(digestObj)
	if err != nil {
		return err
	}
	snap.SnapshotSHA256 = shaHex
	return nil
}

// ComputeEstateDriftDelta compares a signing-time EstateReadEvidenceRecord against a proving-time EstateSnapshot.
// Returns the maximum observed drift percentage across membership count, OS/kernel distribution, and software distribution,
// plus whether drift or staleness exceeded the class's declared tolerance.
func ComputeEstateDriftDelta(
	signing *models.EstateReadEvidenceRecord,
	proving *models.EstateSnapshot,
	declaredSources []models.DeclaredCloneSource,
	tolerancePct float64,
	maxStalenessSec int64,
) (observedPct float64, exceeded bool, summary string) {
	if proving == nil {
		return 100.0, true, "PROVING_SNAPSHOT_MISSING"
	}
	if tolerancePct <= 0 {
		tolerancePct = models.DefaultEstateDriftTolPct
	}
	if signing == nil {
		return 0.0, false, "NO_SIGNING_BASELINE_EVIDENCE"
	}

	var reasons []string

	// 1. Membership count percentage drift
	baseCount := float64(maxInt(signing.ClassMembershipCount, 1))
	countDelta := math.Abs(float64(proving.ClassMembershipCount - signing.ClassMembershipCount))
	memberDriftPct := (countDelta / baseCount) * 100.0

	// 2. OS / Kernel bucket L1 distribution shift (%)
	osDriftPct := computeOSDistributionL1Pct(signing.OSDistSummary, proving.OSBuildKernelDistribution)

	// 3. Software bucket L1 distribution shift (%)
	swDriftPct := computeSoftwareDistributionL1Pct(signing.SWDistSummary, proving.SoftwareVersionDistribution)

	observedPct = math.Max(memberDriftPct, math.Max(osDriftPct, swDriftPct))
	observedPct = math.Round(observedPct*100) / 100

	if observedPct > tolerancePct {
		exceeded = true
		reasons = append(reasons, fmt.Sprintf("drift=%.2f%%>tol=%.2f%% (membership=%d->%d [%.2f%%], os_shift=%.2f%%, sw_shift=%.2f%%)",
			observedPct, tolerancePct, signing.ClassMembershipCount, proving.ClassMembershipCount, memberDriftPct, osDriftPct, swDriftPct))
	}

	// 4. Declared clone source presence check in upstream estate candidate catalog
	if len(declaredSources) > 0 && len(proving.CandidateCloneSources) > 0 {
		candSet := map[string]bool{}
		for _, c := range proving.CandidateCloneSources {
			candSet[c.ImageIdentity] = true
		}
		for _, ds := range declaredSources {
			if ds.SourceMode == models.CloneSourceModeEstateLoader && ds.SourceSystem == proving.SourceSystem {
				if !candSet[ds.ImageIdentity] {
					exceeded = true
					if observedPct <= tolerancePct {
						observedPct = tolerancePct + 1.0
					}
					reasons = append(reasons, fmt.Sprintf("declared_clone_source_missing_in_estate=%s", ds.ImageIdentity))
				}
			}
		}
	}

	// 5. Upstream inventory freshness staleness check
	if maxStalenessSec > 0 && proving.SourceFreshnessAgeSeconds > maxStalenessSec {
		exceeded = true
		reasons = append(reasons, fmt.Sprintf("inventory_stale=%ds>max=%ds", proving.SourceFreshnessAgeSeconds, maxStalenessSec))
	}

	if len(reasons) == 0 {
		summary = fmt.Sprintf("WITHIN_TOLERANCE: observed=%.2f%%<=tol=%.2f%% (members=%d->%d, freshness_age=%ds)",
			observedPct, tolerancePct, signing.ClassMembershipCount, proving.ClassMembershipCount, proving.SourceFreshnessAgeSeconds)
	} else {
		summary = "DRIFT_EXCEEDED: " + strings.Join(reasons, "; ")
	}
	return observedPct, exceeded, summary
}

func computeOSDistributionL1Pct(a, b []models.OSKernelBucket) float64 {
	totA, totB := 0, 0
	mapA := map[string]int{}
	mapB := map[string]int{}
	keys := map[string]bool{}
	for _, x := range a {
		k := x.OSFamily + "|" + x.OSVersionOrBuild + "|" + x.KernelRelease
		mapA[k] += x.Count
		totA += x.Count
		keys[k] = true
	}
	for _, x := range b {
		k := x.OSFamily + "|" + x.OSVersionOrBuild + "|" + x.KernelRelease
		mapB[k] += x.Count
		totB += x.Count
		keys[k] = true
	}
	if totA == 0 && totB == 0 {
		return 0
	}
	var l1 float64
	for k := range keys {
		pa := float64(mapA[k]) / float64(maxInt(totA, 1))
		pb := float64(mapB[k]) / float64(maxInt(totB, 1))
		l1 += math.Abs(pa - pb)
	}
	return (l1 / 2.0) * 100.0
}

func computeSoftwareDistributionL1Pct(a, b []models.SoftwareBucket) float64 {
	totA, totB := 0, 0
	mapA := map[string]int{}
	mapB := map[string]int{}
	keys := map[string]bool{}
	for _, x := range a {
		k := x.ComponentName + "|" + x.Version
		mapA[k] += x.Count
		totA += x.Count
		keys[k] = true
	}
	for _, x := range b {
		k := x.ComponentName + "|" + x.Version
		mapB[k] += x.Count
		totB += x.Count
		keys[k] = true
	}
	if totA == 0 && totB == 0 {
		return 0
	}
	var l1 float64
	for k := range keys {
		pa := float64(mapA[k]) / float64(maxInt(totA, 1))
		pb := float64(mapB[k]) / float64(maxInt(totB, 1))
		l1 += math.Abs(pa - pb)
	}
	return (l1 / 2.0) * 100.0
}

func parseFlexibleTimestamp(raw string, fallback time.Time) time.Time {
	s := strings.TrimSpace(raw)
	if s == "" {
		return fallback
	}
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05"} {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts.UTC()
		}
	}
	return fallback
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
