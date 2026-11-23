package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters/estatereader"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
)

// EstateReadToken returns the configured dedicated read-only Estate Loader token (if set).
func (o *ControlPlaneOrchestrator) EstateReadToken() string {
	return o.estateReadToken
}

// RejectEstateReadCredentialOnMutation enforces Doctrine Rule 2:
// Estate-read credentials (X-Warrant-Estate-Read-Token, WARRANT_ESTATE_READ_TOKEN, or any WARRANT_<SYSTEM>_READ_TOKEN)
// can NEVER dispatch patch orders, execute rollbacks, bind classes, or submit Standing Warrants.
func (o *ControlPlaneOrchestrator) RejectEstateReadCredentialOnMutation(r *http.Request) (int, error) {
	if strings.TrimSpace(r.Header.Get("X-Warrant-Estate-Read-Token")) != "" {
		return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: X-Warrant-Estate-Read-Token is strictly read-only and forbidden on dispatch, signing, and mutation routes")
	}
	candidates := []string{
		strings.TrimSpace(r.Header.Get("X-Warrant-Automation-Token")),
		strings.TrimSpace(r.Header.Get("X-Warrant-Operator-Token")),
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		candidates = append(candidates, strings.TrimSpace(auth[7:]))
	}
	for _, tok := range candidates {
		if tok == "" {
			continue
		}
		if o.estateReadToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(o.estateReadToken)) == 1 {
			return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: WARRANT_ESTATE_READ_TOKEN is strictly read-only and forbidden on dispatch, signing, and mutation routes")
		}
		if o.EstateReaders != nil {
			if sys, matched := o.EstateReaders.IsAnyRegisteredReadToken(tok); matched {
				return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: %s EstateReader read-only credential is forbidden on dispatch, signing, and mutation routes", sys)
			}
		}
	}
	return http.StatusOK, nil
}

// VerifyEstateReadAuth enforces Doctrine Rule 2 on /api/v1/estate-loader/* routes:
//   - Explicitly REJECTS WN-8 dispatch tokens (WARRANT_<SYSTEM>_TOKEN), WARRANT_AUTOMATION_TOKEN, WARRANT_INTAKE_TOKEN,
//     auditor tokens (g1aud_*), sensor tokens (g1tet_*), and any N4 task warrant carrying DISPATCH_DEPLOYMENT_ORDER.
//   - Accepts X-Warrant-Estate-Read-Token / Bearer matching WARRANT_ESTATE_READ_TOKEN or a registered system READ_TOKEN,
//     a 1-of-2 human DSSE header, or interactive Console read access in offline simulator mode when WARRANT_ESTATE_READ_TOKEN is unset.
func (o *ControlPlaneOrchestrator) VerifyEstateReadAuth(r *http.Request, rawBody []byte) (int, error) {
	ctx := r.Context()

	if strings.TrimSpace(r.Header.Get("X-Warrant-Automation-Token")) != "" {
		return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: dispatch/automation header X-Warrant-Automation-Token is forbidden on EstateReader read routes")
	}
	if strings.TrimSpace(r.Header.Get("X-Warrant-Intake-Token")) != "" {
		return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: scanner intake header X-Warrant-Intake-Token is forbidden on EstateReader read routes")
	}
	if taskHdr := strings.TrimSpace(r.Header.Get("X-Warrant-Task-DSSE")); taskHdr != "" {
		if strings.Contains(taskHdr, "DISPATCH_DEPLOYMENT_ORDER") {
			return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: DISPATCH_DEPLOYMENT_ORDER task warrant rejected on EstateReader read route")
		}
	}

	readHdr := strings.TrimSpace(r.Header.Get("X-Warrant-Estate-Read-Token"))
	bearer := ""
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		bearer = strings.TrimSpace(auth[7:])
	}
	opHdr := strings.TrimSpace(r.Header.Get("X-Warrant-Operator-Token"))

	for _, candidate := range []string{readHdr, bearer, opHdr} {
		if candidate == "" {
			continue
		}
		if strings.HasPrefix(candidate, "g1aud_") || strings.HasPrefix(candidate, "g1tet_") {
			return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: auditor and sensor tokens cannot invoke EstateReader")
		}
		if o.automationToken != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(o.automationToken)) == 1 {
			return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: WARRANT_AUTOMATION_TOKEN (dispatch/feed credential) is forbidden on EstateReader read routes")
		}
		if o.intakeToken != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(o.intakeToken)) == 1 {
			return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: WARRANT_INTAKE_TOKEN is forbidden on EstateReader read routes")
		}
		if o.EstateReaders != nil {
			if sys, isDisp := o.EstateReaders.IsAnyRegisteredDispatchToken(candidate); isDisp {
				return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: %s WN-8 dispatch credential is forbidden on EstateReader read routes", sys)
			}
		}
	}

	if _, _, attemptedDSSE, code, dErr := o.verifyRequestScopedDSSE(ctx, r, models.AgentActionReadEstateSnapshot, rawBody); attemptedDSSE {
		return code, dErr
	}

	tok := readHdr
	if tok == "" {
		tok = bearer
	}

	if tok != "" {
		if o.estateReadToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(o.estateReadToken)) == 1 {
			return http.StatusOK, nil
		}
		if o.EstateReaders != nil {
			if _, ok := o.EstateReaders.IsAnyRegisteredReadToken(tok); ok {
				return http.StatusOK, nil
			}
		}
		return http.StatusForbidden, fmt.Errorf("INVALID_ESTATE_READ_CREDENTIAL")
	}

	if o.estateReadToken != "" || o.IsProductionOrLivePosture(ctx) {
		return http.StatusUnauthorized, fmt.Errorf("MISSING_ESTATE_READ_TOKEN: provide X-Warrant-Estate-Read-Token (distinct from WN-8 dispatch credentials)")
	}
	if opHdr != "" && o.operatorToken != "" && subtle.ConstantTimeCompare([]byte(opHdr), []byte(o.operatorToken)) != 1 {
		return http.StatusForbidden, fmt.Errorf("INVALID_ESTATE_READ_CREDENTIAL")
	}
	return http.StatusOK, nil
}

func (o *ControlPlaneOrchestrator) registerEstateLoaderRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/estate-loader/sources", func(w http.ResponseWriter, r *http.Request) {
		if code, err := o.VerifyEstateReadAuth(r, nil); err != nil {
			writeAPIError(w, code, err)
			return
		}
		if o.EstateReaders == nil {
			writeAPIJSON(w, http.StatusOK, []models.EstateSourceDescriptor{})
			return
		}
		writeAPIJSON(w, http.StatusOK, o.EstateReaders.ListDescriptors())
	})

	mux.HandleFunc("GET /api/v1/estate-loader/evidence", func(w http.ResponseWriter, r *http.Request) {
		if code, err := o.VerifyEstateReadAuth(r, nil); err != nil {
			writeAPIError(w, code, err)
			return
		}
		src := r.URL.Query().Get("source_system")
		wrtID := r.URL.Query().Get("warrant_id")
		list, err := o.Store.ListEstateReadEvidence(r.Context(), src, wrtID)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("POST /api/v1/estate-loader/propose", func(w http.ResponseWriter, r *http.Request) {
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if code, authErr := o.VerifyEstateReadAuth(r, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var req models.EstateProposalRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		resp, propErr := o.ExecuteEstateClassProposal(r.Context(), req)
		if propErr != nil {
			msg := propErr.Error()
			switch {
			case strings.Contains(msg, "CREDENTIAL_SEPARATION_VIOLATION"):
				writeAPIError(w, http.StatusForbidden, propErr)
			case strings.Contains(msg, "ESTATE_READ_UNAVAILABLE"):
				writeAPIError(w, http.StatusServiceUnavailable, propErr)
			default:
				writeAPIError(w, http.StatusUnprocessableEntity, propErr)
			}
			return
		}
		writeAPIJSON(w, http.StatusOK, resp)
	})

	// v1.4.1 Console 18-Vendor Configurator & Demo Estate Mock Endpoints
	mux.HandleFunc("GET /api/v1/estate-loader/connectors", func(w http.ResponseWriter, r *http.Request) {
		if code, err := o.VerifyEstateReadAuth(r, nil); err != nil {
			writeAPIError(w, code, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, o.ListVendorConnectorStatuses(r.Context()))
	})

	mux.HandleFunc("PUT /api/v1/estate-loader/connectors/{system_id}", func(w http.ResponseWriter, r *http.Request) {
		rawBody, err := readBoundedBody(w, r, 64<<10)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if code, authErr := o.VerifyConnectorMutationAuth(r.Context(), r, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var req models.VendorConnectorUpdateRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		st, upErr := o.UpdateVendorConnector(r.Context(), r.PathValue("system_id"), req)
		if upErr != nil {
			msg := upErr.Error()
			switch {
			case strings.Contains(msg, "CREDENTIAL_SEPARATION_VIOLATION"):
				writeAPIError(w, http.StatusForbidden, upErr)
			case strings.Contains(msg, "UNKNOWN_ESTATE_SOURCE_SYSTEM"):
				writeAPIError(w, http.StatusNotFound, upErr)
			default:
				writeAPIError(w, http.StatusUnprocessableEntity, upErr)
			}
			return
		}
		writeAPIJSON(w, http.StatusOK, st)
	})

	mux.HandleFunc("POST /api/v1/estate-loader/connectors/demo-mock", func(w http.ResponseWriter, r *http.Request) {
		rawBody, err := readBoundedBody(w, r, 16<<10)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if allowed, reason := o.IsSimulationAllowed(r.Context()); !allowed {
			writeAPIError(w, http.StatusForbidden, fmt.Errorf("%s", reason))
			return
		}
		if code, authErr := o.VerifyConnectorMutationAuth(r.Context(), r, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var req struct {
			SystemID string `json:"system_id"`
		}
		if len(strings.TrimSpace(string(rawBody))) > 0 {
			if err := json.Unmarshal(rawBody, &req); err != nil {
				writeAPIError(w, http.StatusBadRequest, err)
				return
			}
		}
		statuses, mErr := o.ConnectDemoEstateMock(r.Context(), req.SystemID)
		if mErr != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, mErr)
			return
		}
		writeAPIJSON(w, http.StatusOK, statuses)
	})

	mux.HandleFunc("POST /api/v1/estate-loader/connectors/{system_id}/test", func(w http.ResponseWriter, r *http.Request) {
		rawBody, err := readBoundedBody(w, r, 16<<10)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if code, authErr := o.VerifyEstateReadAuth(r, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var req struct {
			WarrantClass  string   `json:"warrant_class"`
			ScopeServices []string `json:"scope_services"`
		}
		if len(strings.TrimSpace(string(rawBody))) > 0 {
			_ = json.Unmarshal(rawBody, &req)
		}
		res, tErr := o.TestVendorConnectorRead(r.Context(), r.PathValue("system_id"), req.WarrantClass, req.ScopeServices)
		if tErr != nil {
			msg := tErr.Error()
			switch {
			case strings.Contains(msg, "CREDENTIAL_SEPARATION_VIOLATION"):
				writeAPIError(w, http.StatusForbidden, tErr)
			case strings.Contains(msg, "UNKNOWN_ESTATE_SOURCE_SYSTEM"):
				writeAPIError(w, http.StatusNotFound, tErr)
			default:
				writeAPIError(w, http.StatusServiceUnavailable, tErr)
			}
			return
		}
		writeAPIJSON(w, http.StatusOK, res)
	})
}

// ExecuteEstateClassProposal reads bounded decision-time estate state from a Tier A or Tier B system
// (plus an optional Tier C corroborating scanner census), records WORM SIGNING_PROPOSAL evidence,
// and returns candidate clone sources for human SO+AO confirmation before 2-of-2 DSSE signing.
func (o *ControlPlaneOrchestrator) ExecuteEstateClassProposal(
	ctx context.Context,
	req models.EstateProposalRequest,
) (*models.EstateProposalResponse, error) {
	if o.EstateReaders == nil {
		return nil, fmt.Errorf("ESTATE_READ_UNAVAILABLE_AT_SIGNING: EstateReader registry is not initialized")
	}
	if len(req.ScopeServices) == 0 {
		req.ScopeServices = []string{"*"}
	}
	if strings.TrimSpace(req.WarrantClass) == "" {
		req.WarrantClass = "KEV-TIER1-STATELESS"
	}

	primaryReader, err := o.EstateReaders.Get(req.SourceSystem)
	if err != nil {
		return nil, err
	}
	if primaryReader.SourceTier() == models.EstateSourceTierCCensus {
		return nil, fmt.Errorf("TIER_C_SCANNER_CANNOT_PROPOSE_CLONE_SOURCES: %s is a Tier C vulnerability scanner (corroborating census only); select a Tier A machine manager or Tier B Kubernetes system as source_system and pass %s in corroborating_scanner",
			primaryReader.SourceSystem(), primaryReader.SourceSystem())
	}

	q := estatereader.EstateReadQuery{
		WarrantClass:  req.WarrantClass,
		ScopeServices: req.ScopeServices,
		ScopeFilter:   req.ScopeFilter,
	}
	primarySnap, err := primaryReader.ReadEstateSnapshot(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("ESTATE_READ_UNAVAILABLE_AT_SIGNING: %w", err)
	}

	now := time.Now().UTC()
	primEv := &models.EstateReadEvidenceRecord{
		EvidenceID:            "ere-sig-" + uuid.NewString()[:8],
		SourceSystem:          primarySnap.SourceSystem,
		SourceTier:            primarySnap.SourceTier,
		HandlerFamily:         primarySnap.HandlerFamily,
		Phase:                 models.EstateReadPhaseSigningProposal,
		QueryIdentity:         primarySnap.QueryIdentity,
		ClassMembershipCount:  primarySnap.ClassMembershipCount,
		OSDistSummary:         primarySnap.OSBuildKernelDistribution,
		SWDistSummary:         primarySnap.SoftwareVersionDistribution,
		CandidateSources:      primarySnap.CandidateCloneSources,
		SourceFreshnessAt:     primarySnap.SourceInventoryFreshnessAt,
		SourceFreshnessAgeSec: primarySnap.SourceFreshnessAgeSeconds,
		ObservedAt:            primarySnap.ObservedAt,
		SnapshotSHA256:        primarySnap.SnapshotSHA256,
	}
	if err := o.Store.AppendEstateReadEvidence(ctx, primEv); err != nil {
		return nil, err
	}
	if o.N4AgentCP != nil {
		_ = o.N4AgentCP.RecordGovernedAdapterAction(
			ctx, "", "", "agt-estate-reader", primarySnap.SourceSystem,
			models.AgentActionReadEstateSnapshot, "", "",
			models.EgressProfileInternalCluster, crypto.SHA256Hex([]byte(primarySnap.QueryIdentity)), primarySnap.SnapshotSHA256,
		)
	}

	serverByImage := map[string]models.EstateSelectableServer{}
	for _, sv := range primarySnap.EphemeralServers {
		if sv.TwinImageIdentity != "" {
			if _, exists := serverByImage[sv.TwinImageIdentity]; !exists {
				serverByImage[sv.TwinImageIdentity] = sv
			}
		}
	}

	proposedSources := make([]models.DeclaredCloneSource, 0, len(primarySnap.CandidateCloneSources))
	for _, cand := range primarySnap.CandidateCloneSources {
		dcs := models.DeclaredCloneSource{
			SourceSystem:          primarySnap.SourceSystem,
			ImageIdentity:         cand.ImageIdentity,
			PlatformFamily:        cand.PlatformFamily,
			SnapshotSHA256:        primarySnap.SnapshotSHA256,
			QueryIdentity:         primarySnap.QueryIdentity,
			SourceMode:            models.CloneSourceModeEstateLoader,
			ImageCreatedAt:        cand.CreatedAt,
			ImageAgeSecondsAtSign: cand.ImageAgeSeconds,
			DeclaredAt:            now.Format(time.RFC3339),
		}
		if sv, ok := serverByImage[cand.ImageIdentity]; ok {
			dcs.SelectedServerID = sv.ServerID
			dcs.SelectedServerHostname = sv.Hostname
		}
		proposedSources = append(proposedSources, dcs)
	}

	recPolicy := strings.ToUpper(strings.TrimSpace(req.EstateDriftPolicy))
	if recPolicy == "" {
		if primarySnap.SourceTier == models.EstateSourceTierAMachine {
			recPolicy = models.EstateDriftPolicyFailClosed
		} else {
			recPolicy = models.EstateDriftPolicyRecordOnly
		}
	}
	recTol := req.DriftTolerancePct
	if recTol <= 0 {
		recTol = models.DefaultEstateDriftTolPct
	}

	out := &models.EstateProposalResponse{
		ProposalID:                   "prp-" + uuid.NewString()[:8],
		PrimarySnapshot:              *primarySnap,
		PrimaryEvidenceID:            primEv.EvidenceID,
		ProposedCloneSources:         proposedSources,
		SelectableServers:            primarySnap.EphemeralServers,
		ProposedEstateSnapshotSHA256: primarySnap.SnapshotSHA256,
		RecommendedDriftPolicy:       recPolicy,
		RecommendedDriftTolerancePct: recTol,
	}

	// Optional Tier C Corroborating Scanner Census Cross-Check (0 clone sources proposed)
	if scannerSlug := strings.TrimSpace(req.CorroboratingScanner); scannerSlug != "" {
		censusReader, cErr := o.EstateReaders.Get(scannerSlug)
		if cErr != nil {
			return nil, cErr
		}
		censusSnap, sErr := censusReader.ReadEstateSnapshot(ctx, q)
		if sErr != nil {
			out.CensusAdvisory = "CENSUS_UNAVAILABLE: " + sErr.Error()
		} else {
			cenEv := &models.EstateReadEvidenceRecord{
				EvidenceID:            "ere-cen-" + uuid.NewString()[:8],
				SourceSystem:          censusSnap.SourceSystem,
				SourceTier:            censusSnap.SourceTier,
				HandlerFamily:         censusSnap.HandlerFamily,
				Phase:                 models.EstateReadPhaseSigningProposal,
				QueryIdentity:         censusSnap.QueryIdentity,
				ClassMembershipCount:  censusSnap.ClassMembershipCount,
				OSDistSummary:         censusSnap.OSBuildKernelDistribution,
				SWDistSummary:         censusSnap.SoftwareVersionDistribution,
				CandidateSources:      []models.CloneSourceCandidate{},
				SourceFreshnessAt:     censusSnap.SourceInventoryFreshnessAt,
				SourceFreshnessAgeSec: censusSnap.SourceFreshnessAgeSeconds,
				ObservedAt:            censusSnap.ObservedAt,
				SnapshotSHA256:        censusSnap.SnapshotSHA256,
			}
			_ = o.Store.AppendEstateReadEvidence(ctx, cenEv)
			if o.N4AgentCP != nil {
				_ = o.N4AgentCP.RecordGovernedAdapterAction(
					ctx, "", "", "agt-estate-reader", censusSnap.SourceSystem,
					models.AgentActionReadEstateSnapshot, "", "",
					models.EgressProfileInternalCluster, crypto.SHA256Hex([]byte(censusSnap.QueryIdentity)), censusSnap.SnapshotSHA256,
				)
			}
			out.CensusSnapshot = censusSnap
			out.CensusEvidenceID = cenEv.EvidenceID
			out.CensusCountDelta = censusSnap.ClassMembershipCount - primarySnap.ClassMembershipCount
			denom := float64(max(primarySnap.ClassMembershipCount, 1))
			out.CensusDeltaPct = math.Round((math.Abs(float64(out.CensusCountDelta))/denom)*10000) / 100
			if out.CensusCountDelta > 0 {
				out.CensusAdvisory = fmt.Sprintf("UNMANAGED_HOST_GAP: scanner %s sees %d more assets (+%.2f%%) than %s",
					censusSnap.SourceSystem, out.CensusCountDelta, out.CensusDeltaPct, primarySnap.SourceSystem)
			} else if out.CensusCountDelta < 0 {
				out.CensusAdvisory = fmt.Sprintf("SCAN_COVERAGE_GAP: %s manages %d more assets (-%.2f%%) than scanner %s",
					primarySnap.SourceSystem, -out.CensusCountDelta, out.CensusDeltaPct, censusSnap.SourceSystem)
			} else {
				out.CensusAdvisory = fmt.Sprintf("CENSUS_ALIGNED: %s and %s agree on %d assets (0.00%% delta)",
					primarySnap.SourceSystem, censusSnap.SourceSystem, primarySnap.ClassMembershipCount)
			}
		}
	}

	return out, nil
}
