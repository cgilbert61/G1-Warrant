package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
	webui "github.com/g1163rt-labs/g1-warrant/web"
	"github.com/google/uuid"
)

var simSeq uint64

// BuildHTTPHandler constructs the full warrantd HTTP router (OpenAPI v3.1 REST + SSE + Auditor Vault + Embedded Console).
func (o *ControlPlaneOrchestrator) BuildHTTPHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"status":       "OK",
			"service":      "warrantd",
			"organization": "G1163RT Security Labs, Inc.",
			"freeze_mode":  o.N1Warrant.CurrentFreezeState().Mode,
		})
	})

	// Real-time SSE Event Stream
	mux.Handle("GET /api/v1/events/stream", o.Broker)

	// Consolidated Bootstrap Snapshot
	mux.HandleFunc("GET /api/v1/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		sb, err := o.Store.ComputeScoreboard(ctx)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		principals, _ := o.Store.ListPrincipals(ctx)
		revocations, _ := o.Store.ListRevocations(ctx)
		warrants, _ := o.Store.ListWarrants(ctx)
		pressure, _ := o.Store.ComputeApprovalPressure(ctx)
		estate, _ := o.Store.ListEstateServices(ctx)
		remediations, _ := o.Store.ListRemediations(ctx)
		exceptions, _ := o.Store.ListExceptions(ctx)
		bridges, _ := o.Store.ListBridges(ctx)
		lockouts, _ := o.Store.ListLockouts(ctx)
		drifts, _ := o.Store.ListDriftIncidents(ctx)
		shadowRuns, _ := o.Store.ListShadowRuns(ctx)
		attestations, _ := o.Store.ListAttestations(ctx)
		agentActions, _ := o.Store.ListAgentActions(ctx)
		auditorTokens, _ := o.Store.ListAuditorTokens(ctx)
		feedStatus, _ := o.Store.GetLiveFeedStatus(ctx)
		kernelPK := o.N5Ledger.KernelPublicKey()

		writeAPIJSON(w, http.StatusOK, map[string]any{
			"scoreboard":     sb,
			"principals":     principals,
			"test_personas":  crypto.BuiltinTestPersonas(),
			"revocations":    revocations,
			"warrants":       warrants,
			"pressure":       pressure,
			"estate":         estate,
			"remediations":   remediations,
			"exceptions":     exceptions,
			"bridges":        bridges,
			"lockouts":       lockouts,
			"drifts":         drifts,
			"shadow_runs":    shadowRuns,
			"attestations":   attestations,
			"agent_actions":  agentActions,
			"auditor_tokens": auditorTokens,
			"feed_status":    feedStatus,
			"kernel_public_key": map[string]string{
				"key_id":          kernelPK.KeyID,
				"alg":             kernelPK.Alg,
				"public_key_b64":  base64.StdEncoding.EncodeToString(kernelPK.PublicKeyBytes),
				"key_fingerprint": kernelPK.KeyFingerprint,
			},
			"webauthn": map[string]any{
				"rp_id":   o.WebAuthnCfg.RPID,
				"origins": o.WebAuthnCfg.AllowedOrigins,
			},
		})
	})

	mux.HandleFunc("GET /api/v1/scoreboard", func(w http.ResponseWriter, r *http.Request) {
		sb, err := o.Store.ComputeScoreboard(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, sb)
	})

	// Principals, Hardware WebAuthn Registration, and Live Revocation
	mux.HandleFunc("GET /api/v1/principals", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListPrincipals(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("POST /api/v1/principals/webauthn/register", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			DisplayName       string `json:"display_name"`
			Email             string `json:"email"`
			Role              string `json:"role"`
			CredentialID      string `json:"credential_id"`
			AttestationObject string `json:"attestation_object"`
			PublicKeySPKI     string `json:"public_key_spki"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		if req.Role != crypto.RoleServiceOwner && req.Role != crypto.RoleAuthorizingOfficial {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("role must be SERVICE_OWNER or AUTHORIZING_OFFICIAL"))
			return
		}
		alg, spkiDER, fp, err := crypto.ParseWebAuthnRegistration(req.AttestationObject, req.PublicKeySPKI, req.CredentialID, o.WebAuthnCfg)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		short := uuid.NewString()[:8]
		p := models.Principal{
			PrincipalID:       fmt.Sprintf("usr-webauthn-%s", short),
			Email:             strings.TrimSpace(req.Email),
			DisplayName:       strings.TrimSpace(req.DisplayName),
			Role:              req.Role,
			KeyID:             fmt.Sprintf("webauthn-%s", short),
			Alg:               alg,
			PublicKeyB64:      base64.StdEncoding.EncodeToString(spkiDER),
			KeyFingerprint:    fp,
			AuthenticatorMode: "WEBAUTHN_HARDWARE",
			CredentialID:      req.CredentialID,
			CreatedAt:         time.Now().UTC(),
		}
		if err := o.Store.UpsertPrincipal(r.Context(), p); err != nil {
			writeAPIError(w, http.StatusConflict, err)
			return
		}
		o.Broker.Broadcast("PRINCIPAL_REGISTERED", p)
		writeAPIJSON(w, http.StatusCreated, p)
	})

	mux.HandleFunc("POST /api/v1/principals/revoke", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PrincipalID    string `json:"principal_id"`
			KeyFingerprint string `json:"key_fingerprint"`
			ReasonCode     string `json:"reason_code"`
			RevokedBy      string `json:"revoked_by"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		if req.ReasonCode == "" {
			req.ReasonCode = "ROLE_DEPARTURE_OR_PIV_REVOCATION"
		}
		if req.RevokedBy == "" {
			req.RevokedBy = "sec-ops-console"
		}
		rev, err := o.N1Warrant.RevokeSigner(r.Context(), req.PrincipalID, req.KeyFingerprint, req.ReasonCode, req.RevokedBy)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusCreated, rev)
	})

	// N1 Standing Warrants
	mux.HandleFunc("GET /api/v1/warrants", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListWarrants(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("POST /api/v1/warrants", func(w http.ResponseWriter, r *http.Request) {
		var env crypto.Envelope
		if err := decodeJSONBody(w, r, &env); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		rec, err := o.N1Warrant.SubmitDualSignedWarrant(r.Context(), env)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusCreated, rec)
	})

	mux.HandleFunc("POST /api/v1/warrants/{id}/verify", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		rec, err := o.N1Warrant.ReverifyWarrantForExecution(r.Context(), id, "", 0, 0)
		if err != nil {
			writeAPIJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"valid":  false,
				"reason": err.Error(),
			})
			return
		}
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"valid":   true,
			"warrant": rec,
		})
	})

	// N1 Asymmetric Emergency Freeze & 2-of-2 Thaw Ceremony
	mux.HandleFunc("POST /api/v1/freeze", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Mode       string `json:"mode"`
			Actor      string `json:"actor"`
			ReasonCode string `json:"reason_code"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		fs, err := o.N1Warrant.TriggerEmergencyFreeze(r.Context(), req.Mode, req.Actor, req.ReasonCode, o.N2Gate.RollbackAllActiveCanaries)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, fs)
	})

	mux.HandleFunc("POST /api/v1/freeze/thaw", func(w http.ResponseWriter, r *http.Request) {
		var env crypto.Envelope
		if err := decodeJSONBody(w, r, &env); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		fs, err := o.N1Warrant.ThawEmergencyFreeze(r.Context(), env)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, fs)
	})

	// Pipeline, Traces, SARIF Intake, and Interactive Simulation Triggers
	mux.HandleFunc("GET /api/v1/pipeline", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListRemediations(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("GET /api/v1/pipeline/{id}/traces", func(w http.ResponseWriter, r *http.Request) {
		traces, err := o.Store.ListTraces(r.Context(), r.PathValue("id"))
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, traces)
	})

	mux.HandleFunc("POST /api/v1/intake/sarif", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		q := r.URL.Query()
		profile := q.Get("profile")
		targetSvc := q.Get("target_service")
		vulnDigest := q.Get("vulnerable_digest")
		maxFindings := 0
		if mf := q.Get("max_findings"); mf != "" {
			if parsed, pErr := strconv.Atoi(mf); pErr == nil && parsed > 0 {
				maxFindings = parsed
			}
		}
		items, err := o.ExecuteSARIFRemediationWithOptions(r.Context(), raw, profile, targetSvc, vulnDigest, maxFindings)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusCreated, items)
	})

	// Optional Live Threat & Scanner Feeds (CISA KEV, Google OSV.dev, Trivy Sidecar)
	mux.HandleFunc("GET /api/v1/feeds/status", func(w http.ResponseWriter, r *http.Request) {
		st, err := o.Store.GetLiveFeedStatus(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, st)
	})

	mux.HandleFunc("POST /api/v1/feeds/config", func(w http.ResponseWriter, r *http.Request) {
		var cfg models.FeedRuntimeConfig
		if err := decodeJSONBody(w, r, &cfg); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		updated, err := o.Feeds.UpdateConfig(r.Context(), cfg)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, updated)
	})

	mux.HandleFunc("POST /api/v1/feeds/sync/kev", func(w http.ResponseWriter, r *http.Request) {
		run, err := o.Feeds.SyncCISAKEV(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, run)
	})

	mux.HandleFunc("POST /api/v1/feeds/sync/osv", func(w http.ResponseWriter, r *http.Request) {
		run, advisories, err := o.Feeds.SyncOSV(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		var ingested []models.RemediationItem
		if r.URL.Query().Get("ingest") == "true" && len(advisories) > 0 {
			ingested, _ = o.IngestOSVAdvisoryToPipeline(r.Context(), advisories[0].OSVID, advisories[0].ServiceID)
		}
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"sync_run":   run,
			"advisories": advisories,
			"ingested":   ingested,
		})
	})

	mux.HandleFunc("POST /api/v1/feeds/osv/ingest", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			OSVID     string `json:"osv_id"`
			ServiceID string `json:"service_id"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		items, err := o.IngestOSVAdvisoryToPipeline(r.Context(), req.OSVID, req.ServiceID)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusCreated, items)
	})

	mux.HandleFunc("POST /api/v1/simulate/{scenario}", func(w http.ResponseWriter, r *http.Request) {
		scenario := r.PathValue("scenario")
		seq := atomic.AddUint64(&simSeq, 1)
		ctx := r.Context()

		switch scenario {
		case "inject-kev":
			cve := fmt.Sprintf("CVE-2026-%05d", 48000+seq)
			svc, err := o.Store.GetEstateService(ctx, "payments-ledger-api")
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
			patchedHash := crypto.SHA256Hex([]byte(fmt.Sprintf("clean-patch-%d", seq)))
			sarif := BuildDeterministicSARIF(
				cve, "CWE-787", 9.8, true, "payments-ledger-api",
				svc.CurrentDigest, "sha256:"+patchedHash,
				"tls_heartbeat_ext_parse_vuln", "TLS_HEARTBEAT", 8443,
			)
			items, err := o.ExecuteSARIFRemediation(ctx, sarif, "STATELESS_CLEAN")
			if err != nil {
				writeAPIError(w, http.StatusUnprocessableEntity, err)
				return
			}
			writeAPIJSON(w, http.StatusOK, map[string]any{"scenario": scenario, "items": items})

		case "bad-syscall":
			cve := fmt.Sprintf("CVE-2026-%05d", 52000+seq)
			svc, err := o.Store.GetEstateService(ctx, "payments-ledger-api")
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
			badHash := crypto.SHA256Hex([]byte(fmt.Sprintf("execve-patch-%d", seq)))
			sarif := BuildDeterministicSARIF(
				cve, "CWE-78", 9.4, true, "payments-ledger-api",
				svc.CurrentDigest, "sha256:"+badHash,
				"tls_heartbeat_ext_parse_vuln", "HTTP_PATH_TRAVERSAL", 8080,
			)
			items, err := o.ExecuteSARIFRemediation(ctx, sarif, "BAD_SYSCALL_EXECVE")
			if err != nil {
				writeAPIError(w, http.StatusUnprocessableEntity, err)
				return
			}
			writeAPIJSON(w, http.StatusOK, map[string]any{"scenario": scenario, "items": items})

		case "stateful-ddl":
			cve := fmt.Sprintf("CVE-2026-%05d", 56000+seq)
			svc, err := o.Store.GetEstateService(ctx, "identity-sso-gateway")
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
			ddlHash := crypto.SHA256Hex([]byte(fmt.Sprintf("ddl-patch-%d", seq)))
			sarif := BuildDeterministicSARIF(
				cve, "CWE-89", 8.9, false, "identity-sso-gateway",
				svc.CurrentDigest, "sha256:"+ddlHash,
				"saml_dsig_xpath_eval_v1", "HTTP_PATH_TRAVERSAL", 8443,
			)
			items, err := o.ExecuteSARIFRemediation(ctx, sarif, "STATEFUL_DDL")
			if err != nil {
				writeAPIError(w, http.StatusUnprocessableEntity, err)
				return
			}
			writeAPIJSON(w, http.StatusOK, map[string]any{"scenario": scenario, "items": items})

		case "runtime-drift":
			lockouts, err := o.Store.ListLockouts(ctx)
			if err != nil || len(lockouts) == 0 {
				writeAPIError(w, http.StatusPreconditionFailed, fmt.Errorf("no active admission lockouts available to drift"))
				return
			}
			target := lockouts[0]
			podName, unixMs, err := o.Deploy.InjectDriftSimulation(ctx, target.ServiceID, target.BannedDigest)
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
			// Immediately run a drift sweep in addition to background watcher for instant response
			_ = o.N3Verify.CheckFleetDriftOnce(ctx)
			writeAPIJSON(w, http.StatusOK, map[string]any{
				"scenario":         scenario,
				"service_id":       target.ServiceID,
				"banned_digest":    target.BannedDigest,
				"rogue_pod_name":   podName,
				"injected_unix_ms": unixMs,
			})

		default:
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("unknown simulation scenario %q", scenario))
		}
	})

	// Exceptions, Estate, Shadow Runs, Bridges, Lockouts, Drift
	mux.HandleFunc("GET /api/v1/exceptions", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListExceptions(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("POST /api/v1/exceptions/{id}/resolve", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Decision     string          `json:"decision"`
			DSSEEnvelope crypto.Envelope `json:"dsse_envelope"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		ex, rem, err := o.ApproveOrRejectException(r.Context(), r.PathValue("id"), req.Decision, req.DSSEEnvelope)
		if err != nil && ex == nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"exception":   ex,
			"remediation": rem,
		})
	})

	mux.HandleFunc("GET /api/v1/estate", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListEstateServices(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("GET /api/v1/shadow/runs", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListShadowRuns(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("GET /api/v1/bridges", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListBridges(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("GET /api/v1/lockouts", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListLockouts(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("GET /api/v1/drift", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListDriftIncidents(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	// N5 OSCAL Vault & Governed Agent Ledger
	mux.HandleFunc("GET /api/v1/attestations", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListAttestations(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("GET /api/v1/attestations/{id}/oscal", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		list, err := o.Store.ListAttestations(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		for _, a := range list {
			if a.AttestationID == id || a.RemediationID == id {
				bundle := map[string]any{
					"attestation_id": a.AttestationID,
					"remediation_id": a.RemediationID,
					"cve_id":         a.CVEID,
					"service_id":     a.ServiceID,
					"warrant_id":     a.WarrantID,
					"dsse_envelope":  a.DSSEEnvelope,
					"oscal_poam":     a.OSCALPOAM,
					"entry_hash":     a.EntryHash,
					"prev_hash":      a.PrevHash,
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"g1-oscal-poam-%s-%s.json\"", a.CVEID, a.AttestationID))
				raw, _ := json.MarshalIndent(bundle, "", "  ")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
				return
			}
		}
		writeAPIError(w, http.StatusNotFound, fmt.Errorf("attestation %q not found", id))
	})

	mux.HandleFunc("POST /api/v1/auditor-tokens", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Label                string   `json:"label"`
			ScopedAttestationIDs []string `json:"scoped_attestation_ids"`
			TTLHours             int      `json:"ttl_hours"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		tok, rawBearer, err := o.N5Ledger.MintScopedAuditorToken(r.Context(), req.Label, "console-operator", req.ScopedAttestationIDs, req.TTLHours)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusCreated, map[string]any{
			"token":       tok,
			"bearer":      rawBearer,
			"auditor_url": fmt.Sprintf("/auditor?token=%s", rawBearer),
		})
	})

	mux.HandleFunc("GET /api/v1/ledger/actions", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListAgentActions(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("POST /api/v1/ledger/verify", func(w http.ResponseWriter, r *http.Request) {
		rep, err := o.Store.VerifyAllLedgerChains(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, rep)
	})

	// Scoped External Auditor Surface (Read-Only, Bearer Token Required)
	mux.HandleFunc("GET /api/v1/auditor/vault", func(w http.ResponseWriter, r *http.Request) {
		bearer := extractAuditorBearer(r)
		if bearer == "" {
			writeAPIError(w, http.StatusUnauthorized, fmt.Errorf("MISSING_AUDITOR_BEARER_TOKEN"))
			return
		}
		tok, err := o.Store.ValidateAuditorToken(r.Context(), bearer)
		if err != nil {
			writeAPIError(w, http.StatusForbidden, err)
			return
		}
		allAtts, err := o.Store.ListAttestations(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		scopeMap := map[string]bool{}
		for _, id := range tok.ScopedAttestationIDs {
			scopeMap[id] = true
		}
		filtered := make([]models.AttestationRecord, 0)
		for _, a := range allAtts {
			if len(scopeMap) == 0 || scopeMap[a.AttestationID] || scopeMap["*"] {
				filtered = append(filtered, a)
			}
		}
		chainRep, _ := o.Store.VerifyAllLedgerChains(r.Context())
		kernelPK := o.N5Ledger.KernelPublicKey()
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"token_metadata": tok,
			"attestations":   filtered,
			"ledger_proof":   chainRep,
			"kernel_public_key": map[string]string{
				"key_id":          kernelPK.KeyID,
				"alg":             kernelPK.Alg,
				"public_key_b64":  base64.StdEncoding.EncodeToString(kernelPK.PublicKeyBytes),
				"key_fingerprint": kernelPK.KeyFingerprint,
			},
		})
	})

	// Embedded Single-Binary React 19 Console (go:embed web/dist)
	subFS, err := fs.Sub(webui.DistFS, "dist")
	if err == nil {
		fileServer := http.FileServer(http.FS(subFS))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeAPIError(w, http.StatusNotFound, fmt.Errorf("unknown API endpoint %s", r.URL.Path))
				return
			}
			cleanPath := strings.TrimPrefix(r.URL.Path, "/")
			if cleanPath != "" {
				if f, openErr := subFS.Open(cleanPath); openErr == nil {
					_ = f.Close()
					fileServer.ServeHTTP(w, r)
					return
				}
			}
			indexBytes, readErr := fs.ReadFile(subFS, "index.html")
			if readErr != nil {
				http.Error(w, "console bundle missing", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(indexBytes)
		})
	}

	// Enforce Federal HTTP Security Headers & Scoped Auditor Bearer Token Isolation across the entire mux
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")

		bearer := extractAuditorBearer(r)
		if strings.HasPrefix(bearer, "g1aud_") && !strings.HasPrefix(r.URL.Path, "/api/v1/auditor/") {
			writeAPIError(w, http.StatusForbidden, fmt.Errorf("AUDITOR_TOKEN_SCOPE_VIOLATION: external auditor tokens cannot access operational endpoint %s", r.URL.Path))
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func extractAuditorBearer(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if q := strings.TrimSpace(r.URL.Query().Get("auditor_token")); q != "" {
		return q
	}
	return ""
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeAPIJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, code int, err error) {
	writeAPIJSON(w, code, map[string]string{
		"error": err.Error(),
	})
}
