package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	webui "github.com/cgilbert61/G1-Warrant/web"
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
		bootState, _ := o.Store.GetBootstrapState(ctx)
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
		checkpoints, _ := o.Store.ListLedgerCheckpoints(ctx)
		feedStatus, _ := o.Store.GetLiveFeedStatus(ctx)
		kernelPK := o.N5Ledger.KernelPublicKey()
		kernelKeyRing, _ := o.Store.ListKernelPublicKeys(ctx)

		var testPersonas any = []crypto.TestSmartcardPersona{}
		if os.Getenv("WARRANT_ENABLE_TEST_SMARTCARDS") == "true" {
			testPersonas = crypto.BuiltinTestPersonas()
		}

		writeAPIJSON(w, http.StatusOK, map[string]any{
			"scoreboard":      sb,
			"bootstrap_state": bootState,
			"principals":      principals,
			"test_personas":   testPersonas,
			"revocations":     revocations,
			"warrants":        warrants,
			"pressure":        pressure,
			"estate":          estate,
			"remediations":    remediations,
			"exceptions":      exceptions,
			"bridges":         bridges,
			"lockouts":        lockouts,
			"drifts":          drifts,
			"shadow_runs":     shadowRuns,
			"attestations":    attestations,
			"agent_actions":   agentActions,
			"auditor_tokens":  auditorTokens,
			"checkpoints":     checkpoints,
			"feed_status":     feedStatus,
			"signer_backend":  o.N5Ledger.SignerBackend(),
			"kernel_public_key": map[string]string{
				"key_id":          kernelPK.KeyID,
				"alg":             kernelPK.Alg,
				"public_key_b64":  base64.StdEncoding.EncodeToString(kernelPK.PublicKeyBytes),
				"key_fingerprint": kernelPK.KeyFingerprint,
			},
			"kernel_public_key_ring": kernelKeyRing,
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

	// Principals, Genesis Seal, 2-of-2 DSSE Ed25519/WebAuthn Enrollment, and 1-of-2 DSSE Live Revocation
	mux.HandleFunc("GET /api/v1/principals", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListPrincipals(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	// POST /api/v1/bootstrap/seal permanently seals genesis bootstrap enrollment once >=1 active SO and >=1 active AO exist.
	mux.HandleFunc("POST /api/v1/bootstrap/seal", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		actor := ""
		if env, isDSSE, dErr := extractGovernanceDSSEFromRequest(r, rawBody); isDSSE {
			if dErr != nil {
				writeAPIError(w, http.StatusBadRequest, dErr)
				return
			}
			_, singleRes, vErr := o.N1Warrant.VerifySingleGovernanceEnvelope(ctx, env, models.GovActionSealBootstrap)
			if vErr != nil {
				writeAPIError(w, http.StatusUnprocessableEntity, vErr)
				return
			}
			actor = singleRes.Signer.PrincipalID
		} else {
			if code, authErr := o.VerifyBootstrapUnsealedAuth(ctx, r); authErr != nil {
				writeAPIError(w, code, authErr)
				return
			}
			actor = "bootstrap-admin-token"
		}

		st, err := o.Store.SealBootstrap(ctx, actor, "EXPLICIT_BOOTSTRAP_SEAL")
		if err != nil {
			writeAPIError(w, http.StatusPreconditionFailed, err)
			return
		}
		o.Broker.Broadcast("BOOTSTRAP_SEALED", st)
		writeAPIJSON(w, http.StatusOK, st)
	})

	// POST /api/v1/principals/register enrolls an Ed25519 public key for AC-5 Slot 1 or Slot 2.
	// Before bootstrap seal: accepts WARRANT_BOOTSTRAP_ADMIN_TOKEN or 2-of-2 DSSE (ENROLL_PRINCIPAL).
	// After bootstrap seal: permanently rejects WARRANT_BOOTSTRAP_ADMIN_TOKEN (403 BOOTSTRAP_SEALED_REQUIRES_DUAL_KEY_DSSE)
	// and requires a 2-of-2 DSSE Principal Governance envelope signed by active SERVICE_OWNER + AUTHORIZING_OFFICIAL.
	mux.HandleFunc("POST /api/v1/principals/register", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		if pkErr := rejectPrivateKeyFields(rawBody); pkErr != nil {
			writeAPIError(w, http.StatusBadRequest, pkErr)
			return
		}

		var req struct {
			PrincipalID  string `json:"principal_id"`
			Email        string `json:"email"`
			DisplayName  string `json:"display_name"`
			Role         string `json:"role"`
			KeyID        string `json:"key_id"`
			Alg          string `json:"alg"`
			PublicKeyB64 string `json:"public_key_b64"`
		}

		if env, isDSSE, dErr := extractGovernanceDSSEFromRequest(r, rawBody); isDSSE {
			if dErr != nil {
				writeAPIError(w, http.StatusBadRequest, dErr)
				return
			}
			gp, _, vErr := o.N1Warrant.VerifyDualGovernanceEnvelope(ctx, env, models.GovActionEnrollPrincipal)
			if vErr != nil {
				writeAPIError(w, http.StatusUnprocessableEntity, vErr)
				return
			}
			req.PrincipalID = gp.PrincipalID
			req.Email = gp.Email
			req.DisplayName = gp.DisplayName
			req.Role = gp.Role
			req.KeyID = gp.KeyID
			req.Alg = gp.Alg
			req.PublicKeyB64 = gp.PublicKeyB64
		} else {
			if code, authErr := o.VerifyBootstrapUnsealedAuth(ctx, r); authErr != nil {
				writeAPIError(w, code, authErr)
				return
			}
			if err := decodeStrictJSONBytes(rawBody, &req); err != nil {
				writeAPIError(w, http.StatusBadRequest, err)
				return
			}
		}

		if req.Role != crypto.RoleServiceOwner && req.Role != crypto.RoleAuthorizingOfficial {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("AC5_INVALID_ENROLLMENT_ROLE: role must be SERVICE_OWNER or AUTHORIZING_OFFICIAL"))
			return
		}
		if strings.TrimSpace(req.PrincipalID) == "" || strings.TrimSpace(req.Email) == "" {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("principal_id and email are required"))
			return
		}
		pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.PublicKeyB64))
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			writeAPIError(w, http.StatusUnprocessableEntity, fmt.Errorf("expected valid 32-byte base64 Ed25519 public_key_b64"))
			return
		}
		fp := crypto.SHA256Hex(pubBytes)
		keyID := strings.TrimSpace(req.KeyID)
		if keyID == "" {
			keyID = fmt.Sprintf("ed25519-%s-%s", strings.TrimSpace(req.PrincipalID), fp[:10])
		}
		p := models.Principal{
			PrincipalID:       strings.TrimSpace(req.PrincipalID),
			Email:             strings.TrimSpace(req.Email),
			DisplayName:       strings.TrimSpace(req.DisplayName),
			Role:              req.Role,
			KeyID:             keyID,
			Alg:               crypto.AlgEd25519,
			PublicKeyB64:      base64.StdEncoding.EncodeToString(pubBytes),
			KeyFingerprint:    fp,
			AuthenticatorMode: "ED25519_ENROLLED",
			CreatedAt:         time.Now().UTC(),
		}
		if err := o.Store.AppendPrincipal(ctx, &p); err != nil {
			writeAPIError(w, http.StatusConflict, err)
			return
		}
		_, _ = o.N5Ledger.CreateCheckpoint(ctx)
		o.Broker.Broadcast("PRINCIPAL_REGISTERED", p)
		writeAPIJSON(w, http.StatusCreated, p)
	})

	// POST /api/v1/principals/webauthn/register enrolls a W3C WebAuthn hardware authenticator.
	// Enforces the exact same genesis bootstrap vs. post-seal 2-of-2 DSSE Principal Governance rules as Ed25519 enrollment.
	mux.HandleFunc("POST /api/v1/principals/webauthn/register", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		if pkErr := rejectPrivateKeyFields(rawBody); pkErr != nil {
			writeAPIError(w, http.StatusBadRequest, pkErr)
			return
		}

		var req struct {
			DisplayName       string `json:"display_name"`
			Email             string `json:"email"`
			Role              string `json:"role"`
			CredentialID      string `json:"credential_id"`
			AttestationObject string `json:"attestation_object"`
			PublicKeySPKI     string `json:"public_key_spki"`
		}

		if env, isDSSE, dErr := extractGovernanceDSSEFromRequest(r, rawBody); isDSSE {
			if dErr != nil {
				writeAPIError(w, http.StatusBadRequest, dErr)
				return
			}
			gp, _, vErr := o.N1Warrant.VerifyDualGovernanceEnvelope(ctx, env, models.GovActionEnrollPrincipal)
			if vErr != nil {
				writeAPIError(w, http.StatusUnprocessableEntity, vErr)
				return
			}
			req.DisplayName = gp.DisplayName
			req.Email = gp.Email
			req.Role = gp.Role
			req.CredentialID = gp.CredentialID
			req.AttestationObject = gp.AttestationObject
			req.PublicKeySPKI = gp.PublicKeySPKI
		} else {
			if code, authErr := o.VerifyBootstrapUnsealedAuth(ctx, r); authErr != nil {
				writeAPIError(w, code, authErr)
				return
			}
			if err := decodeStrictJSONBytes(rawBody, &req); err != nil {
				writeAPIError(w, http.StatusBadRequest, err)
				return
			}
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
		if err := o.Store.AppendPrincipal(ctx, &p); err != nil {
			writeAPIError(w, http.StatusConflict, err)
			return
		}
		_, _ = o.N5Ledger.CreateCheckpoint(ctx)
		o.Broker.Broadcast("PRINCIPAL_REGISTERED", p)
		writeAPIJSON(w, http.StatusCreated, p)
	})

	// POST /api/v1/principals/revoke enforces Asymmetric 1-of-2 DSSE Principal Governance:
	// ANY single active enrolled principal (SERVICE_OWNER or AUTHORIZING_OFFICIAL) can immediately revoke a compromised/lost key,
	// while unauthenticated network callers are rejected fail-closed.
	mux.HandleFunc("POST /api/v1/principals/revoke", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		env, isDSSE, dErr := extractGovernanceDSSEFromRequest(r, rawBody)
		if !isDSSE {
			writeAPIError(w, http.StatusUnauthorized, fmt.Errorf("MISSING_REVOCATION_DSSE_SIGNATURE: POST /api/v1/principals/revoke requires a 1-of-2 DSSE Principal Governance envelope signed by an active principal"))
			return
		}
		if dErr != nil {
			writeAPIError(w, http.StatusBadRequest, dErr)
			return
		}
		gp, singleRes, vErr := o.N1Warrant.VerifySingleGovernanceEnvelope(ctx, env, models.GovActionRevokePrincipal)
		if vErr != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, vErr)
			return
		}
		targetID := strings.TrimSpace(gp.TargetPrincipalID)
		if targetID == "" {
			targetID = strings.TrimSpace(gp.PrincipalID)
		}
		targetFP := strings.TrimSpace(gp.TargetKeyFingerprint)
		if targetID == "" && targetFP == "" {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("target_principal_id or target_key_fingerprint is required in signed revocation payload"))
			return
		}
		reasonCode := strings.TrimSpace(gp.ReasonCode)
		if reasonCode == "" {
			reasonCode = "ROLE_DEPARTURE_OR_PIV_REVOCATION"
		}
		revokedBy := singleRes.Signer.PrincipalID
		rev, err := o.N1Warrant.RevokeSigner(ctx, targetID, targetFP, reasonCode, revokedBy)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		_, _ = o.N5Ledger.CreateCheckpoint(ctx)
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
		_, _ = o.N5Ledger.CreateCheckpoint(r.Context())
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

	// N1 Asymmetric Emergency Freeze (1-of-2 Active Principal DSSE or Authenticated Operator Token) & 2-of-2 Thaw Ceremony
	mux.HandleFunc("POST /api/v1/freeze", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		actor, gp, code, authErr := o.VerifyOperatorOrSinglePrincipalAuth(ctx, r, models.GovActionEmergencyFreeze, rawBody)
		if authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}

		mode := ""
		reasonCode := ""
		if gp != nil && gp.FreezeMode != "" {
			mode = gp.FreezeMode
			reasonCode = gp.ReasonCode
		}
		if mode == "" {
			var req struct {
				Mode       string `json:"mode"`
				Actor      string `json:"actor"`
				ReasonCode string `json:"reason_code"`
			}
			if err := json.Unmarshal(rawBody, &req); err != nil {
				writeAPIError(w, http.StatusBadRequest, err)
				return
			}
			mode = req.Mode
			if reasonCode == "" {
				reasonCode = req.ReasonCode
			}
		}

		fs, err := o.N1Warrant.TriggerEmergencyFreeze(ctx, mode, actor, reasonCode, o.N2Gate.RollbackAllActiveCanaries)
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

	// Atomic 3-Step Quarantined Rollback (Contain-Before-Unban) — Authenticated Operator or 1-of-2 Active Principal Required
	mux.HandleFunc("POST /api/v1/pipeline/{id}/emergency-rollback", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		remID := r.PathValue("id")
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		actor, gp, code, authErr := o.VerifyOperatorOrSinglePrincipalAuth(ctx, r, models.GovActionEmergencyRollback, rawBody)
		if authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		reason := ""
		if gp != nil {
			if gp.RemediationID != "" && gp.RemediationID != remID {
				writeAPIError(w, http.StatusUnprocessableEntity, fmt.Errorf("GOVERNANCE_TARGET_MISMATCH: signed remediation_id %q != URL %q", gp.RemediationID, remID))
				return
			}
			reason = gp.ReasonCode
		}
		if reason == "" && len(bytesTrimSpace(rawBody)) > 0 {
			var req struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(rawBody, &req)
			reason = req.Reason
		}
		rem, err := o.N3Verify.ExecuteEmergencyQuarantinedRollback(ctx, remID, actor, reason)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, rem)
	})

	mux.HandleFunc("POST /api/v1/intake/sarif", func(w http.ResponseWriter, r *http.Request) {
		if code, authErr := o.VerifyIntakeAuth(r); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
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

	// Secret-Exposure Intake (Gitleaks SARIF / Gitleaks JSON / GitGuardian / Cloud Secret Scanners)
	mux.HandleFunc("POST /api/v1/intake/secrets", func(w http.ResponseWriter, r *http.Request) {
		if code, authErr := o.VerifyIntakeAuth(r); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		targetSvc := r.URL.Query().Get("target_service")
		items, err := o.ExecuteSecretRotationRemediation(r.Context(), raw, targetSvc)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusCreated, items)
	})

	// Cilium Tetragon / eBPF Runtime Container Filesystem & Process Immutability Webhook (Dedicated Sensor Auth Required)
	mux.HandleFunc("POST /api/v1/telemetry/tetragon", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		if code, authErr := o.VerifyTetragonSensorAuth(r, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var ev models.TetragonDriftEvent
		if err := json.Unmarshal(rawBody, &ev); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		inc, err := o.N3Verify.HandleTetragonDriftEvent(r.Context(), ev)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusCreated, inc)
	})

	// Append-only Kernel Verification Public-Key Ring (prevents restart invalidation of historical OSCAL bundles)
	mux.HandleFunc("GET /api/v1/kernel-keys", func(w http.ResponseWriter, r *http.Request) {
		ring, err := o.Store.ListKernelPublicKeys(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, ring)
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
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		if _, _, code, authErr := o.VerifyOperatorOrSinglePrincipalAuth(ctx, r, models.GovActionFeedMutation, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var cfg models.FeedRuntimeConfig
		if err := json.Unmarshal(rawBody, &cfg); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		updated, err := o.Feeds.UpdateConfig(ctx, cfg)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, updated)
	})

	mux.HandleFunc("POST /api/v1/feeds/sync/kev", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, _ := readBoundedBody(w, r, 1<<20)
		if _, _, code, authErr := o.VerifyOperatorOrSinglePrincipalAuth(ctx, r, models.GovActionFeedMutation, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		run, err := o.Feeds.SyncCISAKEV(ctx)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, run)
	})

	mux.HandleFunc("POST /api/v1/feeds/sync/osv", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, _ := readBoundedBody(w, r, 1<<20)
		if _, _, code, authErr := o.VerifyOperatorOrSinglePrincipalAuth(ctx, r, models.GovActionFeedMutation, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		run, advisories, err := o.Feeds.SyncOSV(ctx)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		var ingested []models.RemediationItem
		if r.URL.Query().Get("ingest") == "true" && len(advisories) > 0 {
			ingested, _ = o.IngestOSVAdvisoryToPipeline(ctx, advisories[0].OSVID, advisories[0].ServiceID)
		}
		writeAPIJSON(w, http.StatusOK, map[string]any{
			"sync_run":   run,
			"advisories": advisories,
			"ingested":   ingested,
		})
	})

	mux.HandleFunc("POST /api/v1/feeds/osv/ingest", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		if _, _, code, authErr := o.VerifyOperatorOrSinglePrincipalAuth(ctx, r, models.GovActionFeedMutation, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var req struct {
			OSVID     string `json:"osv_id"`
			ServiceID string `json:"service_id"`
		}
		if err := json.Unmarshal(rawBody, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		items, err := o.IngestOSVAdvisoryToPipeline(ctx, req.OSVID, req.ServiceID)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusCreated, items)
	})

	// Interactive Sandbox Simulation Drills — Disabled on Kubernetes or Live Feed Mode, and Authenticated in Simulator Mode
	mux.HandleFunc("POST /api/v1/simulate/{scenario}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if allowed, reason := o.IsSimulationAllowed(ctx); !allowed {
			writeAPIError(w, http.StatusForbidden, fmt.Errorf("%s", reason))
			return
		}
		rawBody, _ := readBoundedBody(w, r, 1<<20)
		if _, _, code, authErr := o.VerifyOperatorOrSinglePrincipalAuth(ctx, r, models.GovActionSimulationDrill, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}

		scenario := r.PathValue("scenario")
		seq := atomic.AddUint64(&simSeq, 1)

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
			_ = o.N3Verify.CheckFleetDriftOnce(ctx)
			writeAPIJSON(w, http.StatusOK, map[string]any{
				"scenario":         scenario,
				"service_id":       target.ServiceID,
				"banned_digest":    target.BannedDigest,
				"rogue_pod_name":   podName,
				"injected_unix_ms": unixMs,
			})

		case "secret-exposure":
			rawGitleaks := []byte(fmt.Sprintf(`[{
				"RuleID": "github-pat",
				"Secret": "SIMULATED_HARVESTED_CREDENTIAL_DRILL_%d",
				"File": "deploy/env.bootstrap",
				"service_id": "payments-ledger-api",
				"secret_resource_kind": "EXTERNAL_SECRET",
				"secret_resource_name": "extsec-payments-vault-creds"
			}]`, seq))
			items, err := o.ExecuteSecretRotationRemediation(ctx, rawGitleaks, "payments-ledger-api")
			if err != nil {
				writeAPIError(w, http.StatusUnprocessableEntity, err)
				return
			}
			writeAPIJSON(w, http.StatusOK, map[string]any{"scenario": scenario, "items": items})

		case "in-pod-webshell":
			probePath := fmt.Sprintf("/var/www/html/artex-probe-%02d.jsp", seq)
			podName, unixMs, err := o.Deploy.InjectFilesystemDriftSimulation(ctx, "checkout-cart-svc", probePath, "/bin/sh")
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
			_ = o.N3Verify.CheckFleetDriftOnce(ctx)
			writeAPIJSON(w, http.StatusOK, map[string]any{
				"scenario":         scenario,
				"service_id":       "checkout-cart-svc",
				"rogue_pod_name":   podName,
				"violating_path":   probePath,
				"injected_unix_ms": unixMs,
			})

		case "poisoned-config":
			cve := fmt.Sprintf("CVE-2026-%05d", 62000+seq)
			svc, err := o.Store.GetEstateService(ctx, "payments-ledger-api")
			if err != nil {
				writeAPIError(w, http.StatusInternalServerError, err)
				return
			}
			badHash := crypto.SHA256Hex([]byte(fmt.Sprintf("poisoned-cfg-%d", seq)))
			sarif := BuildDeterministicSARIF(
				cve, "CWE-209", 5.3, false, "payments-ledger-api",
				svc.CurrentDigest, "sha256:"+badHash,
				"", "ERROR_STACK_TRACE", 8080,
			)
			items, err := o.ExecuteSARIFRemediation(ctx, sarif, "POISONED_BUILD_CONFIG")
			if err != nil {
				writeAPIError(w, http.StatusUnprocessableEntity, err)
				return
			}
			writeAPIJSON(w, http.StatusOK, map[string]any{"scenario": scenario, "items": items})

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
				keyRing, _ := o.Store.ListKernelPublicKeys(r.Context())
				bundle := map[string]any{
					"attestation_id":         a.AttestationID,
					"remediation_id":         a.RemediationID,
					"cve_id":                 a.CVEID,
					"service_id":             a.ServiceID,
					"warrant_id":             a.WarrantID,
					"dsse_envelope":          a.DSSEEnvelope,
					"oscal_poam":             a.OSCALPOAM,
					"entry_hash":             a.EntryHash,
					"prev_hash":              a.PrevHash,
					"kernel_public_key_ring": keyRing,
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

	// POST /api/v1/auditor-tokens — Authenticated Operator or 1-of-2 Active Principal Required
	mux.HandleFunc("POST /api/v1/auditor-tokens", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		actor, gp, code, authErr := o.VerifyOperatorOrSinglePrincipalAuth(ctx, r, models.GovActionMintAuditorToken, rawBody)
		if authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}

		label := ""
		var scopedIDs []string
		ttlHours := 0
		if gp != nil && gp.AuditorLabel != "" {
			label = gp.AuditorLabel
			scopedIDs = gp.ScopedAttestationIDs
			ttlHours = gp.TTLHours
		} else if len(bytesTrimSpace(rawBody)) > 0 {
			var req struct {
				Label                string   `json:"label"`
				ScopedAttestationIDs []string `json:"scoped_attestation_ids"`
				TTLHours             int      `json:"ttl_hours"`
			}
			if err := json.Unmarshal(rawBody, &req); err != nil {
				writeAPIError(w, http.StatusBadRequest, err)
				return
			}
			label = req.Label
			scopedIDs = req.ScopedAttestationIDs
			ttlHours = req.TTLHours
		}

		tok, rawBearer, err := o.N5Ledger.MintScopedAuditorToken(ctx, label, actor, scopedIDs, ttlHours)
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

	mux.HandleFunc("GET /api/v1/ledger/checkpoints", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListLedgerCheckpoints(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("POST /api/v1/ledger/checkpoints", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, _ := readBoundedBody(w, r, 1<<20)
		if _, _, code, authErr := o.VerifyOperatorOrSinglePrincipalAuth(ctx, r, models.GovActionCreateCheckpoint, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		cp, err := o.N5Ledger.CreateCheckpoint(ctx)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusCreated, cp)
	})

	mux.HandleFunc("POST /api/v1/ledger/verify", func(w http.ResponseWriter, r *http.Request) {
		rep, err := o.Store.VerifyAllLedgerChains(r.Context(), o.N5Ledger.Anchor().ExternalWitnessRecords())
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
		chainRep, _ := o.Store.VerifyAllLedgerChains(r.Context(), o.N5Ledger.Anchor().ExternalWitnessRecords())
		kernelPK := o.N5Ledger.KernelPublicKey()
		kernelKeyRing, _ := o.Store.ListKernelPublicKeys(r.Context())
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
			"kernel_public_key_ring": kernelKeyRing,
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

func readBoundedBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dst)
}

func decodeStrictJSONBytes(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if dec.Decode(&trailing) == nil {
		return fmt.Errorf("unexpected trailing JSON tokens")
	}
	return nil
}

// rejectPrivateKeyFields recursively inspects decoded JSON and rejects any payload containing private key fields (HTTP 400).
func rejectPrivateKeyFields(raw []byte) error {
	if len(bytesTrimSpace(raw)) == 0 {
		return nil
	}
	var val any
	if err := json.Unmarshal(raw, &val); err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	return checkNoPrivateKeysInValue(val)
}

func checkNoPrivateKeysInValue(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			lk := strings.ToLower(strings.TrimSpace(k))
			if strings.Contains(lk, "private_key") || strings.Contains(lk, "priv_key") || lk == "seed_hex" || strings.Contains(lk, "secret_key") {
				return fmt.Errorf("PRIVATE_KEY_MATERIAL_REJECTED: field %q is forbidden on network registration endpoints; pass public key (.pub.json) only", k)
			}
			if err := checkNoPrivateKeysInValue(child); err != nil {
				return err
			}
		}
	case []any:
		for _, elem := range t {
			if err := checkNoPrivateKeysInValue(elem); err != nil {
				return err
			}
		}
	}
	return nil
}

func extractGovernanceDSSEFromRequest(r *http.Request, rawBody []byte) (crypto.Envelope, bool, error) {
	if hdrB64 := strings.TrimSpace(r.Header.Get("X-Warrant-Governance-DSSE")); hdrB64 != "" {
		envRaw, err := crypto.DecodeBase64Any(hdrB64)
		if err != nil {
			return crypto.Envelope{}, true, fmt.Errorf("invalid X-Warrant-Governance-DSSE base64: %w", err)
		}
		var env crypto.Envelope
		if err := json.Unmarshal(envRaw, &env); err != nil {
			return crypto.Envelope{}, true, fmt.Errorf("invalid X-Warrant-Governance-DSSE JSON: %w", err)
		}
		return env, true, nil
	}
	if len(bytesTrimSpace(rawBody)) > 0 {
		var probe struct {
			PayloadType string `json:"payloadType"`
		}
		if json.Unmarshal(rawBody, &probe) == nil && probe.PayloadType != "" {
			var env crypto.Envelope
			if err := json.Unmarshal(rawBody, &env); err != nil {
				return crypto.Envelope{}, true, fmt.Errorf("invalid DSSE JSON envelope: %w", err)
			}
			// Check inside base64 payload for accidental private_key fields as well
			if rawP, pErr := env.DecodePayload(); pErr == nil {
				if pkErr := rejectPrivateKeyFields(rawP); pkErr != nil {
					return crypto.Envelope{}, true, pkErr
				}
			}
			return env, true, nil
		}
	}
	return crypto.Envelope{}, false, nil
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
