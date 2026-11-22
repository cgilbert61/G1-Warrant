package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

func (o *ControlPlaneOrchestrator) registerAgentGovernanceRoutes(mux *http.ServeMux) {
	// Commissioning Functions (A1)
	mux.HandleFunc("GET /api/v1/commissioning-functions", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListCommissioningFunctions(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("GET /api/v1/commissioning-functions/pending-transfers", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListPendingSponsorTransfers(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("POST /api/v1/commissioning-functions", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if pkErr := rejectPrivateKeyFields(rawBody); pkErr != nil {
			writeAPIError(w, http.StatusBadRequest, pkErr)
			return
		}

		if env, isDSSE, dErr := extractGovernanceDSSEFromRequest(r, rawBody); isDSSE {
			if dErr != nil {
				writeAPIError(w, http.StatusBadRequest, dErr)
				return
			}
			expectedAction := models.GovActionUpsertCommissioningFunction
			if rawP, pErr := env.DecodePayload(); pErr == nil {
				var probe struct {
					Action string `json:"action"`
				}
				if json.Unmarshal(rawP, &probe) == nil && probe.Action == models.GovActionTransferCommissioningSponsor {
					expectedAction = models.GovActionTransferCommissioningSponsor
				}
			}
			cf, vErr := o.N1Warrant.UpsertCommissioningFunctionDualSigned(ctx, env, expectedAction)
			if vErr != nil {
				writeAPIError(w, statusForAgentGovError(vErr), vErr)
				return
			}
			_, _ = o.N5Ledger.CreateCheckpoint(ctx)
			writeAPIJSON(w, http.StatusCreated, cf)
			return
		}

		if code, authErr := o.VerifyBootstrapUnsealedAuth(ctx, r); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var req models.CommissioningFunction
		if err := json.Unmarshal(rawBody, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		if req.OrphanGraceHours == 0 {
			// Check whether orphan_grace_hours was explicitly passed as 0 or omitted
			var rawMap map[string]json.RawMessage
			if json.Unmarshal(rawBody, &rawMap) == nil {
				if _, explicit := rawMap["orphan_grace_hours"]; !explicit {
					req.OrphanGraceHours = 168
				}
			}
		}
		cf, gErr := o.N1Warrant.UpsertCommissioningFunctionGenesis(ctx, req)
		if gErr != nil {
			writeAPIError(w, statusForAgentGovError(gErr), gErr)
			return
		}
		_, _ = o.N5Ledger.CreateCheckpoint(ctx)
		writeAPIJSON(w, http.StatusCreated, cf)
	})

	mux.HandleFunc("POST /api/v1/commissioning-functions/{id}/transfer", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		fnID := strings.TrimSpace(r.PathValue("id"))
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		env, isDSSE, dErr := extractGovernanceDSSEFromRequest(r, rawBody)
		if !isDSSE {
			writeAPIError(w, http.StatusForbidden, fmt.Errorf("SPONSOR_TRANSFER_REQUIRES_DUAL_KEY_DSSE: submit a 2-of-2 TRANSFER_COMMISSIONING_SPONSOR DSSE envelope"))
			return
		}
		if dErr != nil {
			writeAPIError(w, http.StatusBadRequest, dErr)
			return
		}
		if rawP, pErr := env.DecodePayload(); pErr == nil {
			var probe struct {
				FunctionID string `json:"function_id"`
			}
			if json.Unmarshal(rawP, &probe) == nil && fnID != "" && probe.FunctionID != "" && probe.FunctionID != fnID {
				writeAPIError(w, http.StatusBadRequest, fmt.Errorf("FUNCTION_ID_MISMATCH: URL %q != signed payload %q", fnID, probe.FunctionID))
				return
			}
		}
		cf, vErr := o.N1Warrant.UpsertCommissioningFunctionDualSigned(ctx, env, models.GovActionTransferCommissioningSponsor)
		if vErr != nil {
			writeAPIError(w, statusForAgentGovError(vErr), vErr)
			return
		}
		_, _ = o.N5Ledger.CreateCheckpoint(ctx)
		writeAPIJSON(w, http.StatusOK, cf)
	})

	// Agent Workload Identity Registry & 3-Way SoD Enrollment / Recertification / Kill-Switch / RFC 8693 Token Exchange (A1, A2, A4)
	mux.HandleFunc("GET /api/v1/agents", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListAgentIdentities(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("POST /api/v1/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if pkErr := rejectPrivateKeyFields(rawBody); pkErr != nil {
			writeAPIError(w, http.StatusBadRequest, pkErr)
			return
		}
		env, isDSSE, dErr := extractGovernanceDSSEFromRequest(r, rawBody)
		if !isDSSE {
			writeAPIError(w, http.StatusForbidden, fmt.Errorf("AGENT_ENROLLMENT_REQUIRES_DUAL_KEY_DSSE: submit a 2-of-2 ENROLL_AGENT_IDENTITY DSSE envelope signed by SERVICE_OWNER + AUTHORIZING_OFFICIAL"))
			return
		}
		if dErr != nil {
			writeAPIError(w, http.StatusBadRequest, dErr)
			return
		}
		agent, vErr := o.N1Warrant.EnrollAgentIdentityDualSigned(ctx, env)
		if vErr != nil {
			writeAPIError(w, statusForAgentGovError(vErr), vErr)
			return
		}
		_, _ = o.N5Ledger.CreateCheckpoint(ctx)
		writeAPIJSON(w, http.StatusCreated, agent)
	})

	mux.HandleFunc("POST /api/v1/agents/recertify", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		env, isDSSE, dErr := extractGovernanceDSSEFromRequest(r, rawBody)
		if !isDSSE {
			writeAPIError(w, http.StatusForbidden, fmt.Errorf("AGENT_RECERTIFY_REQUIRES_DUAL_KEY_DSSE: submit a 2-of-2 RECERTIFY_AGENT_IDENTITY DSSE envelope"))
			return
		}
		if dErr != nil {
			writeAPIError(w, http.StatusBadRequest, dErr)
			return
		}
		agent, vErr := o.N1Warrant.RecertifyAgentIdentityDualSigned(ctx, env)
		if vErr != nil {
			writeAPIError(w, statusForAgentGovError(vErr), vErr)
			return
		}
		_, _ = o.N5Ledger.CreateCheckpoint(ctx)
		writeAPIJSON(w, http.StatusOK, agent)
	})

	mux.HandleFunc("POST /api/v1/agents/revoke", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		env, isDSSE, dErr := extractGovernanceDSSEFromRequest(r, rawBody)
		if !isDSSE {
			writeAPIError(w, http.StatusForbidden, fmt.Errorf("AGENT_REVOKE_REQUIRES_DSSE: submit a 1-of-2 Principal Governance or Agent Self-Revocation DSSE envelope"))
			return
		}
		if dErr != nil {
			writeAPIError(w, http.StatusBadRequest, dErr)
			return
		}
		agent, vErr := o.N1Warrant.RevokeAgentIdentity(ctx, env)
		if vErr != nil {
			writeAPIError(w, statusForAgentGovError(vErr), vErr)
			return
		}
		_, _ = o.N5Ledger.CreateCheckpoint(ctx)
		writeAPIJSON(w, http.StatusOK, agent)
	})

	mux.HandleFunc("POST /api/v1/agents/token-exchange", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if pkErr := rejectPrivateKeyFields(rawBody); pkErr != nil {
			writeAPIError(w, http.StatusBadRequest, pkErr)
			return
		}
		var dsseReq crypto.Envelope
		if err := json.Unmarshal(rawBody, &dsseReq); err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("INVALID_TOKEN_EXCHANGE_DSSE: %w", err))
			return
		}
		res, exErr := o.N4AgentCP.ExchangeAgentTaskToken(ctx, dsseReq)
		if exErr != nil {
			writeAPIError(w, statusForAgentGovError(exErr), exErr)
			return
		}
		writeAPIJSON(w, http.StatusOK, res)
	})

	// Event-Driven IGA Lifecycle Ingestion (A2)
	mux.HandleFunc("GET /api/v1/iga/events", func(w http.ResponseWriter, r *http.Request) {
		list, err := o.Store.ListAgentLifecycleEvents(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, list)
	})

	mux.HandleFunc("POST /api/v1/iga/events", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		actor, lineageMode, govEnv, code, authErr := o.VerifyIGAAuth(ctx, r, rawBody)
		if authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var req models.IGAEventRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, fmt.Errorf("invalid IGAEventRequest JSON: %w", err))
			return
		}
		res, pErr := o.N1Warrant.ProcessIGALifecycleEvent(ctx, req, actor, lineageMode, govEnv)
		if pErr != nil {
			writeAPIError(w, statusForAgentGovError(pErr), pErr)
			return
		}
		_, _ = o.N5Ledger.CreateCheckpoint(ctx)
		writeAPIJSON(w, http.StatusOK, res)
	})
}

func statusForAgentGovError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "SOD_BUILDER_CANNOT_SELF_COMMISSION"),
		strings.Contains(msg, "BOOTSTRAP_SEALED_REQUIRES_DUAL_KEY_DSSE"),
		strings.Contains(msg, "N4_TOKEN_EXCHANGE_DENIED"),
		strings.Contains(msg, "AGENT_SELF_REVOKE_SCOPE_VIOLATION"):
		return http.StatusForbidden
	case strings.Contains(msg, "DUPLICATE_"),
		strings.Contains(msg, "COLLIDES_WITH_HUMAN_PRINCIPAL"),
		strings.Contains(msg, "PREVIOUSLY_REVOKED"),
		strings.Contains(msg, "NONCE"):
		return http.StatusConflict
	case strings.Contains(msg, "not found"), strings.Contains(msg, "NOT_FOUND"):
		return http.StatusNotFound
	default:
		return http.StatusUnprocessableEntity
	}
}
