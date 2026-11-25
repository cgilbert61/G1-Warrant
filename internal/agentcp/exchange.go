package agentcp

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
	"github.com/google/uuid"
)

const MaxTokenExchangeRequestTTL = 60 * time.Second

// ParentDelegationPoPPreimage builds the canonical preimage signed by a parent agent's cnf key
// when delegating a narrower task scope to a sub-agent (depth > 0):
// "G1_DELEGATE_ACT_V1|{parent_task_token_id}|{child_agent_id}|{exchange_envelope_id}"
func ParentDelegationPoPPreimage(parentTaskTokenID, childAgentID, exchangeEnvelopeID string) []byte {
	return []byte(fmt.Sprintf(
		"G1_DELEGATE_ACT_V1|%s|%s|%s",
		strings.TrimSpace(parentTaskTokenID),
		strings.TrimSpace(childAgentID),
		strings.TrimSpace(exchangeEnvelopeID),
	))
}

// ExchangeAgentTaskToken implements RFC 8693 Composite Token Exchange (POST /api/v1/agents/token-exchange):
//   1. Verifies caller AgentIdentity Ed25519 PoP DSSE envelope (<= 60s TTL, single-use envelope_id)
//   2. Evaluates live CommissioningFunction sponsorship continuity, grace windows, recertification lease & 0s compromise status
//   3. For sub-agent exchanges (depth > 0), verifies parent task warrant + parent cnf delegation PoP + monotonic attenuation
//   4. Evaluates precompiled OPA policy data.warrant.agent (StandingWarrantScope ∩ AgentCeiling ∩ ParentScope ∩ Request)
//   5. Mints a kernel-signed EphemeralTaskWarrant bound to cnf = callerAgent with nested act lineage
func (cp *ControlPlane) ExchangeAgentTaskToken(ctx context.Context, dsseReq crypto.Envelope, nowOpt ...time.Time) (*models.AgentTokenExchangeResponse, error) {
	now := time.Now().UTC()
	if len(nowOpt) > 0 && !nowOpt[0].IsZero() {
		now = nowOpt[0].UTC()
	}

	logViolation := func(code, agentID, fnID, authMode, warrantID, remID, asset, action string, depth int, act *models.ActorClaim) error {
		if cp.store != nil {
			entry := &models.AgentLedgerEntry{
				ActionID:                "act-" + uuid.NewString()[:8],
				TaskTokenID:             "EXCHANGE_DENIED",
				WarrantID:               nonEmpty(warrantID, "NONE"),
				RemediationID:           remID,
				AuthorityMode:           nonEmpty(authMode, "UNKNOWN_MODE"),
				CommissioningFunctionID: fnID,
				AgentID:                 agentID,
				DelegationDepth:         depth,
				ActChain:                act,
				WorkerName:              nonEmpty(agentID, "UNAUTHENTICATED_AGENT"),
				TargetAsset:             nonEmpty(asset, "UNKNOWN_ASSET"),
				ActionType:              nonEmpty(action, "TOKEN_EXCHANGE"),
				Slot1PrincipalID:        "NONE",
				Slot2PrincipalID:        "NONE",
				EgressProfile:           "BLOCKED_BY_KERNEL",
				RawInputSHA256:          db.GenesisHash,
				ExtractorDigest:         "N4_RFC8693_EXCHANGE",
				TypedOutputSHA256:       db.GenesisHash,
				TokenTTLSec:             0,
				Status:                  "SECURITY_VIOLATION",
				ViolationCode:           code,
				ExecutedAt:              now,
			}
			_ = cp.store.AppendAgentAction(ctx, entry)
			if cp.onBroadcast != nil {
				cp.onBroadcast("AGENT_SECURITY_VIOLATION", entry)
			}
		}
		return fmt.Errorf("N4_TOKEN_EXCHANGE_DENIED (%s)", code)
	}

	if cp.store == nil || cp.policy == nil {
		return nil, errors.New("N4_CONTROL_PLANE_UNINITIALIZED: store and policy engine required for token exchange")
	}
	if dsseReq.PayloadType != crypto.PayloadTypeAgentTokenExchange {
		return nil, logViolation("INVALID_EXCHANGE_PAYLOAD_TYPE", "", "", "", "", "", "", "", 0, nil)
	}
	if len(dsseReq.Signatures) == 0 {
		return nil, logViolation("MISSING_AGENT_POP_SIGNATURE", "", "", "", "", "", "", "", 0, nil)
	}
	rawPayload, err := dsseReq.DecodePayload()
	if err != nil {
		return nil, logViolation("CORRUPT_EXCHANGE_PAYLOAD", "", "", "", "", "", "", "", 0, nil)
	}
	canon, err := crypto.CanonicalizeJSON(rawPayload)
	if err != nil || string(canon) != string(rawPayload) {
		return nil, logViolation("EXCHANGE_PAYLOAD_NOT_CANONICAL_JCS", "", "", "", "", "", "", "", 0, nil)
	}

	var req models.AgentTokenExchangePayload
	if err := json.Unmarshal(rawPayload, &req); err != nil {
		return nil, logViolation("INVALID_EXCHANGE_JSON", "", "", "", "", "", "", "", 0, nil)
	}
	if strings.TrimSpace(req.EnvelopeID) == "" {
		return nil, logViolation("MISSING_EXCHANGE_ENVELOPE_ID", req.AgentID, "", req.AuthorityMode, req.WarrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 0, nil)
	}

	lookupKey := strings.TrimSpace(req.AgentID)
	if lookupKey == "" {
		lookupKey = strings.TrimSpace(dsseReq.Signatures[0].KeyID)
	}
	callerAgent, err := cp.store.ResolveAgentByKeyID(ctx, lookupKey, now)
	if err != nil {
		return nil, logViolation("UNKNOWN_AGENT_IDENTITY", req.AgentID, "", req.AuthorityMode, req.WarrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 0, nil)
	}
	if req.AgentID != "" && req.AgentID != callerAgent.AgentID {
		return nil, logViolation("AGENT_ID_KEY_MISMATCH", req.AgentID, callerAgent.CommissioningFunctionID, req.AuthorityMode, req.WarrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 0, nil)
	}

	// Verify caller Ed25519 signature over PAE (using Revoked=false here so authentic signatures from
	// revoked/compromised agents reach OPA and emit canonical AGENT_REVOKED_KILL_SWITCH / SPONSOR_KEY_COMPROMISED_IMMEDIATE_KILL)
	pubBytes, decErr := crypto.DecodeBase64Any(callerAgent.PublicKeyB64)
	if decErr != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, logViolation("CORRUPT_AGENT_PUBLIC_KEY", callerAgent.AgentID, callerAgent.CommissioningFunctionID, req.AuthorityMode, req.WarrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 0, nil)
	}
	verifyKey := &crypto.PrincipalKey{
		PrincipalID:    callerAgent.AgentID,
		KeyID:          callerAgent.KeyID,
		Alg:            callerAgent.Alg,
		PublicKeyBytes: pubBytes,
		KeyFingerprint: callerAgent.KeyFingerprint,
		Revoked:        false,
	}
	if err := crypto.VerifySingleSignature(dsseReq.PayloadType, rawPayload, dsseReq.Signatures[0], verifyKey, crypto.DefaultWebAuthnConfig()); err != nil {
		return nil, logViolation("FORGED_AGENT_EXCHANGE_POP_SIG", callerAgent.AgentID, callerAgent.CommissioningFunctionID, req.AuthorityMode, req.WarrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 0, nil)
	}

	// Enforce <= 60s request TTL and single-use nonce consumption
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
	if err != nil {
		return nil, logViolation("INVALID_EXCHANGE_EXPIRES_AT", callerAgent.AgentID, callerAgent.CommissioningFunctionID, req.AuthorityMode, req.WarrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 0, nil)
	}
	if strings.TrimSpace(req.IssuedAt) != "" {
		if iss, iErr := time.Parse(time.RFC3339, strings.TrimSpace(req.IssuedAt)); iErr == nil {
			if exp.Sub(iss) > MaxTokenExchangeRequestTTL+time.Second || iss.After(now.Add(30*time.Second)) {
				return nil, logViolation("EXCHANGE_REQUEST_TTL_EXCEEDED_60S", callerAgent.AgentID, callerAgent.CommissioningFunctionID, req.AuthorityMode, req.WarrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 0, nil)
			}
		}
	}
	if !now.Before(exp) || exp.Sub(now) > MaxTokenExchangeRequestTTL+time.Second {
		return nil, logViolation("EXCHANGE_REQUEST_EXPIRED_OR_TTL_GT_60S", callerAgent.AgentID, callerAgent.CommissioningFunctionID, req.AuthorityMode, req.WarrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 0, nil)
	}
	if nErr := cp.store.ConsumeGovernanceEnvelopeNonce(ctx, req.EnvelopeID, "AGENT_TOKEN_EXCHANGE", crypto.SHA256Hex(canon), callerAgent.AgentID, exp); nErr != nil {
		return nil, logViolation("EXCHANGE_NONCE_REPLAY_DETECTED", callerAgent.AgentID, callerAgent.CommissioningFunctionID, req.AuthorityMode, req.WarrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 0, nil)
	}

	reqEgress := strings.TrimSpace(req.RequestedEgressProfile)
	if reqEgress == "" {
		reqEgress = callerAgent.AllowedEgressProfile
	}
	authMode := strings.TrimSpace(req.AuthorityMode)
	if authMode == "" {
		if strings.TrimSpace(req.WarrantID) != "" {
			authMode = models.AuthorityModeWarrantComposite
		} else {
			authMode = models.AuthorityModeAutonomousSponsored
		}
	}

	// Build parent / sub-agent context if ParentTaskWarrant is supplied
	depth := 0
	parentInput := policy.AgentParentTaskInput{}
	var parentAct *models.ActorClaim
	parentTokenID := ""
	effectiveMaxDepth := callerAgent.MaxDelegationDepth
	s1ID, s2ID := "NONE", "NONE"
	warrantID := strings.TrimSpace(req.WarrantID)

	if req.ParentTaskWarrant != nil {
		if len(req.ParentTaskWarrant.Signatures) == 0 || req.ParentTaskWarrant.PayloadType != crypto.PayloadTypeTaskWarrant {
			return nil, logViolation("INVALID_PARENT_TASK_WARRANT", callerAgent.AgentID, callerAgent.CommissioningFunctionID, authMode, warrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 1, nil)
		}
		rawParent, pErr := req.ParentTaskWarrant.DecodePayload()
		if pErr != nil {
			return nil, logViolation("CORRUPT_PARENT_TASK_WARRANT", callerAgent.AgentID, callerAgent.CommissioningFunctionID, authMode, warrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 1, nil)
		}
		kernelPK := cp.signer.PublicKey()
		if vErr := crypto.VerifySingleSignature(req.ParentTaskWarrant.PayloadType, rawParent, req.ParentTaskWarrant.Signatures[0], &kernelPK, crypto.DefaultWebAuthnConfig()); vErr != nil {
			return nil, logViolation("FORGED_PARENT_TASK_SIGNATURE", callerAgent.AgentID, callerAgent.CommissioningFunctionID, authMode, warrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 1, nil)
		}
		var parentTok models.EphemeralTaskWarrantPayload
		if uErr := json.Unmarshal(rawParent, &parentTok); uErr != nil {
			return nil, logViolation("INVALID_PARENT_TASK_JSON", callerAgent.AgentID, callerAgent.CommissioningFunctionID, authMode, warrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, 1, nil)
		}
		depth = parentTok.DelegationDepth + 1
		parentTokenID = parentTok.TaskTokenID
		parentAct = parentTok.Act
		if warrantID == "" {
			warrantID = parentTok.WarrantID
		}
		if req.AuthorityMode == "" && parentTok.AuthorityMode != "" {
			authMode = parentTok.AuthorityMode
		}
		s1ID = parentTok.Slot1PrincipalID
		s2ID = parentTok.Slot2PrincipalID
		if parentTok.MaxDelegationDepth < effectiveMaxDepth {
			effectiveMaxDepth = parentTok.MaxDelegationDepth
		}
		if now.Unix() >= parentTok.ExpiresUnix {
			return nil, logViolation("EXPIRED_PARENT_TASK_WARRANT", callerAgent.AgentID, callerAgent.CommissioningFunctionID, authMode, warrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, depth, parentAct)
		}
		if parentTok.Cnf == nil || parentTok.Cnf.PublicKeyB64 == "" {
			return nil, logViolation("PARENT_TASK_MISSING_CNF_HOLDER", callerAgent.AgentID, callerAgent.CommissioningFunctionID, authMode, warrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, depth, parentAct)
		}
		// Require cryptographic delegation PoP from parent cnf holder whenever delegating across distinct agent keys
		if !strings.EqualFold(parentTok.Cnf.KeyFingerprint, callerAgent.KeyFingerprint) {
			parentPub, pDecErr := crypto.DecodeBase64Any(parentTok.Cnf.PublicKeyB64)
			popSig, sDecErr := crypto.DecodeBase64Any(strings.TrimSpace(req.ParentHolderPoPSigB64))
			preimage := ParentDelegationPoPPreimage(parentTok.TaskTokenID, callerAgent.AgentID, req.EnvelopeID)
			if pDecErr != nil || len(parentPub) != ed25519.PublicKeySize || sDecErr != nil || len(popSig) != ed25519.SignatureSize ||
				!ed25519.Verify(ed25519.PublicKey(parentPub), preimage, popSig) {
				return nil, logViolation("PARENT_HOLDER_POP_VERIFICATION_FAILED", callerAgent.AgentID, callerAgent.CommissioningFunctionID, authMode, warrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, depth, parentAct)
			}
		}

		parentState := models.SponsorshipActive
		if parentTok.Act != nil && parentTok.Act.SponsorshipState != "" {
			parentState = parentTok.Act.SponsorshipState
		}
		if parentTok.Sub != "" {
			if liveParent, lErr := cp.store.GetAgentIdentityAt(ctx, parentTok.Sub, now); lErr == nil {
				parentState = liveParent.SponsorshipState
				if liveParent.Revoked || liveParent.SponsorCompromised ||
					parentState == models.SponsorshipOrphanQuarantined ||
					parentState == models.SponsorshipLeaseExpired {
					return nil, logViolation("PARENT_AGENT_QUARANTINED_OR_REVOKED:"+parentState, callerAgent.AgentID, callerAgent.CommissioningFunctionID, authMode, warrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, depth, parentAct)
				}
			}
		}

		parentInput = policy.AgentParentTaskInput{
			Present:            true,
			TargetAsset:        parentTok.TargetAsset,
			AllowedAction:      parentTok.AllowedAction,
			EgressProfile:      nonEmpty(parentTok.EgressProfile, models.EgressProfileZeroIsolated),
			ExpiresUnix:        parentTok.ExpiresUnix,
			MaxDelegationDepth: parentTok.MaxDelegationDepth,
			SponsorshipState:   parentState,
		}
	}

	// Build Standing Warrant input for WARRANT_DELEGATED_COMPOSITE mode
	warrantInput := policy.AgentWarrantScopeInput{}
	if authMode == models.AuthorityModeWarrantComposite && warrantID != "" {
		if w, wErr := cp.store.GetWarrant(ctx, warrantID); wErr == nil && w != nil {
			wActive := w.LiveStatus == "ACTIVE" && now.Before(w.ExpiresAt)
			warrantInput = policy.AgentWarrantScopeInput{
				Present:       true,
				Active:        wActive,
				ScopeServices: w.ScopeServices,
				ExpiresUnix:   w.ExpiresAt.Unix(),
			}
			s1ID = w.Slot1PrincipalID
			s2ID = w.Slot2PrincipalID
		}
	}

	var graceExpUnix int64
	if callerAgent.GraceExpiresAt != nil {
		graceExpUnix = callerAgent.GraceExpiresAt.Unix()
	}

	nestedAct := &models.ActorClaim{
		AgentID:                 callerAgent.AgentID,
		KeyID:                   callerAgent.KeyID,
		KeyFingerprint:          callerAgent.KeyFingerprint,
		CommissioningFunctionID: callerAgent.CommissioningFunctionID,
		SponsorshipState:        callerAgent.SponsorshipState,
		ParentActor:             parentAct,
	}

	remCount, maxRem, winCount, maxWin := cp.budget.Snapshot(callerAgent.AgentID, req.RemediationID, now)

	agentIn := policy.AgentInput{
		NowUnix:                    now.Unix(),
		AuthorityMode:              authMode,
		RequestedAction:            strings.TrimSpace(req.RequestedAction),
		TargetAsset:                strings.TrimSpace(req.TargetAsset),
		RequestedEgressProfile:     reqEgress,
		RequestedTTLSeconds:        req.RequestedTTLSeconds,
		DelegationDepth:            depth,
		RemediationExchangeCount:   remCount,
		MaxExchangesPerRemediation: maxRem,
		WindowExchangeCount:        winCount,
		MaxExchangesPerWindow:      maxWin,
		Agent: policy.AgentProfileInput{
			AgentID:                      callerAgent.AgentID,
			CommissioningFunctionID:      callerAgent.CommissioningFunctionID,
			Revoked:                      callerAgent.Revoked,
			SponsorshipState:             callerAgent.SponsorshipState,
			SponsorCompromised:           callerAgent.SponsorCompromised,
			GraceActive:                  callerAgent.GraceActive,
			GraceExpiresUnix:             graceExpUnix,
			RecertifyExpiresUnix:         callerAgent.RecertifyExpiresAt.Unix(),
			AllowedActions:               callerAgent.AllowedActions,
			AllowedServices:              callerAgent.AllowedServices,
			AllowedEgressProfile:         callerAgent.AllowedEgressProfile,
			MaxTTLSeconds:                callerAgent.MaxTTLSeconds,
			MaxDelegationDepth:           callerAgent.MaxDelegationDepth,
			AllowAutonomousIntake:        callerAgent.AllowAutonomousIntake,
			BuilderPrincipalID:           callerAgent.BuilderPrincipalID,
			BuilderKeyFingerprint:        callerAgent.BuilderKeyFingerprint,
			CommissionerSOPrincipalID:    callerAgent.CommissionerSOPrincipalID,
			CommissionerSOKeyFingerprint: callerAgent.CommissionerSOKeyFP,
			CommissionerAOPrincipalID:    callerAgent.CommissionerAOPrincipalID,
			CommissionerAOKeyFingerprint: callerAgent.CommissionerAOKeyFP,
		},
		StandingWarrant: warrantInput,
		ParentTask:      parentInput,
	}

	dec, err := cp.policy.EvalAgent(ctx, agentIn)
	if err != nil {
		return nil, err
	}
	if !dec.Allow {
		vCode := strings.Join(dec.Violations, ",")
		if vCode == "" {
			vCode = "OPA_AGENT_INTERSECTION_DENIED"
		}
		return nil, logViolation(vCode, callerAgent.AgentID, callerAgent.CommissioningFunctionID, authMode, warrantID, req.RemediationID, req.TargetAsset, req.RequestedAction, depth, nestedAct)
	}

	if authMode == models.AuthorityModeAutonomousSponsored && warrantID == "" {
		warrantID = "AUTONOMOUS_SPONSORED_INTAKE"
	}

	outPayload := models.EphemeralTaskWarrantPayload{
		TaskTokenID:             "tsk-" + uuid.NewString()[:8],
		WarrantID:               warrantID,
		RemediationID:           req.RemediationID,
		AuthorityMode:           authMode,
		CommissioningFunctionID: callerAgent.CommissioningFunctionID,
		Sub:                     callerAgent.AgentID,
		WorkerName:              callerAgent.AgentID,
		TargetAsset:             strings.TrimSpace(req.TargetAsset),
		AllowedAction:           strings.TrimSpace(req.RequestedAction),
		EgressProfile:           reqEgress,
		ForbiddenPathPrefixes:   models.DefaultForbiddenDiffPrefixes,
		Slot1PrincipalID:        s1ID,
		Slot2PrincipalID:        s2ID,
		Act:                     nestedAct,
		Cnf: &models.ConfirmationClaim{
			Alg:            callerAgent.Alg,
			KeyID:          callerAgent.KeyID,
			PublicKeyB64:   callerAgent.PublicKeyB64,
			KeyFingerprint: callerAgent.KeyFingerprint,
		},
		ParentTaskTokenID:  parentTokenID,
		DelegationDepth:    depth,
		MaxDelegationDepth: effectiveMaxDepth,
		TTLSeconds:         dec.EffectiveTTLSeconds,
		IssuedUnix:         now.Unix(),
		ExpiresUnix:        now.Add(time.Duration(dec.EffectiveTTLSeconds) * time.Second).Unix(),
	}

	mintedEnv, canonOut, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeTaskWarrant, outPayload)
	if err != nil {
		return nil, err
	}
	if err := cp.signer.SignEnvelope(ctx, 1, mintedEnv); err != nil {
		return nil, err
	}

	entry := &models.AgentLedgerEntry{
		ActionID:                "act-" + uuid.NewString()[:8],
		TaskTokenID:             outPayload.TaskTokenID,
		WarrantID:               outPayload.WarrantID,
		RemediationID:           outPayload.RemediationID,
		AuthorityMode:           outPayload.AuthorityMode,
		CommissioningFunctionID: outPayload.CommissioningFunctionID,
		AgentID:                 callerAgent.AgentID,
		DelegationDepth:         depth,
		ActChain:                nestedAct,
		WorkerName:              callerAgent.AgentID,
		TargetAsset:             outPayload.TargetAsset,
		ActionType:              outPayload.AllowedAction,
		Slot1PrincipalID:        s1ID,
		Slot2PrincipalID:        s2ID,
		EgressProfile:           reqEgress,
		RawInputSHA256:          crypto.SHA256Hex(canon),
		ExtractorDigest:         "N4_RFC8693_TOKEN_EXCHANGE",
		TypedOutputSHA256:       crypto.SHA256Hex(canonOut),
		TokenTTLSec:             dec.EffectiveTTLSeconds,
		Status:                  "EXECUTED",
		ExecutedAt:              now,
	}
	_ = cp.store.AppendAgentAction(ctx, entry)
	cp.budget.Record(callerAgent.AgentID, outPayload.RemediationID, now)
	if cp.onBroadcast != nil {
		cp.onBroadcast("AGENT_ACTION_LOGGED", entry)
	}

	return &models.AgentTokenExchangeResponse{
		TaskWarrantDSSE:     *mintedEnv,
		Payload:             outPayload,
		EffectiveTTLSeconds: dec.EffectiveTTLSeconds,
		SponsorshipState:    callerAgent.SponsorshipState,
	}, nil
}
