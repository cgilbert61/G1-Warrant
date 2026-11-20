package warrant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
	"github.com/google/uuid"
)

// Engine implements N1: Standing Warrant Engine, Live Principal/Key Revocation,
// Asymmetric Dual-Mode Emergency Freeze, and Approval Pressure Analytics.
type Engine struct {
	store       *db.Store
	policy      *policy.Engine
	webauthnCfg crypto.WebAuthnConfig
	freezeCache atomic.Value // stores models.FreezeState
	onBroadcast func(eventType string, payload any)
}

// NewEngine constructs the N1 Standing Warrant Engine and loads initial freeze state into memory.
func NewEngine(ctx context.Context, store *db.Store, pol *policy.Engine, webauthnCfg crypto.WebAuthnConfig, onBroadcast func(string, any)) (*Engine, error) {
	e := &Engine{
		store:       store,
		policy:      pol,
		webauthnCfg: webauthnCfg,
		onBroadcast: onBroadcast,
	}
	fs, err := store.GetFreezeState(ctx)
	if err != nil {
		fs = models.FreezeState{
			Mode:       models.FreezeModeOperational,
			Actor:      "sys-warrantd-kernel",
			ReasonCode: "BOOT_DEFAULT",
			UpdatedAt:  time.Now().UTC(),
		}
	}
	e.freezeCache.Store(fs)
	return e, nil
}

// StartFreezeListener subscribes to PostgreSQL LISTEN warrant_freeze_channel for sub-second sync.
func (e *Engine) StartFreezeListener(ctx context.Context) {
	go func() {
		for {
			if ctx.Err() != nil {
				return
			}
			_ = e.store.ListenFreezeNotifications(ctx, func(fs models.FreezeState) {
				e.freezeCache.Store(fs)
				e.emit("FREEZE_STATE_CHANGED", fs)
			})
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()
}

// CurrentFreezeState returns the sub-millisecond in-memory emergency freeze state.
func (e *Engine) CurrentFreezeState() models.FreezeState {
	if v := e.freezeCache.Load(); v != nil {
		return v.(models.FreezeState)
	}
	return models.FreezeState{Mode: models.FreezeModeOperational}
}

// SubmitDualSignedWarrant verifies a 2-of-2 DSSE Warrant Envelope against NIST AC-5,
// live principal revocations, and OPA Rego policy before appending to warrant_envelopes.
func (e *Engine) SubmitDualSignedWarrant(ctx context.Context, env crypto.Envelope) (*models.WarrantRecord, error) {
	resolver := db.StoreKeyResolver{Store: e.store, Ctx: ctx}
	dualRes, err := crypto.VerifyDualHumanCeremony(&env, crypto.PayloadTypeWarrant, resolver, e.webauthnCfg)
	if err != nil {
		return nil, err
	}

	var wp models.WarrantPayload
	if err := json.Unmarshal(dualRes.CanonicalPayload, &wp); err != nil {
		return nil, fmt.Errorf("parse warrant payload: %w", err)
	}
	if wp.WarrantID == "" {
		wp.WarrantID = "wrt-" + uuid.NewString()[:8]
	}
	issuedAt, err := time.Parse(time.RFC3339, wp.IssuedAt)
	if err != nil {
		issuedAt = time.Now().UTC()
	}
	expiresAt, err := time.Parse(time.RFC3339, wp.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid warrant expires_at RFC3339: %w", err)
	}

	ac5Dec, err := e.policy.EvalAC5(ctx, policy.AC5Input{
		Slot1: policy.SignerInput{
			PrincipalID:    dualRes.Slot1.PrincipalID,
			Email:          dualRes.Slot1.Email,
			KeyFingerprint: dualRes.Slot1.KeyFingerprint,
			Role:           dualRes.Slot1.Role,
			Revoked:        dualRes.Slot1.Revoked,
		},
		Slot2: policy.SignerInput{
			PrincipalID:    dualRes.Slot2.PrincipalID,
			Email:          dualRes.Slot2.Email,
			KeyFingerprint: dualRes.Slot2.KeyFingerprint,
			Role:           dualRes.Slot2.Role,
			Revoked:        dualRes.Slot2.Revoked,
		},
		NowUnix:                time.Now().UTC().Unix(),
		ExpiresUnix:            expiresAt.Unix(),
		WarrantClass:           wp.WarrantClass,
		AllowSecretRotation:    wp.AllowSecretRotation || wp.WarrantClass == models.WarrantClassSecretRotation,
		ScopeServices:          wp.ScopeServices,
		MaxCVSS:                wp.MaxCVSS,
		AutoRemediateCWEs:      wp.AutoRemediateCWEs,
		MaxBlastRadiusReplicas: wp.MaxBlastRadiusReplicas,
	})
	if err != nil {
		return nil, err
	}
	if !ac5Dec.Allow {
		return nil, fmt.Errorf("OPA_AC5_DENIED: %s", strings.Join(ac5Dec.Violations, ","))
	}

	if wp.SLABridgeMinutes <= 0 {
		wp.SLABridgeMinutes = 60
	}
	if wp.MaxP99LatencyMs <= 0 {
		wp.MaxP99LatencyMs = 120.0
	}
	if wp.MinCanarySamples <= 0 {
		wp.MinCanarySamples = 500
	}
	if wp.StageDwellSeconds <= 0 {
		wp.StageDwellSeconds = 300
	}

	rec := &models.WarrantRecord{
		WarrantID:              wp.WarrantID,
		WarrantClass:           wp.WarrantClass,
		ScopeServices:          wp.ScopeServices,
		MaxCVSS:                wp.MaxCVSS,
		KEVEligible:            wp.KEVEligible,
		MaxBlastRadiusReplicas: wp.MaxBlastRadiusReplicas,
		AllowStatefulPatches:   wp.AllowStatefulPatches,
		AllowGuardedCanary:     wp.AllowGuardedCanary,
		AllowSecretRotation:    wp.AllowSecretRotation || wp.WarrantClass == models.WarrantClassSecretRotation,
		AutoRemediateCWEs:      wp.AutoRemediateCWEs,
		MinCanarySamples:       wp.MinCanarySamples,
		StageDwellSeconds:      wp.StageDwellSeconds,
		SLABridgeMinutes:       wp.SLABridgeMinutes,
		MaxP99LatencyMs:        wp.MaxP99LatencyMs,
		IssuedAt:               issuedAt,
		ExpiresAt:              expiresAt,
		DSSEEnvelope:           env,
		Slot1PrincipalID:       dualRes.Slot1.PrincipalID,
		Slot1Email:             dualRes.Slot1.Email,
		Slot1KeyFP:             dualRes.Slot1.KeyFingerprint,
		Slot1Role:              dualRes.Slot1.Role,
		Slot2PrincipalID:       dualRes.Slot2.PrincipalID,
		Slot2Email:             dualRes.Slot2.Email,
		Slot2KeyFP:             dualRes.Slot2.KeyFingerprint,
		Slot2Role:              dualRes.Slot2.Role,
		LiveStatus:             "ACTIVE",
		CreatedAt:              time.Now().UTC(),
	}
	if err := e.store.AppendWarrantEnvelope(ctx, rec); err != nil {
		return nil, err
	}
	// Automatically seal genesis bootstrap upon the first valid 2-of-2 Standing Warrant submission
	_, _ = e.store.SealBootstrap(ctx, dualRes.Slot1.PrincipalID+"+"+dualRes.Slot2.PrincipalID, "AUTO_SEALED_ON_FIRST_STANDING_WARRANT")
	e.emit("WARRANT_MINTED", rec)
	return rec, nil
}

// MaxGovernanceTTL bounds Principal Governance and Emergency DSSE envelopes to prevent replay/pre-signing hoarding.
const MaxGovernanceTTL = 15 * time.Minute

func validateGovernanceTiming(gp models.PrincipalGovernancePayload, expectedAction string) (time.Time, error) {
	if strings.TrimSpace(gp.EnvelopeID) == "" {
		return time.Time{}, errors.New("GOVERNANCE_MISSING_ENVELOPE_ID: single-use envelope_id is required")
	}
	if gp.Action != expectedAction {
		return time.Time{}, fmt.Errorf("GOVERNANCE_ACTION_MISMATCH: got %q want %q", gp.Action, expectedAction)
	}
	now := time.Now().UTC()
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(gp.ExpiresAt))
	if err != nil {
		return time.Time{}, fmt.Errorf("GOVERNANCE_INVALID_EXPIRES_AT: valid RFC3339 expires_at is required: %w", err)
	}
	if !now.Before(exp) {
		return time.Time{}, fmt.Errorf("GOVERNANCE_ENVELOPE_EXPIRED: envelope expired at %s", exp.Format(time.RFC3339))
	}
	if exp.Sub(now) > MaxGovernanceTTL {
		return time.Time{}, fmt.Errorf("GOVERNANCE_ENVELOPE_TTL_EXCEEDED: expires_at exceeds maximum 15m TTL ceiling")
	}
	if strings.TrimSpace(gp.IssuedAt) != "" {
		iss, iErr := time.Parse(time.RFC3339, strings.TrimSpace(gp.IssuedAt))
		if iErr != nil {
			return time.Time{}, fmt.Errorf("GOVERNANCE_INVALID_ISSUED_AT: %w", iErr)
		}
		if exp.Sub(iss) > MaxGovernanceTTL || iss.After(now.Add(2*time.Minute)) {
			return time.Time{}, errors.New("GOVERNANCE_ENVELOPE_TTL_EXCEEDED: envelope lifetime must be <= 15m")
		}
	}
	return exp, nil
}

// VerifyDualGovernanceEnvelope verifies a 2-of-2 DSSE Principal Governance envelope (e.g. ENROLL_PRINCIPAL)
// signed by active SERVICE_OWNER + AUTHORIZING_OFFICIAL principals, enforces <=15m TTL, and consumes single-use envelope_id.
func (e *Engine) VerifyDualGovernanceEnvelope(ctx context.Context, env crypto.Envelope, expectedAction string) (*models.PrincipalGovernancePayload, *crypto.DualHumanVerificationResult, error) {
	resolver := db.StoreKeyResolver{Store: e.store, Ctx: ctx}
	dualRes, err := crypto.VerifyDualHumanCeremony(&env, crypto.PayloadTypePrincipalGovernance, resolver, e.webauthnCfg)
	if err != nil {
		return nil, nil, err
	}
	var gp models.PrincipalGovernancePayload
	if err := json.Unmarshal(dualRes.CanonicalPayload, &gp); err != nil {
		return nil, nil, fmt.Errorf("parse governance payload: %w", err)
	}
	exp, err := validateGovernanceTiming(gp, expectedAction)
	if err != nil {
		return nil, nil, err
	}
	signerSummary := dualRes.Slot1.PrincipalID + "+" + dualRes.Slot2.PrincipalID
	if err := e.store.ConsumeGovernanceEnvelopeNonce(ctx, gp.EnvelopeID, expectedAction, dualRes.PayloadSHA256, signerSummary, exp); err != nil {
		return nil, nil, err
	}
	return &gp, dualRes, nil
}

// VerifySingleGovernanceEnvelope verifies a 1-of-2 DSSE Principal Governance envelope (e.g. REVOKE_PRINCIPAL, EMERGENCY_FREEZE)
// signed by ANY single active SERVICE_OWNER or AUTHORIZING_OFFICIAL principal, enforces <=15m TTL, and consumes single-use envelope_id.
func (e *Engine) VerifySingleGovernanceEnvelope(ctx context.Context, env crypto.Envelope, expectedAction string) (*models.PrincipalGovernancePayload, *crypto.SinglePrincipalVerificationResult, error) {
	resolver := db.StoreKeyResolver{Store: e.store, Ctx: ctx}
	singleRes, err := crypto.VerifySingleActivePrincipalCeremony(&env, crypto.PayloadTypePrincipalGovernance, resolver, e.webauthnCfg)
	if err != nil {
		return nil, nil, err
	}
	var gp models.PrincipalGovernancePayload
	if err := json.Unmarshal(singleRes.CanonicalPayload, &gp); err != nil {
		return nil, nil, fmt.Errorf("parse governance payload: %w", err)
	}
	exp, err := validateGovernanceTiming(gp, expectedAction)
	if err != nil {
		return nil, nil, err
	}
	if err := e.store.ConsumeGovernanceEnvelopeNonce(ctx, gp.EnvelopeID, expectedAction, singleRes.PayloadSHA256, singleRes.Signer.PrincipalID, exp); err != nil {
		return nil, nil, err
	}
	return &gp, singleRes, nil
}

// ReverifyWarrantForExecution cryptographically re-verifies both Standing Warrant signatures
// against live principal_revocations and OPA AC-5 rules at N2/N4/N5 execution time.
// Optional actionAndCWE args: [0]=actionKind ("IMAGE_PATCH"|"SECRET_ROTATION"), [1]=findingCWE.
func (e *Engine) ReverifyWarrantForExecution(ctx context.Context, warrantID, targetServiceID string, findingCVSS float64, targetReplicas int, actionAndCWE ...string) (*models.WarrantRecord, error) {
	w, err := e.store.GetWarrant(ctx, warrantID)
	if err != nil {
		return nil, fmt.Errorf("N1_WARRANT_NOT_FOUND: %w", err)
	}
	resolver := db.StoreKeyResolver{Store: e.store, Ctx: ctx}
	dualRes, err := crypto.VerifyDualHumanCeremony(&w.DSSEEnvelope, crypto.PayloadTypeWarrant, resolver, e.webauthnCfg)
	if err != nil {
		return nil, fmt.Errorf("N1_WARRANT_REVERIFY_FAILED: %w", err)
	}

	actionKind := models.RemediationKindImagePatch
	if len(actionAndCWE) > 0 && actionAndCWE[0] != "" {
		actionKind = actionAndCWE[0]
	}
	findingCWE := ""
	if len(actionAndCWE) > 1 {
		findingCWE = actionAndCWE[1]
	}

	ac5Dec, err := e.policy.EvalAC5(ctx, policy.AC5Input{
		Slot1: policy.SignerInput{
			PrincipalID:    dualRes.Slot1.PrincipalID,
			Email:          dualRes.Slot1.Email,
			KeyFingerprint: dualRes.Slot1.KeyFingerprint,
			Role:           dualRes.Slot1.Role,
			Revoked:        dualRes.Slot1.Revoked,
		},
		Slot2: policy.SignerInput{
			PrincipalID:    dualRes.Slot2.PrincipalID,
			Email:          dualRes.Slot2.Email,
			KeyFingerprint: dualRes.Slot2.KeyFingerprint,
			Role:           dualRes.Slot2.Role,
			Revoked:        dualRes.Slot2.Revoked,
		},
		NowUnix:                time.Now().UTC().Unix(),
		ExpiresUnix:            w.ExpiresAt.Unix(),
		WarrantClass:           w.WarrantClass,
		AllowSecretRotation:    w.AllowSecretRotation,
		ActionKind:             actionKind,
		ScopeServices:          w.ScopeServices,
		TargetService:          targetServiceID,
		MaxCVSS:                w.MaxCVSS,
		FindingCVSS:            findingCVSS,
		FindingCWE:             findingCWE,
		AutoRemediateCWEs:      w.AutoRemediateCWEs,
		MaxBlastRadiusReplicas: w.MaxBlastRadiusReplicas,
		TargetReplicas:         targetReplicas,
	})
	if err != nil {
		return nil, err
	}
	if !ac5Dec.Allow {
		return nil, fmt.Errorf("N1_WARRANT_POLICY_DENIED: %s", strings.Join(ac5Dec.Violations, ","))
	}
	return w, nil
}

// RevokeSigner immediately revokes a principal or hardware key in principal_revocations.
func (e *Engine) RevokeSigner(ctx context.Context, principalID, keyFP, reasonCode, revokedBy string) (*models.PrincipalRevocation, error) {
	rev := models.PrincipalRevocation{
		RevocationID:   "rev-" + uuid.NewString()[:8],
		PrincipalID:    principalID,
		KeyFingerprint: keyFP,
		ReasonCode:     reasonCode,
		RevokedBy:      revokedBy,
		RevokedAt:      time.Now().UTC(),
	}
	if err := e.store.RevokePrincipal(ctx, rev); err != nil {
		return nil, err
	}
	e.emit("PRINCIPAL_REVOKED", rev)
	return &rev, nil
}

// TriggerEmergencyFreeze activates FREEZE_HOLD or FREEZE_ROLLBACK in sub-second time.
// Shield containment bridges and N3 drift re-arming are explicitly unaffected.
func (e *Engine) TriggerEmergencyFreeze(ctx context.Context, mode, actor, reasonCode string, onRollbackAll func(context.Context) error) (*models.FreezeState, error) {
	if mode != models.FreezeModeHold && mode != models.FreezeModeRollback {
		return nil, fmt.Errorf("invalid freeze mode %q (expected FREEZE_HOLD or FREEZE_ROLLBACK)", mode)
	}
	if actor == "" {
		return nil, errors.New("freeze actor required")
	}
	if reasonCode == "" {
		reasonCode = "OPERATOR_EMERGENCY_HALT"
	}
	fs := models.FreezeState{
		Mode:       mode,
		Actor:      actor,
		ReasonCode: reasonCode,
		UpdatedAt:  time.Now().UTC(),
	}
	// Update atomic memory cache immediately for sub-millisecond N2 halt
	e.freezeCache.Store(fs)
	if err := e.store.SetFreezeState(ctx, fs); err != nil {
		return nil, err
	}
	if mode == models.FreezeModeRollback && onRollbackAll != nil {
		if err := onRollbackAll(ctx); err != nil {
			return &fs, fmt.Errorf("freeze activated; canary rollback callback reported: %w", err)
		}
	}
	e.emit("FREEZE_STATE_CHANGED", fs)
	return &fs, nil
}

// ThawEmergencyFreeze requires a live 2-of-2 dual-key signature ceremony (AC-5 enforced) to restore OPERATIONAL state.
func (e *Engine) ThawEmergencyFreeze(ctx context.Context, thawEnv crypto.Envelope) (*models.FreezeState, error) {
	resolver := db.StoreKeyResolver{Store: e.store, Ctx: ctx}
	dualRes, err := crypto.VerifyDualHumanCeremony(&thawEnv, crypto.PayloadTypeThaw, resolver, e.webauthnCfg)
	if err != nil {
		return nil, fmt.Errorf("THAW_DUAL_KEY_FAILED: %w", err)
	}
	ac5Dec, err := e.policy.EvalAC5(ctx, policy.AC5Input{
		Slot1: policy.SignerInput{
			PrincipalID:    dualRes.Slot1.PrincipalID,
			Email:          dualRes.Slot1.Email,
			KeyFingerprint: dualRes.Slot1.KeyFingerprint,
			Role:           dualRes.Slot1.Role,
			Revoked:        dualRes.Slot1.Revoked,
		},
		Slot2: policy.SignerInput{
			PrincipalID:    dualRes.Slot2.PrincipalID,
			Email:          dualRes.Slot2.Email,
			KeyFingerprint: dualRes.Slot2.KeyFingerprint,
			Role:           dualRes.Slot2.Role,
			Revoked:        dualRes.Slot2.Revoked,
		},
		NowUnix:     time.Now().UTC().Unix(),
		ExpiresUnix: time.Now().UTC().Add(1 * time.Hour).Unix(),
	})
	if err != nil || !ac5Dec.Allow {
		return nil, fmt.Errorf("THAW_AC5_DENIED: %v", ac5Dec)
	}

	fs := models.FreezeState{
		Mode:       models.FreezeModeOperational,
		Actor:      fmt.Sprintf("%s+%s", dualRes.Slot1.PrincipalID, dualRes.Slot2.PrincipalID),
		ReasonCode: "DUAL_KEY_THAW_CEREMONY_VERIFIED",
		UpdatedAt:  time.Now().UTC(),
		ThawDSSE:   &thawEnv,
	}
	e.freezeCache.Store(fs)
	if err := e.store.SetFreezeState(ctx, fs); err != nil {
		return nil, err
	}
	e.emit("FREEZE_STATE_CHANGED", fs)
	return &fs, nil
}

// ResolveCeilingException verifies a 2-of-2 dual-key signature ceremony to approve or reject a Four-Eyes exception.
func (e *Engine) ResolveCeilingException(ctx context.Context, exceptionID, decision string, env crypto.Envelope) (*models.CeilingException, error) {
	if decision != "APPROVED" && decision != "REJECTED" {
		return nil, errors.New("decision must be APPROVED or REJECTED")
	}
	resolver := db.StoreKeyResolver{Store: e.store, Ctx: ctx}
	if _, err := crypto.VerifyDualHumanCeremony(&env, crypto.PayloadTypeException, resolver, e.webauthnCfg); err != nil {
		return nil, fmt.Errorf("EXCEPTION_CEREMONY_FAILED: %w", err)
	}
	list, err := e.store.ListExceptions(ctx)
	if err != nil {
		return nil, err
	}
	for _, ex := range list {
		if ex.ExceptionID == exceptionID {
			now := time.Now().UTC()
			ex.Status = decision
			ex.ResolutionDSSE = &env
			ex.ResolvedAt = &now
			if err := e.store.UpsertException(ctx, ex); err != nil {
				return nil, err
			}
			e.emit("EXCEPTION_RESOLVED", ex)
			return &ex, nil
		}
	}
	return nil, fmt.Errorf("exception %q not found", exceptionID)
}

func (e *Engine) emit(eventType string, payload any) {
	if e.onBroadcast != nil {
		e.onBroadcast(eventType, payload)
	}
}
