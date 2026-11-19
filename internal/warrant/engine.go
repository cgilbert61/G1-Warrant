package warrant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/db"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
	"github.com/g1163rt-labs/g1-warrant/internal/policy"
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
		ScopeServices:          wp.ScopeServices,
		MaxCVSS:                wp.MaxCVSS,
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

	rec := &models.WarrantRecord{
		WarrantID:              wp.WarrantID,
		WarrantClass:           wp.WarrantClass,
		ScopeServices:          wp.ScopeServices,
		MaxCVSS:                wp.MaxCVSS,
		KEVEligible:            wp.KEVEligible,
		MaxBlastRadiusReplicas: wp.MaxBlastRadiusReplicas,
		AllowStatefulPatches:   wp.AllowStatefulPatches,
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
	e.emit("WARRANT_MINTED", rec)
	return rec, nil
}

// ReverifyWarrantForExecution cryptographically re-verifies both Standing Warrant signatures
// against live principal_revocations and OPA AC-5 rules at N2/N5 execution time.
func (e *Engine) ReverifyWarrantForExecution(ctx context.Context, warrantID, targetServiceID string, findingCVSS float64, targetReplicas int) (*models.WarrantRecord, error) {
	w, err := e.store.GetWarrant(ctx, warrantID)
	if err != nil {
		return nil, fmt.Errorf("N1_WARRANT_NOT_FOUND: %w", err)
	}
	resolver := db.StoreKeyResolver{Store: e.store, Ctx: ctx}
	dualRes, err := crypto.VerifyDualHumanCeremony(&w.DSSEEnvelope, crypto.PayloadTypeWarrant, resolver, e.webauthnCfg)
	if err != nil {
		return nil, fmt.Errorf("N1_WARRANT_REVERIFY_FAILED: %w", err)
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
		ScopeServices:          w.ScopeServices,
		TargetService:          targetServiceID,
		MaxCVSS:                w.MaxCVSS,
		FindingCVSS:            findingCVSS,
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
