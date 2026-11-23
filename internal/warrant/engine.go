package warrant

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
	store           *db.Store
	policy          *policy.Engine
	webauthnCfg     crypto.WebAuthnConfig
	kernelSigner    crypto.EnvelopeSigner
	publisherPubKey ed25519.PublicKey
	freezeCache     atomic.Value // stores models.FreezeState
	onBroadcast     func(eventType string, payload any)
}

// SetPublisherPublicKey configures the authoritative Artifact Publisher / Build Attestor Ed25519 public key
// used to verify AgentIdentity builder provenance signatures when an explicit builder key is not supplied.
func (e *Engine) SetPublisherPublicKey(pub ed25519.PublicKey) {
	if len(pub) == ed25519.PublicKeySize {
		cp := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(cp, pub)
		e.publisherPubKey = cp
	}
}

// NewEngine constructs the N1 Standing Warrant Engine and loads initial freeze state into memory.
func NewEngine(ctx context.Context, store *db.Store, pol *policy.Engine, webauthnCfg crypto.WebAuthnConfig, onBroadcast func(string, any), kernelSigner ...crypto.EnvelopeSigner) (*Engine, error) {
	var ks crypto.EnvelopeSigner
	if len(kernelSigner) > 0 {
		ks = kernelSigner[0]
	}
	e := &Engine{
		store:        store,
		policy:       pol,
		webauthnCfg:  webauthnCfg,
		kernelSigner: ks,
		onBroadcast:  onBroadcast,
	}
	fs, err := store.GetFreezeState(ctx)
	if err != nil {
		fs = models.FreezeState{
			Mode:        models.FreezeModeOperational,
			Actor:       "sys-warrantd-kernel",
			ReasonCode:  "BOOT_DEFAULT",
			FreezeEpoch: 1,
			UpdatedAt:   time.Now().UTC(),
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
		WarrantID:                  wp.WarrantID,
		WarrantClass:               wp.WarrantClass,
		ScopeServices:              wp.ScopeServices,
		ScopeAssets:                wp.ScopeAssets,
		AuthorizedVendorDetections: wp.AuthorizedVendorDetections,
		MaxCVSS:                    wp.MaxCVSS,
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
		CloneTwinCount:         max(wp.CloneTwinCount, models.DefaultCloneTwinCount),
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
	// Automatically seal genesis bootstrap (enforcing >=2 SO + >=2 AO in kubernetes/live modes, >=1 SO + >=1 AO in simulator,
	// signing the Genesis Seal Manifest, and anchoring Checkpoint #0) upon the first valid 2-of-2 Standing Warrant submission.
	if _, err := e.store.SealBootstrap(ctx, dualRes.Slot1.PrincipalID+"+"+dualRes.Slot2.PrincipalID, "AUTO_SEALED_ON_FIRST_STANDING_WARRANT", e.kernelSigner); err != nil {
		return nil, err
	}
	if err := e.store.AppendWarrantEnvelope(ctx, rec); err != nil {
		return nil, err
	}
	e.emit("WARRANT_MINTED", rec)
	return rec, nil
}

// MaxDualGovernanceTTL bounds 2-of-2 Principal Governance ceremonies (15m);
// MaxSingleGovernanceTTL strictly bounds 1-of-2 single-principal actions (5m) to block pre-signing hoarding.
const (
	MaxDualGovernanceTTL   = 15 * time.Minute
	MaxSingleGovernanceTTL = 5 * time.Minute
	MaxGovernanceTTL       = MaxDualGovernanceTTL
)

func validateGovernanceTimingWithMax(gp models.PrincipalGovernancePayload, expectedAction string, maxTTL time.Duration) (time.Time, error) {
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
	if exp.Sub(now) > maxTTL {
		return time.Time{}, fmt.Errorf("GOVERNANCE_ENVELOPE_TTL_EXCEEDED: expires_at exceeds maximum %s TTL ceiling", maxTTL)
	}
	if strings.TrimSpace(gp.IssuedAt) != "" {
		iss, iErr := time.Parse(time.RFC3339, strings.TrimSpace(gp.IssuedAt))
		if iErr != nil {
			return time.Time{}, fmt.Errorf("GOVERNANCE_INVALID_ISSUED_AT: %w", iErr)
		}
		if exp.Sub(iss) > maxTTL || iss.After(now.Add(2*time.Minute)) {
			return time.Time{}, fmt.Errorf("GOVERNANCE_ENVELOPE_TTL_EXCEEDED: envelope lifetime must be <= %s", maxTTL)
		}
	}
	return exp, nil
}

// VerifyDualGovernanceEnvelope verifies a 2-of-2 DSSE Principal Governance envelope (e.g. ENROLL_PRINCIPAL, ROTATE_AND_REVOKE_PRINCIPAL)
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
	exp, err := validateGovernanceTimingWithMax(gp, expectedAction, MaxDualGovernanceTTL)
	if err != nil {
		return nil, nil, err
	}
	signerSummary := dualRes.Slot1.PrincipalID + "+" + dualRes.Slot2.PrincipalID
	if err := e.store.ConsumeGovernanceEnvelopeNonce(ctx, gp.EnvelopeID, expectedAction, dualRes.PayloadSHA256, signerSummary, exp); err != nil {
		return nil, nil, err
	}
	return &gp, dualRes, nil
}

// VerifySingleGovernanceEnvelope verifies a 1-of-2 DSSE Principal Governance envelope (e.g. REVOKE_PRINCIPAL, SEAL_BOOTSTRAP)
// signed by ANY single active SERVICE_OWNER or AUTHORIZING_OFFICIAL principal, enforces <=5m TTL, and consumes single-use envelope_id.
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
	exp, err := validateGovernanceTimingWithMax(gp, expectedAction, MaxSingleGovernanceTTL)
	if err != nil {
		return nil, nil, err
	}
	if err := e.store.ConsumeGovernanceEnvelopeNonce(ctx, gp.EnvelopeID, expectedAction, singleRes.PayloadSHA256, singleRes.Signer.PrincipalID, exp); err != nil {
		return nil, nil, err
	}
	return &gp, singleRes, nil
}

// VerifyRequestScopedSingleGovernanceEnvelope verifies a 1-of-2 DSSE Principal Governance envelope bound to
// canonical http_method, canonical_path, request_body_sha256 (when header-detached), <=5m expires_at, and single-use envelope_id.
// Returns DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION on any signature, scope, TTL, or replay violation.
func (e *Engine) VerifyRequestScopedSingleGovernanceEnvelope(
	ctx context.Context,
	env crypto.Envelope,
	expectedAction string,
	expectedMethod string,
	expectedPath string,
	expectedBodySHA256 string,
	requireBodySHA256 bool,
) (*models.PrincipalGovernancePayload, *crypto.SinglePrincipalVerificationResult, error) {
	resolver := db.StoreKeyResolver{Store: e.store, Ctx: ctx}
	singleRes, err := crypto.VerifySingleActivePrincipalCeremony(&env, crypto.PayloadTypePrincipalGovernance, resolver, e.webauthnCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: %w", err)
	}
	var gp models.PrincipalGovernancePayload
	if err := json.Unmarshal(singleRes.CanonicalPayload, &gp); err != nil {
		return nil, nil, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: parse governance payload: %w", err)
	}
	exp, err := validateGovernanceTimingWithMax(gp, expectedAction, MaxSingleGovernanceTTL)
	if err != nil {
		return nil, nil, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: %w", err)
	}
	if strings.TrimSpace(gp.HTTPMethod) == "" || !strings.EqualFold(strings.TrimSpace(gp.HTTPMethod), expectedMethod) {
		return nil, nil, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: signed http_method %q != request %q", gp.HTTPMethod, expectedMethod)
	}
	if strings.TrimSpace(gp.CanonicalPath) == "" || strings.TrimSpace(gp.CanonicalPath) != expectedPath {
		return nil, nil, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: signed canonical_path %q != request %q", gp.CanonicalPath, expectedPath)
	}
	if requireBodySHA256 {
		if strings.TrimSpace(gp.RequestBodySHA256) == "" || !strings.EqualFold(strings.TrimSpace(gp.RequestBodySHA256), expectedBodySHA256) {
			return nil, nil, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: signed request_body_sha256 %q != actual %q", gp.RequestBodySHA256, expectedBodySHA256)
		}
	} else if strings.TrimSpace(gp.RequestBodySHA256) != "" &&
		!strings.EqualFold(strings.TrimSpace(gp.RequestBodySHA256), expectedBodySHA256) &&
		!strings.EqualFold(strings.TrimSpace(gp.RequestBodySHA256), crypto.SHA256Hex(nil)) {
		return nil, nil, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: signed request_body_sha256 %q mismatch", gp.RequestBodySHA256)
	}

	if err := e.store.ConsumeGovernanceEnvelopeNonce(ctx, gp.EnvelopeID, expectedAction, singleRes.PayloadSHA256, singleRes.Signer.PrincipalID, exp); err != nil {
		return nil, nil, fmt.Errorf("DSSE_REQUEST_SCOPE_OR_NONCE_VIOLATION: %w", err)
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

// RevokeSigner immediately revokes a principal or hardware key prior to bootstrap sealing (or when pre-verified).
func (e *Engine) RevokeSigner(ctx context.Context, principalID, keyFP, reasonCode, revokedBy string) (*models.PrincipalRevocation, error) {
	return e.RevokeSignerWithGovernance(ctx, principalID, keyFP, reasonCode, revokedBy, "", false, nil)
}

// RevokeSignerWithGovernance enforces Quorum Survivor Floor + same-role/self 1-of-2 rules and persists the authorizing DSSE envelope.
func (e *Engine) RevokeSignerWithGovernance(
	ctx context.Context,
	principalID string,
	keyFP string,
	reasonCode string,
	signerPrincipalID string,
	signerRole string,
	isDualSigned bool,
	govEnv *crypto.Envelope,
) (*models.PrincipalRevocation, error) {
	if strings.TrimSpace(reasonCode) == "" {
		reasonCode = "ROLE_DEPARTURE_OR_PIV_REVOCATION"
	}
	rev := models.PrincipalRevocation{
		RevocationID:   "rev-" + uuid.NewString()[:8],
		PrincipalID:    strings.TrimSpace(principalID),
		KeyFingerprint: strings.TrimSpace(keyFP),
		ReasonCode:     strings.TrimSpace(reasonCode),
		RevokedBy:      signerPrincipalID,
		RevokedAt:      time.Now().UTC(),
	}
	lineageMode := ""
	if govEnv != nil {
		if isDualSigned {
			lineageMode = models.LineageModePostSeal2Of2
		} else {
			lineageMode = models.LineageModePostSeal1Of2
		}
	}
	persisted, err := e.store.RevokePrincipalEnforced(ctx, rev, signerPrincipalID, signerRole, lineageMode, isDualSigned, govEnv)
	if err != nil {
		return nil, err
	}
	igaType := models.IGAEventRoleTransfer
	if strings.Contains(strings.ToUpper(persisted.ReasonCode), "COMPROMISE") {
		igaType = models.IGAEventKeyCompromise
	}
	_, _ = e.ProcessIGALifecycleEvent(ctx, models.IGAEventRequest{
		EventType:    igaType,
		PrincipalID:  persisted.PrincipalID,
		ReasonCode:   persisted.ReasonCode,
		SourceSystem: "N1_PRINCIPAL_REVOCATION",
	}, signerPrincipalID, persisted.LineageMode, govEnv)
	e.emit("PRINCIPAL_REVOKED", persisted)
	return persisted, nil
}

// RotateAndRevokePrincipal verifies an atomic 2-of-2 ROTATE_AND_REVOKE_PRINCIPAL DSSE envelope,
// enrolling the replacement principal and revoking the target principal in a single serialized transaction.
func (e *Engine) RotateAndRevokePrincipal(ctx context.Context, env crypto.Envelope) (*models.Principal, *models.PrincipalRevocation, error) {
	gp, dualRes, err := e.VerifyDualGovernanceEnvelope(ctx, env, models.GovActionRotateAndRevokePrincipal)
	if err != nil {
		return nil, nil, err
	}
	if gp.Role != crypto.RoleServiceOwner && gp.Role != crypto.RoleAuthorizingOfficial {
		return nil, nil, errors.New("AC5_INVALID_ENROLLMENT_ROLE: replacement role must be SERVICE_OWNER or AUTHORIZING_OFFICIAL")
	}
	if strings.TrimSpace(gp.Email) == "" {
		return nil, nil, errors.New("replacement email is required in ROTATE_AND_REVOKE_PRINCIPAL payload")
	}

	var newP models.Principal
	if gp.AttestationObject != "" || gp.PublicKeySPKI != "" {
		alg, spkiDER, fp, wErr := crypto.ParseWebAuthnRegistration(gp.AttestationObject, gp.PublicKeySPKI, gp.CredentialID, e.webauthnCfg)
		if wErr != nil {
			return nil, nil, wErr
		}
		short := uuid.NewString()[:8]
		pID := strings.TrimSpace(gp.PrincipalID)
		if pID == "" {
			pID = "usr-webauthn-" + short
		}
		keyID := strings.TrimSpace(gp.KeyID)
		if keyID == "" {
			keyID = "webauthn-" + short
		}
		newP = models.Principal{
			PrincipalID:       pID,
			Email:             strings.TrimSpace(gp.Email),
			DisplayName:       strings.TrimSpace(gp.DisplayName),
			Role:              gp.Role,
			KeyID:             keyID,
			Alg:               alg,
			PublicKeyB64:      base64.StdEncoding.EncodeToString(spkiDER),
			KeyFingerprint:    fp,
			AuthenticatorMode: "WEBAUTHN_HARDWARE",
			CredentialID:      gp.CredentialID,
			CreatedAt:         time.Now().UTC(),
		}
	} else {
		if strings.TrimSpace(gp.PrincipalID) == "" {
			return nil, nil, errors.New("replacement principal_id is required in ROTATE_AND_REVOKE_PRINCIPAL payload")
		}
		pubBytes, pErr := base64.StdEncoding.DecodeString(strings.TrimSpace(gp.PublicKeyB64))
		if pErr != nil || len(pubBytes) != ed25519.PublicKeySize {
			return nil, nil, errors.New("expected valid 32-byte base64 Ed25519 public_key_b64 for replacement principal")
		}
		fp := crypto.SHA256Hex(pubBytes)
		keyID := strings.TrimSpace(gp.KeyID)
		if keyID == "" {
			keyID = fmt.Sprintf("ed25519-%s-%s", strings.TrimSpace(gp.PrincipalID), fp[:10])
		}
		newP = models.Principal{
			PrincipalID:       strings.TrimSpace(gp.PrincipalID),
			Email:             strings.TrimSpace(gp.Email),
			DisplayName:       strings.TrimSpace(gp.DisplayName),
			Role:              gp.Role,
			KeyID:             keyID,
			Alg:               crypto.AlgEd25519,
			PublicKeyB64:      base64.StdEncoding.EncodeToString(pubBytes),
			KeyFingerprint:    fp,
			AuthenticatorMode: "ED25519_ENROLLED",
			CreatedAt:         time.Now().UTC(),
		}
	}

	targetID := strings.TrimSpace(gp.TargetPrincipalID)
	targetFP := strings.TrimSpace(gp.TargetKeyFingerprint)
	if targetID == "" && targetFP == "" {
		return nil, nil, errors.New("target_principal_id or target_key_fingerprint is required in ROTATE_AND_REVOKE_PRINCIPAL payload")
	}
	reasonCode := strings.TrimSpace(gp.ReasonCode)
	if reasonCode == "" {
		reasonCode = "ATOMIC_DUAL_KEY_ROTATION_AND_REVOCATION"
	}
	rev := models.PrincipalRevocation{
		RevocationID:   "rev-" + uuid.NewString()[:8],
		PrincipalID:    targetID,
		KeyFingerprint: targetFP,
		ReasonCode:     reasonCode,
		RevokedBy:      dualRes.Slot1.PrincipalID + "+" + dualRes.Slot2.PrincipalID,
		RevokedAt:      time.Now().UTC(),
	}

	enrolledP, persistedRev, err := e.store.RotateAndRevokePrincipalAtomic(ctx, &newP, rev, env)
	if err != nil {
		return nil, nil, err
	}
	e.emit("PRINCIPAL_REGISTERED", enrolledP)
	e.emit("PRINCIPAL_REVOKED", persistedRev)
	return enrolledP, persistedRev, nil
}

// TriggerEmergencyFreeze activates FREEZE_HOLD or FREEZE_ROLLBACK in sub-second time and increments freeze_epoch.
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
	if err := e.store.TransitionFreezeState(ctx, &fs); err != nil {
		return nil, err
	}
	// Update atomic memory cache immediately with new freeze_epoch for sub-millisecond N2 halt
	e.freezeCache.Store(fs)
	if mode == models.FreezeModeRollback && onRollbackAll != nil {
		if err := onRollbackAll(ctx); err != nil {
			return &fs, fmt.Errorf("freeze activated; canary rollback callback reported: %w", err)
		}
	}
	e.emit("FREEZE_STATE_CHANGED", fs)
	return &fs, nil
}

// ThawEmergencyFreeze requires a live 2-of-2 dual-key signature ceremony (AC-5 enforced) bound to the active
// monotonic freeze_epoch and a single-use envelope_id in governance_envelope_nonces to restore OPERATIONAL state.
func (e *Engine) ThawEmergencyFreeze(ctx context.Context, thawEnv crypto.Envelope) (*models.FreezeState, error) {
	curFS, err := e.store.GetFreezeState(ctx)
	if err != nil {
		return nil, fmt.Errorf("read active freeze state: %w", err)
	}
	if curFS.Mode != models.FreezeModeHold && curFS.Mode != models.FreezeModeRollback {
		return nil, fmt.Errorf("THAW_NOT_FROZEN: system is already %s (freeze_epoch=%d)", curFS.Mode, curFS.FreezeEpoch)
	}

	resolver := db.StoreKeyResolver{Store: e.store, Ctx: ctx}
	dualRes, err := crypto.VerifyDualHumanCeremony(&thawEnv, crypto.PayloadTypeThaw, resolver, e.webauthnCfg)
	if err != nil {
		return nil, fmt.Errorf("THAW_DUAL_KEY_FAILED: %w", err)
	}

	var tp models.ThawPayload
	if err := json.Unmarshal(dualRes.CanonicalPayload, &tp); err != nil {
		return nil, fmt.Errorf("THAW_INVALID_PAYLOAD: %w", err)
	}
	if tp.Action != "THAW" && tp.Action != "THAW_FLEET" {
		return nil, fmt.Errorf("THAW_ACTION_MISMATCH: expected action THAW, got %q", tp.Action)
	}
	if strings.TrimSpace(tp.EnvelopeID) == "" {
		return nil, errors.New("THAW_MISSING_ENVELOPE_ID: single-use envelope_id is required on THAW envelope")
	}
	if tp.FreezeEpoch != curFS.FreezeEpoch {
		return nil, fmt.Errorf("THAW_EPOCH_REPLAY_DETECTED: signed freeze_epoch=%d does not match active freeze_epoch=%d", tp.FreezeEpoch, curFS.FreezeEpoch)
	}
	now := time.Now().UTC()
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(tp.ExpiresAt))
	if err != nil {
		return nil, fmt.Errorf("THAW_INVALID_EXPIRES_AT: valid RFC3339 expires_at is required: %w", err)
	}
	if !now.Before(exp) || exp.Sub(now) > MaxDualGovernanceTTL {
		return nil, fmt.Errorf("THAW_TTL_VIOLATION: THAW envelope expired or exceeds 15m TTL ceiling")
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
		NowUnix:     now.Unix(),
		ExpiresUnix: exp.Unix(),
	})
	if err != nil || !ac5Dec.Allow {
		return nil, fmt.Errorf("THAW_AC5_DENIED: %v", ac5Dec)
	}

	signerSummary := dualRes.Slot1.PrincipalID + "+" + dualRes.Slot2.PrincipalID
	if err := e.store.ConsumeGovernanceEnvelopeNonce(ctx, tp.EnvelopeID, "THAW", dualRes.PayloadSHA256, signerSummary, exp); err != nil {
		return nil, fmt.Errorf("THAW_REPLAY_DETECTED: %w", err)
	}

	fs := models.FreezeState{
		Mode:        models.FreezeModeOperational,
		Actor:       signerSummary,
		ReasonCode:  "DUAL_KEY_THAW_CEREMONY_VERIFIED",
		FreezeEpoch: curFS.FreezeEpoch,
		UpdatedAt:   now,
		ThawDSSE:    &thawEnv,
	}
	if err := e.store.TransitionFreezeState(ctx, &fs); err != nil {
		return nil, err
	}
	e.freezeCache.Store(fs)
	e.emit("FREEZE_STATE_CHANGED", fs)
	return &fs, nil
}

// ResolveCeilingException verifies a 2-of-2 dual-key signature ceremony bound to exceptionID and a single-use envelope_id
// in governance_envelope_nonces to approve or reject a Four-Eyes exception.
func (e *Engine) ResolveCeilingException(ctx context.Context, exceptionID, decision string, env crypto.Envelope) (*models.CeilingException, error) {
	if decision != "APPROVED" && decision != "REJECTED" {
		return nil, errors.New("decision must be APPROVED or REJECTED")
	}
	resolver := db.StoreKeyResolver{Store: e.store, Ctx: ctx}
	dualRes, err := crypto.VerifyDualHumanCeremony(&env, crypto.PayloadTypeException, resolver, e.webauthnCfg)
	if err != nil {
		return nil, fmt.Errorf("EXCEPTION_CEREMONY_FAILED: %w", err)
	}
	var ep models.ExceptionResolutionPayload
	if err := json.Unmarshal(dualRes.CanonicalPayload, &ep); err != nil {
		return nil, fmt.Errorf("EXCEPTION_INVALID_PAYLOAD: %w", err)
	}
	if strings.TrimSpace(ep.ExceptionID) != exceptionID {
		return nil, fmt.Errorf("EXCEPTION_TARGET_MISMATCH: signed exception_id %q != URL %q", ep.ExceptionID, exceptionID)
	}
	if ep.Decision != "" && ep.Decision != decision {
		return nil, fmt.Errorf("EXCEPTION_DECISION_MISMATCH: signed decision %q != request %q", ep.Decision, decision)
	}
	if strings.TrimSpace(ep.EnvelopeID) == "" {
		return nil, errors.New("EXCEPTION_MISSING_ENVELOPE_ID: single-use envelope_id is required on exception resolution envelope")
	}
	now := time.Now().UTC()
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(ep.ExpiresAt))
	if err != nil {
		return nil, fmt.Errorf("EXCEPTION_INVALID_EXPIRES_AT: valid RFC3339 expires_at is required: %w", err)
	}
	if !now.Before(exp) || exp.Sub(now) > MaxDualGovernanceTTL {
		return nil, errors.New("EXCEPTION_TTL_VIOLATION: exception resolution envelope expired or exceeds 15m TTL ceiling")
	}

	list, err := e.store.ListExceptions(ctx)
	if err != nil {
		return nil, err
	}
	for _, ex := range list {
		if ex.ExceptionID == exceptionID {
			if ex.Status != "PENDING_DUAL_KEY" {
				return nil, fmt.Errorf("EXCEPTION_ALREADY_RESOLVED: exception %q is already %s", exceptionID, ex.Status)
			}
			signerSummary := dualRes.Slot1.PrincipalID + "+" + dualRes.Slot2.PrincipalID
			if err := e.store.ConsumeGovernanceEnvelopeNonce(ctx, ep.EnvelopeID, "EXCEPTION_RESOLUTION", dualRes.PayloadSHA256, signerSummary, exp); err != nil {
				return nil, err
			}
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
