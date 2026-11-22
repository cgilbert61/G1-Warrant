package warrant

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

const MaxAgentRecertifyDuration = 90 * 24 * time.Hour

// BootstrapSystemControlPlaneIdentities idempotently registers the kernel-signed internal CommissioningFunction
// (fn-g1-system-control-plane) and internal N4 worker AgentIdentities on startup.
func (e *Engine) BootstrapSystemControlPlaneIdentities(ctx context.Context, workers []models.AgentIdentity) error {
	if e.kernelSigner == nil {
		return nil
	}
	now := time.Now().UTC()

	// 1. Ensure fn-g1-system-control-plane exists
	if _, err := e.store.GetCommissioningFunction(ctx, models.SystemCommissioningFunctionID); err != nil {
		bootEnv, _, bErr := crypto.NewUnsignedEnvelope(crypto.PayloadTypeSystemAuthorityBoot, map[string]any{
			"entity_kind":     "COMMISSIONING_FUNCTION",
			"entity_id":       models.SystemCommissioningFunctionID,
			"key_fingerprint": "",
			"booted_at":       now.Format(time.RFC3339),
		})
		if bErr != nil {
			return bErr
		}
		if err := e.kernelSigner.SignEnvelope(ctx, 1, bootEnv); err != nil {
			return err
		}
		sysCF := &models.CommissioningFunction{
			FunctionID:             models.SystemCommissioningFunctionID,
			DisplayName:            "G1-Warrant Internal Control Plane Core",
			OwningOrgUnit:          "PLATFORM_SECURITY_KERNEL",
			CostCenter:             "CC-G1-CORE-000",
			PrimarySOPrincipalID:   "sys-kernel-so-anchor",
			SecondarySOPrincipalID: "sys-kernel-so-backup",
			PrimaryAOPrincipalID:   "sys-kernel-ao-anchor",
			SecondaryAOPrincipalID: "sys-kernel-ao-backup",
			EscalationContact:      "secops-kernel@g1163rt.internal",
			OrphanGraceHours:       168,
			LineageMode:            models.LineageModeKernelSystemBoot,
			GovernanceDSSE:         bootEnv,
			CreatedAt:              now,
		}
		if err := e.store.AppendCommissioningFunction(ctx, sysCF); err != nil {
			return err
		}
	}

	// 2. Ensure each internal N4 worker identity is registered
	for _, w := range workers {
		if _, err := e.store.GetAgentIdentity(ctx, w.AgentID); err == nil {
			continue
		}
		wCopy := w
		wCopy.AgentKind = models.AgentKindInternalWorker
		wCopy.CommissioningFunctionID = models.SystemCommissioningFunctionID
		wCopy.LineageMode = models.LineageModeKernelSystemBoot
		if wCopy.EnrolledAt.IsZero() {
			wCopy.EnrolledAt = now
		}
		if wCopy.RecertifyExpiresAt.IsZero() {
			wCopy.RecertifyExpiresAt = now.Add(89 * 24 * time.Hour)
		}
		bootEnv, _, bErr := crypto.NewUnsignedEnvelope(crypto.PayloadTypeSystemAuthorityBoot, map[string]any{
			"entity_kind":     "AGENT_IDENTITY",
			"entity_id":       wCopy.AgentID,
			"key_fingerprint": wCopy.KeyFingerprint,
			"booted_at":       now.Format(time.RFC3339),
		})
		if bErr != nil {
			return bErr
		}
		if err := e.kernelSigner.SignEnvelope(ctx, 1, bootEnv); err != nil {
			return err
		}
		wCopy.GovernanceDSSE = bootEnv
		if err := e.store.AppendAgentIdentity(ctx, &wCopy); err != nil {
			return err
		}
	}
	return nil
}

// UpsertCommissioningFunctionDualSigned verifies a 2-of-2 DSSE ceremony (UPSERT_COMMISSIONING_FUNCTION or TRANSFER_COMMISSIONING_SPONSOR)
// and appends an immutable versioned CommissioningFunction row.
func (e *Engine) UpsertCommissioningFunctionDualSigned(ctx context.Context, env crypto.Envelope, expectedAction string) (*models.CommissioningFunction, error) {
	if expectedAction == "" {
		expectedAction = models.GovActionUpsertCommissioningFunction
	}
	gp, dualRes, err := e.VerifyDualGovernanceEnvelope(ctx, env, expectedAction)
	if err != nil {
		return nil, err
	}
	cf, err := e.validateAndBuildCommissioningFunction(ctx, *gp, models.LineageModePostSeal2Of2, &env)
	if err != nil {
		return nil, err
	}
	if err := e.store.AppendCommissioningFunction(ctx, cf); err != nil {
		return nil, err
	}
	if expectedAction == models.GovActionTransferCommissioningSponsor {
		_ = e.store.AppendAgentLifecycleEvent(ctx, &models.AgentLifecycleEvent{
			EventType:           models.GovActionTransferCommissioningSponsor,
			TargetFunctionID:    cf.FunctionID,
			NewSponsorshipState: models.SponsorshipActive,
			ReasonCode:          nonEmptyStr(gp.ReasonCode, "DUAL_KEY_SPONSOR_SUCCESSION_COMPLETED"),
			TriggeredBy:         dualRes.Slot1.PrincipalID + "+" + dualRes.Slot2.PrincipalID,
			LineageMode:         models.LineageModePostSeal2Of2,
			GovernanceDSSE:      &env,
			OccurredAt:          time.Now().UTC(),
		})
	}
	updated, err := e.store.GetCommissioningFunction(ctx, cf.FunctionID)
	if err != nil {
		updated = cf
	}
	e.emit("COMMISSIONING_FUNCTION_UPDATED", updated)
	return updated, nil
}

// UpsertCommissioningFunctionGenesis registers a CommissioningFunction prior to bootstrap sealing.
func (e *Engine) UpsertCommissioningFunctionGenesis(ctx context.Context, cf models.CommissioningFunction) (*models.CommissioningFunction, error) {
	boot, err := e.store.GetBootstrapState(ctx)
	if err != nil {
		return nil, err
	}
	if boot.Sealed {
		return nil, errors.New("BOOTSTRAP_SEALED_REQUIRES_DUAL_KEY_DSSE: CommissioningFunction registration requires 2-of-2 DSSE once bootstrap is sealed")
	}
	grace := cf.OrphanGraceHours
	gp := models.PrincipalGovernancePayload{
		FunctionID:             cf.FunctionID,
		DisplayName:            cf.DisplayName,
		OwningOrgUnit:          cf.OwningOrgUnit,
		CostCenter:             cf.CostCenter,
		PrimarySOPrincipalID:   cf.PrimarySOPrincipalID,
		SecondarySOPrincipalID: cf.SecondarySOPrincipalID,
		PrimaryAOPrincipalID:   cf.PrimaryAOPrincipalID,
		SecondaryAOPrincipalID: cf.SecondaryAOPrincipalID,
		EscalationContact:      cf.EscalationContact,
		OrphanGraceHours:       &grace,
	}
	built, err := e.validateAndBuildCommissioningFunction(ctx, gp, models.LineageModeGenesisSealed, nil)
	if err != nil {
		return nil, err
	}
	if err := e.store.AppendCommissioningFunction(ctx, built); err != nil {
		return nil, err
	}
	updated, err := e.store.GetCommissioningFunction(ctx, built.FunctionID)
	if err != nil {
		updated = built
	}
	e.emit("COMMISSIONING_FUNCTION_UPDATED", updated)
	return updated, nil
}

func (e *Engine) validateAndBuildCommissioningFunction(
	ctx context.Context,
	gp models.PrincipalGovernancePayload,
	lineageMode string,
	govEnv *crypto.Envelope,
) (*models.CommissioningFunction, error) {
	fnID := strings.TrimSpace(gp.FunctionID)
	if fnID == "" {
		return nil, errors.New("MISSING_FUNCTION_ID: function_id is required")
	}
	if fnID == models.SystemCommissioningFunctionID {
		return nil, errors.New("RESERVED_SYSTEM_FUNCTION_ID: fn-g1-system-control-plane is reserved for kernel workers")
	}
	if strings.TrimSpace(gp.OwningOrgUnit) == "" {
		return nil, errors.New("MISSING_OWNING_ORG_UNIT: owning_org_unit is required")
	}
	if strings.TrimSpace(gp.EscalationContact) == "" {
		return nil, errors.New("MISSING_ESCALATION_CONTACT: escalation_contact is required")
	}
	graceHours := 168
	if gp.OrphanGraceHours != nil {
		graceHours = *gp.OrphanGraceHours
	}
	if graceHours < 0 || graceHours > 336 {
		return nil, fmt.Errorf("INVALID_ORPHAN_GRACE_HOURS: orphan_grace_hours=%d must be in [0, 336]", graceHours)
	}

	principals, err := e.store.ListPrincipals(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[string]models.Principal{}
	for _, p := range principals {
		byID[p.PrincipalID] = p
	}

	checkSponsor := func(pid, expectedRole, field string, required bool) error {
		pid = strings.TrimSpace(pid)
		if pid == "" {
			if required {
				return fmt.Errorf("MISSING_SPONSOR_PRINCIPAL: %s is required", field)
			}
			return nil
		}
		p, ok := byID[pid]
		if !ok {
			return fmt.Errorf("UNKNOWN_SPONSOR_PRINCIPAL: %s=%q is not enrolled in principals", field, pid)
		}
		if p.Revoked {
			return fmt.Errorf("REVOKED_SPONSOR_PRINCIPAL: %s=%q is revoked (%s)", field, pid, p.RevokeReason)
		}
		if p.Role != expectedRole {
			return fmt.Errorf("SPONSOR_ROLE_MISMATCH: %s=%q holds role %s, want %s", field, pid, p.Role, expectedRole)
		}
		return nil
	}

	if err := checkSponsor(gp.PrimarySOPrincipalID, crypto.RoleServiceOwner, "primary_so_principal_id", true); err != nil {
		return nil, err
	}
	if err := checkSponsor(gp.SecondarySOPrincipalID, crypto.RoleServiceOwner, "secondary_so_principal_id", false); err != nil {
		return nil, err
	}
	if err := checkSponsor(gp.PrimaryAOPrincipalID, crypto.RoleAuthorizingOfficial, "primary_ao_principal_id", true); err != nil {
		return nil, err
	}
	if err := checkSponsor(gp.SecondaryAOPrincipalID, crypto.RoleAuthorizingOfficial, "secondary_ao_principal_id", false); err != nil {
		return nil, err
	}
	if gp.SecondarySOPrincipalID != "" && strings.TrimSpace(gp.SecondarySOPrincipalID) == strings.TrimSpace(gp.PrimarySOPrincipalID) {
		return nil, errors.New("DUPLICATE_SO_SPONSOR: secondary_so_principal_id must differ from primary_so_principal_id")
	}
	if gp.SecondaryAOPrincipalID != "" && strings.TrimSpace(gp.SecondaryAOPrincipalID) == strings.TrimSpace(gp.PrimaryAOPrincipalID) {
		return nil, errors.New("DUPLICATE_AO_SPONSOR: secondary_ao_principal_id must differ from primary_ao_principal_id")
	}

	return &models.CommissioningFunction{
		FunctionID:             fnID,
		DisplayName:            nonEmptyStr(gp.DisplayName, fnID),
		OwningOrgUnit:          strings.TrimSpace(gp.OwningOrgUnit),
		CostCenter:             strings.TrimSpace(gp.CostCenter),
		PrimarySOPrincipalID:   strings.TrimSpace(gp.PrimarySOPrincipalID),
		SecondarySOPrincipalID: strings.TrimSpace(gp.SecondarySOPrincipalID),
		PrimaryAOPrincipalID:   strings.TrimSpace(gp.PrimaryAOPrincipalID),
		SecondaryAOPrincipalID: strings.TrimSpace(gp.SecondaryAOPrincipalID),
		EscalationContact:      strings.TrimSpace(gp.EscalationContact),
		OrphanGraceHours:       graceHours,
		LineageMode:            lineageMode,
		GovernanceDSSE:         govEnv,
		CreatedAt:              time.Now().UTC(),
	}, nil
}

// EnrollAgentIdentityDualSigned verifies a 2-of-2 ENROLL_AGENT_IDENTITY DSSE ceremony, enforces strict
// 3-Way Separation of Duties (Builder != Commissioner) and Builder Provenance signature verification,
// and appends the AgentIdentity to agent_identities.
func (e *Engine) EnrollAgentIdentityDualSigned(ctx context.Context, env crypto.Envelope) (*models.AgentIdentity, error) {
	gp, dualRes, err := e.VerifyDualGovernanceEnvelope(ctx, env, models.GovActionEnrollAgentIdentity)
	if err != nil {
		return nil, err
	}
	agent, err := e.validateAndBuildAgentIdentity(
		ctx,
		*gp,
		dualRes.Slot1.PrincipalID, dualRes.Slot1.KeyFingerprint,
		dualRes.Slot2.PrincipalID, dualRes.Slot2.KeyFingerprint,
		models.LineageModePostSeal2Of2,
		&env,
	)
	if err != nil {
		return nil, err
	}
	if err := e.store.AppendAgentIdentity(ctx, agent); err != nil {
		return nil, err
	}
	enrolled, err := e.store.GetAgentIdentity(ctx, agent.AgentID)
	if err != nil {
		enrolled = agent
	}
	e.emit("AGENT_IDENTITY_ENROLLED", enrolled)
	return enrolled, nil
}

// EnrollAgentIdentityGenesis enrolls an AgentIdentity prior to bootstrap sealing (used for sandbox setup/seeding).
func (e *Engine) EnrollAgentIdentityGenesis(ctx context.Context, gp models.PrincipalGovernancePayload, soPrincipalID, soKeyFP, aoPrincipalID, aoKeyFP string) (*models.AgentIdentity, error) {
	boot, err := e.store.GetBootstrapState(ctx)
	if err != nil {
		return nil, err
	}
	if boot.Sealed {
		return nil, errors.New("BOOTSTRAP_SEALED_REQUIRES_DUAL_KEY_DSSE: agent enrollment requires 2-of-2 DSSE once bootstrap is sealed")
	}
	agent, err := e.validateAndBuildAgentIdentity(ctx, gp, soPrincipalID, soKeyFP, aoPrincipalID, aoKeyFP, models.LineageModeGenesisSealed, nil)
	if err != nil {
		return nil, err
	}
	if err := e.store.AppendAgentIdentity(ctx, agent); err != nil {
		return nil, err
	}
	enrolled, err := e.store.GetAgentIdentity(ctx, agent.AgentID)
	if err != nil {
		enrolled = agent
	}
	e.emit("AGENT_IDENTITY_ENROLLED", enrolled)
	return enrolled, nil
}

func (e *Engine) validateAndBuildAgentIdentity(
	ctx context.Context,
	gp models.PrincipalGovernancePayload,
	soID, soFP, aoID, aoFP string,
	lineageMode string,
	govEnv *crypto.Envelope,
) (*models.AgentIdentity, error) {
	agentID := strings.TrimSpace(gp.AgentID)
	if agentID == "" {
		return nil, errors.New("MISSING_AGENT_ID: agent_id is required")
	}
	kind := strings.TrimSpace(gp.AgentKind)
	if kind == "" {
		kind = models.AgentKindExternalAutonomous
	}
	if kind != models.AgentKindInternalWorker && kind != models.AgentKindExternalAutonomous {
		return nil, fmt.Errorf("INVALID_AGENT_KIND: got %q, want INTERNAL_WORKER or EXTERNAL_AUTONOMOUS_AGENT", kind)
	}
	fnID := strings.TrimSpace(gp.CommissioningFunctionID)
	if fnID == "" {
		return nil, errors.New("UNOWNED_AGENT_NO_COMMISSIONING_FUNCTION: commissioning_function_id is required")
	}
	cf, err := e.store.GetCommissioningFunction(ctx, fnID)
	if err != nil {
		return nil, fmt.Errorf("COMMISSIONING_FUNCTION_NOT_FOUND: %w", err)
	}
	if cf.ContinuityStatus == models.SponsorshipOrphanQuarantined || cf.ContinuityStatus == models.SponsorshipRevokedCompromise {
		return nil, fmt.Errorf("COMMISSIONING_FUNCTION_UNHEALTHY: function %s is %s", fnID, cf.ContinuityStatus)
	}

	pubBytes, err := crypto.DecodeBase64Any(strings.TrimSpace(gp.PublicKeyB64))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, errors.New("INVALID_AGENT_PUBLIC_KEY: expected 32-byte base64 Ed25519 public_key_b64")
	}
	if crypto.IsForbiddenLegacyPublicSeedKey(pubBytes) {
		return nil, errors.New("FORBIDDEN_LEGACY_PUBLIC_SEED_KEY: agent public key derives from revoked public string seed")
	}
	canonPubB64 := base64.StdEncoding.EncodeToString(pubBytes)
	agentFP := crypto.SHA256Hex(pubBytes)
	keyID := strings.TrimSpace(gp.KeyID)
	if keyID == "" {
		keyID = fmt.Sprintf("ed25519-%s-%s", agentID, agentFP[:10])
	}

	artDigest := strings.TrimSpace(gp.ArtifactDigest)
	if !strings.HasPrefix(artDigest, "sha256:") && !strings.HasPrefix(artDigest, "sha256-") {
		return nil, fmt.Errorf("INVALID_ARTIFACT_DIGEST: %q must start with sha256:", artDigest)
	}

	builderID := strings.TrimSpace(gp.BuilderPrincipalID)
	if builderID == "" {
		return nil, errors.New("MISSING_BUILDER_PRINCIPAL_ID: builder_principal_id is required for 3-Way SoD provenance")
	}

	var builderPub ed25519.PublicKey
	if strings.TrimSpace(gp.BuilderPublicKeyB64) != "" {
		bPubBytes, bErr := crypto.DecodeBase64Any(strings.TrimSpace(gp.BuilderPublicKeyB64))
		if bErr != nil || len(bPubBytes) != ed25519.PublicKeySize {
			return nil, errors.New("INVALID_BUILDER_PUBLIC_KEY: expected 32-byte base64 Ed25519 builder_public_key_b64")
		}
		builderPub = ed25519.PublicKey(bPubBytes)
	} else if len(e.publisherPubKey) == ed25519.PublicKeySize {
		builderPub = e.publisherPubKey
	} else {
		return nil, errors.New("MISSING_BUILDER_PUBLIC_KEY: builder_public_key_b64 or configured publisher public key required")
	}
	builderFP := crypto.SHA256Hex(builderPub)
	if gp.BuilderKeyFingerprint != "" && !strings.EqualFold(strings.TrimSpace(gp.BuilderKeyFingerprint), builderFP) {
		return nil, fmt.Errorf("BUILDER_FINGERPRINT_MISMATCH: payload=%s computed=%s", gp.BuilderKeyFingerprint, builderFP)
	}

	// Enforce 3-Way Separation of Duties: Builder != Commissioner (signing SO/AO AND CommissioningFunction sponsors)
	if builderID == soID || builderID == aoID ||
		builderID == cf.PrimarySOPrincipalID || builderID == cf.SecondarySOPrincipalID ||
		builderID == cf.PrimaryAOPrincipalID || builderID == cf.SecondaryAOPrincipalID ||
		strings.EqualFold(builderFP, soFP) || strings.EqualFold(builderFP, aoFP) {
		return nil, fmt.Errorf(
			"SOD_BUILDER_CANNOT_SELF_COMMISSION: builder %s (%s) cannot match commissioning Service Owner (%s) or Authorizing Official (%s)",
			builderID, builderFP, soID, aoID,
		)
	}
	// Also check against all enrolled principals attached to commissioning function sponsors
	if principals, pErr := e.store.ListPrincipals(ctx); pErr == nil {
		sponsorIDs := map[string]bool{
			soID:                      true,
			aoID:                      true,
			cf.PrimarySOPrincipalID:   true,
			cf.SecondarySOPrincipalID: true,
			cf.PrimaryAOPrincipalID:   true,
			cf.SecondaryAOPrincipalID: true,
		}
		for _, p := range principals {
			if sponsorIDs[p.PrincipalID] && strings.EqualFold(p.KeyFingerprint, builderFP) {
				return nil, fmt.Errorf(
					"SOD_BUILDER_CANNOT_SELF_COMMISSION: builder key fingerprint %s matches enrolled commissioning sponsor %s",
					builderFP, p.PrincipalID,
				)
			}
		}
	}

	// Verify cryptographic Builder Provenance signature over (agent_id, artifact_digest, public_key_b64)
	if err := crypto.VerifyAgentBuilderProvenance(agentID, artDigest, canonPubB64, gp.BuilderProvenanceSigB64, builderPub); err != nil {
		return nil, err
	}

	if len(gp.AllowedActions) == 0 {
		return nil, errors.New("EMPTY_ALLOWED_ACTIONS: at least one allowed_actions entry is required")
	}
	if len(gp.AllowedServices) == 0 {
		return nil, errors.New("EMPTY_ALLOWED_SERVICES: at least one allowed_services entry (or '*') is required")
	}
	egress := strings.TrimSpace(gp.AllowedEgressProfile)
	if egress == "" {
		egress = models.EgressProfileZeroIsolated
	}
	if egress != models.EgressProfileZeroIsolated && egress != models.EgressProfileInternalCluster {
		return nil, fmt.Errorf("INVALID_EGRESS_PROFILE: %q must be ZERO_EGRESS_ISOLATED or INTERNAL_CLUSTER_ONLY", egress)
	}
	maxTTL := gp.MaxTTLSeconds
	if maxTTL <= 0 {
		maxTTL = 120
	}
	if maxTTL < 1 || maxTTL > 300 {
		return nil, fmt.Errorf("INVALID_MAX_TTL_SECONDS: %d must be in [1, 300]", maxTTL)
	}
	if gp.MaxDelegationDepth < 0 || gp.MaxDelegationDepth > 3 {
		return nil, fmt.Errorf("INVALID_MAX_DELEGATION_DEPTH: %d must be in [0, 3]", gp.MaxDelegationDepth)
	}

	now := time.Now().UTC()
	var recertExp time.Time
	switch {
	case strings.TrimSpace(gp.RecertifyExpiresAt) != "":
		parsed, pErr := time.Parse(time.RFC3339, strings.TrimSpace(gp.RecertifyExpiresAt))
		if pErr != nil {
			return nil, fmt.Errorf("INVALID_RECERTIFY_EXPIRES_AT: %w", pErr)
		}
		recertExp = parsed.UTC()
	case gp.RecertifyDays > 0:
		recertExp = now.Add(time.Duration(gp.RecertifyDays) * 24 * time.Hour)
	default:
		recertExp = now.Add(30 * 24 * time.Hour)
	}
	if !recertExp.After(now) || recertExp.Sub(now) > MaxAgentRecertifyDuration+time.Minute {
		return nil, errors.New("INVALID_RECERTIFY_LEASE: recertify_expires_at must be in the future and <= 90 days from enrollment")
	}

	return &models.AgentIdentity{
		AgentID:                   agentID,
		DisplayName:               nonEmptyStr(gp.DisplayName, agentID),
		AgentKind:                 kind,
		CommissioningFunctionID:   fnID,
		KeyID:                     keyID,
		Alg:                       crypto.AlgEd25519,
		PublicKeyB64:              canonPubB64,
		KeyFingerprint:            agentFP,
		SPIFFEID:                  strings.TrimSpace(gp.SPIFFEID),
		ArtifactDigest:            artDigest,
		BuilderPrincipalID:        builderID,
		BuilderPublicKeyB64:       base64.StdEncoding.EncodeToString(builderPub),
		BuilderKeyFingerprint:     builderFP,
		BuilderProvenanceSigB64:   strings.TrimSpace(gp.BuilderProvenanceSigB64),
		AllowedActions:            gp.AllowedActions,
		AllowedServices:           gp.AllowedServices,
		AllowedEgressProfile:      egress,
		MaxTTLSeconds:             maxTTL,
		MaxDelegationDepth:        gp.MaxDelegationDepth,
		AllowAutonomousIntake:     gp.AllowAutonomousIntake,
		RecertifyExpiresAt:        recertExp,
		CommissionerSOPrincipalID: soID,
		CommissionerSOKeyFP:       soFP,
		CommissionerAOPrincipalID: aoID,
		CommissionerAOKeyFP:       aoFP,
		LineageMode:               lineageMode,
		GovernanceDSSE:            govEnv,
		EnrolledAt:                now,
	}, nil
}

// RecertifyAgentIdentityDualSigned renews an enrolled AgentIdentity's recertification lease (<= 90 days) via 2-of-2 DSSE.
func (e *Engine) RecertifyAgentIdentityDualSigned(ctx context.Context, env crypto.Envelope) (*models.AgentIdentity, error) {
	gp, dualRes, err := e.VerifyDualGovernanceEnvelope(ctx, env, models.GovActionRecertifyAgentIdentity)
	if err != nil {
		return nil, err
	}
	targetID := strings.TrimSpace(gp.AgentID)
	if targetID == "" {
		return nil, errors.New("MISSING_AGENT_ID: agent_id is required in RECERTIFY_AGENT_IDENTITY")
	}
	cur, err := e.store.GetAgentIdentity(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if cur.Revoked || cur.SponsorCompromised {
		return nil, fmt.Errorf("REVOKED_AGENT_CANNOT_BE_RECERTIFIED: agent %s is permanently revoked (%s)", cur.AgentID, cur.SponsorshipState)
	}
	if cur.BuilderPrincipalID == dualRes.Slot1.PrincipalID || cur.BuilderPrincipalID == dualRes.Slot2.PrincipalID ||
		strings.EqualFold(cur.BuilderKeyFingerprint, dualRes.Slot1.KeyFingerprint) ||
		strings.EqualFold(cur.BuilderKeyFingerprint, dualRes.Slot2.KeyFingerprint) {
		return nil, errors.New("SOD_BUILDER_CANNOT_SELF_COMMISSION: original builder cannot co-sign agent recertification")
	}

	now := time.Now().UTC()
	var nextExp time.Time
	switch {
	case strings.TrimSpace(gp.RecertifyExpiresAt) != "":
		parsed, pErr := time.Parse(time.RFC3339, strings.TrimSpace(gp.RecertifyExpiresAt))
		if pErr != nil {
			return nil, fmt.Errorf("INVALID_RECERTIFY_EXPIRES_AT: %w", pErr)
		}
		nextExp = parsed.UTC()
	case gp.RecertifyDays > 0:
		nextExp = now.Add(time.Duration(gp.RecertifyDays) * 24 * time.Hour)
	default:
		nextExp = now.Add(90 * 24 * time.Hour)
	}
	if !nextExp.After(now) || nextExp.Sub(now) > MaxAgentRecertifyDuration+time.Minute {
		return nil, errors.New("INVALID_RECERTIFY_LEASE: recertify_expires_at must be > now and <= 90 days")
	}

	ev := &models.AgentLifecycleEvent{
		EventType:           models.GovActionRecertifyAgentIdentity,
		TargetAgentID:       cur.AgentID,
		TargetFunctionID:    cur.CommissioningFunctionID,
		NewSponsorshipState: models.SponsorshipActive,
		RecertifyExpiresAt:  &nextExp,
		ReasonCode:          nonEmptyStr(gp.ReasonCode, "DUAL_KEY_RECERTIFICATION_RENEWAL"),
		TriggeredBy:         dualRes.Slot1.PrincipalID + "+" + dualRes.Slot2.PrincipalID,
		LineageMode:         models.LineageModePostSeal2Of2,
		GovernanceDSSE:      &env,
		OccurredAt:          now,
	}
	if err := e.store.AppendAgentLifecycleEvent(ctx, ev); err != nil {
		return nil, err
	}
	updated, err := e.store.GetAgentIdentity(ctx, cur.AgentID)
	if err != nil {
		return nil, err
	}
	e.emit("AGENT_IDENTITY_RECERTIFIED", updated)
	return updated, nil
}

// RevokeAgentIdentity executes an immediate 0-second fail-closed kill-switch revocation of an AgentIdentity.
// Accepts EITHER a 1-of-2 (or 2-of-2) human Principal Governance DSSE envelope OR an agent self-revocation DSSE envelope.
func (e *Engine) RevokeAgentIdentity(ctx context.Context, env crypto.Envelope) (*models.AgentIdentity, error) {
	if len(env.Signatures) == 0 {
		return nil, errors.New("DSSE_SIGNATURE_REQUIRED: REVOKE_AGENT_IDENTITY requires at least 1 signature")
	}

	var targetAgentID, reasonCode, triggeredBy, lineageMode string
	newState := models.SponsorshipRevokedKillSwitch

	// First attempt 1-of-2 / 2-of-2 active human principal verification
	if gp, singleRes, hErr := e.VerifySingleGovernanceEnvelope(ctx, env, models.GovActionRevokeAgentIdentity); hErr == nil {
		targetAgentID = strings.TrimSpace(gp.AgentID)
		if targetAgentID == "" {
			targetAgentID = strings.TrimSpace(gp.TargetPrincipalID)
		}
		reasonCode = nonEmptyStr(gp.ReasonCode, "HUMAN_1OF2_AGENT_KILL_SWITCH")
		triggeredBy = singleRes.Signer.PrincipalID
		lineageMode = models.LineageModePostSeal1Of2
	} else {
		// Attempt agent self-revocation signed by the target agent's own Ed25519 key
		rawPayload, decErr := env.DecodePayload()
		if decErr != nil {
			return nil, hErr
		}
		canon, cErr := crypto.CanonicalizeJSON(rawPayload)
		if cErr != nil || string(canon) != string(rawPayload) {
			return nil, errors.New("DSSE_PAYLOAD_NOT_CANONICAL_JCS")
		}
		var gp models.PrincipalGovernancePayload
		if uErr := json.Unmarshal(rawPayload, &gp); uErr != nil || gp.Action != models.GovActionRevokeAgentIdentity {
			return nil, hErr
		}
		exp, tErr := validateGovernanceTimingWithMax(gp, models.GovActionRevokeAgentIdentity, MaxSingleGovernanceTTL)
		if tErr != nil {
			return nil, tErr
		}
		lookupID := strings.TrimSpace(env.Signatures[0].KeyID)
		if lookupID == "" {
			lookupID = strings.TrimSpace(gp.AgentID)
		}
		selfAgent, rErr := e.store.ResolveAgentByKeyID(ctx, lookupID, time.Now().UTC())
		if rErr != nil {
			return nil, hErr
		}
		if gp.AgentID != "" && gp.AgentID != selfAgent.AgentID {
			return nil, errors.New("AGENT_SELF_REVOKE_SCOPE_VIOLATION: an agent key may only self-revoke its own agent_id")
		}
		pubBytes, _ := crypto.DecodeBase64Any(selfAgent.PublicKeyB64)
		agentPK := &crypto.PrincipalKey{
			PrincipalID:    selfAgent.AgentID,
			KeyID:          selfAgent.KeyID,
			Alg:            selfAgent.Alg,
			PublicKeyBytes: pubBytes,
			KeyFingerprint: selfAgent.KeyFingerprint,
			Revoked:        selfAgent.Revoked,
			RevokeReason:   selfAgent.RevokeReason,
		}
		if vErr := crypto.VerifySingleSignature(env.PayloadType, rawPayload, env.Signatures[0], agentPK, e.webauthnCfg); vErr != nil {
			return nil, fmt.Errorf("AGENT_SELF_REVOKE_SIG_INVALID: %w", vErr)
		}
		if nErr := e.store.ConsumeGovernanceEnvelopeNonce(ctx, gp.EnvelopeID, models.GovActionRevokeAgentIdentity, crypto.SHA256Hex(canon), selfAgent.AgentID, exp); nErr != nil {
			return nil, nErr
		}
		targetAgentID = selfAgent.AgentID
		reasonCode = nonEmptyStr(gp.ReasonCode, "AGENT_SELF_REVOCATION")
		triggeredBy = selfAgent.AgentID
		lineageMode = models.LineageModeAgentSelfRevoke
	}

	if targetAgentID == "" {
		return nil, errors.New("MISSING_AGENT_ID: agent_id is required in REVOKE_AGENT_IDENTITY")
	}
	cur, err := e.store.GetAgentIdentity(ctx, targetAgentID)
	if err != nil {
		return nil, err
	}
	if strings.Contains(strings.ToUpper(reasonCode), "COMPROMISE") {
		newState = models.SponsorshipRevokedCompromise
	}
	ev := &models.AgentLifecycleEvent{
		EventType:           models.GovActionRevokeAgentIdentity,
		TargetAgentID:       cur.AgentID,
		TargetFunctionID:    cur.CommissioningFunctionID,
		NewSponsorshipState: newState,
		ReasonCode:          reasonCode,
		TriggeredBy:         triggeredBy,
		LineageMode:         lineageMode,
		GovernanceDSSE:      &env,
		OccurredAt:          time.Now().UTC(),
	}
	if err := e.store.AppendAgentLifecycleEvent(ctx, ev); err != nil {
		return nil, err
	}
	updated, err := e.store.GetAgentIdentity(ctx, cur.AgentID)
	if err != nil {
		return nil, err
	}
	e.emit("AGENT_IDENTITY_REVOKED", updated)
	return updated, nil
}

// ProcessIGALifecycleEvent processes an authenticated HR/IAM lifecycle signal (ROLE_TRANSFER, ORG_REORG,
// LEAVE_OF_ABSENCE, TERMINATION, KEY_COMPROMISE), driving deterministic CommissioningFunction succession,
// bounded grace windows, or immediate 0s KEY_COMPROMISE cutoff.
func (e *Engine) ProcessIGALifecycleEvent(
	ctx context.Context,
	req models.IGAEventRequest,
	triggeredBy string,
	lineageMode string,
	govEnv *crypto.Envelope,
) (map[string]any, error) {
	evType := strings.ToUpper(strings.TrimSpace(req.EventType))
	switch evType {
	case models.IGAEventRoleTransfer, models.IGAEventOrgReorg, models.IGAEventLeaveOfAbsence, models.IGAEventTermination, models.IGAEventKeyCompromise:
	default:
		return nil, fmt.Errorf("UNSUPPORTED_IGA_EVENT_TYPE: %q (expected ROLE_TRANSFER, ORG_REORG, LEAVE_OF_ABSENCE, TERMINATION, or KEY_COMPROMISE)", req.EventType)
	}
	pid := strings.TrimSpace(req.PrincipalID)
	if pid == "" {
		return nil, errors.New("MISSING_PRINCIPAL_ID: principal_id is required on IGA event")
	}
	effTime := time.Now().UTC()
	if req.EffectiveTime != nil && !req.EffectiveTime.IsZero() {
		effTime = req.EffectiveTime.UTC()
	}
	if lineageMode == "" {
		lineageMode = models.LineageModeIGAWebhookAuth
	}
	reason := nonEmptyStr(req.ReasonCode, "IGA_"+evType)

	// Find all CommissioningFunctions referencing pid
	allFns, err := e.store.ListCommissioningFunctions(ctx)
	if err != nil {
		return nil, err
	}
	var affectedFnIDs []string
	for _, fn := range allFns {
		if fn.PrimarySOPrincipalID == pid || fn.SecondarySOPrincipalID == pid ||
			fn.PrimaryAOPrincipalID == pid || fn.SecondaryAOPrincipalID == pid {
			affectedFnIDs = append(affectedFnIDs, fn.FunctionID)
		}
	}

	if len(affectedFnIDs) == 0 {
		// Still record principal-scoped audit event in agent_lifecycle_events
		ev := &models.AgentLifecycleEvent{
			EventID:             req.EventID,
			EventType:           evType,
			AffectedPrincipalID: pid,
			NewSponsorshipState: models.SponsorshipActive,
			ReasonCode:          reason,
			TriggeredBy:         nonEmptyStr(triggeredBy, "iga-webhook"),
			LineageMode:         lineageMode,
			GovernanceDSSE:      govEnv,
			OccurredAt:          effTime,
		}
		if err := e.store.AppendAgentLifecycleEvent(ctx, ev); err != nil {
			return nil, err
		}
		return map[string]any{
			"event_type":          evType,
			"principal_id":        pid,
			"affected_functions":  []models.CommissioningFunction{},
			"affected_agents":     []models.AgentIdentity{},
			"lifecycle_events":    []models.AgentLifecycleEvent{*ev},
		}, nil
	}

	// First record the raw IGA departure/compromise event for each affected CommissioningFunction
	var recordedEvents []models.AgentLifecycleEvent
	for idx, fnID := range affectedFnIDs {
		evID := ""
		if idx == 0 && strings.TrimSpace(req.EventID) != "" {
			evID = strings.TrimSpace(req.EventID)
		}
		initialState := models.SponsorshipSecondaryContinuity
		if evType == models.IGAEventKeyCompromise {
			initialState = models.SponsorshipRevokedCompromise
		}
		ev := models.AgentLifecycleEvent{
			EventID:             evID,
			EventType:           evType,
			TargetFunctionID:    fnID,
			AffectedPrincipalID: pid,
			NewSponsorshipState: initialState,
			ReasonCode:          reason,
			TriggeredBy:         nonEmptyStr(triggeredBy, "iga-webhook"),
			LineageMode:         lineageMode,
			GovernanceDSSE:      govEnv,
			OccurredAt:          effTime,
		}
		if err := e.store.AppendAgentLifecycleEvent(ctx, &ev); err != nil {
			return nil, err
		}
		recordedEvents = append(recordedEvents, ev)
	}

	// Re-evaluate post-event function & agent states at effTime (and current wall clock)
	nowEval := time.Now().UTC()
	updatedFns := make([]models.CommissioningFunction, 0, len(affectedFnIDs))
	for _, fnID := range affectedFnIDs {
		fnAfter, fErr := e.store.GetCommissioningFunction(ctx, fnID)
		if fErr != nil {
			continue
		}
		if evType != models.IGAEventKeyCompromise && (fnAfter.ActiveSOCount == 0 || fnAfter.ActiveAOCount == 0) {
			graceExp := effTime.Add(time.Duration(fnAfter.OrphanGraceHours) * time.Hour)
			postState := models.SponsorshipGraceEscalated
			if fnAfter.OrphanGraceHours <= 0 || !nowEval.Before(graceExp) {
				postState = models.SponsorshipOrphanQuarantined
			}
			graceEv := models.AgentLifecycleEvent{
				EventType:           postState,
				TargetFunctionID:    fnID,
				AffectedPrincipalID: pid,
				NewSponsorshipState: postState,
				GraceExpiresAt:      &graceExp,
				ReasonCode:          reason,
				TriggeredBy:         nonEmptyStr(triggeredBy, "iga-webhook"),
				LineageMode:         lineageMode,
				GovernanceDSSE:      govEnv,
				OccurredAt:          effTime,
			}
			_ = e.store.AppendAgentLifecycleEvent(ctx, &graceEv)
			recordedEvents = append(recordedEvents, graceEv)
			if refreshed, rErr := e.store.GetCommissioningFunction(ctx, fnID); rErr == nil {
				fnAfter = refreshed
			}
		}
		updatedFns = append(updatedFns, *fnAfter)

		switch fnAfter.ContinuityStatus {
		case models.SponsorshipRevokedCompromise:
			e.emit("IGA_KEY_COMPROMISE_QUARANTINE", fnAfter)
		case models.SponsorshipOrphanQuarantined:
			e.emit("GHOST_AGENT_ORPHAN_QUARANTINED", fnAfter)
		case models.SponsorshipGraceEscalated:
			e.emit("AGENT_SPONSOR_GRACE_ESCALATED", fnAfter)
		case models.SponsorshipSecondaryContinuity:
			e.emit("PENDING_SPONSOR_SUCCESSION", fnAfter)
		}
	}

	allAgents, _ := e.store.ListAgentIdentities(ctx)
	fnSet := map[string]bool{}
	for _, id := range affectedFnIDs {
		fnSet[id] = true
	}
	var affectedAgents []models.AgentIdentity
	for _, a := range allAgents {
		if fnSet[a.CommissioningFunctionID] {
			affectedAgents = append(affectedAgents, a)
		}
	}
	pendingTransfers, _ := e.store.ListPendingSponsorTransfers(ctx)

	return map[string]any{
		"event_type":                evType,
		"principal_id":              pid,
		"affected_functions":        updatedFns,
		"affected_agents":           affectedAgents,
		"pending_sponsor_transfers": pendingTransfers,
		"lifecycle_events":          recordedEvents,
	}, nil
}

func nonEmptyStr(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}
