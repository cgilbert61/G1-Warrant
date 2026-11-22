package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	lockCommissioningChain  int64 = 1001008
	lockAgentIdentityChain  int64 = 1001009
	lockAgentLifecycleChain int64 = 1001010
)

// ComputeCommissioningFunctionEntryHash computes the deterministic SHA-256 chain link for commissioning_functions.
func ComputeCommissioningFunctionEntryHash(prevHash string, cf models.CommissioningFunction) string {
	material := strings.Join([]string{
		"commissioning_functions",
		prevHash,
		cf.FunctionID,
		cf.DisplayName,
		cf.OwningOrgUnit,
		cf.CostCenter,
		cf.PrimarySOPrincipalID,
		cf.SecondarySOPrincipalID,
		cf.PrimaryAOPrincipalID,
		cf.SecondaryAOPrincipalID,
		cf.EscalationContact,
		strconv.Itoa(cf.OrphanGraceHours),
		cf.LineageMode,
	}, "|")
	return crypto.SHA256Hex([]byte(material))
}

// ComputeAgentIdentityEntryHash computes the deterministic SHA-256 chain link for agent_identities.
func ComputeAgentIdentityEntryHash(prevHash string, a models.AgentIdentity) string {
	acts := append([]string(nil), a.AllowedActions...)
	svcs := append([]string(nil), a.AllowedServices...)
	sort.Strings(acts)
	sort.Strings(svcs)
	material := strings.Join([]string{
		"agent_identities",
		prevHash,
		a.AgentID,
		a.AgentKind,
		a.CommissioningFunctionID,
		a.KeyID,
		a.Alg,
		a.PublicKeyB64,
		strings.ToLower(a.KeyFingerprint),
		a.ArtifactDigest,
		a.BuilderPrincipalID,
		strings.ToLower(a.BuilderKeyFingerprint),
		a.BuilderProvenanceSigB64,
		strings.Join(acts, ","),
		strings.Join(svcs, ","),
		a.AllowedEgressProfile,
		strconv.Itoa(a.MaxTTLSeconds),
		strconv.Itoa(a.MaxDelegationDepth),
		strconv.FormatBool(a.AllowAutonomousIntake),
		a.CommissionerSOPrincipalID,
		a.CommissionerAOPrincipalID,
		a.LineageMode,
	}, "|")
	return crypto.SHA256Hex([]byte(material))
}

// ComputeAgentLifecycleEntryHash computes the deterministic SHA-256 chain link for agent_lifecycle_events.
func ComputeAgentLifecycleEntryHash(prevHash string, ev models.AgentLifecycleEvent) string {
	material := strings.Join([]string{
		"agent_lifecycle_events",
		prevHash,
		ev.EventID,
		ev.EventType,
		ev.TargetAgentID,
		ev.TargetFunctionID,
		ev.AffectedPrincipalID,
		ev.NewSponsorshipState,
		ev.ReasonCode,
		ev.TriggeredBy,
		ev.LineageMode,
	}, "|")
	return crypto.SHA256Hex([]byte(material))
}

// AppendCommissioningFunction appends a versioned CommissioningFunction row to commissioning_functions (WORM).
func (s *Store) AppendCommissioningFunction(ctx context.Context, cf *models.CommissioningFunction) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockCommissioningChain); err != nil {
		return err
	}

	prevHash := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM commissioning_functions ORDER BY seq_no DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if cf.CreatedAt.IsZero() {
		cf.CreatedAt = time.Now().UTC()
	}
	if cf.OrphanGraceHours < 0 || cf.OrphanGraceHours > 336 {
		return fmt.Errorf("INVALID_ORPHAN_GRACE_HOURS: orphan_grace_hours=%d must be in [0, 336]", cf.OrphanGraceHours)
	}
	cf.PrevHash = prevHash
	cf.EntryHash = ComputeCommissioningFunctionEntryHash(prevHash, *cf)

	var dsseRaw []byte
	if cf.GovernanceDSSE != nil {
		dsseRaw, err = crypto.CanonicalizeStruct(cf.GovernanceDSSE)
		if err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO commissioning_functions (
			function_id, display_name, owning_org_unit, cost_center,
			primary_so_principal_id, secondary_so_principal_id,
			primary_ao_principal_id, secondary_ao_principal_id,
			escalation_contact, orphan_grace_hours,
			lineage_mode, governance_dsse, prev_hash, entry_hash, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
	`,
		cf.FunctionID, cf.DisplayName, cf.OwningOrgUnit, cf.CostCenter,
		cf.PrimarySOPrincipalID, cf.SecondarySOPrincipalID,
		cf.PrimaryAOPrincipalID, cf.SecondaryAOPrincipalID,
		cf.EscalationContact, cf.OrphanGraceHours,
		cf.LineageMode, dsseRaw, cf.PrevHash, cf.EntryHash, cf.CreatedAt,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AppendAgentIdentity enrolls an immutable AgentIdentity row in agent_identities (WORM),
// enforcing strict key uniqueness across both human principals and existing/revoked agents.
func (s *Store) AppendAgentIdentity(ctx context.Context, a *models.AgentIdentity) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, lk := range []int64{lockPrincipalChain, lockRevocationChain, lockCommissioningChain, lockAgentIdentityChain} {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lk); err != nil {
			return err
		}
	}

	// Verify target CommissioningFunction exists
	var fnExists int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM commissioning_functions WHERE function_id = $1`, a.CommissioningFunctionID).Scan(&fnExists); err != nil {
		return err
	}
	if fnExists == 0 {
		return fmt.Errorf("COMMISSIONING_FUNCTION_NOT_FOUND: %q must be registered before enrolling agents", a.CommissioningFunctionID)
	}

	// Strict Key Separation: an AgentIdentity public key / fingerprint / key_id can NEVER collide with any human Principal
	var humanConflict string
	hErr := tx.QueryRow(ctx, `
		SELECT principal_id FROM principals
		WHERE principal_id = $1
		   OR key_id = $2
		   OR public_key_b64 = $3
		   OR lower(key_fingerprint) = lower($4)
		LIMIT 1
	`, a.AgentID, a.KeyID, a.PublicKeyB64, a.KeyFingerprint).Scan(&humanConflict)
	if hErr == nil {
		return fmt.Errorf("AGENT_KEY_COLLIDES_WITH_HUMAN_PRINCIPAL: agent %s key/id matches human principal %s", a.AgentID, humanConflict)
	}
	if !errors.Is(hErr, pgx.ErrNoRows) {
		return hErr
	}

	// Reject any key fingerprint present in principal_revocations
	var revConflict string
	rErr := tx.QueryRow(ctx, `
		SELECT revocation_id FROM principal_revocations WHERE lower(key_fingerprint) = lower($1) LIMIT 1
	`, a.KeyFingerprint).Scan(&revConflict)
	if rErr == nil {
		return fmt.Errorf("AGENT_KEY_PREVIOUSLY_REVOKED: fingerprint %s appears in principal_revocations (%s)", a.KeyFingerprint, revConflict)
	}
	if !errors.Is(rErr, pgx.ErrNoRows) {
		return rErr
	}

	// Reject duplicate agent_id, key_id, public_key_b64, or key_fingerprint in agent_identities
	var agentConflict string
	aErr := tx.QueryRow(ctx, `
		SELECT agent_id FROM agent_identities
		WHERE agent_id = $1
		   OR key_id = $2
		   OR public_key_b64 = $3
		   OR lower(key_fingerprint) = lower($4)
		LIMIT 1
	`, a.AgentID, a.KeyID, a.PublicKeyB64, a.KeyFingerprint).Scan(&agentConflict)
	if aErr == nil {
		return fmt.Errorf("DUPLICATE_AGENT_IDENTITY_OR_KEY: conflicts with enrolled agent %s", agentConflict)
	}
	if !errors.Is(aErr, pgx.ErrNoRows) {
		return aErr
	}

	prevHash := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM agent_identities ORDER BY seq_no DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if a.EnrolledAt.IsZero() {
		a.EnrolledAt = time.Now().UTC()
	}
	a.PrevHash = prevHash
	a.EntryHash = ComputeAgentIdentityEntryHash(prevHash, *a)

	actionsJSON, err := json.Marshal(a.AllowedActions)
	if err != nil {
		return err
	}
	servicesJSON, err := json.Marshal(a.AllowedServices)
	if err != nil {
		return err
	}
	var dsseRaw []byte
	if a.GovernanceDSSE != nil {
		dsseRaw, err = crypto.CanonicalizeStruct(a.GovernanceDSSE)
		if err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_identities (
			agent_id, display_name, agent_kind, commissioning_function_id,
			key_id, alg, public_key_b64, key_fingerprint, spiffe_id,
			artifact_digest, builder_principal_id, builder_public_key_b64, builder_key_fingerprint, builder_provenance_sig_b64,
			allowed_actions, allowed_services, allowed_egress_profile,
			max_ttl_seconds, max_delegation_depth, allow_autonomous_intake, recertify_expires_at,
			commissioner_so_principal_id, commissioner_so_key_fp,
			commissioner_ao_principal_id, commissioner_ao_key_fp,
			lineage_mode, governance_dsse, prev_hash, entry_hash, enrolled_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30
		)
	`,
		a.AgentID, a.DisplayName, a.AgentKind, a.CommissioningFunctionID,
		a.KeyID, a.Alg, a.PublicKeyB64, a.KeyFingerprint, a.SPIFFEID,
		a.ArtifactDigest, a.BuilderPrincipalID, a.BuilderPublicKeyB64, a.BuilderKeyFingerprint, a.BuilderProvenanceSigB64,
		actionsJSON, servicesJSON, a.AllowedEgressProfile,
		a.MaxTTLSeconds, a.MaxDelegationDepth, a.AllowAutonomousIntake, a.RecertifyExpiresAt,
		a.CommissionerSOPrincipalID, a.CommissionerSOKeyFP,
		a.CommissionerAOPrincipalID, a.CommissionerAOKeyFP,
		a.LineageMode, dsseRaw, a.PrevHash, a.EntryHash, a.EnrolledAt,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AppendAgentLifecycleEvent appends an immutable lifecycle/IGA event to agent_lifecycle_events (WORM).
func (s *Store) AppendAgentLifecycleEvent(ctx context.Context, ev *models.AgentLifecycleEvent) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockAgentLifecycleChain); err != nil {
		return err
	}
	prevHash := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM agent_lifecycle_events ORDER BY seq_no DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if ev.EventID == "" {
		ev.EventID = "ale-" + uuid.NewString()[:8]
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	ev.PrevHash = prevHash
	ev.EntryHash = ComputeAgentLifecycleEntryHash(prevHash, *ev)

	var dsseRaw []byte
	if ev.GovernanceDSSE != nil {
		dsseRaw, err = crypto.CanonicalizeStruct(ev.GovernanceDSSE)
		if err != nil {
			return err
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO agent_lifecycle_events (
			event_id, event_type, target_agent_id, target_function_id, affected_principal_id,
			new_sponsorship_state, grace_expires_at, recertify_expires_at,
			reason_code, triggered_by, lineage_mode, governance_dsse,
			prev_hash, entry_hash, occurred_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
	`,
		ev.EventID, ev.EventType, ev.TargetAgentID, ev.TargetFunctionID, ev.AffectedPrincipalID,
		ev.NewSponsorshipState, ev.GraceExpiresAt, ev.RecertifyExpiresAt,
		ev.ReasonCode, ev.TriggeredBy, ev.LineageMode, dsseRaw,
		ev.PrevHash, ev.EntryHash, ev.OccurredAt,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListAgentLifecycleEvents returns all WORM agent_lifecycle_events ordered newest first.
func (s *Store) ListAgentLifecycleEvents(ctx context.Context) ([]models.AgentLifecycleEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, event_type, target_agent_id, target_function_id, affected_principal_id,
		       new_sponsorship_state, grace_expires_at, recertify_expires_at,
		       reason_code, triggered_by, lineage_mode, governance_dsse,
		       prev_hash, entry_hash, occurred_at
		FROM agent_lifecycle_events ORDER BY seq_no DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AgentLifecycleEvent{}
	for rows.Next() {
		var ev models.AgentLifecycleEvent
		var dsseRaw []byte
		if err := rows.Scan(
			&ev.EventID, &ev.EventType, &ev.TargetAgentID, &ev.TargetFunctionID, &ev.AffectedPrincipalID,
			&ev.NewSponsorshipState, &ev.GraceExpiresAt, &ev.RecertifyExpiresAt,
			&ev.ReasonCode, &ev.TriggeredBy, &ev.LineageMode, &dsseRaw,
			&ev.PrevHash, &ev.EntryHash, &ev.OccurredAt,
		); err != nil {
			return nil, err
		}
		if len(dsseRaw) > 0 {
			var env crypto.Envelope
			if json.Unmarshal(dsseRaw, &env) == nil {
				ev.GovernanceDSSE = &env
			}
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

type functionSponsorshipEval struct {
	fn              models.CommissioningFunction
	compromised     bool
	graceActive     bool
	graceExpiresAt  *time.Time
}

func (s *Store) evaluateAllFunctionsAndEvents(ctx context.Context, now time.Time) (map[string]functionSponsorshipEval, []models.AgentLifecycleEvent, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// 1. Load latest revision per function_id with its authority_seq
	type fnRow struct {
		authSeq int64
		cf      models.CommissioningFunction
	}
	fRows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (function_id)
		       authority_seq, function_id, display_name, owning_org_unit, cost_center,
		       primary_so_principal_id, secondary_so_principal_id,
		       primary_ao_principal_id, secondary_ao_principal_id,
		       escalation_contact, orphan_grace_hours,
		       lineage_mode, governance_dsse, prev_hash, entry_hash, created_at
		FROM commissioning_functions
		ORDER BY function_id ASC, seq_no DESC
	`)
	if err != nil {
		return nil, nil, err
	}
	var latestFns []fnRow
	for fRows.Next() {
		var r fnRow
		var dsseRaw []byte
		if err := fRows.Scan(
			&r.authSeq, &r.cf.FunctionID, &r.cf.DisplayName, &r.cf.OwningOrgUnit, &r.cf.CostCenter,
			&r.cf.PrimarySOPrincipalID, &r.cf.SecondarySOPrincipalID,
			&r.cf.PrimaryAOPrincipalID, &r.cf.SecondaryAOPrincipalID,
			&r.cf.EscalationContact, &r.cf.OrphanGraceHours,
			&r.cf.LineageMode, &dsseRaw, &r.cf.PrevHash, &r.cf.EntryHash, &r.cf.CreatedAt,
		); err != nil {
			fRows.Close()
			return nil, nil, err
		}
		if len(dsseRaw) > 0 {
			var env crypto.Envelope
			if json.Unmarshal(dsseRaw, &env) == nil {
				r.cf.GovernanceDSSE = &env
			}
		}
		latestFns = append(latestFns, r)
	}
	if err := fRows.Err(); err != nil {
		fRows.Close()
		return nil, nil, err
	}
	fRows.Close()

	// 2. Load human principals + revocations
	principals, err := s.ListPrincipals(ctx)
	if err != nil {
		return nil, nil, err
	}
	pMap := map[string]models.Principal{}
	for _, p := range principals {
		pMap[p.PrincipalID] = p
	}

	// 3. Load all lifecycle events in chronological seq_no ASC order with authority_seq
	type evWithAuth struct {
		authSeq int64
		ev      models.AgentLifecycleEvent
	}
	evRows, err := s.pool.Query(ctx, `
		SELECT authority_seq, event_id, event_type, target_agent_id, target_function_id, affected_principal_id,
		       new_sponsorship_state, grace_expires_at, recertify_expires_at,
		       reason_code, triggered_by, lineage_mode, governance_dsse,
		       prev_hash, entry_hash, occurred_at
		FROM agent_lifecycle_events ORDER BY seq_no ASC
	`)
	if err != nil {
		return nil, nil, err
	}
	var allEvs []evWithAuth
	var plainEvs []models.AgentLifecycleEvent
	for evRows.Next() {
		var row evWithAuth
		var dsseRaw []byte
		if err := evRows.Scan(
			&row.authSeq, &row.ev.EventID, &row.ev.EventType, &row.ev.TargetAgentID, &row.ev.TargetFunctionID, &row.ev.AffectedPrincipalID,
			&row.ev.NewSponsorshipState, &row.ev.GraceExpiresAt, &row.ev.RecertifyExpiresAt,
			&row.ev.ReasonCode, &row.ev.TriggeredBy, &row.ev.LineageMode, &dsseRaw,
			&row.ev.PrevHash, &row.ev.EntryHash, &row.ev.OccurredAt,
		); err != nil {
			evRows.Close()
			return nil, nil, err
		}
		if len(dsseRaw) > 0 {
			var env crypto.Envelope
			if json.Unmarshal(dsseRaw, &env) == nil {
				row.ev.GovernanceDSSE = &env
			}
		}
		allEvs = append(allEvs, row)
		plainEvs = append(plainEvs, row.ev)
	}
	if err := evRows.Err(); err != nil {
		evRows.Close()
		return nil, nil, err
	}
	evRows.Close()

	// 4. Evaluate each CommissioningFunction's live sponsorship continuity
	evalMap := make(map[string]functionSponsorshipEval, len(latestFns))
	for _, fr := range latestFns {
		cf := fr.cf
		if cf.FunctionID == models.SystemCommissioningFunctionID && cf.LineageMode == models.LineageModeKernelSystemBoot {
			cf.ActiveSOCount = 2
			cf.ActiveAOCount = 2
			cf.ContinuityStatus = models.SponsorshipActive
			evalMap[cf.FunctionID] = functionSponsorshipEval{fn: cf}
			continue
		}

		departedAfterRev := map[string]time.Time{}
		compromisedAfterRev := map[string]bool{}
		var explicitGraceExp *time.Time
		for _, er := range allEvs {
			if er.authSeq < fr.authSeq {
				continue
			}
			if er.ev.AffectedPrincipalID != "" {
				switch er.ev.EventType {
				case models.IGAEventKeyCompromise:
					compromisedAfterRev[er.ev.AffectedPrincipalID] = true
				case models.IGAEventRoleTransfer, models.IGAEventOrgReorg, models.IGAEventLeaveOfAbsence, models.IGAEventTermination, models.GovActionRevokePrincipal:
					if _, exists := departedAfterRev[er.ev.AffectedPrincipalID]; !exists {
						departedAfterRev[er.ev.AffectedPrincipalID] = er.ev.OccurredAt
					}
				}
			}
			if er.ev.TargetFunctionID == cf.FunctionID && er.ev.GraceExpiresAt != nil {
				tCopy := *er.ev.GraceExpiresAt
				explicitGraceExp = &tCopy
			}
		}

		sponsorActive := func(pid string, expectedRole string) (active bool, departed bool, compromised bool, depTime time.Time) {
			pid = strings.TrimSpace(pid)
			if pid == "" {
				return false, false, false, time.Time{}
			}
			if compromisedAfterRev[pid] {
				return false, true, true, now
			}
			p, ok := pMap[pid]
			if !ok || p.Role != expectedRole {
				return false, true, false, cf.CreatedAt
			}
			if p.Revoked {
				if strings.Contains(strings.ToUpper(p.RevokeReason), "COMPROMISE") {
					return false, true, true, now
				}
				return false, true, false, cf.CreatedAt
			}
			if dt, dep := departedAfterRev[pid]; dep {
				return false, true, false, dt
			}
			return true, false, false, time.Time{}
		}

		var departedList []string
		var latestLossTime time.Time
		anyCompromised := false
		activeSO := 0
		activeAO := 0

		for _, cand := range []struct {
			id   string
			role string
		}{
			{cf.PrimarySOPrincipalID, crypto.RoleServiceOwner},
			{cf.SecondarySOPrincipalID, crypto.RoleServiceOwner},
			{cf.PrimaryAOPrincipalID, crypto.RoleAuthorizingOfficial},
			{cf.SecondaryAOPrincipalID, crypto.RoleAuthorizingOfficial},
		} {
			if strings.TrimSpace(cand.id) == "" {
				continue
			}
			act, dep, comp, dt := sponsorActive(cand.id, cand.role)
			if comp {
				anyCompromised = true
			}
			if dep {
				departedList = append(departedList, cand.id)
				if dt.After(latestLossTime) {
					latestLossTime = dt
				}
			}
			if act {
				if cand.role == crypto.RoleServiceOwner {
					activeSO++
				} else {
					activeAO++
				}
			}
		}

		cf.ActiveSOCount = activeSO
		cf.ActiveAOCount = activeAO
		cf.DepartedSponsors = departedList

		var graceExp *time.Time
		graceAct := false

		switch {
		case anyCompromised:
			cf.ContinuityStatus = models.SponsorshipRevokedCompromise
			cf.PendingSponsorSuccession = true
		case activeSO == 0 || activeAO == 0:
			cf.PendingSponsorSuccession = true
			graceAct = true
			if explicitGraceExp != nil {
				graceExp = explicitGraceExp
			} else {
				base := latestLossTime
				if base.IsZero() {
					base = cf.CreatedAt
				}
				calc := base.Add(time.Duration(cf.OrphanGraceHours) * time.Hour)
				graceExp = &calc
			}
			if cf.OrphanGraceHours <= 0 || !now.Before(*graceExp) {
				cf.ContinuityStatus = models.SponsorshipOrphanQuarantined
			} else {
				cf.ContinuityStatus = models.SponsorshipGraceEscalated
			}
		case len(departedList) > 0:
			cf.ContinuityStatus = models.SponsorshipSecondaryContinuity
			cf.PendingSponsorSuccession = true
		default:
			cf.ContinuityStatus = models.SponsorshipActive
			cf.PendingSponsorSuccession = false
		}

		evalMap[cf.FunctionID] = functionSponsorshipEval{
			fn:             cf,
			compromised:    anyCompromised,
			graceActive:    graceAct,
			graceExpiresAt: graceExp,
		}
	}

	return evalMap, plainEvs, nil
}

// ListCommissioningFunctions returns the active revision of every registered CommissioningFunction with live sponsor continuity status.
func (s *Store) ListCommissioningFunctions(ctx context.Context) ([]models.CommissioningFunction, error) {
	evalMap, _, err := s.evaluateAllFunctionsAndEvents(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	out := make([]models.CommissioningFunction, 0, len(evalMap))
	for _, ev := range evalMap {
		out = append(out, ev.fn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FunctionID < out[j].FunctionID })
	return out, nil
}

// GetCommissioningFunction returns a single CommissioningFunction with live sponsor continuity status.
func (s *Store) GetCommissioningFunction(ctx context.Context, functionID string) (*models.CommissioningFunction, error) {
	evalMap, _, err := s.evaluateAllFunctionsAndEvents(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	ev, ok := evalMap[functionID]
	if !ok {
		return nil, fmt.Errorf("commissioning function %q not found", functionID)
	}
	cp := ev.fn
	return &cp, nil
}

// ListAgentIdentitiesAt evaluates all enrolled AgentIdentities and their live IGA sponsorship state at timestamp `now`.
func (s *Store) ListAgentIdentitiesAt(ctx context.Context, now time.Time) ([]models.AgentIdentity, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	evalMap, allEvs, err := s.evaluateAllFunctionsAndEvents(ctx, now)
	if err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, display_name, agent_kind, commissioning_function_id,
		       key_id, alg, public_key_b64, key_fingerprint, spiffe_id,
		       artifact_digest, builder_principal_id, builder_public_key_b64, builder_key_fingerprint, builder_provenance_sig_b64,
		       allowed_actions, allowed_services, allowed_egress_profile,
		       max_ttl_seconds, max_delegation_depth, allow_autonomous_intake, recertify_expires_at,
		       commissioner_so_principal_id, commissioner_so_key_fp,
		       commissioner_ao_principal_id, commissioner_ao_key_fp,
		       lineage_mode, governance_dsse, prev_hash, entry_hash, enrolled_at
		FROM agent_identities ORDER BY seq_no ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rawAgents []models.AgentIdentity
	for rows.Next() {
		var a models.AgentIdentity
		var actRaw, svcRaw, dsseRaw []byte
		if err := rows.Scan(
			&a.AgentID, &a.DisplayName, &a.AgentKind, &a.CommissioningFunctionID,
			&a.KeyID, &a.Alg, &a.PublicKeyB64, &a.KeyFingerprint, &a.SPIFFEID,
			&a.ArtifactDigest, &a.BuilderPrincipalID, &a.BuilderPublicKeyB64, &a.BuilderKeyFingerprint, &a.BuilderProvenanceSigB64,
			&actRaw, &svcRaw, &a.AllowedEgressProfile,
			&a.MaxTTLSeconds, &a.MaxDelegationDepth, &a.AllowAutonomousIntake, &a.RecertifyExpiresAt,
			&a.CommissionerSOPrincipalID, &a.CommissionerSOKeyFP,
			&a.CommissionerAOPrincipalID, &a.CommissionerAOKeyFP,
			&a.LineageMode, &dsseRaw, &a.PrevHash, &a.EntryHash, &a.EnrolledAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(actRaw, &a.AllowedActions)
		_ = json.Unmarshal(svcRaw, &a.AllowedServices)
		if len(dsseRaw) > 0 {
			var env crypto.Envelope
			if json.Unmarshal(dsseRaw, &env) == nil {
				a.GovernanceDSSE = &env
			}
		}
		rawAgents = append(rawAgents, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]models.AgentIdentity, 0, len(rawAgents))
	for _, a := range rawAgents {
		fnEval, hasFn := evalMap[a.CommissioningFunctionID]
		a.SponsorshipState = models.SponsorshipActive
		if hasFn {
			a.SponsorshipState = fnEval.fn.ContinuityStatus
			a.SponsorCompromised = fnEval.compromised
			a.GraceActive = fnEval.graceActive
			a.GraceExpiresAt = fnEval.graceExpiresAt
		} else {
			a.SponsorshipState = models.SponsorshipOrphanQuarantined
		}

		// Fold agent-specific lifecycle events in chronological order
		for _, ev := range allEvs {
			if ev.TargetAgentID != a.AgentID {
				continue
			}
			switch ev.EventType {
			case models.GovActionRecertifyAgentIdentity:
				if ev.RecertifyExpiresAt != nil {
					a.RecertifyExpiresAt = *ev.RecertifyExpiresAt
				}
			case models.GovActionRevokeAgentIdentity:
				a.Revoked = true
				a.RevokeReason = ev.ReasonCode
				if ev.NewSponsorshipState == models.SponsorshipRevokedCompromise {
					a.SponsorCompromised = true
					a.SponsorshipState = models.SponsorshipRevokedCompromise
				} else {
					a.SponsorshipState = models.SponsorshipRevokedKillSwitch
				}
			case models.IGAEventKeyCompromise:
				a.Revoked = true
				a.SponsorCompromised = true
				a.RevokeReason = ev.ReasonCode
				a.SponsorshipState = models.SponsorshipRevokedCompromise
			default:
				if ev.GraceExpiresAt != nil && a.GraceActive {
					tCopy := *ev.GraceExpiresAt
					a.GraceExpiresAt = &tCopy
					if !now.Before(tCopy) {
						a.SponsorshipState = models.SponsorshipOrphanQuarantined
					} else if !a.Revoked && !a.SponsorCompromised {
						a.SponsorshipState = models.SponsorshipGraceEscalated
					}
				}
			}
		}

		if a.SponsorCompromised && !a.Revoked {
			a.Revoked = true
			a.SponsorshipState = models.SponsorshipRevokedCompromise
			if a.RevokeReason == "" {
				a.RevokeReason = "SPONSOR_KEY_COMPROMISED"
			}
		}
		if !a.Revoked && !a.SponsorCompromised && !now.Before(a.RecertifyExpiresAt) {
			a.SponsorshipState = models.SponsorshipLeaseExpired
		}
		out = append(out, a)
	}
	return out, nil
}

// ListAgentIdentities returns all enrolled AgentIdentities evaluated at the current UTC timestamp.
func (s *Store) ListAgentIdentities(ctx context.Context) ([]models.AgentIdentity, error) {
	return s.ListAgentIdentitiesAt(ctx, time.Now().UTC())
}

// GetAgentIdentity returns a single enrolled AgentIdentity with live IGA sponsorship state.
func (s *Store) GetAgentIdentity(ctx context.Context, agentID string) (*models.AgentIdentity, error) {
	return s.GetAgentIdentityAt(ctx, agentID, time.Now().UTC())
}

// GetAgentIdentityAt returns a single enrolled AgentIdentity evaluated at `now`.
func (s *Store) GetAgentIdentityAt(ctx context.Context, agentID string, now time.Time) (*models.AgentIdentity, error) {
	all, err := s.ListAgentIdentitiesAt(ctx, now)
	if err != nil {
		return nil, err
	}
	for _, a := range all {
		if a.AgentID == agentID {
			cp := a
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("agent identity %q not found", agentID)
}

// ResolveAgentByKeyID looks up an enrolled AgentIdentity by key_id or agent_id.
func (s *Store) ResolveAgentByKeyID(ctx context.Context, keyOrAgentID string, now time.Time) (*models.AgentIdentity, error) {
	all, err := s.ListAgentIdentitiesAt(ctx, now)
	if err != nil {
		return nil, err
	}
	for _, a := range all {
		if a.KeyID == keyOrAgentID || a.AgentID == keyOrAgentID {
			cp := a
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("unknown agent key_id or agent_id %q", keyOrAgentID)
}

// ListPendingSponsorTransfers computes Action Inbox items for CommissioningFunctions requiring sponsor succession.
func (s *Store) ListPendingSponsorTransfers(ctx context.Context) ([]models.PendingSponsorTransfer, error) {
	now := time.Now().UTC()
	evalMap, _, err := s.evaluateAllFunctionsAndEvents(ctx, now)
	if err != nil {
		return nil, err
	}
	agents, err := s.ListAgentIdentitiesAt(ctx, now)
	if err != nil {
		return nil, err
	}
	out := []models.PendingSponsorTransfer{}
	for _, ev := range evalMap {
		if !ev.fn.PendingSponsorSuccession {
			continue
		}
		affected := 0
		var earliest *time.Time
		for _, a := range agents {
			if a.CommissioningFunctionID == ev.fn.FunctionID {
				affected++
				if a.GraceExpiresAt != nil && (earliest == nil || a.GraceExpiresAt.Before(*earliest)) {
					tCopy := *a.GraceExpiresAt
					earliest = &tCopy
				}
			}
		}
		out = append(out, models.PendingSponsorTransfer{
			FunctionID:            ev.fn.FunctionID,
			DisplayName:           ev.fn.DisplayName,
			OwningOrgUnit:         ev.fn.OwningOrgUnit,
			EscalationContact:     ev.fn.EscalationContact,
			ContinuityStatus:      ev.fn.ContinuityStatus,
			DepartedPrincipals:    ev.fn.DepartedSponsors,
			AffectedAgentsCount:   affected,
			EarliestGraceExpiryAt: earliest,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FunctionID < out[j].FunctionID })
	return out, nil
}

func (s *Store) verifyCommissioningFunctionChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT function_id, display_name, owning_org_unit, cost_center,
		       primary_so_principal_id, secondary_so_principal_id,
		       primary_ao_principal_id, secondary_ao_principal_id,
		       escalation_contact, orphan_grace_hours, lineage_mode,
		       prev_hash, entry_hash
		FROM commissioning_functions ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var cf models.CommissioningFunction
		if err := rows.Scan(
			&cf.FunctionID, &cf.DisplayName, &cf.OwningOrgUnit, &cf.CostCenter,
			&cf.PrimarySOPrincipalID, &cf.SecondarySOPrincipalID,
			&cf.PrimaryAOPrincipalID, &cf.SecondaryAOPrincipalID,
			&cf.EscalationContact, &cf.OrphanGraceHours, &cf.LineageMode,
			&cf.PrevHash, &cf.EntryHash,
		); err != nil {
			return models.ChainTableStatus{}, err
		}
		if cf.PrevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "commissioning_functions", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s", cf.FunctionID),
			}, nil
		}
		recomputed := ComputeCommissioningFunctionEntryHash(cf.PrevHash, cf)
		if recomputed != cf.EntryHash {
			return models.ChainTableStatus{
				TableName: "commissioning_functions", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", cf.FunctionID),
			}, nil
		}
		expectedPrev = cf.EntryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "commissioning_functions", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}

func (s *Store) verifyAgentIdentityChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT agent_id, agent_kind, commissioning_function_id,
		       key_id, alg, public_key_b64, key_fingerprint,
		       artifact_digest, builder_principal_id, builder_key_fingerprint, builder_provenance_sig_b64,
		       allowed_actions, allowed_services, allowed_egress_profile,
		       max_ttl_seconds, max_delegation_depth, allow_autonomous_intake,
		       commissioner_so_principal_id, commissioner_ao_principal_id, lineage_mode,
		       prev_hash, entry_hash
		FROM agent_identities ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var a models.AgentIdentity
		var actRaw, svcRaw []byte
		if err := rows.Scan(
			&a.AgentID, &a.AgentKind, &a.CommissioningFunctionID,
			&a.KeyID, &a.Alg, &a.PublicKeyB64, &a.KeyFingerprint,
			&a.ArtifactDigest, &a.BuilderPrincipalID, &a.BuilderKeyFingerprint, &a.BuilderProvenanceSigB64,
			&actRaw, &svcRaw, &a.AllowedEgressProfile,
			&a.MaxTTLSeconds, &a.MaxDelegationDepth, &a.AllowAutonomousIntake,
			&a.CommissionerSOPrincipalID, &a.CommissionerAOPrincipalID, &a.LineageMode,
			&a.PrevHash, &a.EntryHash,
		); err != nil {
			return models.ChainTableStatus{}, err
		}
		_ = json.Unmarshal(actRaw, &a.AllowedActions)
		_ = json.Unmarshal(svcRaw, &a.AllowedServices)
		if a.PrevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "agent_identities", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s", a.AgentID),
			}, nil
		}
		recomputed := ComputeAgentIdentityEntryHash(a.PrevHash, a)
		if recomputed != a.EntryHash {
			return models.ChainTableStatus{
				TableName: "agent_identities", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", a.AgentID),
			}, nil
		}
		expectedPrev = a.EntryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "agent_identities", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}

func (s *Store) verifyAgentLifecycleChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, event_type, target_agent_id, target_function_id, affected_principal_id,
		       new_sponsorship_state, reason_code, triggered_by, lineage_mode,
		       prev_hash, entry_hash
		FROM agent_lifecycle_events ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var ev models.AgentLifecycleEvent
		if err := rows.Scan(
			&ev.EventID, &ev.EventType, &ev.TargetAgentID, &ev.TargetFunctionID, &ev.AffectedPrincipalID,
			&ev.NewSponsorshipState, &ev.ReasonCode, &ev.TriggeredBy, &ev.LineageMode,
			&ev.PrevHash, &ev.EntryHash,
		); err != nil {
			return models.ChainTableStatus{}, err
		}
		if ev.PrevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "agent_lifecycle_events", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s", ev.EventID),
			}, nil
		}
		recomputed := ComputeAgentLifecycleEntryHash(ev.PrevHash, ev)
		if recomputed != ev.EntryHash {
			return models.ChainTableStatus{
				TableName: "agent_lifecycle_events", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", ev.EventID),
			}, nil
		}
		expectedPrev = ev.EntryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "agent_lifecycle_events", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}
