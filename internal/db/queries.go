package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
)

// ListWarrants returns all Standing Warrants annotated with live revocation/expiration status.
func (s *Store) ListWarrants(ctx context.Context) ([]models.WarrantRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT w.warrant_id, w.warrant_class, w.scope_services, w.max_cvss, w.kev_eligible,
		       w.max_blast_radius_replicas, w.allow_stateful_patches, w.sla_bridge_minutes, w.max_p99_latency_ms,
		       w.issued_at, w.expires_at, w.dsse_envelope,
		       w.slot1_principal_id, w.slot1_email, w.slot1_key_fp, w.slot1_role,
		       w.slot2_principal_id, w.slot2_email, w.slot2_key_fp, w.slot2_role,
		       w.prev_hash, w.entry_hash, w.created_at,
		       COALESCE(rev.reason_code, '') AS rev_reason
		FROM warrant_envelopes w
		LEFT JOIN LATERAL (
			SELECT reason_code FROM principal_revocations pr
			WHERE pr.principal_id IN (w.slot1_principal_id, w.slot2_principal_id)
			   OR lower(pr.key_fingerprint) IN (lower(w.slot1_key_fp), lower(w.slot2_key_fp))
			ORDER BY pr.revoked_at DESC LIMIT 1
		) rev ON TRUE
		ORDER BY w.seq_no DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now().UTC()
	out := []models.WarrantRecord{}
	for rows.Next() {
		var w models.WarrantRecord
		var scopeRaw, envRaw []byte
		if err := rows.Scan(
			&w.WarrantID, &w.WarrantClass, &scopeRaw, &w.MaxCVSS, &w.KEVEligible,
			&w.MaxBlastRadiusReplicas, &w.AllowStatefulPatches, &w.SLABridgeMinutes, &w.MaxP99LatencyMs,
			&w.IssuedAt, &w.ExpiresAt, &envRaw,
			&w.Slot1PrincipalID, &w.Slot1Email, &w.Slot1KeyFP, &w.Slot1Role,
			&w.Slot2PrincipalID, &w.Slot2Email, &w.Slot2KeyFP, &w.Slot2Role,
			&w.PrevHash, &w.EntryHash, &w.CreatedAt, &w.RevocationReason,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(scopeRaw, &w.ScopeServices)
		_ = json.Unmarshal(envRaw, &w.DSSEEnvelope)
		switch {
		case w.RevocationReason != "":
			w.LiveStatus = "REVOKED_SIGNER"
		case !now.Before(w.ExpiresAt):
			w.LiveStatus = "EXPIRED"
		default:
			w.LiveStatus = "ACTIVE"
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// GetWarrant fetches a single Standing Warrant by warrant_id.
func (s *Store) GetWarrant(ctx context.Context, warrantID string) (*models.WarrantRecord, error) {
	all, err := s.ListWarrants(ctx)
	if err != nil {
		return nil, err
	}
	for _, w := range all {
		if w.WarrantID == warrantID {
			cp := w
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("warrant %q not found", warrantID)
}

// FindMatchingWarrant locates the newest ACTIVE Standing Warrant covering serviceID and cvssScore.
func (s *Store) FindMatchingWarrant(ctx context.Context, serviceID string, cvssScore float64) (*models.WarrantRecord, error) {
	all, err := s.ListWarrants(ctx)
	if err != nil {
		return nil, err
	}
	for _, w := range all {
		if w.LiveStatus != "ACTIVE" || cvssScore > w.MaxCVSS {
			continue
		}
		for _, svc := range w.ScopeServices {
			if svc == "*" || svc == serviceID {
				cp := w
				return &cp, nil
			}
		}
	}
	return nil, fmt.Errorf("NO_MATCHING_ACTIVE_WARRANT for service=%s cvss=%.1f", serviceID, cvssScore)
}

// GetFreezeState fetches the singleton emergency freeze state.
func (s *Store) GetFreezeState(ctx context.Context) (models.FreezeState, error) {
	var fs models.FreezeState
	var thawRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT mode, actor, reason_code, thaw_dsse, updated_at
		FROM system_freeze_state WHERE singleton_id = 1
	`).Scan(&fs.Mode, &fs.Actor, &fs.ReasonCode, &thawRaw, &fs.UpdatedAt)
	if err != nil {
		return fs, err
	}
	if len(thawRaw) > 0 {
		var env crypto.Envelope
		if json.Unmarshal(thawRaw, &env) == nil {
			fs.ThawDSSE = &env
		}
	}
	return fs, nil
}

// SetFreezeState updates the singleton freeze posture and fires PostgreSQL LISTEN/NOTIFY via trigger.
func (s *Store) SetFreezeState(ctx context.Context, fs models.FreezeState) error {
	var thawRaw []byte
	if fs.ThawDSSE != nil {
		var err error
		thawRaw, err = crypto.CanonicalizeStruct(fs.ThawDSSE)
		if err != nil {
			return err
		}
	}
	if fs.UpdatedAt.IsZero() {
		fs.UpdatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE system_freeze_state
		SET mode = $1, actor = $2, reason_code = $3, thaw_dsse = $4, updated_at = $5
		WHERE singleton_id = 1
	`, fs.Mode, fs.Actor, fs.ReasonCode, thawRaw, fs.UpdatedAt)
	return err
}

// ListenFreezeNotifications subscribes to PostgreSQL LISTEN warrant_freeze_channel.
func (s *Store) ListenFreezeNotifications(ctx context.Context, onChange func(models.FreezeState)) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `LISTEN warrant_freeze_channel`); err != nil {
		return err
	}
	for {
		notif, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var payload struct {
			Mode       string `json:"mode"`
			Actor      string `json:"actor"`
			ReasonCode string `json:"reason_code"`
			UpdatedAt  string `json:"updated_at"`
		}
		if json.Unmarshal([]byte(notif.Payload), &payload) == nil {
			ts, _ := time.Parse(time.RFC3339, payload.UpdatedAt)
			onChange(models.FreezeState{
				Mode:       payload.Mode,
				Actor:      payload.Actor,
				ReasonCode: payload.ReasonCode,
				UpdatedAt:  ts,
			})
		}
	}
}

// UpsertEstateService saves or updates a registered workload in estate_services.
func (s *Store) UpsertEstateService(ctx context.Context, svc models.EstateService) error {
	syscallsJSON, _ := json.Marshal(svc.BaselineSyscalls)
	checklistJSON, _ := json.Marshal(svc.EligibilityChecklist)
	sbomJSON, _ := json.Marshal(svc.SBOMPURLs)
	if len(svc.SBOMPURLs) == 0 {
		sbomJSON = []byte("[]")
	}
	if svc.UpdatedAt.IsZero() {
		svc.UpdatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO estate_services (
			service_id, display_name, namespace, tier, warrant_class, current_digest, current_purl, sbom_purls,
			replicas, test_coverage_pct, otel_health_probes, readonly_shadow_replica,
			rollback_automation_verified, baseline_syscalls, eligible, eligibility_checklist, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (service_id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			namespace = EXCLUDED.namespace,
			tier = EXCLUDED.tier,
			warrant_class = EXCLUDED.warrant_class,
			current_digest = EXCLUDED.current_digest,
			current_purl = EXCLUDED.current_purl,
			sbom_purls = CASE WHEN jsonb_array_length(EXCLUDED.sbom_purls) > 0 THEN EXCLUDED.sbom_purls ELSE estate_services.sbom_purls END,
			replicas = EXCLUDED.replicas,
			test_coverage_pct = EXCLUDED.test_coverage_pct,
			otel_health_probes = EXCLUDED.otel_health_probes,
			readonly_shadow_replica = EXCLUDED.readonly_shadow_replica,
			rollback_automation_verified = EXCLUDED.rollback_automation_verified,
			baseline_syscalls = EXCLUDED.baseline_syscalls,
			eligible = EXCLUDED.eligible,
			eligibility_checklist = EXCLUDED.eligibility_checklist,
			updated_at = EXCLUDED.updated_at
	`,
		svc.ServiceID, svc.DisplayName, svc.Namespace, svc.Tier, svc.WarrantClass, svc.CurrentDigest, svc.CurrentPURL, sbomJSON,
		svc.Replicas, svc.TestCoveragePct, svc.OtelHealthProbes, svc.ReadonlyShadowReplica,
		svc.RollbackAutomationVerified, syscallsJSON, svc.Eligible, checklistJSON, svc.UpdatedAt,
	)
	return err
}

// ListEstateServices returns all registered estate services.
func (s *Store) ListEstateServices(ctx context.Context) ([]models.EstateService, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT service_id, display_name, namespace, tier, warrant_class, current_digest, current_purl, sbom_purls,
		       replicas, test_coverage_pct, otel_health_probes, readonly_shadow_replica,
		       rollback_automation_verified, baseline_syscalls, eligible, eligibility_checklist, updated_at
		FROM estate_services ORDER BY tier ASC, service_id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.EstateService{}
	for rows.Next() {
		var svc models.EstateService
		var sbomRaw, sysRaw, checkRaw []byte
		if err := rows.Scan(
			&svc.ServiceID, &svc.DisplayName, &svc.Namespace, &svc.Tier, &svc.WarrantClass, &svc.CurrentDigest, &svc.CurrentPURL, &sbomRaw,
			&svc.Replicas, &svc.TestCoveragePct, &svc.OtelHealthProbes, &svc.ReadonlyShadowReplica,
			&svc.RollbackAutomationVerified, &sysRaw, &svc.Eligible, &checkRaw, &svc.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(sbomRaw, &svc.SBOMPURLs)
		_ = json.Unmarshal(sysRaw, &svc.BaselineSyscalls)
		_ = json.Unmarshal(checkRaw, &svc.EligibilityChecklist)
		out = append(out, svc)
	}
	return out, rows.Err()
}

// GetEstateService returns a single workload by service_id.
func (s *Store) GetEstateService(ctx context.Context, serviceID string) (*models.EstateService, error) {
	svcs, err := s.ListEstateServices(ctx)
	if err != nil {
		return nil, err
	}
	for _, svc := range svcs {
		if svc.ServiceID == serviceID {
			cp := svc
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("estate service %q not found", serviceID)
}

// UpsertRemediation inserts or updates a RemediationItem in remediation_items.
func (s *Store) UpsertRemediation(ctx context.Context, item *models.RemediationItem) error {
	var patchRaw, shadowRaw []byte
	if item.PatchMetadata != nil {
		patchRaw, _ = json.Marshal(item.PatchMetadata)
	}
	if item.ShadowReport != nil {
		shadowRaw, _ = json.Marshal(item.ShadowReport)
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	item.UpdatedAt = time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO remediation_items (
			remediation_id, cve_id, cwe_id, is_kev, cvss_score, service_id, warrant_id,
			vulnerable_digest, patched_digest, package_purl, vulnerable_symbol, exploit_vector,
			stage, status_health, blocker_code, canary_weight,
			stateless_passed, schema_diff_passed, syscall_diff_passed,
			twin_replay_status, pod_sweep_matched, pod_sweep_total,
			lockout_policy_id, bridge_id, bridge_sla_minutes, attestation_id,
			patch_metadata, shadow_report, created_at, bridged_at, closed_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
			$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32
		)
		ON CONFLICT (remediation_id) DO UPDATE SET
			warrant_id = EXCLUDED.warrant_id,
			patched_digest = EXCLUDED.patched_digest,
			stage = EXCLUDED.stage,
			status_health = EXCLUDED.status_health,
			blocker_code = EXCLUDED.blocker_code,
			canary_weight = EXCLUDED.canary_weight,
			stateless_passed = EXCLUDED.stateless_passed,
			schema_diff_passed = EXCLUDED.schema_diff_passed,
			syscall_diff_passed = EXCLUDED.syscall_diff_passed,
			twin_replay_status = EXCLUDED.twin_replay_status,
			pod_sweep_matched = EXCLUDED.pod_sweep_matched,
			pod_sweep_total = EXCLUDED.pod_sweep_total,
			lockout_policy_id = EXCLUDED.lockout_policy_id,
			bridge_id = EXCLUDED.bridge_id,
			attestation_id = EXCLUDED.attestation_id,
			patch_metadata = EXCLUDED.patch_metadata,
			shadow_report = EXCLUDED.shadow_report,
			bridged_at = EXCLUDED.bridged_at,
			closed_at = EXCLUDED.closed_at,
			updated_at = EXCLUDED.updated_at
	`,
		item.RemediationID, item.CVEID, item.CWEID, item.IsKEV, item.CVSSScore, item.ServiceID, item.WarrantID,
		item.VulnerableDigest, item.PatchedDigest, item.PackagePURL, item.VulnerableSymbol, item.ExploitVector,
		item.Stage, item.StatusHealth, item.BlockerCode, item.CanaryWeight,
		item.StatelessPassed, item.SchemaDiffPassed, item.SyscallPassed,
		item.TwinReplayStatus, item.PodSweepMatched, item.PodSweepTotal,
		item.LockoutPolicyID, item.BridgeID, item.BridgeSLAMIN, item.AttestationID,
		patchRaw, shadowRaw, item.CreatedAt, item.BridgedAt, item.ClosedAt, item.UpdatedAt,
	)
	return err
}

// ListRemediations returns all Race Pipeline remediation items ordered newest first.
func (s *Store) ListRemediations(ctx context.Context) ([]models.RemediationItem, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT remediation_id, cve_id, cwe_id, is_kev, cvss_score, service_id, warrant_id,
		       vulnerable_digest, patched_digest, package_purl, vulnerable_symbol, exploit_vector,
		       stage, status_health, blocker_code, canary_weight,
		       stateless_passed, schema_diff_passed, syscall_diff_passed,
		       twin_replay_status, pod_sweep_matched, pod_sweep_total,
		       lockout_policy_id, bridge_id, bridge_sla_minutes, attestation_id,
		       patch_metadata, shadow_report, created_at, bridged_at, closed_at, updated_at
		FROM remediation_items ORDER BY updated_at DESC, created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.RemediationItem{}
	for rows.Next() {
		var r models.RemediationItem
		var patchRaw, shadowRaw []byte
		if err := rows.Scan(
			&r.RemediationID, &r.CVEID, &r.CWEID, &r.IsKEV, &r.CVSSScore, &r.ServiceID, &r.WarrantID,
			&r.VulnerableDigest, &r.PatchedDigest, &r.PackagePURL, &r.VulnerableSymbol, &r.ExploitVector,
			&r.Stage, &r.StatusHealth, &r.BlockerCode, &r.CanaryWeight,
			&r.StatelessPassed, &r.SchemaDiffPassed, &r.SyscallPassed,
			&r.TwinReplayStatus, &r.PodSweepMatched, &r.PodSweepTotal,
			&r.LockoutPolicyID, &r.BridgeID, &r.BridgeSLAMIN, &r.AttestationID,
			&patchRaw, &shadowRaw, &r.CreatedAt, &r.BridgedAt, &r.ClosedAt, &r.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(patchRaw) > 0 {
			var pm models.ExtractedPatchMetadata
			if json.Unmarshal(patchRaw, &pm) == nil {
				r.PatchMetadata = &pm
			}
		}
		if len(shadowRaw) > 0 {
			var sr models.ShadowComparisonReport
			if json.Unmarshal(shadowRaw, &sr) == nil {
				r.ShadowReport = &sr
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRemediation fetches a single RemediationItem by remediation_id.
func (s *Store) GetRemediation(ctx context.Context, id string) (*models.RemediationItem, error) {
	items, err := s.ListRemediations(ctx)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if it.RemediationID == id {
			cp := it
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("remediation %q not found", id)
}

// AppendTrace records a millisecond-timestamped deterministic state machine event.
func (s *Store) AppendTrace(ctx context.Context, t models.TraceEvent) error {
	if t.OccurredAt.IsZero() {
		t.OccurredAt = time.Now().UTC()
	}
	fieldsJSON, _ := json.Marshal(t.Fields)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO remediation_traces (trace_id, remediation_id, engine, step_code, outcome, actor_or_token, evidence_hash, fields, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, t.TraceID, t.RemediationID, t.Engine, t.StepCode, t.Outcome, t.ActorOrToken, t.EvidenceHash, fieldsJSON, t.OccurredAt)
	return err
}

// ListTraces returns deterministic trace events for a remediation in chronological order.
func (s *Store) ListTraces(ctx context.Context, remediationID string) ([]models.TraceEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT trace_id, remediation_id, engine, step_code, outcome, actor_or_token, evidence_hash, fields, occurred_at
		FROM remediation_traces WHERE remediation_id = $1 ORDER BY seq_no ASC
	`, remediationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.TraceEvent{}
	for rows.Next() {
		var t models.TraceEvent
		var fieldsRaw []byte
		if err := rows.Scan(&t.TraceID, &t.RemediationID, &t.Engine, &t.StepCode, &t.Outcome, &t.ActorOrToken, &t.EvidenceHash, &fieldsRaw, &t.OccurredAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(fieldsRaw, &t.Fields)
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpsertBridge inserts or updates a containment bridge in containment_bridges.
func (s *Store) UpsertBridge(ctx context.Context, b models.ContainmentBridge) error {
	if b.ArmedAt.IsZero() {
		b.ArmedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO containment_bridges (
			bridge_id, remediation_id, service_id, cve_id, bridge_type, status,
			sla_minutes, blocker_reason_code, cilium_manifest_yaml, k8s_netpol_yaml, envoy_filter_json,
			armed_at, retired_at, rearmed_count
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (bridge_id) DO UPDATE SET
			status = EXCLUDED.status,
			blocker_reason_code = EXCLUDED.blocker_reason_code,
			retired_at = EXCLUDED.retired_at,
			rearmed_count = EXCLUDED.rearmed_count
	`,
		b.BridgeID, b.RemediationID, b.ServiceID, b.CVEID, b.BridgeType, b.Status,
		b.SLABridgeMinutes, b.BlockerReasonCode, b.CiliumManifestYAML, b.K8sNetpolYAML, b.EnvoyFilterJSON,
		b.ArmedAt, b.RetiredAt, b.RearmedCount,
	)
	return err
}

// ListBridges lists all containment bridges ordered by active status then armed_at.
func (s *Store) ListBridges(ctx context.Context) ([]models.ContainmentBridge, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT bridge_id, remediation_id, service_id, cve_id, bridge_type, status,
		       sla_minutes, blocker_reason_code, cilium_manifest_yaml, k8s_netpol_yaml, envoy_filter_json,
		       armed_at, retired_at, rearmed_count
		FROM containment_bridges
		ORDER BY CASE WHEN status = 'REARMED_DRIFT' THEN 0 WHEN status = 'ARMED' THEN 1 ELSE 2 END, armed_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.ContainmentBridge{}
	for rows.Next() {
		var b models.ContainmentBridge
		if err := rows.Scan(
			&b.BridgeID, &b.RemediationID, &b.ServiceID, &b.CVEID, &b.BridgeType, &b.Status,
			&b.SLABridgeMinutes, &b.BlockerReasonCode, &b.CiliumManifestYAML, &b.K8sNetpolYAML, &b.EnvoyFilterJSON,
			&b.ArmedAt, &b.RetiredAt, &b.RearmedCount,
		); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetBridge retrieves a containment bridge by bridge_id.
func (s *Store) GetBridge(ctx context.Context, bridgeID string) (*models.ContainmentBridge, error) {
	bridges, err := s.ListBridges(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range bridges {
		if b.BridgeID == bridgeID {
			cp := b
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("bridge %q not found", bridgeID)
}

// UpsertLockout persists a permanent AdmissionLockout record.
func (s *Store) UpsertLockout(ctx context.Context, l models.AdmissionLockout) error {
	if l.EnforcedAt.IsZero() {
		l.EnforcedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO admission_lockouts (
			lockout_id, remediation_id, service_id, cve_id, banned_digest, patched_digest,
			policy_name, vap_manifest_yaml, gatekeeper_rego, enforced_at, drift_count, last_drift_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (lockout_id) DO UPDATE SET
			drift_count = EXCLUDED.drift_count,
			last_drift_at = EXCLUDED.last_drift_at
	`,
		l.LockoutID, l.RemediationID, l.ServiceID, l.CVEID, l.BannedDigest, l.PatchedDigest,
		l.PolicyName, l.VAPManifestYAML, l.GatekeeperRego, l.EnforcedAt, l.DriftCount, l.LastDriftAt,
	)
	return err
}

// ListLockouts returns all permanent Admission Lockout entries.
func (s *Store) ListLockouts(ctx context.Context) ([]models.AdmissionLockout, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT lockout_id, remediation_id, service_id, cve_id, banned_digest, patched_digest,
		       policy_name, vap_manifest_yaml, gatekeeper_rego, enforced_at, drift_count, last_drift_at
		FROM admission_lockouts ORDER BY enforced_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AdmissionLockout{}
	for rows.Next() {
		var l models.AdmissionLockout
		if err := rows.Scan(
			&l.LockoutID, &l.RemediationID, &l.ServiceID, &l.CVEID, &l.BannedDigest, &l.PatchedDigest,
			&l.PolicyName, &l.VAPManifestYAML, &l.GatekeeperRego, &l.EnforcedAt, &l.DriftCount, &l.LastDriftAt,
		); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// RecordDriftIncident inserts a runtime drift incident and increments the lockout drift counter.
func (s *Store) RecordDriftIncident(ctx context.Context, inc models.DriftIncident) error {
	if inc.DetectedAt.IsZero() {
		inc.DetectedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO drift_incidents (
			incident_id, lockout_id, remediation_id, service_id, cve_id,
			detected_digest, rogue_pod_name, rearmed_bridge_id, detection_latency_ms, detected_at, resolved_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (incident_id) DO NOTHING
	`,
		inc.IncidentID, inc.LockoutID, inc.RemediationID, inc.ServiceID, inc.CVEID,
		inc.DetectedDigest, inc.RoguePodName, inc.RearmedBridgeID, inc.DetectionLatencyMs, inc.DetectedAt, inc.ResolvedAt,
	)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE admission_lockouts SET drift_count = drift_count + 1, last_drift_at = $2 WHERE lockout_id = $1
	`, inc.LockoutID, inc.DetectedAt)
	return err
}

// ListDriftIncidents lists all runtime drift violations newest first.
func (s *Store) ListDriftIncidents(ctx context.Context) ([]models.DriftIncident, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT incident_id, lockout_id, remediation_id, service_id, cve_id,
		       detected_digest, rogue_pod_name, rearmed_bridge_id, detection_latency_ms, detected_at, resolved_at
		FROM drift_incidents ORDER BY detected_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.DriftIncident{}
	for rows.Next() {
		var inc models.DriftIncident
		if err := rows.Scan(
			&inc.IncidentID, &inc.LockoutID, &inc.RemediationID, &inc.ServiceID, &inc.CVEID,
			&inc.DetectedDigest, &inc.RoguePodName, &inc.RearmedBridgeID, &inc.DetectionLatencyMs, &inc.DetectedAt, &inc.ResolvedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

// UpsertException persists a Four-Eyes Ceiling Exception record.
func (s *Store) UpsertException(ctx context.Context, ex models.CeilingException) error {
	var resRaw []byte
	if ex.ResolutionDSSE != nil {
		resRaw, _ = crypto.CanonicalizeStruct(ex.ResolutionDSSE)
	}
	if ex.CreatedAt.IsZero() {
		ex.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ceiling_exceptions (
			exception_id, remediation_id, service_id, cve_id, warrant_class, trigger_code,
			ddl_count, orm_mutations, serialization_breaks, api_backward_compatible,
			shadow_replay_status, syscall_diff_summary, active_bridge_id, status, resolution_dsse, created_at, resolved_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (exception_id) DO UPDATE SET
			status = EXCLUDED.status,
			resolution_dsse = EXCLUDED.resolution_dsse,
			resolved_at = EXCLUDED.resolved_at
	`,
		ex.ExceptionID, ex.RemediationID, ex.ServiceID, ex.CVEID, ex.WarrantClass, ex.TriggerCode,
		ex.DDLCount, ex.ORMMutations, ex.SerializationBreaks, ex.APIBackwardCompatible,
		ex.ShadowReplayStatus, ex.SyscallDiffSummary, ex.ActiveBridgeID, ex.Status, resRaw, ex.CreatedAt, ex.ResolvedAt,
	)
	return err
}

// ListExceptions lists Four-Eyes Ceiling Exceptions ordered pending first.
func (s *Store) ListExceptions(ctx context.Context) ([]models.CeilingException, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT exception_id, remediation_id, service_id, cve_id, warrant_class, trigger_code,
		       ddl_count, orm_mutations, serialization_breaks, api_backward_compatible,
		       shadow_replay_status, syscall_diff_summary, active_bridge_id, status, resolution_dsse, created_at, resolved_at
		FROM ceiling_exceptions
		ORDER BY CASE WHEN status = 'PENDING_DUAL_KEY' THEN 0 ELSE 1 END, created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.CeilingException{}
	for rows.Next() {
		var ex models.CeilingException
		var resRaw []byte
		if err := rows.Scan(
			&ex.ExceptionID, &ex.RemediationID, &ex.ServiceID, &ex.CVEID, &ex.WarrantClass, &ex.TriggerCode,
			&ex.DDLCount, &ex.ORMMutations, &ex.SerializationBreaks, &ex.APIBackwardCompatible,
			&ex.ShadowReplayStatus, &ex.SyscallDiffSummary, &ex.ActiveBridgeID, &ex.Status, &resRaw, &ex.CreatedAt, &ex.ResolvedAt,
		); err != nil {
			return nil, err
		}
		if len(resRaw) > 0 {
			var env crypto.Envelope
			if json.Unmarshal(resRaw, &env) == nil {
				ex.ResolutionDSSE = &env
			}
		}
		out = append(out, ex)
	}
	return out, rows.Err()
}

// SaveShadowRun saves an N2 Differential Shadow comparison report.
func (s *Store) SaveShadowRun(ctx context.Context, rep models.ShadowComparisonReport) error {
	if rep.EvaluatedAt.IsZero() {
		rep.EvaluatedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO shadow_comparison_runs (run_id, remediation_id, service_id, stage_weight, passed, failure_code, report_json, evaluated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (run_id) DO UPDATE SET report_json = EXCLUDED.report_json, passed = EXCLUDED.passed
	`, rep.RunID, rep.RemediationID, rep.ServiceID, rep.StageWeight, rep.Passed, rep.FailureCode, raw, rep.EvaluatedAt)
	return err
}

// ListShadowRuns lists Differential Shadow comparison runs newest first.
func (s *Store) ListShadowRuns(ctx context.Context) ([]models.ShadowComparisonReport, error) {
	rows, err := s.pool.Query(ctx, `SELECT report_json FROM shadow_comparison_runs ORDER BY evaluated_at DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.ShadowComparisonReport{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var rep models.ShadowComparisonReport
		if json.Unmarshal(raw, &rep) == nil {
			out = append(out, rep)
		}
	}
	return out, rows.Err()
}

// ListAgentActions returns the hash-chained N4 Governed Agent Ledger entries.
func (s *Store) ListAgentActions(ctx context.Context) ([]models.AgentLedgerEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT action_id, task_token_id, warrant_id, remediation_id, worker_name, target_asset, action_type,
		       slot1_principal_id, slot2_principal_id, egress_profile,
		       raw_input_sha256, extractor_digest, typed_output_sha256,
		       token_ttl_sec, status, violation_code, prev_hash, entry_hash, executed_at
		FROM agent_action_ledger ORDER BY seq_no DESC LIMIT 250
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AgentLedgerEntry{}
	for rows.Next() {
		var e models.AgentLedgerEntry
		if err := rows.Scan(
			&e.ActionID, &e.TaskTokenID, &e.WarrantID, &e.RemediationID, &e.WorkerName, &e.TargetAsset, &e.ActionType,
			&e.Slot1PrincipalID, &e.Slot2PrincipalID, &e.EgressProfile,
			&e.RawInputSHA256, &e.ExtractorDigest, &e.TypedOutputSHA256,
			&e.TokenTTLSec, &e.Status, &e.ViolationCode, &e.PrevHash, &e.EntryHash, &e.ExecutedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAttestations returns all DSSE-signed OSCAL POA&M closure records newest first.
func (s *Store) ListAttestations(ctx context.Context) ([]models.AttestationRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT attestation_id, remediation_id, service_id, cve_id, is_kev, warrant_id,
		       slot1_principal_id, slot1_email, slot2_principal_id, slot2_email,
		       twin_transcript_sha256, fleet_digest_manifest, lockout_policy_id, reverify_expires_at,
		       dsse_envelope, oscal_poam_json, ttvr_seconds, prev_hash, entry_hash, minted_at
		FROM attestation_records ORDER BY seq_no DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AttestationRecord{}
	for rows.Next() {
		var a models.AttestationRecord
		var manifestRaw, envRaw, oscalRaw []byte
		if err := rows.Scan(
			&a.AttestationID, &a.RemediationID, &a.ServiceID, &a.CVEID, &a.IsKEV, &a.WarrantID,
			&a.Slot1PrincipalID, &a.Slot1Email, &a.Slot2PrincipalID, &a.Slot2Email,
			&a.TwinTranscriptSHA256, &manifestRaw, &a.LockoutPolicyID, &a.ReverifyExpiresAt,
			&envRaw, &oscalRaw, &a.TTVRSeconds, &a.PrevHash, &a.EntryHash, &a.MintedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(manifestRaw, &a.FleetDigestManifest)
		_ = json.Unmarshal(envRaw, &a.DSSEEnvelope)
		_ = json.Unmarshal(oscalRaw, &a.OSCALPOAM)
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateAuditorToken persists a hashed, time-bounded external auditor bearer token.
func (s *Store) CreateAuditorToken(ctx context.Context, tok models.AuditorShareToken, rawBearer string) error {
	idsJSON, _ := json.Marshal(tok.ScopedAttestationIDs)
	tokHash := crypto.SHA256Hex([]byte(rawBearer))
	_, err := s.pool.Exec(ctx, `
		INSERT INTO auditor_tokens (token_id, token_hash, label, scoped_attestation_ids, created_by, expires_at, revoked, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, tok.TokenID, tokHash, tok.Label, idsJSON, tok.CreatedBy, tok.ExpiresAt, tok.Revoked, tok.CreatedAt)
	return err
}

// ValidateAuditorToken verifies a raw bearer token and returns its scoped AuditorShareToken.
func (s *Store) ValidateAuditorToken(ctx context.Context, rawBearer string) (*models.AuditorShareToken, error) {
	tokHash := crypto.SHA256Hex([]byte(rawBearer))
	var tok models.AuditorShareToken
	var idsRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT token_id, label, scoped_attestation_ids, created_by, expires_at, revoked, created_at
		FROM auditor_tokens WHERE token_hash = $1
	`, tokHash).Scan(&tok.TokenID, &tok.Label, &idsRaw, &tok.CreatedBy, &tok.ExpiresAt, &tok.Revoked, &tok.CreatedAt)
	if err != nil {
		return nil, errors.New("INVALID_AUDITOR_TOKEN")
	}
	if tok.Revoked || !time.Now().UTC().Before(tok.ExpiresAt) {
		return nil, errors.New("EXPIRED_OR_REVOKED_AUDITOR_TOKEN")
	}
	_ = json.Unmarshal(idsRaw, &tok.ScopedAttestationIDs)
	return &tok, nil
}

// ListAuditorTokens lists minted auditor token metadata (never exposing raw bearer values).
func (s *Store) ListAuditorTokens(ctx context.Context) ([]models.AuditorShareToken, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT token_id, label, scoped_attestation_ids, created_by, expires_at, revoked, created_at
		FROM auditor_tokens ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AuditorShareToken{}
	for rows.Next() {
		var tok models.AuditorShareToken
		var idsRaw []byte
		if err := rows.Scan(&tok.TokenID, &tok.Label, &idsRaw, &tok.CreatedBy, &tok.ExpiresAt, &tok.Revoked, &tok.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(idsRaw, &tok.ScopedAttestationIDs)
		out = append(out, tok)
	}
	return out, rows.Err()
}

// ComputeApprovalPressure calculates Approval Pressure Analytics per Warrant Class (N1).
func (s *Store) ComputeApprovalPressure(ctx context.Context) ([]models.ApprovalPressureStat, error) {
	warrants, err := s.ListWarrants(ctx)
	if err != nil {
		return nil, err
	}
	exceptions, err := s.ListExceptions(ctx)
	if err != nil {
		return nil, err
	}
	classes := map[string]*models.ApprovalPressureStat{}
	ensure := func(cls string) *models.ApprovalPressureStat {
		if cls == "" {
			cls = "UNCLASSIFIED"
		}
		st, ok := classes[cls]
		if !ok {
			st = &models.ApprovalPressureStat{WarrantClass: cls}
			classes[cls] = st
		}
		return st
	}
	for _, w := range warrants {
		st := ensure(w.WarrantClass)
		if w.LiveStatus == "ACTIVE" {
			st.ActiveWarrants++
		}
	}
	cutoff24h := time.Now().UTC().Add(-24 * time.Hour)
	for _, ex := range exceptions {
		st := ensure(ex.WarrantClass)
		if ex.Status == "PENDING_DUAL_KEY" {
			st.PendingExceptions++
		}
		if ex.Status == "APPROVED" && ex.ResolvedAt != nil && ex.ResolvedAt.After(cutoff24h) {
			st.OverridesLast24h++
		}
	}

	out := make([]models.ApprovalPressureStat, 0, len(classes))
	for _, st := range classes {
		st.PressureScore = float64(st.PendingExceptions)*30.0 + float64(st.OverridesLast24h)*20.0
		if st.PressureScore > 100 {
			st.PressureScore = 100
		}
		switch {
		case st.PendingExceptions >= 3 || st.PressureScore >= 70:
			st.PressureStatus = "PRESSURE_HIGH"
		case st.PendingExceptions >= 1 || st.PressureScore >= 30:
			st.PressureStatus = "ELEVATED"
		default:
			st.PressureStatus = "NOMINAL"
		}
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WarrantClass < out[j].WarrantClass })
	return out, nil
}

// ComputeScoreboard calculates the Global Command Bar KPIs deterministically in a single SQL round-trip.
func (s *Store) ComputeScoreboard(ctx context.Context) (*models.GlobalScoreboard, error) {
	var fs models.FreezeState
	var thawRaw []byte
	var activeWarrants, activeBridges, eligibleCount, totalServices, pendingInbox, driftCount, rollbackCount int
	var medianTTVR, medianBridgeAge int64

	err := s.pool.QueryRow(ctx, `
		SELECT
			f.mode,
			f.actor,
			f.reason_code,
			f.thaw_dsse,
			f.updated_at,
			(
				SELECT COUNT(*)
				FROM warrant_envelopes w
				WHERE w.expires_at > NOW()
				  AND NOT EXISTS (
				      SELECT 1 FROM principal_revocations pr
				      WHERE pr.principal_id IN (w.slot1_principal_id, w.slot2_principal_id)
				         OR lower(pr.key_fingerprint) IN (lower(w.slot1_key_fp), lower(w.slot2_key_fp))
				  )
			) AS active_warrants,
			COALESCE((
				SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY a.ttvr_seconds)
				FROM attestation_records a
				WHERE a.minted_at > NOW() - INTERVAL '30 days'
			), 0)::BIGINT AS median_ttvr,
			(
				SELECT COUNT(*)
				FROM containment_bridges b
				WHERE b.status IN ('ARMED', 'REARMED_DRIFT')
			) AS active_bridges,
			COALESCE((
				SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY GREATEST(0, EXTRACT(EPOCH FROM (NOW() - b.armed_at))::BIGINT))
				FROM containment_bridges b
				WHERE b.status IN ('ARMED', 'REARMED_DRIFT')
			), 0)::BIGINT AS median_bridge_age,
			(SELECT COUNT(*) FROM estate_services WHERE eligible = TRUE) AS eligible_services,
			(SELECT COUNT(*) FROM estate_services) AS total_services,
			(SELECT COUNT(*) FROM ceiling_exceptions WHERE status = 'PENDING_DUAL_KEY') AS pending_inbox,
			(SELECT COUNT(*) FROM remediation_items WHERE status_health = 'DRIFT_VIOLATION') AS drift_count,
			(SELECT COUNT(*) FROM remediation_items WHERE status_health = 'ROLLBACK_FAILED') AS rollback_count
		FROM system_freeze_state f
		WHERE f.singleton_id = 1
	`).Scan(
		&fs.Mode,
		&fs.Actor,
		&fs.ReasonCode,
		&thawRaw,
		&fs.UpdatedAt,
		&activeWarrants,
		&medianTTVR,
		&activeBridges,
		&medianBridgeAge,
		&eligibleCount,
		&totalServices,
		&pendingInbox,
		&driftCount,
		&rollbackCount,
	)
	if err != nil {
		return nil, err
	}
	if len(thawRaw) > 0 {
		var env crypto.Envelope
		if json.Unmarshal(thawRaw, &env) == nil {
			fs.ThawDSSE = &env
		}
	}

	var eligPct float64
	if totalServices > 0 {
		eligPct = (float64(eligibleCount) / float64(totalServices)) * 100.0
	}

	return &models.GlobalScoreboard{
		FreezeState:                fs,
		ActiveWarrantsCount:        activeWarrants,
		FleetMedianTTVRSeconds:     medianTTVR,
		ActiveBridgesArmed:         activeBridges,
		MedianBridgeAgeSeconds:     medianBridgeAge,
		AutonomousEligibilityPct:   eligPct,
		EligibleServicesCount:      eligibleCount,
		TotalServicesCount:         totalServices,
		AwaitingDualKeyInboxCount:  pendingInbox,
		ActiveDriftViolationsCount: driftCount,
		RollbackFailuresCount:      rollbackCount,
	}, nil
}
