package db

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/jackc/pgx/v5"
)

// ListWarrants returns all Standing Warrants annotated with live revocation/expiration status.
func (s *Store) ListWarrants(ctx context.Context) ([]models.WarrantRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT w.warrant_id, w.warrant_class, w.scope_services, w.scope_assets, w.authorized_vendor_detections, w.max_cvss, w.kev_eligible,
		       w.max_blast_radius_replicas, w.allow_stateful_patches,
		       w.allow_guarded_canary, w.allow_secret_rotation, w.auto_remediate_cwes,
		       w.min_canary_samples, w.stage_dwell_seconds,
		       w.sla_bridge_minutes, w.max_p99_latency_ms,
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
		var scopeRaw, scopeAssetsRaw, authVendorRaw, cwesRaw, envRaw []byte
		if err := rows.Scan(
			&w.WarrantID, &w.WarrantClass, &scopeRaw, &scopeAssetsRaw, &authVendorRaw, &w.MaxCVSS, &w.KEVEligible,
			&w.MaxBlastRadiusReplicas, &w.AllowStatefulPatches,
			&w.AllowGuardedCanary, &w.AllowSecretRotation, &cwesRaw,
			&w.MinCanarySamples, &w.StageDwellSeconds,
			&w.SLABridgeMinutes, &w.MaxP99LatencyMs,
			&w.IssuedAt, &w.ExpiresAt, &envRaw,
			&w.Slot1PrincipalID, &w.Slot1Email, &w.Slot1KeyFP, &w.Slot1Role,
			&w.Slot2PrincipalID, &w.Slot2Email, &w.Slot2KeyFP, &w.Slot2Role,
			&w.PrevHash, &w.EntryHash, &w.CreatedAt, &w.RevocationReason,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(scopeRaw, &w.ScopeServices)
		_ = json.Unmarshal(scopeAssetsRaw, &w.ScopeAssets)
		_ = json.Unmarshal(authVendorRaw, &w.AuthorizedVendorDetections)
		_ = json.Unmarshal(cwesRaw, &w.AutoRemediateCWEs)
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

// FindMatchingWarrant locates the newest ACTIVE image-patch Standing Warrant covering serviceID and cvssScore/CWE.
func (s *Store) FindMatchingWarrant(ctx context.Context, serviceID string, cvssScore float64, cweOpt ...string) (*models.WarrantRecord, error) {
	all, err := s.ListWarrants(ctx)
	if err != nil {
		return nil, err
	}
	targetCWE := ""
	if len(cweOpt) > 0 {
		targetCWE = strings.ToUpper(strings.TrimSpace(cweOpt[0]))
	}

	// Pass 1: Prefer warrant explicitly matching targetCWE in AutoRemediateCWEs when finding is an attack-path CWE
	if targetCWE != "" {
		for _, w := range all {
			if w.LiveStatus != "ACTIVE" || w.WarrantClass == models.WarrantClassSecretRotation || cvssScore > w.MaxCVSS {
				continue
			}
			cweMatched := false
			for _, c := range w.AutoRemediateCWEs {
				if strings.EqualFold(c, targetCWE) {
					cweMatched = true
					break
				}
			}
			if !cweMatched {
				continue
			}
			for _, svc := range w.ScopeServices {
				if svc == "*" || svc == serviceID {
					cp := w
					return &cp, nil
				}
			}
		}
	}

	// Pass 2: Standard scope + CVSS ceiling match (excluding dedicated SECRET-ROTATION-STATELESS warrants)
	for _, w := range all {
		if w.LiveStatus != "ACTIVE" || w.WarrantClass == models.WarrantClassSecretRotation || cvssScore > w.MaxCVSS {
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

// FindMatchingSecretWarrant locates the newest ACTIVE SECRET-ROTATION-STATELESS (or allow_secret_rotation) warrant for serviceID.
func (s *Store) FindMatchingSecretWarrant(ctx context.Context, serviceID string) (*models.WarrantRecord, error) {
	all, err := s.ListWarrants(ctx)
	if err != nil {
		return nil, err
	}
	for _, w := range all {
		if w.LiveStatus != "ACTIVE" {
			continue
		}
		if w.WarrantClass != models.WarrantClassSecretRotation && !w.AllowSecretRotation {
			continue
		}
		for _, svc := range w.ScopeServices {
			if svc == "*" || svc == serviceID {
				cp := w
				return &cp, nil
			}
		}
	}
	return nil, fmt.Errorf("NO_ACTIVE_SECRET_ROTATION_WARRANT for service=%s", serviceID)
}

// GetFreezeState fetches the singleton emergency freeze state including monotonic freeze_epoch.
func (s *Store) GetFreezeState(ctx context.Context) (models.FreezeState, error) {
	var fs models.FreezeState
	var thawRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT mode, actor, reason_code, freeze_epoch, thaw_dsse, updated_at
		FROM system_freeze_state WHERE singleton_id = 1
	`).Scan(&fs.Mode, &fs.Actor, &fs.ReasonCode, &fs.FreezeEpoch, &thawRaw, &fs.UpdatedAt)
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

// TransitionFreezeState updates the singleton freeze posture, increments freeze_epoch on every freeze entry,
// populates fs.FreezeEpoch, and fires PostgreSQL LISTEN/NOTIFY via trigger.
func (s *Store) TransitionFreezeState(ctx context.Context, fs *models.FreezeState) error {
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
	return s.pool.QueryRow(ctx, `
		UPDATE system_freeze_state
		SET mode = $1,
		    actor = $2,
		    reason_code = $3,
		    freeze_epoch = CASE WHEN $1 IN ('FREEZE_HOLD', 'FREEZE_ROLLBACK') THEN freeze_epoch + 1 ELSE freeze_epoch END,
		    thaw_dsse = $4,
		    updated_at = $5
		WHERE singleton_id = 1
		RETURNING freeze_epoch
	`, fs.Mode, fs.Actor, fs.ReasonCode, thawRaw, fs.UpdatedAt).Scan(&fs.FreezeEpoch)
}

// SetFreezeState updates the singleton freeze posture and fires PostgreSQL LISTEN/NOTIFY via trigger.
func (s *Store) SetFreezeState(ctx context.Context, fs models.FreezeState) error {
	return s.TransitionFreezeState(ctx, &fs)
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
			Mode        string `json:"mode"`
			Actor       string `json:"actor"`
			ReasonCode  string `json:"reason_code"`
			FreezeEpoch int64  `json:"freeze_epoch"`
			UpdatedAt   string `json:"updated_at"`
		}
		if json.Unmarshal([]byte(notif.Payload), &payload) == nil {
			ts, _ := time.Parse(time.RFC3339, payload.UpdatedAt)
			onChange(models.FreezeState{
				Mode:        payload.Mode,
				Actor:       payload.Actor,
				ReasonCode:  payload.ReasonCode,
				FreezeEpoch: payload.FreezeEpoch,
				UpdatedAt:   ts,
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
	volPathsJSON, _ := json.Marshal(svc.VolatileJSONPaths)
	if len(svc.VolatileJSONPaths) == 0 {
		volPathsJSON = []byte("[]")
	}
	unordPathsJSON, _ := json.Marshal(svc.UnorderedArrayPaths)
	if len(svc.UnorderedArrayPaths) == 0 {
		unordPathsJSON = []byte("[]")
	}
	egressJSON, _ := json.Marshal(svc.AllowedEgressServices)
	if len(svc.AllowedEgressServices) == 0 {
		egressJSON = []byte(`["kube-dns.kube-system.svc.cluster.local"]`)
	}
	if svc.AutonomyTier == "" {
		if svc.Eligible {
			svc.AutonomyTier = models.AutonomyTier1FullAutonomous
		} else {
			svc.AutonomyTier = models.AutonomyTier3ContainAndCAB
		}
	}
	if svc.ShadowDBMode == "" {
		if svc.ReadonlyShadowReplica {
			svc.ShadowDBMode = "EPHEMERAL_COW_BRANCH"
		} else {
			svc.ShadowDBMode = "NONE"
		}
	}
	if svc.UpdatedAt.IsZero() {
		svc.UpdatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO estate_services (
			service_id, display_name, namespace, tier, warrant_class, current_digest, current_purl, sbom_purls,
			replicas, test_coverage_pct, otel_health_probes, readonly_shadow_replica, shadow_db_mode,
			rollback_automation_verified, readonly_root_filesystem, noexec_tmp_mounts, allowed_egress_services,
			allow_kube_apiserver_egress, baseline_syscalls, volatile_json_paths, unordered_array_paths,
			eligible, autonomy_tier, eligibility_checklist, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
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
			shadow_db_mode = EXCLUDED.shadow_db_mode,
			rollback_automation_verified = EXCLUDED.rollback_automation_verified,
			readonly_root_filesystem = EXCLUDED.readonly_root_filesystem,
			noexec_tmp_mounts = EXCLUDED.noexec_tmp_mounts,
			allowed_egress_services = EXCLUDED.allowed_egress_services,
			allow_kube_apiserver_egress = EXCLUDED.allow_kube_apiserver_egress,
			baseline_syscalls = EXCLUDED.baseline_syscalls,
			volatile_json_paths = EXCLUDED.volatile_json_paths,
			unordered_array_paths = EXCLUDED.unordered_array_paths,
			eligible = EXCLUDED.eligible,
			autonomy_tier = EXCLUDED.autonomy_tier,
			eligibility_checklist = EXCLUDED.eligibility_checklist,
			updated_at = EXCLUDED.updated_at
	`,
		svc.ServiceID, svc.DisplayName, svc.Namespace, svc.Tier, svc.WarrantClass, svc.CurrentDigest, svc.CurrentPURL, sbomJSON,
		svc.Replicas, svc.TestCoveragePct, svc.OtelHealthProbes, svc.ReadonlyShadowReplica, svc.ShadowDBMode,
		svc.RollbackAutomationVerified, svc.ReadOnlyRootFilesystem, svc.NoExecTmpMounts, egressJSON,
		svc.AllowKubeAPIServerEgress, syscallsJSON, volPathsJSON, unordPathsJSON,
		svc.Eligible, svc.AutonomyTier, checklistJSON, svc.UpdatedAt,
	)
	return err
}

// ListEstateServices returns all registered estate services.
func (s *Store) ListEstateServices(ctx context.Context) ([]models.EstateService, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT service_id, display_name, namespace, tier, warrant_class, current_digest, current_purl, sbom_purls,
		       replicas, test_coverage_pct, otel_health_probes, readonly_shadow_replica, shadow_db_mode,
		       rollback_automation_verified, readonly_root_filesystem, noexec_tmp_mounts, allowed_egress_services,
		       allow_kube_apiserver_egress, baseline_syscalls, volatile_json_paths, unordered_array_paths,
		       eligible, autonomy_tier, eligibility_checklist, updated_at
		FROM estate_services ORDER BY tier ASC, service_id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.EstateService{}
	for rows.Next() {
		var svc models.EstateService
		var sbomRaw, egressRaw, sysRaw, volRaw, unordRaw, checkRaw []byte
		if err := rows.Scan(
			&svc.ServiceID, &svc.DisplayName, &svc.Namespace, &svc.Tier, &svc.WarrantClass, &svc.CurrentDigest, &svc.CurrentPURL, &sbomRaw,
			&svc.Replicas, &svc.TestCoveragePct, &svc.OtelHealthProbes, &svc.ReadonlyShadowReplica, &svc.ShadowDBMode,
			&svc.RollbackAutomationVerified, &svc.ReadOnlyRootFilesystem, &svc.NoExecTmpMounts, &egressRaw,
			&svc.AllowKubeAPIServerEgress, &sysRaw, &volRaw, &unordRaw,
			&svc.Eligible, &svc.AutonomyTier, &checkRaw, &svc.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(sbomRaw, &svc.SBOMPURLs)
		_ = json.Unmarshal(egressRaw, &svc.AllowedEgressServices)
		_ = json.Unmarshal(sysRaw, &svc.BaselineSyscalls)
		_ = json.Unmarshal(volRaw, &svc.VolatileJSONPaths)
		_ = json.Unmarshal(unordRaw, &svc.UnorderedArrayPaths)
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
	var patchRaw, shadowRaw, assetIdentRaw []byte
	if item.PatchMetadata != nil {
		patchRaw, _ = json.Marshal(item.PatchMetadata)
	}
	if item.ShadowReport != nil {
		shadowRaw, _ = json.Marshal(item.ShadowReport)
	}
	if item.AssetIdentity != nil {
		assetIdentRaw, _ = json.Marshal(item.AssetIdentity)
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	item.UpdatedAt = time.Now().UTC()
	if item.AssuranceTier == "" {
		item.AssuranceTier = "PENDING"
	}
	if item.RemediationKind == "" {
		item.RemediationKind = models.RemediationKindImagePatch
	}
	if item.CVEMappingStatus == "" {
		item.CVEMappingStatus = models.CVEMappingStatusMapped
	}
	if item.NormalizedDetectionState == "" {
		item.NormalizedDetectionState = models.DetectionStateActive
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO remediation_items (
			remediation_id, remediation_kind, cve_id, cwe_id, is_kev, chained_exploit_enabler, cvss_score, service_id, warrant_id,
			secret_resource_name, vulnerable_digest, patched_digest, package_purl, vulnerable_symbol, exploit_vector,
			stage, status_health, blocker_code, canary_weight,
			stateless_passed, schema_diff_passed, syscall_diff_passed,
			twin_replay_status, assurance_tier, pod_sweep_matched, pod_sweep_total,
			lockout_policy_id, bridge_id, bridge_sla_minutes, attestation_id,
			finder_vendor, vendor_detection_id, cve_mapping_status, normalized_detection_state,
			asset_identity_json, first_seen_at, last_seen_at,
			distributor_id, latest_order_id, closure_completeness,
			targeted_asset_count, landed_asset_count, failed_asset_count, pending_asset_count, reboot_waiting_count, rolled_back_asset_count,
			patch_metadata, shadow_report, created_at, bridged_at, closed_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
			$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,
			$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,
			$47,$48,$49,$50,$51,$52
		)
		ON CONFLICT (remediation_id) DO UPDATE SET
			remediation_kind = EXCLUDED.remediation_kind,
			warrant_id = EXCLUDED.warrant_id,
			secret_resource_name = EXCLUDED.secret_resource_name,
			patched_digest = EXCLUDED.patched_digest,
			stage = EXCLUDED.stage,
			status_health = EXCLUDED.status_health,
			blocker_code = EXCLUDED.blocker_code,
			canary_weight = EXCLUDED.canary_weight,
			stateless_passed = EXCLUDED.stateless_passed,
			schema_diff_passed = EXCLUDED.schema_diff_passed,
			syscall_diff_passed = EXCLUDED.syscall_diff_passed,
			twin_replay_status = EXCLUDED.twin_replay_status,
			assurance_tier = EXCLUDED.assurance_tier,
			pod_sweep_matched = EXCLUDED.pod_sweep_matched,
			pod_sweep_total = EXCLUDED.pod_sweep_total,
			lockout_policy_id = EXCLUDED.lockout_policy_id,
			bridge_id = EXCLUDED.bridge_id,
			attestation_id = EXCLUDED.attestation_id,
			finder_vendor = EXCLUDED.finder_vendor,
			vendor_detection_id = EXCLUDED.vendor_detection_id,
			cve_mapping_status = EXCLUDED.cve_mapping_status,
			normalized_detection_state = EXCLUDED.normalized_detection_state,
			asset_identity_json = EXCLUDED.asset_identity_json,
			first_seen_at = EXCLUDED.first_seen_at,
			last_seen_at = EXCLUDED.last_seen_at,
			distributor_id = EXCLUDED.distributor_id,
			latest_order_id = EXCLUDED.latest_order_id,
			closure_completeness = EXCLUDED.closure_completeness,
			targeted_asset_count = EXCLUDED.targeted_asset_count,
			landed_asset_count = EXCLUDED.landed_asset_count,
			failed_asset_count = EXCLUDED.failed_asset_count,
			pending_asset_count = EXCLUDED.pending_asset_count,
			reboot_waiting_count = EXCLUDED.reboot_waiting_count,
			rolled_back_asset_count = EXCLUDED.rolled_back_asset_count,
			patch_metadata = EXCLUDED.patch_metadata,
			shadow_report = EXCLUDED.shadow_report,
			bridged_at = EXCLUDED.bridged_at,
			closed_at = EXCLUDED.closed_at,
			updated_at = EXCLUDED.updated_at
	`,
		item.RemediationID, item.RemediationKind, item.CVEID, item.CWEID, item.IsKEV, item.ChainedExploitEnabler, item.CVSSScore, item.ServiceID, item.WarrantID,
		item.SecretResourceName, item.VulnerableDigest, item.PatchedDigest, item.PackagePURL, item.VulnerableSymbol, item.ExploitVector,
		item.Stage, item.StatusHealth, item.BlockerCode, item.CanaryWeight,
		item.StatelessPassed, item.SchemaDiffPassed, item.SyscallPassed,
		item.TwinReplayStatus, item.AssuranceTier, item.PodSweepMatched, item.PodSweepTotal,
		item.LockoutPolicyID, item.BridgeID, item.BridgeSLAMIN, item.AttestationID,
		item.FinderVendor, item.VendorDetectionID, item.CVEMappingStatus, item.NormalizedDetectionState,
		assetIdentRaw, item.FirstSeenAt, item.LastSeenAt,
		item.DistributorID, item.LatestOrderID, item.ClosureCompleteness,
		item.TargetedAssetCount, item.LandedAssetCount, item.FailedAssetCount, item.PendingAssetCount, item.RebootWaitingCount, item.RolledBackAssetCount,
		patchRaw, shadowRaw, item.CreatedAt, item.BridgedAt, item.ClosedAt, item.UpdatedAt,
	)
	return err
}

// ListRemediations returns all Race Pipeline remediation items ordered newest first.
func (s *Store) ListRemediations(ctx context.Context) ([]models.RemediationItem, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT remediation_id, remediation_kind, cve_id, cwe_id, is_kev, chained_exploit_enabler, cvss_score, service_id, warrant_id,
		       secret_resource_name, vulnerable_digest, patched_digest, package_purl, vulnerable_symbol, exploit_vector,
		       stage, status_health, blocker_code, canary_weight,
		       stateless_passed, schema_diff_passed, syscall_diff_passed,
		       twin_replay_status, assurance_tier, pod_sweep_matched, pod_sweep_total,
		       lockout_policy_id, bridge_id, bridge_sla_minutes, attestation_id,
		       finder_vendor, vendor_detection_id, cve_mapping_status, normalized_detection_state,
		       asset_identity_json, first_seen_at, last_seen_at,
		       distributor_id, latest_order_id, closure_completeness,
		       targeted_asset_count, landed_asset_count, failed_asset_count, pending_asset_count, reboot_waiting_count, rolled_back_asset_count,
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
		var patchRaw, shadowRaw, assetIdentRaw []byte
		if err := rows.Scan(
			&r.RemediationID, &r.RemediationKind, &r.CVEID, &r.CWEID, &r.IsKEV, &r.ChainedExploitEnabler, &r.CVSSScore, &r.ServiceID, &r.WarrantID,
			&r.SecretResourceName, &r.VulnerableDigest, &r.PatchedDigest, &r.PackagePURL, &r.VulnerableSymbol, &r.ExploitVector,
			&r.Stage, &r.StatusHealth, &r.BlockerCode, &r.CanaryWeight,
			&r.StatelessPassed, &r.SchemaDiffPassed, &r.SyscallPassed,
			&r.TwinReplayStatus, &r.AssuranceTier, &r.PodSweepMatched, &r.PodSweepTotal,
			&r.LockoutPolicyID, &r.BridgeID, &r.BridgeSLAMIN, &r.AttestationID,
			&r.FinderVendor, &r.VendorDetectionID, &r.CVEMappingStatus, &r.NormalizedDetectionState,
			&assetIdentRaw, &r.FirstSeenAt, &r.LastSeenAt,
			&r.DistributorID, &r.LatestOrderID, &r.ClosureCompleteness,
			&r.TargetedAssetCount, &r.LandedAssetCount, &r.FailedAssetCount, &r.PendingAssetCount, &r.RebootWaitingCount, &r.RolledBackAssetCount,
			&patchRaw, &shadowRaw, &r.CreatedAt, &r.BridgedAt, &r.ClosedAt, &r.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(assetIdentRaw) > 0 {
			var ai models.AssetIdentity
			if json.Unmarshal(assetIdentRaw, &ai) == nil {
				r.AssetIdentity = &ai
			}
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
	if b.ContainmentMode == "" {
		b.ContainmentMode = models.ContainmentModeZeroProseQuarantine
	}
	peersJSON, _ := json.Marshal(b.AllowedEgressPeers)
	if len(b.AllowedEgressPeers) == 0 {
		peersJSON = []byte(`["kube-dns.kube-system.svc.cluster.local"]`)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO containment_bridges (
			bridge_id, remediation_id, service_id, cve_id, bridge_type, containment_mode, rulepack_id,
			metadata_plane_blocked, allowed_egress_peers, status,
			sla_minutes, blocker_reason_code, cilium_manifest_yaml, k8s_netpol_yaml, envoy_filter_json,
			armed_at, retired_at, rearmed_count
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (bridge_id) DO UPDATE SET
			containment_mode = EXCLUDED.containment_mode,
			rulepack_id = EXCLUDED.rulepack_id,
			metadata_plane_blocked = EXCLUDED.metadata_plane_blocked,
			allowed_egress_peers = EXCLUDED.allowed_egress_peers,
			status = EXCLUDED.status,
			blocker_reason_code = EXCLUDED.blocker_reason_code,
			retired_at = EXCLUDED.retired_at,
			rearmed_count = EXCLUDED.rearmed_count
	`,
		b.BridgeID, b.RemediationID, b.ServiceID, b.CVEID, b.BridgeType, b.ContainmentMode, b.RulepackID,
		b.MetadataPlaneBlocked, peersJSON, b.Status,
		b.SLABridgeMinutes, b.BlockerReasonCode, b.CiliumManifestYAML, b.K8sNetpolYAML, b.EnvoyFilterJSON,
		b.ArmedAt, b.RetiredAt, b.RearmedCount,
	)
	return err
}

// ListBridges lists all containment bridges ordered by active status then armed_at.
func (s *Store) ListBridges(ctx context.Context) ([]models.ContainmentBridge, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT bridge_id, remediation_id, service_id, cve_id, bridge_type, containment_mode, rulepack_id,
		       metadata_plane_blocked, allowed_egress_peers, status,
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
		var peersRaw []byte
		if err := rows.Scan(
			&b.BridgeID, &b.RemediationID, &b.ServiceID, &b.CVEID, &b.BridgeType, &b.ContainmentMode, &b.RulepackID,
			&b.MetadataPlaneBlocked, &peersRaw, &b.Status,
			&b.SLABridgeMinutes, &b.BlockerReasonCode, &b.CiliumManifestYAML, &b.K8sNetpolYAML, &b.EnvoyFilterJSON,
			&b.ArmedAt, &b.RetiredAt, &b.RearmedCount,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(peersRaw, &b.AllowedEgressPeers)
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
	if l.Status == "" {
		l.Status = "ENFORCED"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO admission_lockouts (
			lockout_id, remediation_id, service_id, cve_id, banned_digest, patched_digest,
			policy_name, status, suspended_reason, vap_manifest_yaml, gatekeeper_rego, enforced_at, drift_count, last_drift_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (lockout_id) DO UPDATE SET
			status = EXCLUDED.status,
			suspended_reason = EXCLUDED.suspended_reason,
			drift_count = EXCLUDED.drift_count,
			last_drift_at = EXCLUDED.last_drift_at
	`,
		l.LockoutID, l.RemediationID, l.ServiceID, l.CVEID, l.BannedDigest, l.PatchedDigest,
		l.PolicyName, l.Status, l.SuspendedReason, l.VAPManifestYAML, l.GatekeeperRego, l.EnforcedAt, l.DriftCount, l.LastDriftAt,
	)
	return err
}

// ListLockouts returns all permanent Admission Lockout entries.
func (s *Store) ListLockouts(ctx context.Context) ([]models.AdmissionLockout, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT lockout_id, remediation_id, service_id, cve_id, banned_digest, patched_digest,
		       policy_name, status, suspended_reason, vap_manifest_yaml, gatekeeper_rego, enforced_at, drift_count, last_drift_at
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
			&l.PolicyName, &l.Status, &l.SuspendedReason, &l.VAPManifestYAML, &l.GatekeeperRego, &l.EnforcedAt, &l.DriftCount, &l.LastDriftAt,
		); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// RecordDriftIncident inserts a runtime drift incident and increments the lockout drift counter when applicable.
func (s *Store) RecordDriftIncident(ctx context.Context, inc models.DriftIncident) error {
	if inc.DetectedAt.IsZero() {
		inc.DetectedAt = time.Now().UTC()
	}
	if inc.DriftKind == "" {
		inc.DriftKind = models.DriftKindBannedDigest
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO drift_incidents (
			incident_id, drift_kind, lockout_id, remediation_id, service_id, cve_id,
			detected_digest, violating_artifact, rogue_pod_name, pod_cordoned, pod_recycled,
			rearmed_bridge_id, detection_latency_ms, detected_at, resolved_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (incident_id) DO NOTHING
	`,
		inc.IncidentID, inc.DriftKind, inc.LockoutID, inc.RemediationID, inc.ServiceID, inc.CVEID,
		inc.DetectedDigest, inc.ViolatingArtifact, inc.RoguePodName, inc.PodCordoned, inc.PodRecycled,
		inc.RearmedBridgeID, inc.DetectionLatencyMs, inc.DetectedAt, inc.ResolvedAt,
	)
	if err != nil {
		return err
	}
	if inc.LockoutID != "" && inc.LockoutID != "TETRAGON_EBPF_RUNTIME" {
		_, _ = s.pool.Exec(ctx, `
			UPDATE admission_lockouts SET drift_count = drift_count + 1, last_drift_at = $2 WHERE lockout_id = $1
		`, inc.LockoutID, inc.DetectedAt)
	}
	return nil
}

// ListDriftIncidents lists all runtime drift violations newest first.
func (s *Store) ListDriftIncidents(ctx context.Context) ([]models.DriftIncident, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT incident_id, drift_kind, lockout_id, remediation_id, service_id, cve_id,
		       detected_digest, violating_artifact, rogue_pod_name, pod_cordoned, pod_recycled,
		       rearmed_bridge_id, detection_latency_ms, detected_at, resolved_at
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
			&inc.IncidentID, &inc.DriftKind, &inc.LockoutID, &inc.RemediationID, &inc.ServiceID, &inc.CVEID,
			&inc.DetectedDigest, &inc.ViolatingArtifact, &inc.RoguePodName, &inc.PodCordoned, &inc.PodRecycled,
			&inc.RearmedBridgeID, &inc.DetectionLatencyMs, &inc.DetectedAt, &inc.ResolvedAt,
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
		SELECT action_id, task_token_id, warrant_id, remediation_id,
		       authority_mode, commissioning_function_id, agent_id, delegation_depth, act_chain_json,
		       worker_name, target_asset, action_type,
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
		var actRaw []byte
		if err := rows.Scan(
			&e.ActionID, &e.TaskTokenID, &e.WarrantID, &e.RemediationID,
			&e.AuthorityMode, &e.CommissioningFunctionID, &e.AgentID, &e.DelegationDepth, &actRaw,
			&e.WorkerName, &e.TargetAsset, &e.ActionType,
			&e.Slot1PrincipalID, &e.Slot2PrincipalID, &e.EgressProfile,
			&e.RawInputSHA256, &e.ExtractorDigest, &e.TypedOutputSHA256,
			&e.TokenTTLSec, &e.Status, &e.ViolationCode, &e.PrevHash, &e.EntryHash, &e.ExecutedAt,
		); err != nil {
			return nil, err
		}
		if len(actRaw) > 0 {
			var act models.ActorClaim
			if json.Unmarshal(actRaw, &act) == nil {
				e.ActChain = &act
			}
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
		       twin_transcript_sha256, assurance_tier,
		       closure_completeness, targeted_asset_count, landed_asset_count, failed_asset_count, pending_asset_count, reboot_waiting_count,
		       distributor_id, distributor_order_id, distributor_report_sha256,
		       signer_backend, fleet_digest_manifest, lockout_policy_id, reverify_expires_at,
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
			&a.TwinTranscriptSHA256, &a.AssuranceTier,
			&a.ClosureCompleteness, &a.TargetedAssetCount, &a.LandedAssetCount, &a.FailedAssetCount, &a.PendingAssetCount, &a.RebootWaitingCount,
			&a.DistributorID, &a.DistributorOrderID, &a.DistributorReportSHA256,
			&a.SignerBackend, &manifestRaw, &a.LockoutPolicyID, &a.ReverifyExpiresAt,
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
			f.freeze_epoch,
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
		&fs.FreezeEpoch,
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

	activeAgents := 0
	quarantinedAgents := 0
	if agents, aErr := s.ListAgentIdentities(ctx); aErr == nil {
		for _, a := range agents {
			switch a.SponsorshipState {
			case models.SponsorshipOrphanQuarantined, models.SponsorshipLeaseExpired, models.SponsorshipRevokedCompromise, models.SponsorshipRevokedKillSwitch:
				quarantinedAgents++
			default:
				activeAgents++
			}
		}
	}
	pendingTransfersCount := 0
	if transfers, tErr := s.ListPendingSponsorTransfers(ctx); tErr == nil {
		pendingTransfersCount = len(transfers)
	}

	var unmappedCount, partialClosuresCount int
	_ = s.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM remediation_items WHERE cve_mapping_status = 'UNMAPPED_VENDOR_ADVISORY'),
			(SELECT COUNT(*) FROM attestation_records WHERE closure_completeness = 'PARTIAL')
	`).Scan(&unmappedCount, &partialClosuresCount)

	return &models.GlobalScoreboard{
		FreezeState:                  fs,
		ActiveWarrantsCount:          activeWarrants,
		ActiveAgentsCount:            activeAgents,
		QuarantinedAgentsCount:       quarantinedAgents,
		PendingSponsorTransfersCount: pendingTransfersCount,
		FleetMedianTTVRSeconds:       medianTTVR,
		ActiveBridgesArmed:           activeBridges,
		MedianBridgeAgeSeconds:       medianBridgeAge,
		AutonomousEligibilityPct:     eligPct,
		EligibleServicesCount:        eligibleCount,
		TotalServicesCount:           totalServices,
		AwaitingDualKeyInboxCount:    pendingInbox + pendingTransfersCount,
		ActiveDriftViolationsCount:   driftCount,
		RollbackFailuresCount:        rollbackCount,
		UnmappedAdvisoriesCount:      unmappedCount,
		PartialClosuresCount:         partialClosuresCount,
	}, nil
}

// RegisterKernelPublicKey appends the active kernel attestation public key into the immutable, hash-chained kernel_public_keys ring.
// Any key beyond seq_no = 1 MUST carry a valid rotation_dsse signed by the preceding kernel key (or 2-of-2 active SO+AO principals)
// OR match the configured external KMS signing identity (WARRANT_KMS_SIGN_URL + WARRANT_KMS_PUBLIC_KEY_B64).
func (s *Store) RegisterKernelPublicKey(ctx context.Context, pk crypto.PrincipalKey, backendMode string, rotationDSSE ...*crypto.Envelope) error {
	pubB64 := base64.StdEncoding.EncodeToString(pk.PublicKeyBytes)

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKernelKeyChain); err != nil {
		return err
	}

	var existPubB64 string
	err = tx.QueryRow(ctx, `SELECT public_key_b64 FROM kernel_public_keys WHERE key_id = $1`, pk.KeyID).Scan(&existPubB64)
	if err == nil {
		if existPubB64 == pubB64 {
			return nil
		}
		return fmt.Errorf("KERNEL_KEY_CONFLICT: key_id %q already registered with different public key", pk.KeyID)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	prevHash := GenesisHash
	var prevKeyID, prevAlg, prevPubB64, prevFP string
	err = tx.QueryRow(ctx, `
		SELECT entry_hash, key_id, alg, public_key_b64, key_fingerprint
		FROM kernel_public_keys ORDER BY seq_no DESC LIMIT 1
	`).Scan(&prevHash, &prevKeyID, &prevAlg, &prevPubB64, &prevFP)
	hasPriorKey := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	var rotEnv *crypto.Envelope
	if len(rotationDSSE) > 0 {
		rotEnv = rotationDSSE[0]
	}

	if hasPriorKey {
		if rotEnv == nil {
			return fmt.Errorf(
				"%s: kernel key rotation beyond seq_no=1 requires rotation_dsse signed by preceding kernel key %s or 2-of-2 ROTATE_KERNEL_KEY principals",
				CodeUnattestedAuthorityLineageInsert, prevKeyID,
			)
		}
		prevPubBytes, _ := crypto.DecodeBase64Any(prevPubB64)
		prevPK := &crypto.PrincipalKey{
			PrincipalID:    "sys-warrantd-kernel",
			Role:           crypto.RoleAttestationKernel,
			KeyID:          prevKeyID,
			Alg:            prevAlg,
			PublicKeyBytes: prevPubBytes,
			KeyFingerprint: prevFP,
		}
		rec := models.KernelPublicKeyRecord{
			KeyID:          pk.KeyID,
			Alg:            pk.Alg,
			PublicKeyB64:   pubB64,
			KeyFingerprint: pk.KeyFingerprint,
			BackendMode:    backendMode,
		}
		resolver := StoreKeyResolver{Store: s, Ctx: ctx}
		if vErr := verifyKernelKeyRotationDSSE(rotEnv, rec, prevPK, resolver, s.WebAuthnConfig()); vErr != nil {
			return vErr
		}
	}

	var rotRaw []byte
	if rotEnv != nil {
		rotRaw, err = crypto.CanonicalizeStruct(rotEnv)
		if err != nil {
			return err
		}
	}

	entryHash := ComputeKernelKeyEntryHash(prevHash, pk.KeyID, pk.Alg, pubB64, pk.KeyFingerprint, backendMode)

	_, err = tx.Exec(ctx, `
		INSERT INTO kernel_public_keys (key_id, alg, public_key_b64, key_fingerprint, backend_mode, rotation_dsse, prev_hash, entry_hash, registered_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, pk.KeyID, pk.Alg, pubB64, pk.KeyFingerprint, backendMode, rotRaw, prevHash, entryHash, time.Now().UTC())
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListKernelPublicKeys returns all historical and active kernel verification public keys newest first.
func (s *Store) ListKernelPublicKeys(ctx context.Context) ([]models.KernelPublicKeyRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT key_id, alg, public_key_b64, key_fingerprint, backend_mode, rotation_dsse, prev_hash, entry_hash, registered_at
		FROM kernel_public_keys
		ORDER BY seq_no DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.KernelPublicKeyRecord{}
	for rows.Next() {
		var r models.KernelPublicKeyRecord
		var rotRaw []byte
		if err := rows.Scan(&r.KeyID, &r.Alg, &r.PublicKeyB64, &r.KeyFingerprint, &r.BackendMode, &rotRaw, &r.PrevHash, &r.EntryHash, &r.RegisteredAt); err != nil {
			return nil, err
		}
		if len(rotRaw) > 0 {
			var env crypto.Envelope
			if json.Unmarshal(rotRaw, &env) == nil {
				r.RotationDSSE = &env
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
