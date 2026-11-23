package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// UpsertAssetIdentityAlias registers or updates a scanner hostname/IP/UUID/cloud-ID alias mapping to an EstateService & canonical AssetKey.
func (s *Store) UpsertAssetIdentityAlias(ctx context.Context, alias models.AssetIdentityAlias) error {
	key := strings.ToLower(strings.TrimSpace(alias.AliasKey))
	if key == "" {
		return fmt.Errorf("empty alias_key")
	}
	if alias.AliasType == "" {
		alias.AliasType = "HOSTNAME"
	}
	if alias.AssetKey == "" {
		alias.AssetKey = key
	}
	if alias.PlatformFamily == "" {
		alias.PlatformFamily = "ESTATE_HOST"
	}
	if alias.CreatedAt.IsZero() {
		alias.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO asset_identity_aliases (
			alias_key, alias_type, service_id, asset_key, hostname, ipv4, ipv6,
			scanner_asset_id, cloud_instance_id, platform_family, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (alias_key) DO UPDATE SET
			alias_type = EXCLUDED.alias_type,
			service_id = EXCLUDED.service_id,
			asset_key = EXCLUDED.asset_key,
			hostname = EXCLUDED.hostname,
			ipv4 = EXCLUDED.ipv4,
			ipv6 = EXCLUDED.ipv6,
			scanner_asset_id = EXCLUDED.scanner_asset_id,
			cloud_instance_id = EXCLUDED.cloud_instance_id,
			platform_family = EXCLUDED.platform_family
	`,
		key, alias.AliasType, alias.ServiceID, alias.AssetKey, alias.Hostname, alias.IPv4, alias.IPv6,
		alias.ScannerAssetID, alias.CloudInstanceID, alias.PlatformFamily, alias.CreatedAt,
	)
	return err
}

// ListAssetIdentityAliases lists all configured scanner asset-identity aliases.
func (s *Store) ListAssetIdentityAliases(ctx context.Context) ([]models.AssetIdentityAlias, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT alias_key, alias_type, service_id, asset_key, hostname, ipv4, ipv6,
		       scanner_asset_id, cloud_instance_id, platform_family, created_at
		FROM asset_identity_aliases ORDER BY service_id ASC, alias_key ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.AssetIdentityAlias{}
	for rows.Next() {
		var a models.AssetIdentityAlias
		if err := rows.Scan(
			&a.AliasKey, &a.AliasType, &a.ServiceID, &a.AssetKey, &a.Hostname, &a.IPv4, &a.IPv6,
			&a.ScannerAssetID, &a.CloudInstanceID, &a.PlatformFamily, &a.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// BuildFinderAliasMaps builds lowercase lookup maps (alias -> service_id, alias -> asset_key) combining estate_services and asset_identity_aliases.
func (s *Store) BuildFinderAliasMaps(ctx context.Context) (map[string]string, map[string]string) {
	toSvc := map[string]string{}
	toAsset := map[string]string{}

	if svcs, err := s.ListEstateServices(ctx); err == nil {
		for _, svc := range svcs {
			low := strings.ToLower(svc.ServiceID)
			toSvc[low] = svc.ServiceID
			toAsset[low] = svc.ServiceID
		}
	}
	if aliases, err := s.ListAssetIdentityAliases(ctx); err == nil {
		for _, a := range aliases {
			tokens := []string{a.AliasKey, a.AssetKey, a.Hostname, a.IPv4, a.IPv6, a.ScannerAssetID, a.CloudInstanceID}
			for _, tok := range tokens {
				low := strings.ToLower(strings.TrimSpace(tok))
				if low == "" {
					continue
				}
				toSvc[low] = a.ServiceID
				toAsset[low] = a.AssetKey
			}
		}
	}
	return toSvc, toAsset
}

// FindMatchingWarrantForFinding evaluates Standing Warrant matching while enforcing the WN-7 Fail-Visible Unmapped Advisory rule:
// if f.CVEMappingStatus == "UNMAPPED_VENDOR_ADVISORY", a Standing Warrant ONLY matches if it explicitly lists f.VendorDetectionID
// (or "*") in AuthorizedVendorDetections! Otherwise returns ErrUnmappedVendorDetectionRequiresBinding.
func (s *Store) FindMatchingWarrantForFinding(ctx context.Context, serviceID string, f models.ExtractedFinding) (*models.WarrantRecord, error) {
	if f.CVEMappingStatus == models.CVEMappingStatusUnmappedVendor {
		detID := strings.ToUpper(strings.TrimSpace(f.VendorDetectionID))
		all, err := s.ListWarrants(ctx)
		if err != nil {
			return nil, err
		}
		for _, w := range all {
			if w.LiveStatus != "ACTIVE" || w.WarrantClass == models.WarrantClassSecretRotation || f.CVSSScore > w.MaxCVSS {
				continue
			}
			detAuthorized := false
			for _, authDet := range w.AuthorizedVendorDetections {
				if strings.EqualFold(strings.TrimSpace(authDet), detID) || strings.TrimSpace(authDet) == "*" {
					detAuthorized = true
					break
				}
			}
			if !detAuthorized {
				continue
			}
			for _, svc := range w.ScopeServices {
				if svc == "*" || svc == serviceID {
					cp := w
					return &cp, nil
				}
			}
		}
		return nil, fmt.Errorf("UNMAPPED_FINDING_REQUIRES_CLASS_BINDING: vendor detection %s has no CVE mapping and no active Standing Warrant explicitly authorizing %s", detID, detID)
	}
	return s.FindMatchingWarrant(ctx, serviceID, f.CVSSScore, f.CWEID)
}

// InsertDeploymentOrder immutably persists a DeploymentOrder (including its NativeRollbackSpec) BEFORE Wave 1 executes.
// Protected by PostgreSQL WORM trigger trg_worm_deployment_orders.
func (s *Store) InsertDeploymentOrder(ctx context.Context, order *models.DeploymentOrder) error {
	if order.CreatedAt.IsZero() {
		order.CreatedAt = time.Now().UTC()
	}
	if order.WaveNumber <= 0 {
		order.WaveNumber = 1
	}
	if order.TotalWaves <= 0 {
		order.TotalWaves = max(1, len(order.RolloutPlan.Waves))
	}
	fixRaw, err := json.Marshal(order.FixIdentity)
	if err != nil {
		return err
	}
	targetsRaw, err := json.Marshal(order.TargetAssets)
	if err != nil {
		return err
	}
	planRaw, err := json.Marshal(order.RolloutPlan)
	if err != nil {
		return err
	}
	rbRaw, err := json.Marshal(order.RollbackInstruction)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO deployment_orders (
			order_id, warrant_id, task_token_id, remediation_id, service_id,
			distributor_id, platform_family, fix_identity_json, target_assets_json,
			rollout_plan_json, rollback_instruction_json, native_job_ref,
			wave_number, total_waves, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
	`,
		order.OrderID, order.WarrantID, order.TaskTokenID, order.RemediationID, order.ServiceID,
		order.DistributorID, order.PlatformFamily, fixRaw, targetsRaw,
		planRaw, rbRaw, order.NativeJobRef,
		order.WaveNumber, order.TotalWaves, order.CreatedAt,
	)
	return err
}

// ListDeploymentOrders lists immutable DeploymentOrders newest first (optionally filtered by remediationID).
func (s *Store) ListDeploymentOrders(ctx context.Context, remediationID string) ([]models.DeploymentOrder, error) {
	query := `
		SELECT order_id, warrant_id, task_token_id, remediation_id, service_id,
		       distributor_id, platform_family, fix_identity_json, target_assets_json,
		       rollout_plan_json, rollback_instruction_json, native_job_ref,
		       wave_number, total_waves, created_at
		FROM deployment_orders
	`
	var args []any
	if strings.TrimSpace(remediationID) != "" {
		query += ` WHERE remediation_id = $1`
		args = append(args, strings.TrimSpace(remediationID))
	}
	query += ` ORDER BY seq_no DESC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.DeploymentOrder{}
	for rows.Next() {
		var o models.DeploymentOrder
		var fixRaw, targetsRaw, planRaw, rbRaw []byte
		if err := rows.Scan(
			&o.OrderID, &o.WarrantID, &o.TaskTokenID, &o.RemediationID, &o.ServiceID,
			&o.DistributorID, &o.PlatformFamily, &fixRaw, &targetsRaw,
			&planRaw, &rbRaw, &o.NativeJobRef,
			&o.WaveNumber, &o.TotalWaves, &o.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(fixRaw, &o.FixIdentity)
		_ = json.Unmarshal(targetsRaw, &o.TargetAssets)
		_ = json.Unmarshal(planRaw, &o.RolloutPlan)
		_ = json.Unmarshal(rbRaw, &o.RollbackInstruction)
		out = append(out, o)
	}
	return out, rows.Err()
}

// GetDeploymentOrder fetches one DeploymentOrder by order_id.
func (s *Store) GetDeploymentOrder(ctx context.Context, orderID string) (*models.DeploymentOrder, error) {
	all, err := s.ListDeploymentOrders(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, o := range all {
		if o.OrderID == orderID {
			cp := o
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("deployment order %q not found", orderID)
}

// AppendDeploymentResult appends an immutable per-asset DeploymentResult (or rollback result) to deployment_results.
func (s *Store) AppendDeploymentResult(ctx context.Context, res *models.DeploymentResult) error {
	if res.ObservedAt.IsZero() {
		res.ObservedAt = time.Now().UTC()
	}
	if res.WaveNumber <= 0 {
		res.WaveNumber = 1
	}
	res.RecomputeCounts()
	assetsRaw, err := json.Marshal(res.AssetResults)
	if err != nil {
		return err
	}
	if len(res.AssetResults) == 0 {
		assetsRaw = []byte("[]")
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO deployment_results (
			result_id, order_id, remediation_id, distributor_id, native_job_ref,
			wave_number, evidence_granularity, asset_results_json,
			targeted_count, landed_count, failed_count, pending_count,
			reboot_waiting_count, unreachable_count, rolled_back_count,
			stalled, is_rollback, rollback_reason, raw_distributor_report_sha256, observed_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
		)
	`,
		res.ResultID, res.OrderID, res.RemediationID, res.DistributorID, res.NativeJobRef,
		res.WaveNumber, res.EvidenceGranularity, assetsRaw,
		res.TargetedCount, res.LandedCount, res.FailedCount, res.PendingCount,
		res.RebootWaitingCount, res.UnreachableCount, res.RolledBackCount,
		res.Stalled, res.IsRollback, res.RollbackReason, res.RawDistributorReportSHA256, res.ObservedAt,
	)
	return err
}

// ListDeploymentResults lists append-only DeploymentResult records newest first (optionally filtered by orderID).
func (s *Store) ListDeploymentResults(ctx context.Context, orderID string) ([]models.DeploymentResult, error) {
	query := `
		SELECT result_id, order_id, remediation_id, distributor_id, native_job_ref,
		       wave_number, evidence_granularity, asset_results_json,
		       targeted_count, landed_count, failed_count, pending_count,
		       reboot_waiting_count, unreachable_count, rolled_back_count,
		       stalled, is_rollback, rollback_reason, raw_distributor_report_sha256, observed_at
		FROM deployment_results
	`
	var args []any
	if strings.TrimSpace(orderID) != "" {
		query += ` WHERE order_id = $1`
		args = append(args, strings.TrimSpace(orderID))
	}
	query += ` ORDER BY seq_no DESC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.DeploymentResult{}
	for rows.Next() {
		var r models.DeploymentResult
		var assetsRaw []byte
		if err := rows.Scan(
			&r.ResultID, &r.OrderID, &r.RemediationID, &r.DistributorID, &r.NativeJobRef,
			&r.WaveNumber, &r.EvidenceGranularity, &assetsRaw,
			&r.TargetedCount, &r.LandedCount, &r.FailedCount, &r.PendingCount,
			&r.RebootWaitingCount, &r.UnreachableCount, &r.RolledBackCount,
			&r.Stalled, &r.IsRollback, &r.RollbackReason, &r.RawDistributorReportSHA256, &r.ObservedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(assetsRaw, &r.AssetResults)
		out = append(out, r)
	}
	return out, rows.Err()
}
