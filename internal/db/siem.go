package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const lockSIEMConfigAuditChain int64 = 1001014

// ComputeSIEMConfigAuditEntryHash computes the deterministic SHA-256 chain link for WORM siem_config_audit.
func ComputeSIEMConfigAuditEntryHash(prevHash string, rec models.SIEMConfigAuditRecord) string {
	material := strings.Join([]string{
		"siem_config_audit",
		prevHash,
		rec.AuditID,
		rec.DestinationID,
		rec.SIEMVendor,
		rec.Action,
		rec.Actor,
		rec.ConfigSHA256,
		rec.OccurredAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}, "|")
	return crypto.SHA256Hex([]byte(material))
}

// UpsertSIEMDestinationWithAudit creates or updates a SIEM destination in PostgreSQL (storing ONLY a credential
// reference URI — never raw secrets) and atomically appends a hash-chained WORM record into siem_config_audit.
func (s *Store) UpsertSIEMDestinationWithAudit(
	ctx context.Context,
	dest *models.SIEMDestination,
	action string,
	actor string,
) (*models.SIEMConfigAuditRecord, error) {
	now := time.Now().UTC().Truncate(time.Second)
	if dest.CreatedAt.IsZero() {
		dest.CreatedAt = now
	}
	dest.UpdatedAt = now
	if dest.CreatedBy == "" {
		dest.CreatedBy = actor
	}
	dest.UpdatedBy = actor
	if dest.BatchSize <= 0 {
		dest.BatchSize = 50
	}
	if dest.ScheduleSeconds <= 0 {
		dest.ScheduleSeconds = 10
	}
	if strings.TrimSpace(dest.CredentialRef) == "" {
		dest.CredentialRef = "none://"
	}

	optsJSON, _ := json.Marshal(dest.VendorOptions)
	if len(dest.VendorOptions) == 0 {
		optsJSON = []byte("{}")
	}
	recTypesJSON, _ := json.Marshal(dest.RecordTypes)
	if len(dest.RecordTypes) == 0 {
		recTypesJSON = []byte("[]")
	}
	viewsJSON, _ := json.Marshal(dest.ConsoleViews)
	if len(dest.ConsoleViews) == 0 {
		viewsJSON = []byte(`["VIEW1_RACE","VIEW4_CONTAINMENT","VIEW5_AUDITOR"]`)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockSIEMConfigAuditChain); err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO siem_destinations (
			destination_id, display_name, siem_vendor, endpoint, credential_ref,
			format, vendor_options_json, record_types, batch_size, schedule_seconds,
			enabled, console_views, created_by, updated_by, created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
		)
		ON CONFLICT (destination_id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			siem_vendor = EXCLUDED.siem_vendor,
			endpoint = EXCLUDED.endpoint,
			credential_ref = EXCLUDED.credential_ref,
			format = EXCLUDED.format,
			vendor_options_json = EXCLUDED.vendor_options_json,
			record_types = EXCLUDED.record_types,
			batch_size = EXCLUDED.batch_size,
			schedule_seconds = EXCLUDED.schedule_seconds,
			enabled = EXCLUDED.enabled,
			console_views = EXCLUDED.console_views,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at,
			next_attempt_at = NULL
	`,
		dest.DestinationID, dest.DisplayName, dest.SIEMVendor, dest.Endpoint, dest.CredentialRef,
		dest.Format, optsJSON, recTypesJSON, dest.BatchSize, dest.ScheduleSeconds,
		dest.Enabled, viewsJSON, dest.CreatedBy, dest.UpdatedBy, dest.CreatedAt, dest.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	auditRec, err := appendSIEMConfigAuditTx(ctx, tx, *dest, action, actor, now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return auditRec, nil
}

// DeleteSIEMDestinationWithAudit removes an active SIEM destination and records a WORM DELETE_DESTINATION audit entry.
func (s *Store) DeleteSIEMDestinationWithAudit(ctx context.Context, destinationID, actor string) (*models.SIEMConfigAuditRecord, error) {
	existing, err := s.GetSIEMDestination(ctx, destinationID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockSIEMConfigAuditChain); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM siem_destinations WHERE destination_id = $1`, destinationID); err != nil {
		return nil, err
	}
	auditRec, err := appendSIEMConfigAuditTx(ctx, tx, *existing, "DELETE_DESTINATION", actor, now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return auditRec, nil
}

func appendSIEMConfigAuditTx(
	ctx context.Context,
	tx pgx.Tx,
	snap models.SIEMDestination,
	action string,
	actor string,
	occurredAt time.Time,
) (*models.SIEMConfigAuditRecord, error) {
	prevHash := GenesisHash
	err := tx.QueryRow(ctx, `SELECT entry_hash FROM siem_config_audit ORDER BY seq_no DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	cfgSHA, canonBytes, err := crypto.CanonicalSHA256Hex(snap)
	if err != nil {
		raw, _ := json.Marshal(snap)
		canonBytes = raw
		cfgSHA = crypto.SHA256Hex(raw)
	}

	rec := models.SIEMConfigAuditRecord{
		AuditID:        "scfg-" + uuid.NewString()[:8],
		DestinationID:  snap.DestinationID,
		SIEMVendor:     snap.SIEMVendor,
		Action:         action,
		Actor:          actor,
		ConfigSnapshot: snap,
		ConfigSHA256:   cfgSHA,
		PrevHash:       prevHash,
		OccurredAt:     occurredAt.UTC().Truncate(time.Second),
	}
	rec.EntryHash = ComputeSIEMConfigAuditEntryHash(prevHash, rec)

	err = tx.QueryRow(ctx, `
		INSERT INTO siem_config_audit (
			audit_id, destination_id, siem_vendor, action, actor,
			config_snapshot_json, config_sha256, prev_hash, entry_hash, occurred_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING seq_no
	`,
		rec.AuditID, rec.DestinationID, rec.SIEMVendor, rec.Action, rec.Actor,
		canonBytes, rec.ConfigSHA256, rec.PrevHash, rec.EntryHash, rec.OccurredAt,
	).Scan(&rec.SeqNo)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// ListSIEMDestinations returns all configured SIEM destinations ordered by created_at ASC.
func (s *Store) ListSIEMDestinations(ctx context.Context) ([]models.SIEMDestination, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT destination_id, display_name, siem_vendor, endpoint, credential_ref,
		       format, vendor_options_json, record_types, batch_size, schedule_seconds,
		       enabled, console_views, sent_count, queued_count, failed_count, retry_count,
		       last_sent_at, last_error, last_error_at, last_transport_status, next_attempt_at,
		       created_by, updated_by, created_at, updated_at
		FROM siem_destinations
		ORDER BY created_at ASC, destination_id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.SIEMDestination{}
	for rows.Next() {
		var d models.SIEMDestination
		var optsRaw, typesRaw, viewsRaw []byte
		if err := rows.Scan(
			&d.DestinationID, &d.DisplayName, &d.SIEMVendor, &d.Endpoint, &d.CredentialRef,
			&d.Format, &optsRaw, &typesRaw, &d.BatchSize, &d.ScheduleSeconds,
			&d.Enabled, &viewsRaw, &d.SentCount, &d.QueuedCount, &d.FailedCount, &d.RetryCount,
			&d.LastSentAt, &d.LastError, &d.LastErrorAt, &d.LastTransportStatus, &d.NextAttemptAt,
			&d.CreatedBy, &d.UpdatedBy, &d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(optsRaw, &d.VendorOptions)
		_ = json.Unmarshal(typesRaw, &d.RecordTypes)
		_ = json.Unmarshal(viewsRaw, &d.ConsoleViews)
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetSIEMDestination retrieves a single SIEM destination by destination_id.
func (s *Store) GetSIEMDestination(ctx context.Context, destinationID string) (*models.SIEMDestination, error) {
	all, err := s.ListSIEMDestinations(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range all {
		if d.DestinationID == destinationID {
			cp := d
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("siem destination %q not found", destinationID)
}

// ListSIEMConfigAudit returns all WORM hash-chained SIEM configuration audit records ordered by seq_no DESC.
func (s *Store) ListSIEMConfigAudit(ctx context.Context) ([]models.SIEMConfigAuditRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT seq_no, audit_id, destination_id, siem_vendor, action, actor,
		       config_snapshot_json, config_sha256, prev_hash, entry_hash, occurred_at
		FROM siem_config_audit
		ORDER BY seq_no DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.SIEMConfigAuditRecord{}
	for rows.Next() {
		var r models.SIEMConfigAuditRecord
		var snapRaw []byte
		if err := rows.Scan(
			&r.SeqNo, &r.AuditID, &r.DestinationID, &r.SIEMVendor, &r.Action, &r.Actor,
			&snapRaw, &r.ConfigSHA256, &r.PrevHash, &r.EntryHash, &r.OccurredAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(snapRaw, &r.ConfigSnapshot)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) verifySIEMConfigAuditChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT seq_no, audit_id, destination_id, siem_vendor, action, actor,
		       config_sha256, prev_hash, entry_hash, occurred_at
		FROM siem_config_audit
		ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var rec models.SIEMConfigAuditRecord
		if err := rows.Scan(
			&rec.SeqNo, &rec.AuditID, &rec.DestinationID, &rec.SIEMVendor, &rec.Action, &rec.Actor,
			&rec.ConfigSHA256, &rec.PrevHash, &rec.EntryHash, &rec.OccurredAt,
		); err != nil {
			return models.ChainTableStatus{}, err
		}
		if rec.PrevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "siem_config_audit", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s", rec.AuditID),
			}, nil
		}
		recomputed := ComputeSIEMConfigAuditEntryHash(rec.PrevHash, rec)
		if recomputed != rec.EntryHash {
			return models.ChainTableStatus{
				TableName: "siem_config_audit", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", rec.AuditID),
			}, nil
		}
		expectedPrev = rec.EntryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "siem_config_audit", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}

// GetSIEMStreamCursors returns a map of stream_name -> last_acked_seq for destination_id.
func (s *Store) GetSIEMStreamCursors(ctx context.Context, destinationID string) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT stream_name, last_acked_seq FROM siem_stream_cursors WHERE destination_id = $1
	`, destinationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int64{}
	for rows.Next() {
		var name string
		var seq int64
		if err := rows.Scan(&name, &seq); err != nil {
			return nil, err
		}
		out[name] = seq
	}
	return out, rows.Err()
}

// RecordSIEMStreamBatchAck advances last_acked_seq atomically and updates delivery counters on success.
func (s *Store) RecordSIEMStreamBatchAck(
	ctx context.Context,
	destinationID string,
	streamName string,
	ackedSeq int64,
	sentDelta int64,
	transportStatus string,
) error {
	now := time.Now().UTC()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO siem_stream_cursors (destination_id, stream_name, last_acked_seq, updated_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (destination_id, stream_name) DO UPDATE SET
			last_acked_seq = GREATEST(siem_stream_cursors.last_acked_seq, EXCLUDED.last_acked_seq),
			updated_at = EXCLUDED.updated_at
	`, destinationID, streamName, ackedSeq, now)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		UPDATE siem_destinations
		SET sent_count = sent_count + $2,
		    last_sent_at = $3,
		    last_error = '',
		    last_transport_status = $4,
		    retry_count = 0,
		    next_attempt_at = NULL
		WHERE destination_id = $1
	`, destinationID, sentDelta, now, transportStatus)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RecordSIEMDeliveryFailure records a failed send without advancing last_acked_seq (zero record loss),
// scheduling an exponential-backoff retry and surfacing the error in Warrant's UI views.
func (s *Store) RecordSIEMDeliveryFailure(
	ctx context.Context,
	destinationID string,
	errMsg string,
	transportStatus string,
	queuedBacklog int64,
) error {
	now := time.Now().UTC()
	var currentRetry int64
	_ = s.pool.QueryRow(ctx, `SELECT retry_count FROM siem_destinations WHERE destination_id = $1`, destinationID).Scan(&currentRetry)
	nextRetry := currentRetry + 1
	backoffSec := int64(2) << minInt64(nextRetry, 6) // 4s, 8s, 16s ... max 128s
	nextAt := now.Add(time.Duration(backoffSec) * time.Second)

	_, err := s.pool.Exec(ctx, `
		UPDATE siem_destinations
		SET failed_count = failed_count + 1,
		    retry_count = $2,
		    queued_count = $3,
		    last_error = $4,
		    last_error_at = $5,
		    last_transport_status = $6,
		    next_attempt_at = $7
		WHERE destination_id = $1
	`, destinationID, nextRetry, queuedBacklog, truncateStr(errMsg, 512), now, transportStatus, nextAt)
	return err
}

// UpdateSIEMQueuedCount updates the live pending backlog count for destination_id.
func (s *Store) UpdateSIEMQueuedCount(ctx context.Context, destinationID string, queued int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE siem_destinations SET queued_count = $2 WHERE destination_id = $1`, destinationID, queued)
	return err
}

// StreamsForSIEMRecordType maps each canonical SIEM record family to its ordered PostgreSQL source stream(s).
func StreamsForSIEMRecordType(recordType string) []string {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case models.SIEMRecordSignedClosure:
		return []string{"attestation_records"}
	case models.SIEMRecordWORMLedger:
		return []string{
			"ledger_checkpoints",
			"agent_action_ledger",
			"principals",
			"principal_revocations",
			"kernel_public_keys",
			"commissioning_functions",
			"agent_identities",
			"agent_lifecycle_events",
			"estate_read_evidence",
		}
	case models.SIEMRecordAuthClassSigning:
		return []string{"warrant_envelopes", "ceiling_exceptions_resolved"}
	case models.SIEMRecordDispatchResult:
		return []string{"deployment_orders", "deployment_results"}
	case models.SIEMRecordShieldEvent:
		return []string{"containment_bridges", "drift_incidents"}
	case models.SIEMRecordTwinProofVerdict:
		return []string{"twin_proof_traces"}
	case models.SIEMRecordIngestEvent:
		return []string{"ingest_traces", "feed_sync_runs"}
	case models.SIEMRecordSIEMConfigAudit:
		return []string{"siem_config_audit"}
	default:
		return nil
	}
}

type siemStreamQuerySpec struct {
	recordType string
	countSQL   string
	batchSQL   string
}

var siemStreamSpecs = map[string]siemStreamQuerySpec{
	"attestation_records": {
		recordType: models.SIEMRecordSignedClosure,
		countSQL:   `SELECT COUNT(*) FROM attestation_records WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, attestation_id, minted_at, service_id, cve_id, warrant_id, remediation_id, seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM attestation_records t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"warrant_envelopes": {
		recordType: models.SIEMRecordAuthClassSigning,
		countSQL:   `SELECT COUNT(*) FROM warrant_envelopes WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, warrant_id, created_at, '', '', warrant_id, '', seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM warrant_envelopes t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"ceiling_exceptions_resolved": {
		recordType: models.SIEMRecordAuthClassSigning,
		countSQL:   `SELECT COUNT(*) FROM ceiling_exceptions WHERE resolved_at IS NOT NULL AND (EXTRACT(EPOCH FROM resolved_at)*1000000)::BIGINT > $1`,
		batchSQL:   `SELECT (EXTRACT(EPOCH FROM resolved_at)*1000000)::BIGINT AS cseq, exception_id, resolved_at, service_id, cve_id, '', remediation_id, 0::BIGINT, '', '', row_to_json(t)::text FROM ceiling_exceptions t WHERE resolved_at IS NOT NULL AND (EXTRACT(EPOCH FROM resolved_at)*1000000)::BIGINT > $1 ORDER BY cseq ASC, exception_id ASC LIMIT $2`,
	},
	"agent_action_ledger": {
		recordType: models.SIEMRecordWORMLedger,
		countSQL:   `SELECT COUNT(*) FROM agent_action_ledger WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, action_id, executed_at, target_asset, '', warrant_id, remediation_id, seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM agent_action_ledger t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"principals": {
		recordType: models.SIEMRecordWORMLedger,
		countSQL:   `SELECT COUNT(*) FROM principals WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, principal_id, created_at, '', '', '', '', seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM principals t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"principal_revocations": {
		recordType: models.SIEMRecordWORMLedger,
		countSQL:   `SELECT COUNT(*) FROM principal_revocations WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, revocation_id, revoked_at, '', '', '', '', seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM principal_revocations t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"kernel_public_keys": {
		recordType: models.SIEMRecordWORMLedger,
		countSQL:   `SELECT COUNT(*) FROM kernel_public_keys WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, key_id, registered_at, '', '', '', '', seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM kernel_public_keys t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"commissioning_functions": {
		recordType: models.SIEMRecordWORMLedger,
		countSQL:   `SELECT COUNT(*) FROM commissioning_functions WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, function_id || '#' || seq_no::text, created_at, '', '', '', '', seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM commissioning_functions t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"agent_identities": {
		recordType: models.SIEMRecordWORMLedger,
		countSQL:   `SELECT COUNT(*) FROM agent_identities WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, agent_id, enrolled_at, '', '', '', '', seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM agent_identities t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"agent_lifecycle_events": {
		recordType: models.SIEMRecordWORMLedger,
		countSQL:   `SELECT COUNT(*) FROM agent_lifecycle_events WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, event_id, occurred_at, '', '', '', '', seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM agent_lifecycle_events t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"estate_read_evidence": {
		recordType: models.SIEMRecordWORMLedger,
		countSQL:   `SELECT COUNT(*) FROM estate_read_evidence WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, evidence_id, observed_at, '', '', warrant_id, remediation_id, seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM estate_read_evidence t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"ledger_checkpoints": {
		recordType: models.SIEMRecordWORMLedger,
		countSQL:   `SELECT COUNT(*) FROM ledger_checkpoints WHERE (EXTRACT(EPOCH FROM anchored_at)*1000000)::BIGINT > $1`,
		batchSQL:   `SELECT (EXTRACT(EPOCH FROM anchored_at)*1000000)::BIGINT AS cseq, checkpoint_id, anchored_at, '', '', '', '', 0::BIGINT, '', combined_merkle_root, row_to_json(t)::text FROM ledger_checkpoints t WHERE (EXTRACT(EPOCH FROM anchored_at)*1000000)::BIGINT > $1 ORDER BY cseq ASC, checkpoint_id ASC LIMIT $2`,
	},
	"deployment_orders": {
		recordType: models.SIEMRecordDispatchResult,
		countSQL:   `SELECT COUNT(*) FROM deployment_orders WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, order_id, created_at, service_id, COALESCE(fix_identity_json->>'cve_id',''), warrant_id, remediation_id, seq_no, '', '', row_to_json(t)::text FROM deployment_orders t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"deployment_results": {
		recordType: models.SIEMRecordDispatchResult,
		countSQL:   `SELECT COUNT(*) FROM deployment_results WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, result_id, observed_at, '', '', '', remediation_id, seq_no, '', raw_distributor_report_sha256, row_to_json(t)::text FROM deployment_results t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
	"containment_bridges": {
		recordType: models.SIEMRecordShieldEvent,
		countSQL:   `SELECT COUNT(*) FROM containment_bridges WHERE (EXTRACT(EPOCH FROM COALESCE(retired_at, armed_at))*1000000)::BIGINT > $1`,
		batchSQL:   `SELECT (EXTRACT(EPOCH FROM COALESCE(b.retired_at, b.armed_at))*1000000)::BIGINT AS cseq, b.bridge_id, COALESCE(b.retired_at, b.armed_at), b.service_id, b.cve_id, COALESCE((SELECT r.warrant_id FROM remediation_items r WHERE r.remediation_id = b.remediation_id),''), b.remediation_id, 0::BIGINT, '', '', row_to_json(b)::text FROM containment_bridges b WHERE (EXTRACT(EPOCH FROM COALESCE(b.retired_at, b.armed_at))*1000000)::BIGINT > $1 ORDER BY cseq ASC, b.bridge_id ASC LIMIT $2`,
	},
	"drift_incidents": {
		recordType: models.SIEMRecordShieldEvent,
		countSQL:   `SELECT COUNT(*) FROM drift_incidents WHERE (EXTRACT(EPOCH FROM detected_at)*1000000)::BIGINT > $1`,
		batchSQL:   `SELECT (EXTRACT(EPOCH FROM detected_at)*1000000)::BIGINT AS cseq, incident_id, detected_at, service_id, cve_id, '', remediation_id, 0::BIGINT, '', detected_digest, row_to_json(t)::text FROM drift_incidents t WHERE (EXTRACT(EPOCH FROM detected_at)*1000000)::BIGINT > $1 ORDER BY cseq ASC, incident_id ASC LIMIT $2`,
	},
	"twin_proof_traces": {
		recordType: models.SIEMRecordTwinProofVerdict,
		countSQL:   `SELECT COUNT(*) FROM remediation_traces WHERE seq_no > $1 AND step_code IN ('ISOLATED_TWIN_EXPLOIT_REPLAY','CLONE_TWIN_PROVING_COMPLETED','CLONE_TWIN_PROVING_BLOCKED','PASSIVE_FLEET_DIGEST_SWEEP')`,
		batchSQL:   `SELECT t.seq_no, t.trace_id, t.occurred_at, COALESCE(r.service_id,''), COALESCE(r.cve_id,''), COALESCE(r.warrant_id,''), t.remediation_id, t.seq_no, '', t.evidence_hash, json_build_object('trace', row_to_json(t), 'clone_twin_proving', r.clone_twin_proving_json, 'patch_target_layer', r.patch_target_layer)::text FROM remediation_traces t LEFT JOIN remediation_items r ON r.remediation_id = t.remediation_id WHERE t.seq_no > $1 AND t.step_code IN ('ISOLATED_TWIN_EXPLOIT_REPLAY','CLONE_TWIN_PROVING_COMPLETED','CLONE_TWIN_PROVING_BLOCKED','PASSIVE_FLEET_DIGEST_SWEEP') ORDER BY t.seq_no ASC LIMIT $2`,
	},
	"ingest_traces": {
		recordType: models.SIEMRecordIngestEvent,
		countSQL:   `SELECT COUNT(*) FROM remediation_traces WHERE seq_no > $1 AND step_code IN ('SARIF_EXTRACTED_TYPED_SCHEMA','FINDER_EXTRACTED_TYPED_SCHEMA','SECRET_EXPOSURE_FINGERPRINTED_AND_SANITIZED')`,
		batchSQL:   `SELECT t.seq_no, t.trace_id, t.occurred_at, COALESCE(r.service_id,''), COALESCE(r.cve_id,''), COALESCE(r.warrant_id,''), t.remediation_id, t.seq_no, '', t.evidence_hash, row_to_json(t)::text FROM remediation_traces t LEFT JOIN remediation_items r ON r.remediation_id = t.remediation_id WHERE t.seq_no > $1 AND t.step_code IN ('SARIF_EXTRACTED_TYPED_SCHEMA','FINDER_EXTRACTED_TYPED_SCHEMA','SECRET_EXPOSURE_FINGERPRINTED_AND_SANITIZED') ORDER BY t.seq_no ASC LIMIT $2`,
	},
	"feed_sync_runs": {
		recordType: models.SIEMRecordIngestEvent,
		countSQL:   `SELECT COUNT(*) FROM feed_sync_runs WHERE (EXTRACT(EPOCH FROM synced_at)*1000000)::BIGINT > $1`,
		batchSQL:   `SELECT (EXTRACT(EPOCH FROM synced_at)*1000000)::BIGINT AS cseq, sync_id, synced_at, '', '', '', '', 0::BIGINT, '', raw_input_sha256, row_to_json(t)::text FROM feed_sync_runs t WHERE (EXTRACT(EPOCH FROM synced_at)*1000000)::BIGINT > $1 ORDER BY cseq ASC, sync_id ASC LIMIT $2`,
	},
	"siem_config_audit": {
		recordType: models.SIEMRecordSIEMConfigAudit,
		countSQL:   `SELECT COUNT(*) FROM siem_config_audit WHERE seq_no > $1`,
		batchSQL:   `SELECT seq_no, audit_id, occurred_at, '', '', '', '', seq_no, prev_hash, entry_hash, row_to_json(t)::text FROM siem_config_audit t WHERE seq_no > $1 ORDER BY seq_no ASC LIMIT $2`,
	},
}

// CountPendingSIEMStreamRecords returns the number of unshipped records behind afterSeq on streamName.
func (s *Store) CountPendingSIEMStreamRecords(ctx context.Context, streamName string, afterSeq int64) (int64, error) {
	spec, ok := siemStreamSpecs[streamName]
	if !ok {
		return 0, nil
	}
	var cnt int64
	err := s.pool.QueryRow(ctx, spec.countSQL, afterSeq).Scan(&cnt)
	return cnt, err
}

// FetchOrderedSIEMStreamBatch fetches up to limit records strictly in ascending sequence/cursor order (never reordering ledger records)
// while preserving 100% of original table columns, signatures, seals, seq_no, prev_hash, and entry_hash in RawRecord.
func (s *Store) FetchOrderedSIEMStreamBatch(
	ctx context.Context,
	streamName string,
	afterSeq int64,
	limit int,
) ([]models.SIEMExportEnvelope, error) {
	spec, ok := siemStreamSpecs[streamName]
	if !ok {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, spec.batchSQL, afterSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]models.SIEMExportEnvelope, 0, limit)
	for rows.Next() {
		var env models.SIEMExportEnvelope
		var rawJSON string
		if err := rows.Scan(
			&env.CursorSeq,
			&env.RecordID,
			&env.OccurredAt,
			&env.ServiceID,
			&env.CVEID,
			&env.WarrantID,
			&env.RemediationID,
			&env.LedgerSeqNo,
			&env.PrevHash,
			&env.EntryHash,
			&rawJSON,
		); err != nil {
			return nil, err
		}
		env.StreamName = streamName
		env.RecordType = spec.recordType
		env.RawRecord = map[string]any{}
		_ = json.Unmarshal([]byte(rawJSON), &env.RawRecord)
		env.Severity = deriveSIEMSeverity(spec.recordType, streamName, env.RawRecord)
		env.SignatureSummary = extractSIEMSignatureSummary(env.RawRecord)
		env.Summary = fmt.Sprintf("G1-Warrant %s [%s] id=%s seq=%d", spec.recordType, streamName, env.RecordID, env.CursorSeq)
		out = append(out, env)
	}
	return out, rows.Err()
}

func deriveSIEMSeverity(recType, streamName string, raw map[string]any) int {
	if streamName == "drift_incidents" {
		return 9
	}
	if status, ok := raw["status"].(string); ok && (status == "SECURITY_VIOLATION" || status == "REARMED_DRIFT") {
		return 9
	}
	switch recType {
	case models.SIEMRecordShieldEvent:
		return 7
	case models.SIEMRecordAuthClassSigning, models.SIEMRecordSignedClosure:
		return 5
	default:
		return 4
	}
}

func extractSIEMSignatureSummary(raw map[string]any) string {
	for _, k := range []string{"dsse_envelope", "governance_dsse", "rotation_dsse", "resolution_dsse"} {
		v, ok := raw[k].(map[string]any)
		if !ok || v == nil {
			continue
		}
		sigs, ok := v["signatures"].([]any)
		if !ok || len(sigs) == 0 {
			continue
		}
		parts := make([]string, 0, len(sigs))
		for _, s := range sigs {
			sm, ok := s.(map[string]any)
			if !ok {
				continue
			}
			keyID, _ := sm["keyid"].(string)
			sigB64, _ := sm["sig"].(string)
			if len(sigB64) > 24 {
				sigB64 = sigB64[:24] + "..."
			}
			parts = append(parts, fmt.Sprintf("%s:%s", keyID, sigB64))
		}
		if len(parts) > 0 {
			return strings.Join(parts, ",")
		}
	}
	return ""
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
