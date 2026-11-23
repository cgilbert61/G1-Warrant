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
	"github.com/jackc/pgx/v5"
)

const lockEstateEvidenceChain int64 = 1001011

// ComputeEstateReadEvidenceEntryHash computes the deterministic SHA-256 chain link for estate_read_evidence.
func ComputeEstateReadEvidenceEntryHash(prevHash string, rec models.EstateReadEvidenceRecord) string {
	material := strings.Join([]string{
		"estate_read_evidence",
		prevHash,
		rec.EvidenceID,
		rec.SourceSystem,
		rec.SourceTier,
		rec.HandlerFamily,
		rec.Phase,
		rec.WarrantID,
		rec.RemediationID,
		rec.QueryIdentity,
		fmt.Sprintf("%d", rec.ClassMembershipCount),
		rec.SourceFreshnessAt.UTC().Format(time.RFC3339),
		rec.SnapshotSHA256,
	}, "|")
	return crypto.SHA256Hex([]byte(material))
}

// AppendEstateReadEvidence appends a bounded estate-reading evidence summary to WORM estate_read_evidence.
// Warrant never persists per-host or raw asset-inventory mirror rows.
func (s *Store) AppendEstateReadEvidence(ctx context.Context, rec *models.EstateReadEvidenceRecord) error {
	if rec.ObservedAt.IsZero() {
		rec.ObservedAt = time.Now().UTC()
	}
	if rec.SourceFreshnessAt.IsZero() {
		rec.SourceFreshnessAt = rec.ObservedAt
	}
	rec.SourceFreshnessAt = rec.SourceFreshnessAt.UTC().Truncate(time.Second)
	rec.ObservedAt = rec.ObservedAt.UTC().Truncate(time.Second)

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockEstateEvidenceChain); err != nil {
		return err
	}

	prevHash := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM estate_read_evidence ORDER BY seq_no DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	rec.PrevHash = prevHash
	rec.EntryHash = ComputeEstateReadEvidenceEntryHash(prevHash, *rec)

	osJSON, _ := json.Marshal(rec.OSDistSummary)
	if len(rec.OSDistSummary) == 0 {
		osJSON = []byte("[]")
	}
	swJSON, _ := json.Marshal(rec.SWDistSummary)
	if len(rec.SWDistSummary) == 0 {
		swJSON = []byte("[]")
	}
	candJSON, _ := json.Marshal(rec.CandidateSources)
	if len(rec.CandidateSources) == 0 {
		candJSON = []byte("[]")
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO estate_read_evidence (
			evidence_id, source_system, source_tier, handler_family, phase,
			warrant_id, remediation_id, query_identity, class_membership_count,
			os_dist_summary_json, sw_dist_summary_json, candidate_sources_json,
			source_freshness_at, source_freshness_age_sec, observed_at,
			snapshot_sha256, prev_hash, entry_hash
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18
		)
	`,
		rec.EvidenceID, rec.SourceSystem, rec.SourceTier, rec.HandlerFamily, rec.Phase,
		rec.WarrantID, rec.RemediationID, rec.QueryIdentity, rec.ClassMembershipCount,
		osJSON, swJSON, candJSON,
		rec.SourceFreshnessAt, rec.SourceFreshnessAgeSec, rec.ObservedAt,
		rec.SnapshotSHA256, rec.PrevHash, rec.EntryHash,
	)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListEstateReadEvidence returns bounded estate-read evidence records newest first, optionally filtered by sourceSystem or warrantID.
func (s *Store) ListEstateReadEvidence(ctx context.Context, sourceSystem, warrantID string) ([]models.EstateReadEvidenceRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT evidence_id, source_system, source_tier, handler_family, phase,
		       warrant_id, remediation_id, query_identity, class_membership_count,
		       os_dist_summary_json, sw_dist_summary_json, candidate_sources_json,
		       source_freshness_at, source_freshness_age_sec, observed_at,
		       snapshot_sha256, prev_hash, entry_hash
		FROM estate_read_evidence
		WHERE ($1 = '' OR source_system = $1)
		  AND ($2 = '' OR warrant_id = $2)
		ORDER BY seq_no DESC
	`, strings.TrimSpace(sourceSystem), strings.TrimSpace(warrantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.EstateReadEvidenceRecord{}
	for rows.Next() {
		var rec models.EstateReadEvidenceRecord
		var osRaw, swRaw, candRaw []byte
		if err := rows.Scan(
			&rec.EvidenceID, &rec.SourceSystem, &rec.SourceTier, &rec.HandlerFamily, &rec.Phase,
			&rec.WarrantID, &rec.RemediationID, &rec.QueryIdentity, &rec.ClassMembershipCount,
			&osRaw, &swRaw, &candRaw,
			&rec.SourceFreshnessAt, &rec.SourceFreshnessAgeSec, &rec.ObservedAt,
			&rec.SnapshotSHA256, &rec.PrevHash, &rec.EntryHash,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(osRaw, &rec.OSDistSummary)
		_ = json.Unmarshal(swRaw, &rec.SWDistSummary)
		_ = json.Unmarshal(candRaw, &rec.CandidateSources)
		out = append(out, rec)
	}
	return out, rows.Err()
}

// FindEstateReadEvidenceBySnapshot locates the recorded evidence row matching snapshotSHA256 (and optional sourceSystem).
func (s *Store) FindEstateReadEvidenceBySnapshot(ctx context.Context, sourceSystem, snapshotSHA256 string) (*models.EstateReadEvidenceRecord, error) {
	if strings.TrimSpace(snapshotSHA256) == "" {
		return nil, fmt.Errorf("empty snapshot_sha256")
	}
	all, err := s.ListEstateReadEvidence(ctx, sourceSystem, "")
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if strings.EqualFold(r.SnapshotSHA256, strings.TrimSpace(snapshotSHA256)) {
			cp := r
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("estate_read_evidence for snapshot_sha256 %q not found", snapshotSHA256)
}

func (s *Store) verifyEstateReadEvidenceChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT evidence_id, source_system, source_tier, handler_family, phase,
		       warrant_id, remediation_id, query_identity, class_membership_count,
		       source_freshness_at, snapshot_sha256, prev_hash, entry_hash
		FROM estate_read_evidence ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var rec models.EstateReadEvidenceRecord
		if err := rows.Scan(
			&rec.EvidenceID, &rec.SourceSystem, &rec.SourceTier, &rec.HandlerFamily, &rec.Phase,
			&rec.WarrantID, &rec.RemediationID, &rec.QueryIdentity, &rec.ClassMembershipCount,
			&rec.SourceFreshnessAt, &rec.SnapshotSHA256, &rec.PrevHash, &rec.EntryHash,
		); err != nil {
			return models.ChainTableStatus{}, err
		}
		if rec.PrevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "estate_read_evidence", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s", rec.EvidenceID),
			}, nil
		}
		recomputed := ComputeEstateReadEvidenceEntryHash(rec.PrevHash, rec)
		if recomputed != rec.EntryHash {
			return models.ChainTableStatus{
				TableName: "estate_read_evidence", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", rec.EvidenceID),
			}, nil
		}
		expectedPrev = rec.EntryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "estate_read_evidence", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}
