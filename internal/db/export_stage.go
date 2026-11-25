package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/jackc/pgx/v5"
)

// StagedAttestationExport is a point-in-time consistent evidence snapshot frozen inside a single
// REPEATABLE READ READ ONLY PostgreSQL transaction before streaming OSCAL/3PAO exports.
type StagedAttestationExport struct {
	AttestationID   string                   `json:"attestation_id"`
	StagedAt        time.Time                `json:"staged_at"`
	IsolationLevel  string                   `json:"isolation_level"`
	SnapshotSHA256  string                   `json:"snapshot_sha256"`
	Attestation     models.AttestationRecord `json:"attestation"`
	TraceCount      int                      `json:"trace_count"`
	TraceDigestList []string                 `json:"trace_digest_list,omitempty"`
}

// ComputeStagedExportDigest computes a canonical SHA-256 digest over an attestation entry hash
// and its frozen trace evidence hashes for point-in-time export integrity verification.
func ComputeStagedExportDigest(attestationID, entryHash string, traceHashes []string) (string, error) {
	payload := map[string]any{
		"attestation_id": attestationID,
		"entry_hash":     entryHash,
		"trace_hashes":   traceHashes,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(raw), nil
}

// StageAttestationExport freezes an attestation record and its associated remediation_traces
// inside a single REPEATABLE READ READ ONLY transaction to prevent torn reads under concurrent writes.
func (s *Store) StageAttestationExport(ctx context.Context, attestationID string) (*StagedAttestationExport, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin repeatable-read export tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var rec models.AttestationRecord
	var dsseRaw, oscalRaw, manifestRaw []byte
	err = tx.QueryRow(ctx, `
		SELECT attestation_id, remediation_id, service_id, cve_id, is_kev, warrant_id,
		       slot1_principal_id, slot1_email, slot2_principal_id, slot2_email,
		       twin_transcript_sha256, assurance_tier, closure_completeness,
		       targeted_asset_count, landed_asset_count, failed_asset_count,
		       pending_asset_count, reboot_waiting_count, distributor_id,
		       distributor_order_id, distributor_report_sha256, signer_backend,
		       fleet_digest_manifest_json, lockout_policy_id, reverify_expires_at,
		       dsse_envelope_json, oscal_poam_json, ttvr_seconds, minted_at,
		       prev_hash, entry_hash
		FROM attestation_records
		WHERE attestation_id = $1
	`, attestationID).Scan(
		&rec.AttestationID, &rec.RemediationID, &rec.ServiceID, &rec.CVEID, &rec.IsKEV, &rec.WarrantID,
		&rec.Slot1PrincipalID, &rec.Slot1Email, &rec.Slot2PrincipalID, &rec.Slot2Email,
		&rec.TwinTranscriptSHA256, &rec.AssuranceTier, &rec.ClosureCompleteness,
		&rec.TargetedAssetCount, &rec.LandedAssetCount, &rec.FailedAssetCount,
		&rec.PendingAssetCount, &rec.RebootWaitingCount, &rec.DistributorID,
		&rec.DistributorOrderID, &rec.DistributorReportSHA256, &rec.SignerBackend,
		&manifestRaw, &rec.LockoutPolicyID, &rec.ReverifyExpiresAt,
		&dsseRaw, &oscalRaw, &rec.TTVRSeconds, &rec.MintedAt,
		&rec.PrevHash, &rec.EntryHash,
	)
	if err != nil {
		return nil, fmt.Errorf("stage attestation %q: %w", attestationID, err)
	}
	_ = json.Unmarshal(manifestRaw, &rec.FleetDigestManifest)
	_ = json.Unmarshal(dsseRaw, &rec.DSSEEnvelope)
	_ = json.Unmarshal(oscalRaw, &rec.OSCALPOAM)

	rows, err := tx.Query(ctx, `
		SELECT evidence_hash
		FROM remediation_traces
		WHERE remediation_id = $1
		ORDER BY occurred_at ASC, trace_id ASC
	`, rec.RemediationID)
	if err != nil {
		return nil, fmt.Errorf("stage remediation traces for %q: %w", rec.RemediationID, err)
	}
	defer rows.Close()

	var traceHashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		traceHashes = append(traceHashes, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	snapDigest, err := ComputeStagedExportDigest(rec.AttestationID, rec.EntryHash, traceHashes)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit read-only staged export tx: %w", err)
	}

	return &StagedAttestationExport{
		AttestationID:   rec.AttestationID,
		StagedAt:        time.Now().UTC(),
		IsolationLevel:  "REPEATABLE_READ_READ_ONLY",
		SnapshotSHA256:  snapDigest,
		Attestation:     rec,
		TraceCount:      len(traceHashes),
		TraceDigestList: traceHashes,
	}, nil
}
