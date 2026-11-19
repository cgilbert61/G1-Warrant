package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
)

// ComputeCombinedMerkleRoot computes a binary Merkle tree root over the three ledger terminal hashes and row counts.
func ComputeCombinedMerkleRoot(wHead string, wRows int, aHead string, aRows int, attHead string, attRows int) string {
	leafW := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:warrant_envelopes:%d:%s", wRows, wHead)))
	leafA := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:agent_action_ledger:%d:%s", aRows, aHead)))
	leafAtt := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:attestation_records:%d:%s", attRows, attHead)))
	leftBranch := crypto.SHA256Hex([]byte("NODE:" + leafW + ":" + leafA))
	rightBranch := crypto.SHA256Hex([]byte("NODE:" + leafAtt + ":" + leafAtt))
	return crypto.SHA256Hex([]byte("MERKLE_ROOT_V1:" + leftBranch + ":" + rightBranch))
}

// SaveLedgerCheckpoint inserts an immutable Merkle root checkpoint record.
func (s *Store) SaveLedgerCheckpoint(ctx context.Context, cp models.LedgerCheckpoint) error {
	if cp.AnchoredAt.IsZero() {
		cp.AnchoredAt = time.Now().UTC()
	}
	envJSON, err := crypto.CanonicalizeStruct(cp.DSSEEnvelope)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO ledger_checkpoints (
			checkpoint_id, warrant_head_hash, warrant_row_count,
			agent_head_hash, agent_row_count,
			attestation_head_hash, attestation_row_count,
			combined_merkle_root, dsse_envelope,
			external_anchor_target, external_receipt_hash, anchored_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (combined_merkle_root) DO NOTHING
	`,
		cp.CheckpointID, cp.WarrantHeadHash, cp.WarrantRowCount,
		cp.AgentHeadHash, cp.AgentRowCount,
		cp.AttestationHeadHash, cp.AttestationRowCount,
		cp.CombinedMerkleRoot, envJSON,
		cp.ExternalAnchorTarget, cp.ExternalReceiptHash, cp.AnchoredAt,
	)
	return err
}

// ListLedgerCheckpoints returns anchored Merkle checkpoints newest first.
func (s *Store) ListLedgerCheckpoints(ctx context.Context) ([]models.LedgerCheckpoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT checkpoint_id, warrant_head_hash, warrant_row_count,
		       agent_head_hash, agent_row_count,
		       attestation_head_hash, attestation_row_count,
		       combined_merkle_root, dsse_envelope,
		       external_anchor_target, external_receipt_hash, anchored_at
		FROM ledger_checkpoints ORDER BY anchored_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.LedgerCheckpoint{}
	for rows.Next() {
		var cp models.LedgerCheckpoint
		var envRaw []byte
		if err := rows.Scan(
			&cp.CheckpointID, &cp.WarrantHeadHash, &cp.WarrantRowCount,
			&cp.AgentHeadHash, &cp.AgentRowCount,
			&cp.AttestationHeadHash, &cp.AttestationRowCount,
			&cp.CombinedMerkleRoot, &envRaw,
			&cp.ExternalAnchorTarget, &cp.ExternalReceiptHash, &cp.AnchoredAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(envRaw, &cp.DSSEEnvelope)
		out = append(out, cp)
	}
	return out, rows.Err()
}

// VerifyHistoricalCheckpointConsistency checks that every anchored Merkle checkpoint still matches
// the exact historical row entry_hash inside PostgreSQL (detecting superuser trigger-disable rewrites).
func (s *Store) VerifyHistoricalCheckpointConsistency(ctx context.Context, externalRecords []models.LedgerCheckpoint) (bool, string, string, string) {
	checkpoints := externalRecords
	if len(checkpoints) == 0 {
		dbCPs, err := s.ListLedgerCheckpoints(ctx)
		if err != nil || len(dbCPs) == 0 {
			return true, "", "", ""
		}
		checkpoints = dbCPs
	}

	latest := checkpoints[0]
	for _, cp := range checkpoints {
		recomputedRoot := ComputeCombinedMerkleRoot(
			cp.WarrantHeadHash, cp.WarrantRowCount,
			cp.AgentHeadHash, cp.AgentRowCount,
			cp.AttestationHeadHash, cp.AttestationRowCount,
		)
		if !strings.EqualFold(recomputedRoot, cp.CombinedMerkleRoot) {
			return false, latest.CheckpointID, latest.CombinedMerkleRoot, fmt.Sprintf("checkpoint %s merkle root mismatch", cp.CheckpointID)
		}
		if ok, detail := s.checkHashAtOffset(ctx, "warrant_envelopes", cp.WarrantRowCount, cp.WarrantHeadHash); !ok {
			return false, latest.CheckpointID, latest.CombinedMerkleRoot, detail
		}
		if ok, detail := s.checkHashAtOffset(ctx, "agent_action_ledger", cp.AgentRowCount, cp.AgentHeadHash); !ok {
			return false, latest.CheckpointID, latest.CombinedMerkleRoot, detail
		}
		if ok, detail := s.checkHashAtOffset(ctx, "attestation_records", cp.AttestationRowCount, cp.AttestationHeadHash); !ok {
			return false, latest.CheckpointID, latest.CombinedMerkleRoot, detail
		}
	}
	return true, latest.CheckpointID, latest.CombinedMerkleRoot, ""
}

func (s *Store) checkHashAtOffset(ctx context.Context, tableName string, rowCount int, expectedHash string) (bool, string) {
	if rowCount == 0 {
		if expectedHash != GenesisHash {
			return false, fmt.Sprintf("%s expected genesis hash at count 0", tableName)
		}
		return true, ""
	}
	var query string
	switch tableName {
	case "warrant_envelopes":
		query = `SELECT entry_hash FROM warrant_envelopes ORDER BY seq_no ASC OFFSET $1 LIMIT 1`
	case "agent_action_ledger":
		query = `SELECT entry_hash FROM agent_action_ledger ORDER BY seq_no ASC OFFSET $1 LIMIT 1`
	case "attestation_records":
		query = `SELECT entry_hash FROM attestation_records ORDER BY seq_no ASC OFFSET $1 LIMIT 1`
	default:
		return false, "unknown ledger table"
	}
	var actual string
	err := s.pool.QueryRow(ctx, query, rowCount-1).Scan(&actual)
	if err != nil {
		return false, fmt.Sprintf("DB_SUPERUSER_TRUNCATION_DETECTED on %s: anchored row %d missing (%v)", tableName, rowCount, err)
	}
	if actual != expectedHash {
		return false, fmt.Sprintf("DB_SUPERUSER_REWRITE_DETECTED on %s at row %d: db=%s != external_anchor=%s", tableName, rowCount, actual, expectedHash)
	}
	return true, ""
}
