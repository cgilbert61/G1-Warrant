package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

// ComputeCombinedMerkleRoot computes the legacy V1 binary Merkle tree root over the 3 core ledger tables
// (retained for verifying pre-existing v1.0.0 upgraded checkpoints).
func ComputeCombinedMerkleRoot(wHead string, wRows int, aHead string, aRows int, attHead string, attRows int) string {
	leafW := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:warrant_envelopes:%d:%s", wRows, wHead)))
	leafA := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:agent_action_ledger:%d:%s", aRows, aHead)))
	leafAtt := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:attestation_records:%d:%s", attRows, attHead)))
	leftBranch := crypto.SHA256Hex([]byte("NODE:" + leafW + ":" + leafA))
	rightBranch := crypto.SHA256Hex([]byte("NODE:" + leafAtt + ":" + leafAtt))
	return crypto.SHA256Hex([]byte("MERKLE_ROOT_V1:" + leftBranch + ":" + rightBranch))
}

// ComputeCombinedMerkleRootV2 computes a 6-leaf binary Merkle tree root over the 6 v1.0.1–v1.0.4 immutable tables:
// warrant_envelopes, agent_action_ledger, attestation_records, principals, principal_revocations, and kernel_public_keys.
func ComputeCombinedMerkleRootV2(
	wHead string, wRows int,
	aHead string, aRows int,
	attHead string, attRows int,
	pHead string, pRows int,
	revHead string, revRows int,
	kHead string, kRows int,
) string {
	leafW := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:warrant_envelopes:%d:%s", wRows, wHead)))
	leafA := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:agent_action_ledger:%d:%s", aRows, aHead)))
	leafAtt := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:attestation_records:%d:%s", attRows, attHead)))
	leafP := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:principals:%d:%s", pRows, pHead)))
	leafRev := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:principal_revocations:%d:%s", revRows, revHead)))
	leafK := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:kernel_public_keys:%d:%s", kRows, kHead)))

	n1 := crypto.SHA256Hex([]byte("NODE:" + leafW + ":" + leafA))
	n2 := crypto.SHA256Hex([]byte("NODE:" + leafAtt + ":" + leafP))
	n3 := crypto.SHA256Hex([]byte("NODE:" + leafRev + ":" + leafK))

	leftSub := crypto.SHA256Hex([]byte("NODE:" + n1 + ":" + n2))
	rightSub := crypto.SHA256Hex([]byte("NODE:" + n3 + ":" + n3))
	return crypto.SHA256Hex([]byte("MERKLE_ROOT_V2:" + leftSub + ":" + rightSub))
}

// ComputeCombinedMerkleRootV3 computes a 9-leaf binary Merkle tree root over all 9 immutable WORM tables (v1.1.0+):
// warrant_envelopes, agent_action_ledger, attestation_records, principals, principal_revocations, kernel_public_keys,
// commissioning_functions, agent_identities, and agent_lifecycle_events.
func ComputeCombinedMerkleRootV3(
	wHead string, wRows int,
	aHead string, aRows int,
	attHead string, attRows int,
	pHead string, pRows int,
	revHead string, revRows int,
	kHead string, kRows int,
	cfHead string, cfRows int,
	aiHead string, aiRows int,
	aleHead string, aleRows int,
) string {
	coreV2 := ComputeCombinedMerkleRootV2(wHead, wRows, aHead, aRows, attHead, attRows, pHead, pRows, revHead, revRows, kHead, kRows)
	leafCF := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:commissioning_functions:%d:%s", cfRows, cfHead)))
	leafAI := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:agent_identities:%d:%s", aiRows, aiHead)))
	leafALE := crypto.SHA256Hex([]byte(fmt.Sprintf("LEAF:agent_lifecycle_events:%d:%s", aleRows, aleHead)))

	n4 := crypto.SHA256Hex([]byte("NODE:" + leafCF + ":" + leafAI))
	n5 := crypto.SHA256Hex([]byte("NODE:" + leafALE + ":" + leafALE))
	agentSub := crypto.SHA256Hex([]byte("NODE:" + n4 + ":" + n5))
	return crypto.SHA256Hex([]byte("MERKLE_ROOT_V3:" + coreV2 + ":" + agentSub))
}

// SaveLedgerCheckpoint inserts an immutable 9-chain (or V2/V1) Merkle root checkpoint record.
func (s *Store) SaveLedgerCheckpoint(ctx context.Context, cp models.LedgerCheckpoint) error {
	if cp.AnchoredAt.IsZero() {
		cp.AnchoredAt = time.Now().UTC()
	}
	if cp.MerkleVersion <= 0 {
		cp.MerkleVersion = 3
	}
	if cp.CommissioningHeadHash == "" {
		cp.CommissioningHeadHash = GenesisHash
	}
	if cp.AgentIdentityHeadHash == "" {
		cp.AgentIdentityHeadHash = GenesisHash
	}
	if cp.AgentLifecycleHeadHash == "" {
		cp.AgentLifecycleHeadHash = GenesisHash
	}
	envJSON, err := crypto.CanonicalizeStruct(cp.DSSEEnvelope)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO ledger_checkpoints (
			checkpoint_id, merkle_version,
			warrant_head_hash, warrant_row_count,
			agent_head_hash, agent_row_count,
			attestation_head_hash, attestation_row_count,
			principal_head_hash, principal_row_count,
			revocation_head_hash, revocation_row_count,
			kernel_key_head_hash, kernel_key_row_count,
			commissioning_head_hash, commissioning_row_count,
			agent_identity_head_hash, agent_identity_row_count,
			agent_lifecycle_head_hash, agent_lifecycle_row_count,
			combined_merkle_root, dsse_envelope,
			external_anchor_target, external_receipt_hash, anchored_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
		ON CONFLICT (combined_merkle_root) DO NOTHING
	`,
		cp.CheckpointID, cp.MerkleVersion,
		cp.WarrantHeadHash, cp.WarrantRowCount,
		cp.AgentHeadHash, cp.AgentRowCount,
		cp.AttestationHeadHash, cp.AttestationRowCount,
		cp.PrincipalHeadHash, cp.PrincipalRowCount,
		cp.RevocationHeadHash, cp.RevocationRowCount,
		cp.KernelKeyHeadHash, cp.KernelKeyRowCount,
		cp.CommissioningHeadHash, cp.CommissioningRowCount,
		cp.AgentIdentityHeadHash, cp.AgentIdentityRowCount,
		cp.AgentLifecycleHeadHash, cp.AgentLifecycleRowCount,
		cp.CombinedMerkleRoot, envJSON,
		cp.ExternalAnchorTarget, cp.ExternalReceiptHash, cp.AnchoredAt,
	)
	return err
}

// ListLedgerCheckpoints returns anchored Merkle checkpoints newest first.
func (s *Store) ListLedgerCheckpoints(ctx context.Context) ([]models.LedgerCheckpoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT checkpoint_id, merkle_version,
		       warrant_head_hash, warrant_row_count,
		       agent_head_hash, agent_row_count,
		       attestation_head_hash, attestation_row_count,
		       principal_head_hash, principal_row_count,
		       revocation_head_hash, revocation_row_count,
		       kernel_key_head_hash, kernel_key_row_count,
		       commissioning_head_hash, commissioning_row_count,
		       agent_identity_head_hash, agent_identity_row_count,
		       agent_lifecycle_head_hash, agent_lifecycle_row_count,
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
			&cp.CheckpointID, &cp.MerkleVersion,
			&cp.WarrantHeadHash, &cp.WarrantRowCount,
			&cp.AgentHeadHash, &cp.AgentRowCount,
			&cp.AttestationHeadHash, &cp.AttestationRowCount,
			&cp.PrincipalHeadHash, &cp.PrincipalRowCount,
			&cp.RevocationHeadHash, &cp.RevocationRowCount,
			&cp.KernelKeyHeadHash, &cp.KernelKeyRowCount,
			&cp.CommissioningHeadHash, &cp.CommissioningRowCount,
			&cp.AgentIdentityHeadHash, &cp.AgentIdentityRowCount,
			&cp.AgentLifecycleHeadHash, &cp.AgentLifecycleRowCount,
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

// VerifyHistoricalCheckpointConsistency checks that every anchored Merkle checkpoint (V1 3-chain, V2 6-chain, or V3 9-chain)
// still matches the exact historical row entry_hash inside PostgreSQL, AND when external witness checkpoints are supplied,
// catches unanchored superuser key/agent injections into root-of-trust authority tables.
func (s *Store) VerifyHistoricalCheckpointConsistency(ctx context.Context, externalRecords []models.LedgerCheckpoint) (bool, string, string, string) {
	checkpoints := externalRecords
	hasExternalWitness := len(externalRecords) > 0
	if !hasExternalWitness {
		dbCPs, err := s.ListLedgerCheckpoints(ctx)
		if err != nil || len(dbCPs) == 0 {
			return true, "", "", ""
		}
		checkpoints = dbCPs
	}

	latest := checkpoints[0]
	for _, cp := range checkpoints {
		var recomputedRoot string
		switch cp.MerkleVersion {
		case 1:
			recomputedRoot = ComputeCombinedMerkleRoot(
				cp.WarrantHeadHash, cp.WarrantRowCount,
				cp.AgentHeadHash, cp.AgentRowCount,
				cp.AttestationHeadHash, cp.AttestationRowCount,
			)
		case 2:
			recomputedRoot = ComputeCombinedMerkleRootV2(
				cp.WarrantHeadHash, cp.WarrantRowCount,
				cp.AgentHeadHash, cp.AgentRowCount,
				cp.AttestationHeadHash, cp.AttestationRowCount,
				cp.PrincipalHeadHash, cp.PrincipalRowCount,
				cp.RevocationHeadHash, cp.RevocationRowCount,
				cp.KernelKeyHeadHash, cp.KernelKeyRowCount,
			)
		default:
			recomputedRoot = ComputeCombinedMerkleRootV3(
				cp.WarrantHeadHash, cp.WarrantRowCount,
				cp.AgentHeadHash, cp.AgentRowCount,
				cp.AttestationHeadHash, cp.AttestationRowCount,
				cp.PrincipalHeadHash, cp.PrincipalRowCount,
				cp.RevocationHeadHash, cp.RevocationRowCount,
				cp.KernelKeyHeadHash, cp.KernelKeyRowCount,
				cp.CommissioningHeadHash, cp.CommissioningRowCount,
				cp.AgentIdentityHeadHash, cp.AgentIdentityRowCount,
				cp.AgentLifecycleHeadHash, cp.AgentLifecycleRowCount,
			)
		}
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
		if cp.MerkleVersion >= 2 {
			if ok, detail := s.checkHashAtOffset(ctx, "principals", cp.PrincipalRowCount, cp.PrincipalHeadHash); !ok {
				return false, latest.CheckpointID, latest.CombinedMerkleRoot, detail
			}
			if ok, detail := s.checkHashAtOffset(ctx, "principal_revocations", cp.RevocationRowCount, cp.RevocationHeadHash); !ok {
				return false, latest.CheckpointID, latest.CombinedMerkleRoot, detail
			}
			if ok, detail := s.checkHashAtOffset(ctx, "kernel_public_keys", cp.KernelKeyRowCount, cp.KernelKeyHeadHash); !ok {
				return false, latest.CheckpointID, latest.CombinedMerkleRoot, detail
			}
		}
		if cp.MerkleVersion >= 3 {
			if ok, detail := s.checkHashAtOffset(ctx, "commissioning_functions", cp.CommissioningRowCount, cp.CommissioningHeadHash); !ok {
				return false, latest.CheckpointID, latest.CombinedMerkleRoot, detail
			}
			if ok, detail := s.checkHashAtOffset(ctx, "agent_identities", cp.AgentIdentityRowCount, cp.AgentIdentityHeadHash); !ok {
				return false, latest.CheckpointID, latest.CombinedMerkleRoot, detail
			}
			if ok, detail := s.checkHashAtOffset(ctx, "agent_lifecycle_events", cp.AgentLifecycleRowCount, cp.AgentLifecycleHeadHash); !ok {
				return false, latest.CheckpointID, latest.CombinedMerkleRoot, detail
			}
		}
	}

	if hasExternalWitness && latest.MerkleVersion >= 2 {
		checks := []struct {
			table    string
			expected int
		}{
			{"principals", latest.PrincipalRowCount},
			{"principal_revocations", latest.RevocationRowCount},
			{"kernel_public_keys", latest.KernelKeyRowCount},
		}
		if latest.MerkleVersion >= 3 {
			checks = append(checks,
				struct {
					table    string
					expected int
				}{"commissioning_functions", latest.CommissioningRowCount},
				struct {
					table    string
					expected int
				}{"agent_identities", latest.AgentIdentityRowCount},
				struct {
					table    string
					expected int
				}{"agent_lifecycle_events", latest.AgentLifecycleRowCount},
			)
		}
		for _, chk := range checks {
			var actualCount int
			if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM "+chk.table).Scan(&actualCount); err == nil {
				if actualCount != chk.expected {
					return false, latest.CheckpointID, latest.CombinedMerkleRoot, fmt.Sprintf(
						"DB_SUPERUSER_UNANCHORED_KEY_INJECTION_DETECTED on %s: db_rows=%d != external_anchor_rows=%d",
						chk.table, actualCount, chk.expected,
					)
				}
			}
		}
	}

	return true, latest.CheckpointID, latest.CombinedMerkleRoot, ""
}

func (s *Store) checkHashAtOffset(ctx context.Context, tableName string, rowCount int, expectedHash string) (bool, string) {
	if rowCount == 0 {
		if expectedHash != "" && expectedHash != GenesisHash {
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
	case "principals":
		query = `SELECT entry_hash FROM principals ORDER BY seq_no ASC OFFSET $1 LIMIT 1`
	case "principal_revocations":
		query = `SELECT entry_hash FROM principal_revocations ORDER BY seq_no ASC OFFSET $1 LIMIT 1`
	case "kernel_public_keys":
		query = `SELECT entry_hash FROM kernel_public_keys ORDER BY seq_no ASC OFFSET $1 LIMIT 1`
	case "commissioning_functions":
		query = `SELECT entry_hash FROM commissioning_functions ORDER BY seq_no ASC OFFSET $1 LIMIT 1`
	case "agent_identities":
		query = `SELECT entry_hash FROM agent_identities ORDER BY seq_no ASC OFFSET $1 LIMIT 1`
	case "agent_lifecycle_events":
		query = `SELECT entry_hash FROM agent_lifecycle_events ORDER BY seq_no ASC OFFSET $1 LIMIT 1`
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
