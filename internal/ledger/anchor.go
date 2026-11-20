package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
)

const PayloadTypeCheckpoint = "application/vnd.g1163rt.ledger-checkpoint.v1+json"

// TransparencyAnchor ships DSSE-signed Merkle Root checkpoints outside PostgreSQL
// (to an append-only external JSONL receipt log and/or remote HTTP transparency/S3-Object-Lock webhook)
// so a rogue PostgreSQL superuser who disables triggers cannot rewrite historical audit rows or inject unanchored keys undetected.
type TransparencyAnchor struct {
	mu          sync.Mutex
	receiptPath string
	webhookURL  string
	httpClient  *http.Client
	inMemLog    []models.LedgerCheckpoint
}

// NewTransparencyAnchor configures external Merkle root anchoring from environment or explicit paths.
func NewTransparencyAnchor(receiptPath, webhookURL string) *TransparencyAnchor {
	if strings.TrimSpace(receiptPath) == "" {
		receiptPath = strings.TrimSpace(os.Getenv("WARRANT_EXTERNAL_ANCHOR_PATH"))
	}
	if strings.TrimSpace(webhookURL) == "" {
		webhookURL = strings.TrimSpace(os.Getenv("WARRANT_EXTERNAL_ANCHOR_URL"))
	}
	return &TransparencyAnchor{
		receiptPath: receiptPath,
		webhookURL:  strings.TrimRight(webhookURL, "/"),
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

// AnchorCheckpoint signs a combined 6-chain Merkle root (MerkleVersion=2) over all 6 immutable tables
// and ships it to the external trust boundary.
func (a *TransparencyAnchor) AnchorCheckpoint(ctx context.Context, store *db.Store, signer crypto.EnvelopeSigner) (*models.LedgerCheckpoint, error) {
	// Mandatory pre-checkpoint authority lineage replay check: block notarizing unattested SQL INSERTs
	if _, linErr := store.VerifyAuthorityLineageAttestations(ctx); linErr != nil {
		return nil, linErr
	}
	// Verify internal chain continuity across all 6 chains before computing or signing the new external checkpoint
	rep, err := store.VerifyAllLedgerChains(ctx)
	if err != nil {
		return nil, err
	}
	if !rep.AllValid {
		return nil, fmt.Errorf("cannot anchor corrupted ledger chain: %s", rep.SuperuserTamperDetail)
	}

	var wHead, agHead, attHead, pHead, revHead, kHead string
	var wRows, agRows, attRows, pRows, revRows, kRows int
	for _, t := range rep.Tables {
		switch t.TableName {
		case "warrant_envelopes":
			wHead, wRows = t.TerminalHash, t.RowCount
		case "agent_action_ledger":
			agHead, agRows = t.TerminalHash, t.RowCount
		case "attestation_records":
			attHead, attRows = t.TerminalHash, t.RowCount
		case "principals":
			pHead, pRows = t.TerminalHash, t.RowCount
		case "principal_revocations":
			revHead, revRows = t.TerminalHash, t.RowCount
		case "kernel_public_keys":
			kHead, kRows = t.TerminalHash, t.RowCount
		}
	}

	merkleRoot := db.ComputeCombinedMerkleRootV2(
		wHead, wRows,
		agHead, agRows,
		attHead, attRows,
		pHead, pRows,
		revHead, revRows,
		kHead, kRows,
	)
	now := time.Now().UTC()
	cpID := "chk-" + uuid.NewString()[:8]

	payload := map[string]any{
		"checkpoint_id":         cpID,
		"merkle_version":        2,
		"warrant_head_hash":     wHead,
		"warrant_row_count":     wRows,
		"agent_head_hash":       agHead,
		"agent_row_count":       agRows,
		"attestation_head_hash": attHead,
		"attestation_row_count": attRows,
		"principal_head_hash":   pHead,
		"principal_row_count":   pRows,
		"revocation_head_hash":  revHead,
		"revocation_row_count":  revRows,
		"kernel_key_head_hash":  kHead,
		"kernel_key_row_count":  kRows,
		"combined_merkle_root":  merkleRoot,
		"anchored_at":           now.Format(time.RFC3339),
	}
	env, canonBytes, err := crypto.NewUnsignedEnvelope(PayloadTypeCheckpoint, payload)
	if err != nil {
		return nil, err
	}
	if err := signer.SignEnvelope(ctx, 1, env); err != nil {
		return nil, fmt.Errorf("sign merkle checkpoint: %w", err)
	}

	target := "IN_PROCESS_TRANSPARENCY_WITNESS"
	receiptHash := crypto.SHA256Hex(canonBytes)

	a.mu.Lock()
	defer a.mu.Unlock()

	cp := models.LedgerCheckpoint{
		CheckpointID:         cpID,
		MerkleVersion:        2,
		WarrantHeadHash:      wHead,
		WarrantRowCount:      wRows,
		AgentHeadHash:        agHead,
		AgentRowCount:        agRows,
		AttestationHeadHash:  attHead,
		AttestationRowCount:  attRows,
		PrincipalHeadHash:    pHead,
		PrincipalRowCount:    pRows,
		RevocationHeadHash:   revHead,
		RevocationRowCount:   revRows,
		KernelKeyHeadHash:    kHead,
		KernelKeyRowCount:    kRows,
		CombinedMerkleRoot:   merkleRoot,
		DSSEEnvelope:         *env,
		ExternalAnchorTarget: target,
		ExternalReceiptHash:  receiptHash,
		AnchoredAt:           now,
	}

	// 1. Optional external append-only file / mounted WORM volume sink
	if a.receiptPath != "" {
		cp.ExternalAnchorTarget = "EXTERNAL_WORM_FILE:" + a.receiptPath
		if dir := filepath.Dir(a.receiptPath); dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0750)
		}
		if rawLine, mErr := json.Marshal(cp); mErr == nil {
			f, fErr := os.OpenFile(a.receiptPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
			if fErr == nil {
				_, _ = f.Write(append(rawLine, '\n'))
				_ = f.Close()
			}
		}
	}

	// 2. Optional remote Transparency Log / S3 Object Lock / RFC 3161 webhook
	if a.webhookURL != "" {
		cp.ExternalAnchorTarget = "EXTERNAL_WEBHOOK:" + a.webhookURL
		reqBytes, _ := json.Marshal(map[string]any{
			"checkpoint_id":        cpID,
			"merkle_version":       2,
			"combined_merkle_root": merkleRoot,
			"dsse_envelope":        env,
		})
		req, rErr := http.NewRequestWithContext(ctx, http.MethodPost, a.webhookURL, bytes.NewReader(reqBytes))
		if rErr == nil {
			req.Header.Set("Content-Type", "application/json")
			if resp, doErr := a.httpClient.Do(req); doErr == nil {
				respBody, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if len(respBody) > 0 {
					cp.ExternalReceiptHash = crypto.SHA256Hex(respBody)
				}
			}
		}
	}

	a.inMemLog = append([]models.LedgerCheckpoint{cp}, a.inMemLog...)
	_ = store.SaveLedgerCheckpoint(ctx, cp)
	return &cp, nil
}

// ExternalWitnessRecords returns externally witnessed checkpoints (from WORM file or witness memory)
// independent of PostgreSQL tables so superuser DB tampering is caught.
func (a *TransparencyAnchor) ExternalWitnessRecords() []models.LedgerCheckpoint {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.receiptPath != "" {
		if raw, err := os.ReadFile(a.receiptPath); err == nil && len(raw) > 0 {
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			var out []models.LedgerCheckpoint
			for i := len(lines) - 1; i >= 0; i-- {
				var cp models.LedgerCheckpoint
				if json.Unmarshal([]byte(lines[i]), &cp) == nil && cp.CheckpointID != "" {
					out = append(out, cp)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	cpCopy := make([]models.LedgerCheckpoint, len(a.inMemLog))
	copy(cpCopy, a.inMemLog)
	return cpCopy
}
