package db

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	CodeQuorumSurvivorFloorViolation     = "QUORUM_SURVIVOR_FLOOR_VIOLATION"
	CodeUnattestedAuthorityLineageInsert = "UNATTESTED_AUTHORITY_LINEAGE_INSERT_DETECTED"
)

// IsQuorumSurvivorFloorError returns true when an error represents a 1-of-2 survivor floor or cross-role revocation violation.
func IsQuorumSurvivorFloorError(err error) bool {
	return err != nil && strings.Contains(err.Error(), CodeQuorumSurvivorFloorViolation)
}

// IsUnattestedAuthorityLineageError returns true when an unattested SQL INSERT into principals, principal_revocations, or kernel_public_keys is detected.
func IsUnattestedAuthorityLineageError(err error) bool {
	return err != nil && strings.Contains(err.Error(), CodeUnattestedAuthorityLineageInsert)
}

// ComputeGenesisManifestSHA256 computes a canonical SHA-256 digest over the ordered genesis entry_hash sets
// of principals (1..genesis_principal_max_seq) and principal_revocations (1..genesis_revocation_max_seq).
func ComputeGenesisManifestSHA256(principalEntryHashes, revocationEntryHashes []string) string {
	material := "GENESIS_SEAL_MANIFEST_V1|principals:" +
		strings.Join(principalEntryHashes, ",") +
		"|revocations:" +
		strings.Join(revocationEntryHashes, ",")
	return crypto.SHA256Hex([]byte(material))
}

func collectGenesisManifestTx(ctx context.Context, tx pgx.Tx, maxPSeqOpt, maxRSeqOpt int64) (int64, int64, string, error) {
	var pHashes []string
	var maxPSeq int64
	pQuery := `SELECT seq_no, entry_hash FROM principals ORDER BY seq_no ASC`
	var pRows pgx.Rows
	var err error
	if maxPSeqOpt > 0 {
		pRows, err = tx.Query(ctx, `SELECT seq_no, entry_hash FROM principals WHERE seq_no <= $1 ORDER BY seq_no ASC`, maxPSeqOpt)
	} else {
		pRows, err = tx.Query(ctx, pQuery)
	}
	if err != nil {
		return 0, 0, "", err
	}
	for pRows.Next() {
		var seq int64
		var eh string
		if sErr := pRows.Scan(&seq, &eh); sErr != nil {
			pRows.Close()
			return 0, 0, "", sErr
		}
		if seq > maxPSeq {
			maxPSeq = seq
		}
		pHashes = append(pHashes, eh)
	}
	if err := pRows.Err(); err != nil {
		pRows.Close()
		return 0, 0, "", err
	}
	pRows.Close()

	var rHashes []string
	var maxRSeq int64
	var rRows pgx.Rows
	if maxRSeqOpt > 0 {
		rRows, err = tx.Query(ctx, `SELECT seq_no, entry_hash FROM principal_revocations WHERE seq_no <= $1 ORDER BY seq_no ASC`, maxRSeqOpt)
	} else if maxPSeqOpt > 0 && maxRSeqOpt == 0 {
		// Upgraded DB with 0 genesis revocations
		rRows = nil
	} else {
		rRows, err = tx.Query(ctx, `SELECT seq_no, entry_hash FROM principal_revocations ORDER BY seq_no ASC`)
	}
	if err != nil {
		return 0, 0, "", err
	}
	if rRows != nil {
		for rRows.Next() {
			var seq int64
			var eh string
			if sErr := rRows.Scan(&seq, &eh); sErr != nil {
				rRows.Close()
				return 0, 0, "", sErr
			}
			if seq > maxRSeq {
				maxRSeq = seq
			}
			rHashes = append(rHashes, eh)
		}
		if err := rRows.Err(); err != nil {
			rRows.Close()
			return 0, 0, "", err
		}
		rRows.Close()
	}

	return maxPSeq, maxRSeq, ComputeGenesisManifestSHA256(pHashes, rHashes), nil
}

// EnsureGenesisSealSigned backfills a kernel-signed Genesis Seal Manifest on databases that were already sealed
// during a v1.0.0/v1.0.1 upgrade prior to v1.0.2. Once genesis_seal_dsse is non-null, PostgreSQL trigger freezes it forever.
func (s *Store) EnsureGenesisSealSigned(ctx context.Context, signer crypto.EnvelopeSigner) error {
	if signer == nil {
		return nil
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, lk := range []int64{lockPrincipalChain, lockRevocationChain, lockBootstrapSeal} {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lk); err != nil {
			return err
		}
	}

	var sealed bool
	var actor, reason string
	var sealedAt *time.Time
	var maxP, maxR int64
	var sealRaw []byte
	if err := tx.QueryRow(ctx, `
		SELECT sealed, sealed_by, sealed_reason, sealed_at, genesis_principal_max_seq, genesis_revocation_max_seq, genesis_seal_dsse
		FROM bootstrap_state WHERE singleton_id = 1
	`).Scan(&sealed, &actor, &reason, &sealedAt, &maxP, &maxR, &sealRaw); err != nil {
		return err
	}
	if !sealed || len(sealRaw) > 0 {
		return nil
	}

	effMaxP, effMaxR, manifestSHA, err := collectGenesisManifestTx(ctx, tx, maxP, maxR)
	if err != nil {
		return err
	}
	nowStr := time.Now().UTC().Format(time.RFC3339)
	if sealedAt != nil {
		nowStr = sealedAt.UTC().Format(time.RFC3339)
	}
	payload := map[string]any{
		"sealed_by":                  actor,
		"sealed_reason":              reason,
		"sealed_at":                  nowStr,
		"genesis_principal_max_seq":  effMaxP,
		"genesis_revocation_max_seq": effMaxR,
		"genesis_manifest_sha256":    manifestSHA,
	}
	env, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeGenesisSeal, payload)
	if err != nil {
		return err
	}
	if err := signer.SignEnvelope(ctx, 1, env); err != nil {
		return err
	}
	envJSON, err := crypto.CanonicalizeStruct(env)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE bootstrap_state
		SET genesis_principal_max_seq = $1,
		    genesis_revocation_max_seq = $2,
		    genesis_manifest_sha256 = $3,
		    genesis_seal_dsse = $4
		WHERE singleton_id = 1
	`, effMaxP, effMaxR, manifestSHA, envJSON); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RevokePrincipalEnforced executes a serialized, quorum-floor-protected revocation in principal_revocations:
//   - Acquires lockPrincipalChain (1001004) + lockRevocationChain (1001005) in deterministic order
//   - For 1-of-2 revocations (!isDualSigned), enforces that signer can ONLY revoke itself or a same-role peer
//   - Verifies that AFTER applying the revocation, >= 1 active SERVICE_OWNER AND >= 1 active AUTHORIZING_OFFICIAL survive
//   - Persists lineage_mode and governance_dsse for replayable authority lineage attestation
func (s *Store) RevokePrincipalEnforced(
	ctx context.Context,
	rev models.PrincipalRevocation,
	signerPrincipalID string,
	signerRole string,
	lineageMode string,
	isDualSigned bool,
	govDSSE *crypto.Envelope,
) (*models.PrincipalRevocation, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockPrincipalChain); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockRevocationChain); err != nil {
		return nil, err
	}

	var sealed bool
	if err := tx.QueryRow(ctx, `SELECT sealed FROM bootstrap_state WHERE singleton_id = 1`).Scan(&sealed); err != nil {
		return nil, err
	}
	if sealed && govDSSE == nil {
		return nil, errors.New("MISSING_REVOCATION_DSSE_SIGNATURE: post-seal revocations require a signed DSSE governance envelope")
	}

	var targetID, targetFP, targetRole string
	switch {
	case rev.PrincipalID != "":
		err = tx.QueryRow(ctx, `
			SELECT principal_id, key_fingerprint, role FROM principals WHERE principal_id = $1 LIMIT 1
		`, rev.PrincipalID).Scan(&targetID, &targetFP, &targetRole)
	case rev.KeyFingerprint != "":
		err = tx.QueryRow(ctx, `
			SELECT principal_id, key_fingerprint, role FROM principals WHERE lower(key_fingerprint) = lower($1) LIMIT 1
		`, rev.KeyFingerprint).Scan(&targetID, &targetFP, &targetRole)
	default:
		return nil, errors.New("REVOCATION_TARGET_NOT_FOUND: principal_id or key_fingerprint required")
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("REVOCATION_TARGET_NOT_FOUND: target principal not found")
		}
		return nil, err
	}
	rev.PrincipalID = targetID
	rev.KeyFingerprint = targetFP

	// Enforce same-role or self-revocation rule on 1-of-2 revocations
	if !isDualSigned {
		if targetID != signerPrincipalID && targetRole != signerRole {
			return nil, fmt.Errorf(
				"%s: 1-of-2 revocation by %s (%s) cannot revoke cross-role principal %s (%s); submit an atomic 2-of-2 ROTATE_AND_REVOKE_PRINCIPAL envelope",
				CodeQuorumSurvivorFloorViolation, signerPrincipalID, signerRole, targetID, targetRole,
			)
		}
	}

	// Enforce Quorum Survivor Floor: >= 1 active SERVICE_OWNER and >= 1 active AUTHORIZING_OFFICIAL must remain after revocation
	var remSO, remAO int
	if err := tx.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE p.role = 'SERVICE_OWNER'),
			COUNT(*) FILTER (WHERE p.role = 'AUTHORIZING_OFFICIAL')
		FROM principals p
		WHERE p.principal_id <> $1
		  AND lower(p.key_fingerprint) <> lower($2)
		  AND NOT EXISTS (
		      SELECT 1 FROM principal_revocations pr
		      WHERE pr.principal_id = p.principal_id OR lower(pr.key_fingerprint) = lower(p.key_fingerprint)
		  )
	`, targetID, targetFP).Scan(&remSO, &remAO); err != nil {
		return nil, err
	}
	if remSO < 1 || remAO < 1 {
		return nil, fmt.Errorf(
			"%s: revoking %s (%s) would leave %d active SERVICE_OWNER and %d active AUTHORIZING_OFFICIAL (<1 required); use an atomic 2-of-2 ROTATE_AND_REVOKE_PRINCIPAL ceremony",
			CodeQuorumSurvivorFloorViolation, targetID, targetRole, remSO, remAO,
		)
	}

	prevHash := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM principal_revocations ORDER BY seq_no DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if rev.RevokedAt.IsZero() {
		rev.RevokedAt = time.Now().UTC()
	}
	if rev.RevocationID == "" {
		rev.RevocationID = "rev-" + uuid.NewString()[:8]
	}
	if lineageMode == "" {
		if sealed {
			if isDualSigned {
				lineageMode = models.LineageModePostSeal2Of2
			} else {
				lineageMode = models.LineageModePostSeal1Of2
			}
		} else {
			lineageMode = models.LineageModeGenesisSealed
		}
	}
	rev.LineageMode = lineageMode
	rev.GovernanceDSSE = govDSSE
	rev.PrevHash = prevHash
	rev.EntryHash = ComputeRevocationEntryHash(prevHash, rev)

	var dsseRaw []byte
	if govDSSE != nil {
		dsseRaw, err = crypto.CanonicalizeStruct(govDSSE)
		if err != nil {
			return nil, err
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO principal_revocations (
			revocation_id, principal_id, key_fingerprint, reason_code, revoked_by,
			lineage_mode, governance_dsse, prev_hash, entry_hash, revoked_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`,
		rev.RevocationID, rev.PrincipalID, rev.KeyFingerprint, rev.ReasonCode, rev.RevokedBy,
		rev.LineageMode, dsseRaw, rev.PrevHash, rev.EntryHash, rev.RevokedAt,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &rev, nil
}

// RotateAndRevokePrincipalAtomic atomically enrolls a replacement principal AND revokes a target principal
// inside a single serialized transaction authorized by a 2-of-2 ROTATE_AND_REVOKE_PRINCIPAL DSSE envelope,
// verifying that >= 1 active SERVICE_OWNER and >= 1 active AUTHORIZING_OFFICIAL remain at commit.
func (s *Store) RotateAndRevokePrincipalAtomic(
	ctx context.Context,
	newP *models.Principal,
	rev models.PrincipalRevocation,
	govDSSE crypto.Envelope,
) (*models.Principal, *models.PrincipalRevocation, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockPrincipalChain); err != nil {
		return nil, nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockRevocationChain); err != nil {
		return nil, nil, err
	}

	// Resolve target to revoke first
	var targetID, targetFP, targetRole string
	switch {
	case rev.PrincipalID != "":
		err = tx.QueryRow(ctx, `
			SELECT principal_id, key_fingerprint, role FROM principals WHERE principal_id = $1 LIMIT 1
		`, rev.PrincipalID).Scan(&targetID, &targetFP, &targetRole)
	case rev.KeyFingerprint != "":
		err = tx.QueryRow(ctx, `
			SELECT principal_id, key_fingerprint, role FROM principals WHERE lower(key_fingerprint) = lower($1) LIMIT 1
		`, rev.KeyFingerprint).Scan(&targetID, &targetFP, &targetRole)
	default:
		return nil, nil, errors.New("REVOCATION_TARGET_NOT_FOUND: target_principal_id or target_key_fingerprint required")
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, errors.New("REVOCATION_TARGET_NOT_FOUND: target principal not found")
		}
		return nil, nil, err
	}
	rev.PrincipalID = targetID
	rev.KeyFingerprint = targetFP

	// Reject previously revoked replacement key
	var revReason string
	revErr := tx.QueryRow(ctx, `
		SELECT reason_code FROM principal_revocations
		WHERE principal_id = $1 OR lower(key_fingerprint) = lower($2)
		LIMIT 1
	`, newP.PrincipalID, newP.KeyFingerprint).Scan(&revReason)
	if revErr == nil {
		return nil, nil, fmt.Errorf("AC5_REVOKED_KEY_REENROLLMENT_FORBIDDEN: replacement key %s was previously revoked (%s)", newP.KeyFingerprint, revReason)
	}
	if !errors.Is(revErr, pgx.ErrNoRows) {
		return nil, nil, revErr
	}

	// Reject duplicate principal_id, key_id, public_key_b64, key_fingerprint, or active email (allowing email reuse ONLY for the target being atomically revoked)
	var dupID string
	dupErr := tx.QueryRow(ctx, `
		SELECT p.principal_id
		FROM principals p
		WHERE p.principal_id = $1
		   OR p.key_id = $2
		   OR p.public_key_b64 = $3
		   OR lower(p.key_fingerprint) = lower($4)
		   OR (
		       lower(p.email) = lower($5)
		       AND p.principal_id <> $6
		       AND NOT EXISTS (
		           SELECT 1 FROM principal_revocations pr
		           WHERE pr.principal_id = p.principal_id OR lower(pr.key_fingerprint) = lower(p.key_fingerprint)
		       )
		   )
		LIMIT 1
	`, newP.PrincipalID, newP.KeyID, newP.PublicKeyB64, newP.KeyFingerprint, newP.Email, targetID).Scan(&dupID)
	if dupErr == nil {
		return nil, nil, fmt.Errorf("AC5_DUPLICATE_PRINCIPAL_OR_KEY: replacement principal/key conflicts with existing principal %s", dupID)
	}
	if !errors.Is(dupErr, pgx.ErrNoRows) {
		return nil, nil, dupErr
	}

	dsseRaw, err := crypto.CanonicalizeStruct(govDSSE)
	if err != nil {
		return nil, nil, err
	}

	// 1. Append replacement principal
	pPrev := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM principals ORDER BY seq_no DESC LIMIT 1`).Scan(&pPrev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, err
	}
	if newP.CreatedAt.IsZero() {
		newP.CreatedAt = time.Now().UTC()
	}
	newP.LineageMode = models.LineageModePostSeal2Of2
	newP.GovernanceDSSE = &govDSSE
	newP.PrevHash = pPrev
	newP.EntryHash = ComputePrincipalEntryHash(pPrev, *newP)

	if _, err := tx.Exec(ctx, `
		INSERT INTO principals (
			principal_id, email, display_name, role, key_id, alg, public_key_b64, key_fingerprint,
			authenticator_mode, credential_id, lineage_mode, governance_dsse, prev_hash, entry_hash, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
	`,
		newP.PrincipalID, newP.Email, newP.DisplayName, newP.Role, newP.KeyID, newP.Alg, newP.PublicKeyB64, newP.KeyFingerprint,
		newP.AuthenticatorMode, newP.CredentialID, newP.LineageMode, dsseRaw, newP.PrevHash, newP.EntryHash, newP.CreatedAt,
	); err != nil {
		return nil, nil, err
	}

	// 2. Append target revocation
	rPrev := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM principal_revocations ORDER BY seq_no DESC LIMIT 1`).Scan(&rPrev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, err
	}
	if rev.RevokedAt.IsZero() {
		rev.RevokedAt = time.Now().UTC()
	}
	if rev.RevocationID == "" {
		rev.RevocationID = "rev-" + uuid.NewString()[:8]
	}
	rev.LineageMode = models.LineageModePostSeal2Of2
	rev.GovernanceDSSE = &govDSSE
	rev.PrevHash = rPrev
	rev.EntryHash = ComputeRevocationEntryHash(rPrev, rev)

	if _, err := tx.Exec(ctx, `
		INSERT INTO principal_revocations (
			revocation_id, principal_id, key_fingerprint, reason_code, revoked_by,
			lineage_mode, governance_dsse, prev_hash, entry_hash, revoked_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	`,
		rev.RevocationID, rev.PrincipalID, rev.KeyFingerprint, rev.ReasonCode, rev.RevokedBy,
		rev.LineageMode, dsseRaw, rev.PrevHash, rev.EntryHash, rev.RevokedAt,
	); err != nil {
		return nil, nil, err
	}

	// 3. Verify post-rotation Quorum Survivor Floor (>= 1 active SO and >= 1 active AO)
	var remSO, remAO int
	if err := tx.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE p.role = 'SERVICE_OWNER'),
			COUNT(*) FILTER (WHERE p.role = 'AUTHORIZING_OFFICIAL')
		FROM principals p
		WHERE NOT EXISTS (
		      SELECT 1 FROM principal_revocations pr
		      WHERE pr.principal_id = p.principal_id OR lower(pr.key_fingerprint) = lower(p.key_fingerprint)
		  )
	`).Scan(&remSO, &remAO); err != nil {
		return nil, nil, err
	}
	if remSO < 1 || remAO < 1 {
		return nil, nil, fmt.Errorf(
			"%s: atomic rotation revoking %s (%s) and enrolling %s (%s) would leave %d active SERVICE_OWNER and %d active AUTHORIZING_OFFICIAL",
			CodeQuorumSurvivorFloorViolation, targetID, targetRole, newP.PrincipalID, newP.Role, remSO, remAO,
		)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return newP, &rev, nil
}

// SignKernelKeyRotation creates a DSSE rotation attestation signed by the preceding kernel key.
func SignKernelKeyRotation(ctx context.Context, prevSigner crypto.EnvelopeSigner, newPK crypto.PrincipalKey, backendMode string) (*crypto.Envelope, error) {
	if prevSigner == nil {
		return nil, errors.New("nil previous kernel signer")
	}
	pubB64 := base64.StdEncoding.EncodeToString(newPK.PublicKeyBytes)
	payload := models.KernelKeyRotationPayload{
		EnvelopeID:        "krot-" + uuid.NewString(),
		NewKeyID:          newPK.KeyID,
		NewAlg:            newPK.Alg,
		NewPublicKeyB64:   pubB64,
		NewKeyFingerprint: newPK.KeyFingerprint,
		BackendMode:       backendMode,
		IssuedAt:          time.Now().UTC().Format(time.RFC3339),
	}
	env, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeKernelKeyRotation, payload)
	if err != nil {
		return nil, err
	}
	if err := prevSigner.SignEnvelope(ctx, 1, env); err != nil {
		return nil, err
	}
	return env, nil
}

// VerifyAuthorityLineageAttestations replays principals, principal_revocations, and kernel_public_keys
// from seq_no = 1 forward, verifying the kernel-signed Genesis Seal Manifest and every post-seal DSSE
// Governance / Kernel Rotation envelope against keys active at that exact historical point.
// Rejects any raw SQL INSERT into root-of-trust tables with UNATTESTED_AUTHORITY_LINEAGE_INSERT_DETECTED.
func (s *Store) VerifyAuthorityLineageAttestations(ctx context.Context) (string, error) {
	webauthnCfg := s.WebAuthnConfig()

	// 1. Load all principals in seq_no ASC
	type pRow struct {
		seqNo        int64
		authoritySeq int64
		p            models.Principal
		pk           *crypto.PrincipalKey
	}
	pRowsDB, err := s.pool.Query(ctx, `
		SELECT seq_no, authority_seq, principal_id, email, display_name, role, key_id, alg,
		       public_key_b64, key_fingerprint, lineage_mode, governance_dsse, prev_hash, entry_hash
		FROM principals ORDER BY seq_no ASC
	`)
	if err != nil {
		return "principals", err
	}
	var allP []pRow
	for pRowsDB.Next() {
		var r pRow
		var dsseRaw []byte
		if err := pRowsDB.Scan(
			&r.seqNo, &r.authoritySeq, &r.p.PrincipalID, &r.p.Email, &r.p.DisplayName, &r.p.Role,
			&r.p.KeyID, &r.p.Alg, &r.p.PublicKeyB64, &r.p.KeyFingerprint,
			&r.p.LineageMode, &dsseRaw, &r.p.PrevHash, &r.p.EntryHash,
		); err != nil {
			pRowsDB.Close()
			return "principals", err
		}
		if len(dsseRaw) > 0 {
			var env crypto.Envelope
			if err := json.Unmarshal(dsseRaw, &env); err != nil {
				pRowsDB.Close()
				return "principals", fmt.Errorf("%s: invalid governance_dsse JSON on principal %s", CodeUnattestedAuthorityLineageInsert, r.p.PrincipalID)
			}
			r.p.GovernanceDSSE = &env
		}
		pubBytes, decErr := crypto.DecodeBase64Any(r.p.PublicKeyB64)
		if decErr != nil {
			pRowsDB.Close()
			return "principals", fmt.Errorf("%s: invalid public_key_b64 on principal %s", CodeUnattestedAuthorityLineageInsert, r.p.PrincipalID)
		}
		r.pk = &crypto.PrincipalKey{
			PrincipalID:    r.p.PrincipalID,
			Email:          r.p.Email,
			DisplayName:    r.p.DisplayName,
			Role:           r.p.Role,
			KeyID:          r.p.KeyID,
			Alg:            r.p.Alg,
			PublicKeyBytes: pubBytes,
			KeyFingerprint: r.p.KeyFingerprint,
		}
		allP = append(allP, r)
	}
	if err := pRowsDB.Err(); err != nil {
		pRowsDB.Close()
		return "principals", err
	}
	pRowsDB.Close()

	// 2. Load all principal_revocations in seq_no ASC
	type rRow struct {
		seqNo        int64
		authoritySeq int64
		rev          models.PrincipalRevocation
	}
	rRowsDB, err := s.pool.Query(ctx, `
		SELECT seq_no, authority_seq, revocation_id, principal_id, key_fingerprint, reason_code,
		       revoked_by, lineage_mode, governance_dsse, prev_hash, entry_hash
		FROM principal_revocations ORDER BY seq_no ASC
	`)
	if err != nil {
		return "principal_revocations", err
	}
	var allR []rRow
	for rRowsDB.Next() {
		var r rRow
		var dsseRaw []byte
		if err := rRowsDB.Scan(
			&r.seqNo, &r.authoritySeq, &r.rev.RevocationID, &r.rev.PrincipalID, &r.rev.KeyFingerprint,
			&r.rev.ReasonCode, &r.rev.RevokedBy, &r.rev.LineageMode, &dsseRaw, &r.rev.PrevHash, &r.rev.EntryHash,
		); err != nil {
			rRowsDB.Close()
			return "principal_revocations", err
		}
		if len(dsseRaw) > 0 {
			var env crypto.Envelope
			if err := json.Unmarshal(dsseRaw, &env); err != nil {
				rRowsDB.Close()
				return "principal_revocations", fmt.Errorf("%s: invalid governance_dsse JSON on revocation %s", CodeUnattestedAuthorityLineageInsert, r.rev.RevocationID)
			}
			r.rev.GovernanceDSSE = &env
		}
		allR = append(allR, r)
	}
	if err := rRowsDB.Err(); err != nil {
		rRowsDB.Close()
		return "principal_revocations", err
	}
	rRowsDB.Close()

	// 3. Load bootstrap_state and replay Principal + Revocation authority lineage
	boot, err := s.GetBootstrapState(ctx)
	if err != nil {
		return "principals", err
	}

	activeByKeyID := crypto.MapKeyResolver{}
	principalByID := map[string]*crypto.PrincipalKey{}
	principalByFP := map[string]*crypto.PrincipalKey{}

	applyEnroll := func(pk *crypto.PrincipalKey) {
		cp := *pk
		activeByKeyID[cp.KeyID] = &cp
		principalByID[cp.PrincipalID] = &cp
		principalByFP[strings.ToLower(cp.KeyFingerprint)] = &cp
	}
	applyRevoke := func(principalID, keyFP, reason string) {
		for _, pk := range activeByKeyID {
			if pk.PrincipalID == principalID || strings.EqualFold(pk.KeyFingerprint, keyFP) {
				pk.Revoked = true
				pk.RevokeReason = reason
			}
		}
	}
	countActiveRoles := func() (int, int) {
		so, ao := 0, 0
		for _, pk := range activeByKeyID {
			if pk.Revoked {
				continue
			}
			switch pk.Role {
			case crypto.RoleServiceOwner:
				so++
			case crypto.RoleAuthorizingOfficial:
				ao++
			}
		}
		return so, ao
	}

	var genPHashes, genRHashes []string
	type postStep struct {
		sortSeq int64
		enroll  *pRow
		revoke  *rRow
	}
	var postSteps []postStep
	rotateByEnvPayload := map[string]*postStep{}

	if !boot.Sealed {
		// Unsealed genesis setup: load all current genesis rows into active resolver for kernel key dual-sign checks
		for i := range allP {
			applyEnroll(allP[i].pk)
		}
		for i := range allR {
			applyRevoke(allR[i].rev.PrincipalID, allR[i].rev.KeyFingerprint, allR[i].rev.ReasonCode)
		}
	} else {
		for i := range allP {
			if allP[i].seqNo <= boot.GenesisPrincipalMaxSeq {
				genPHashes = append(genPHashes, allP[i].p.EntryHash)
				applyEnroll(allP[i].pk)
			} else {
				rowCopy := allP[i]
				if rowCopy.p.GovernanceDSSE == nil {
					return "principals", fmt.Errorf(
						"%s: post-seal principal %s (seq_no=%d > genesis_max=%d) lacks governance_dsse",
						CodeUnattestedAuthorityLineageInsert, rowCopy.p.PrincipalID, rowCopy.seqNo, boot.GenesisPrincipalMaxSeq,
					)
				}
				step := postStep{sortSeq: rowCopy.authoritySeq, enroll: &rowCopy}
				postSteps = append(postSteps, step)
				rotateByEnvPayload[rowCopy.p.GovernanceDSSE.Payload] = &postSteps[len(postSteps)-1]
			}
		}
		for i := range allR {
			if allR[i].seqNo <= boot.GenesisRevocationMaxSeq {
				genRHashes = append(genRHashes, allR[i].rev.EntryHash)
				applyRevoke(allR[i].rev.PrincipalID, allR[i].rev.KeyFingerprint, allR[i].rev.ReasonCode)
			} else {
				rowCopy := allR[i]
				if rowCopy.rev.GovernanceDSSE == nil {
					return "principal_revocations", fmt.Errorf(
						"%s: post-seal revocation %s (seq_no=%d > genesis_max=%d) lacks governance_dsse",
						CodeUnattestedAuthorityLineageInsert, rowCopy.rev.RevocationID, rowCopy.seqNo, boot.GenesisRevocationMaxSeq,
					)
				}
				if paired, ok := rotateByEnvPayload[rowCopy.rev.GovernanceDSSE.Payload]; ok && paired.revoke == nil {
					paired.revoke = &rowCopy
				} else {
					postSteps = append(postSteps, postStep{sortSeq: rowCopy.authoritySeq, revoke: &rowCopy})
				}
			}
		}

		// Verify Genesis Seal Manifest digest
		expectedManifest := ComputeGenesisManifestSHA256(genPHashes, genRHashes)
		if boot.GenesisManifestSHA256 != "" && !strings.EqualFold(boot.GenesisManifestSHA256, expectedManifest) {
			return "principals", fmt.Errorf(
				"%s: genesis_manifest_sha256 mismatch (bootstrap_state=%s recomputed=%s)",
				CodeUnattestedAuthorityLineageInsert, boot.GenesisManifestSHA256, expectedManifest,
			)
		}

		// Replay all post-seal authority mutations in causal authority_seq order
		sort.Slice(postSteps, func(i, j int) bool { return postSteps[i].sortSeq < postSteps[j].sortSeq })
		for _, st := range postSteps {
			switch {
			case st.enroll != nil && st.revoke != nil:
				// Atomic 2-of-2 ROTATE_AND_REVOKE_PRINCIPAL step
				env := st.enroll.p.GovernanceDSSE
				dualRes, vErr := crypto.VerifyDualHumanCeremony(env, crypto.PayloadTypePrincipalGovernance, activeByKeyID, webauthnCfg)
				if vErr != nil {
					return "principals", fmt.Errorf("%s: post-seal atomic rotation %s failed 2-of-2 verification: %w", CodeUnattestedAuthorityLineageInsert, st.enroll.p.PrincipalID, vErr)
				}
				var gp models.PrincipalGovernancePayload
				if err := json.Unmarshal(dualRes.CanonicalPayload, &gp); err != nil || gp.Action != models.GovActionRotateAndRevokePrincipal {
					return "principals", fmt.Errorf("%s: invalid ROTATE_AND_REVOKE_PRINCIPAL payload on %s", CodeUnattestedAuthorityLineageInsert, st.enroll.p.PrincipalID)
				}
				if err := verifyEnrolledPrincipalMatchesPayload(st.enroll.p, gp, webauthnCfg); err != nil {
					return "principals", err
				}
				if err := verifyRevocationMatchesPayload(st.revoke.rev, gp); err != nil {
					return "principal_revocations", err
				}
				applyEnroll(st.enroll.pk)
				applyRevoke(st.revoke.rev.PrincipalID, st.revoke.rev.KeyFingerprint, st.revoke.rev.ReasonCode)
				if remSO, remAO := countActiveRoles(); remSO < 1 || remAO < 1 {
					return "principal_revocations", fmt.Errorf("%s: post-rotation survivor floor violated (SO=%d AO=%d)", CodeUnattestedAuthorityLineageInsert, remSO, remAO)
				}

			case st.enroll != nil:
				// Post-seal 2-of-2 ENROLL_PRINCIPAL step
				env := st.enroll.p.GovernanceDSSE
				dualRes, vErr := crypto.VerifyDualHumanCeremony(env, crypto.PayloadTypePrincipalGovernance, activeByKeyID, webauthnCfg)
				if vErr != nil {
					return "principals", fmt.Errorf("%s: post-seal principal %s failed 2-of-2 governance DSSE verification: %w", CodeUnattestedAuthorityLineageInsert, st.enroll.p.PrincipalID, vErr)
				}
				var gp models.PrincipalGovernancePayload
				if err := json.Unmarshal(dualRes.CanonicalPayload, &gp); err != nil || gp.Action != models.GovActionEnrollPrincipal {
					return "principals", fmt.Errorf("%s: principal %s governance_dsse action mismatch", CodeUnattestedAuthorityLineageInsert, st.enroll.p.PrincipalID)
				}
				if err := verifyEnrolledPrincipalMatchesPayload(st.enroll.p, gp, webauthnCfg); err != nil {
					return "principals", err
				}
				applyEnroll(st.enroll.pk)

			case st.revoke != nil:
				// Post-seal 1-of-2 (or 2-of-2) REVOKE_PRINCIPAL step
				env := st.revoke.rev.GovernanceDSSE
				var gp models.PrincipalGovernancePayload
				isDual := len(env.Signatures) >= 2
				if isDual {
					dualRes, vErr := crypto.VerifyDualHumanCeremony(env, crypto.PayloadTypePrincipalGovernance, activeByKeyID, webauthnCfg)
					if vErr != nil {
						return "principal_revocations", fmt.Errorf("%s: post-seal 2-of-2 revocation %s failed verification: %w", CodeUnattestedAuthorityLineageInsert, st.revoke.rev.RevocationID, vErr)
					}
					if err := json.Unmarshal(dualRes.CanonicalPayload, &gp); err != nil {
						return "principal_revocations", fmt.Errorf("%s: invalid revocation payload on %s", CodeUnattestedAuthorityLineageInsert, st.revoke.rev.RevocationID)
					}
				} else {
					singleRes, vErr := crypto.VerifySingleActivePrincipalCeremony(env, crypto.PayloadTypePrincipalGovernance, activeByKeyID, webauthnCfg)
					if vErr != nil {
						return "principal_revocations", fmt.Errorf("%s: post-seal 1-of-2 revocation %s failed verification: %w", CodeUnattestedAuthorityLineageInsert, st.revoke.rev.RevocationID, vErr)
					}
					if err := json.Unmarshal(singleRes.CanonicalPayload, &gp); err != nil {
						return "principal_revocations", fmt.Errorf("%s: invalid revocation payload on %s", CodeUnattestedAuthorityLineageInsert, st.revoke.rev.RevocationID)
					}
					targetPK := principalByID[st.revoke.rev.PrincipalID]
					if targetPK == nil {
						targetPK = principalByFP[strings.ToLower(st.revoke.rev.KeyFingerprint)]
					}
					if targetPK == nil {
						return "principal_revocations", fmt.Errorf("%s: revocation %s references unknown principal %s", CodeUnattestedAuthorityLineageInsert, st.revoke.rev.RevocationID, st.revoke.rev.PrincipalID)
					}
					if targetPK.PrincipalID != singleRes.Signer.PrincipalID && targetPK.Role != singleRes.Signer.Role {
						return "principal_revocations", fmt.Errorf("%s: 1-of-2 revocation %s violated cross-role restriction", CodeUnattestedAuthorityLineageInsert, st.revoke.rev.RevocationID)
					}
				}
				if gp.Action != models.GovActionRevokePrincipal && gp.Action != models.GovActionRotateAndRevokePrincipal {
					return "principal_revocations", fmt.Errorf("%s: unexpected action %q on revocation %s", CodeUnattestedAuthorityLineageInsert, gp.Action, st.revoke.rev.RevocationID)
				}
				if err := verifyRevocationMatchesPayload(st.revoke.rev, gp); err != nil {
					return "principal_revocations", err
				}
				applyRevoke(st.revoke.rev.PrincipalID, st.revoke.rev.KeyFingerprint, st.revoke.rev.ReasonCode)
				if remSO, remAO := countActiveRoles(); remSO < 1 || remAO < 1 {
					return "principal_revocations", fmt.Errorf("%s: revocation %s violated survivor floor (SO=%d AO=%d)", CodeUnattestedAuthorityLineageInsert, st.revoke.rev.RevocationID, remSO, remAO)
				}
			}
		}
	}

	// 4. Replay kernel_public_keys from seq_no = 1 forward AND verify bootstrap_state.genesis_seal_dsse against verified kernel keys
	kRows, err := s.pool.Query(ctx, `
		SELECT seq_no, key_id, alg, public_key_b64, key_fingerprint, backend_mode, rotation_dsse
		FROM kernel_public_keys ORDER BY seq_no ASC
	`)
	if err != nil {
		return "kernel_public_keys", err
	}
	defer kRows.Close()

	verifiedKernelKeys := map[string]*crypto.PrincipalKey{}
	var prevKernelPK *crypto.PrincipalKey
	kmsURL := strings.TrimSpace(os.Getenv("WARRANT_KMS_SIGN_URL"))
	kmsPubB64 := strings.TrimSpace(os.Getenv("WARRANT_KMS_PUBLIC_KEY_B64"))

	kIdx := 0
	for kRows.Next() {
		var seqNo int64
		var rec models.KernelPublicKeyRecord
		var rotRaw []byte
		if err := kRows.Scan(&seqNo, &rec.KeyID, &rec.Alg, &rec.PublicKeyB64, &rec.KeyFingerprint, &rec.BackendMode, &rotRaw); err != nil {
			return "kernel_public_keys", err
		}
		pubBytes, decErr := crypto.DecodeBase64Any(rec.PublicKeyB64)
		if decErr != nil {
			return "kernel_public_keys", fmt.Errorf("%s: invalid public_key_b64 on kernel key %s", CodeUnattestedAuthorityLineageInsert, rec.KeyID)
		}
		curPK := &crypto.PrincipalKey{
			PrincipalID:    "sys-warrantd-kernel",
			Role:           crypto.RoleAttestationKernel,
			KeyID:          rec.KeyID,
			Alg:            rec.Alg,
			PublicKeyBytes: pubBytes,
			KeyFingerprint: rec.KeyFingerprint,
		}

		if kIdx > 0 {
			matchesConfiguredKMS := rec.BackendMode == "NON_EXPORTABLE_EXTERNAL_KMS_HSM" && kmsURL != "" && kmsPubB64 != "" && kmsPubB64 == rec.PublicKeyB64
			if !matchesConfiguredKMS {
				if len(rotRaw) == 0 {
					return "kernel_public_keys", fmt.Errorf(
						"%s: kernel_public_keys row %s (seq_no=%d > 1) lacks rotation_dsse signed by preceding kernel key or 2-of-2 principals",
						CodeUnattestedAuthorityLineageInsert, rec.KeyID, seqNo,
					)
				}
				var rotEnv crypto.Envelope
				if err := json.Unmarshal(rotRaw, &rotEnv); err != nil {
					return "kernel_public_keys", fmt.Errorf("%s: invalid rotation_dsse JSON on kernel key %s", CodeUnattestedAuthorityLineageInsert, rec.KeyID)
				}
				if rotEnv.PayloadType != crypto.PayloadTypeKernelKeyRotation {
					return "kernel_public_keys", fmt.Errorf("%s: unexpected rotation_dsse payloadType %q on kernel key %s", CodeUnattestedAuthorityLineageInsert, rotEnv.PayloadType, rec.KeyID)
				}
				rawRotPayload, pErr := rotEnv.DecodePayload()
				if pErr != nil {
					return "kernel_public_keys", fmt.Errorf("%s: decode rotation_dsse payload on %s: %w", CodeUnattestedAuthorityLineageInsert, rec.KeyID, pErr)
				}
				canonRot, cErr := crypto.CanonicalizeJSON(rawRotPayload)
				if cErr != nil || string(canonRot) != string(rawRotPayload) {
					return "kernel_public_keys", fmt.Errorf("%s: non-canonical rotation_dsse JCS on kernel key %s", CodeUnattestedAuthorityLineageInsert, rec.KeyID)
				}
				var rotBody models.KernelKeyRotationPayload
				if err := json.Unmarshal(rawRotPayload, &rotBody); err != nil {
					return "kernel_public_keys", fmt.Errorf("%s: parse rotation_dsse payload on %s: %w", CodeUnattestedAuthorityLineageInsert, rec.KeyID, err)
				}
				if rotBody.NewKeyID != rec.KeyID || rotBody.NewPublicKeyB64 != rec.PublicKeyB64 || !strings.EqualFold(rotBody.NewKeyFingerprint, rec.KeyFingerprint) {
					return "kernel_public_keys", fmt.Errorf("%s: rotation_dsse key binding mismatch on kernel key %s", CodeUnattestedAuthorityLineageInsert, rec.KeyID)
				}

				signedByPrevKernel := len(rotEnv.Signatures) >= 1 && prevKernelPK != nil &&
					rotEnv.Signatures[0].KeyID == prevKernelPK.KeyID &&
					crypto.VerifySingleSignature(rotEnv.PayloadType, rawRotPayload, rotEnv.Signatures[0], prevKernelPK, webauthnCfg) == nil
				if !signedByPrevKernel {
					if _, dualErr := crypto.VerifyDualHumanCeremony(&rotEnv, crypto.PayloadTypeKernelKeyRotation, activeByKeyID, webauthnCfg); dualErr != nil {
						return "kernel_public_keys", fmt.Errorf(
							"%s: rotation_dsse on kernel key %s failed both preceding-kernel and 2-of-2 AC-5 verification: %w",
							CodeUnattestedAuthorityLineageInsert, rec.KeyID, dualErr,
						)
					}
				}
			}
		}

		verifiedKernelKeys[curPK.KeyID] = curPK
		prevKernelPK = curPK
		kIdx++
	}
	if err := kRows.Err(); err != nil {
		return "kernel_public_keys", err
	}

	// 5. Verify kernel-signed Genesis Seal DSSE on sealed bootstrap_state
	if boot.Sealed && boot.GenesisSealDSSE != nil {
		rawSeal, err := boot.GenesisSealDSSE.DecodePayload()
		if err != nil {
			return "principals", fmt.Errorf("%s: decode genesis_seal_dsse: %w", CodeUnattestedAuthorityLineageInsert, err)
		}
		canonSeal, err := crypto.CanonicalizeJSON(rawSeal)
		if err != nil || string(canonSeal) != string(rawSeal) {
			return "principals", fmt.Errorf("%s: non-canonical genesis_seal_dsse JCS", CodeUnattestedAuthorityLineageInsert)
		}
		var sealBody struct {
			GenesisPrincipalMaxSeq  int64  `json:"genesis_principal_max_seq"`
			GenesisRevocationMaxSeq int64  `json:"genesis_revocation_max_seq"`
			GenesisManifestSHA256   string `json:"genesis_manifest_sha256"`
		}
		if err := json.Unmarshal(rawSeal, &sealBody); err != nil {
			return "principals", fmt.Errorf("%s: parse genesis_seal_dsse: %w", CodeUnattestedAuthorityLineageInsert, err)
		}
		expectedManifest := ComputeGenesisManifestSHA256(genPHashes, genRHashes)
		if sealBody.GenesisPrincipalMaxSeq != boot.GenesisPrincipalMaxSeq ||
			sealBody.GenesisRevocationMaxSeq != boot.GenesisRevocationMaxSeq ||
			!strings.EqualFold(sealBody.GenesisManifestSHA256, expectedManifest) {
			return "principals", fmt.Errorf("%s: genesis_seal_dsse manifest mismatch against bootstrap_state/principals", CodeUnattestedAuthorityLineageInsert)
		}
		if len(boot.GenesisSealDSSE.Signatures) == 0 {
			return "principals", fmt.Errorf("%s: genesis_seal_dsse has zero signatures", CodeUnattestedAuthorityLineageInsert)
		}
		sig := boot.GenesisSealDSSE.Signatures[0]
		kpk := verifiedKernelKeys[sig.KeyID]
		if kpk == nil {
			return "principals", fmt.Errorf("%s: genesis_seal_dsse signed by unverified kernel key %q", CodeUnattestedAuthorityLineageInsert, sig.KeyID)
		}
		if err := crypto.VerifySingleSignature(boot.GenesisSealDSSE.PayloadType, rawSeal, sig, kpk, webauthnCfg); err != nil {
			return "principals", fmt.Errorf("%s: genesis_seal_dsse signature invalid: %w", CodeUnattestedAuthorityLineageInsert, err)
		}
	} else if boot.Sealed && len(verifiedKernelKeys) > 0 && boot.SealedBy != "migration-006" {
		return "principals", fmt.Errorf("%s: sealed bootstrap_state lacks kernel-signed genesis_seal_dsse", CodeUnattestedAuthorityLineageInsert)
	}

	return "", nil
}

func verifyEnrolledPrincipalMatchesPayload(p models.Principal, gp models.PrincipalGovernancePayload, webauthnCfg crypto.WebAuthnConfig) error {
	if gp.Role != p.Role {
		return fmt.Errorf("%s: principal %s role %q != signed governance payload role %q", CodeUnattestedAuthorityLineageInsert, p.PrincipalID, p.Role, gp.Role)
	}
	if !strings.EqualFold(strings.TrimSpace(gp.Email), strings.TrimSpace(p.Email)) {
		return fmt.Errorf("%s: principal %s email %q != signed governance payload email %q", CodeUnattestedAuthorityLineageInsert, p.PrincipalID, p.Email, gp.Email)
	}
	if p.AuthenticatorMode == "WEBAUTHN_HARDWARE" || gp.AttestationObject != "" || gp.PublicKeySPKI != "" {
		_, spkiDER, fp, err := crypto.ParseWebAuthnRegistration(gp.AttestationObject, gp.PublicKeySPKI, gp.CredentialID, webauthnCfg)
		if err != nil {
			return fmt.Errorf("%s: principal %s webauthn registration payload invalid: %w", CodeUnattestedAuthorityLineageInsert, p.PrincipalID, err)
		}
		if !strings.EqualFold(fp, p.KeyFingerprint) || base64.StdEncoding.EncodeToString(spkiDER) != p.PublicKeyB64 {
			return fmt.Errorf("%s: principal %s webauthn key mismatch against signed governance payload", CodeUnattestedAuthorityLineageInsert, p.PrincipalID)
		}
		return nil
	}
	if strings.TrimSpace(gp.PublicKeyB64) != p.PublicKeyB64 {
		return fmt.Errorf("%s: principal %s public_key_b64 mismatch against signed governance payload", CodeUnattestedAuthorityLineageInsert, p.PrincipalID)
	}
	return nil
}

func verifyRevocationMatchesPayload(rev models.PrincipalRevocation, gp models.PrincipalGovernancePayload) error {
	signedID := strings.TrimSpace(gp.TargetPrincipalID)
	if signedID == "" && gp.Action == models.GovActionRevokePrincipal {
		signedID = strings.TrimSpace(gp.PrincipalID)
	}
	signedFP := strings.TrimSpace(gp.TargetKeyFingerprint)
	if signedID == "" && signedFP == "" {
		return fmt.Errorf("%s: revocation %s signed payload missing target_principal_id and target_key_fingerprint", CodeUnattestedAuthorityLineageInsert, rev.RevocationID)
	}
	if signedID != "" && signedID != rev.PrincipalID {
		return fmt.Errorf("%s: revocation %s principal_id %q != signed target %q", CodeUnattestedAuthorityLineageInsert, rev.RevocationID, rev.PrincipalID, signedID)
	}
	if signedFP != "" && !strings.EqualFold(signedFP, rev.KeyFingerprint) {
		return fmt.Errorf("%s: revocation %s key_fingerprint %q != signed target %q", CodeUnattestedAuthorityLineageInsert, rev.RevocationID, rev.KeyFingerprint, signedFP)
	}
	return nil
}
