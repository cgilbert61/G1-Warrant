package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/g1163rt-labs/g1-warrant/db/migrations"
	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

const (
	lockWarrantChain     int64 = 1001001
	lockAgentActionChain int64 = 1001002
	lockAttestationChain int64 = 1001003
)

// Store manages PostgreSQL persistence, append-only hash chains, and LISTEN/NOTIFY streams.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore connects to PostgreSQL and verifies connectivity.
func NewStore(ctx context.Context, connString string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse postgres config: %w", err)
	}
	cfg.MaxConns = 25
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Pool exposes the underlying pgxpool.Pool for LISTEN/NOTIFY and verification tests.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// Close closes the database connection pool.
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Migrate executes all embedded SQL migration files in lexicographical order.
func (s *Store) Migrate(ctx context.Context) error {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		sqlBytes, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := s.pool.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("exec migration %s: %w", name, err)
		}
	}
	return nil
}

// UpsertPrincipal registers or updates a principal key in the principals registry.
func (s *Store) UpsertPrincipal(ctx context.Context, p models.Principal) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO principals (
			principal_id, email, display_name, role, key_id, alg, public_key_b64, key_fingerprint, authenticator_mode, credential_id
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (principal_id) DO UPDATE SET
			key_id = EXCLUDED.key_id,
			alg = EXCLUDED.alg,
			public_key_b64 = EXCLUDED.public_key_b64,
			key_fingerprint = EXCLUDED.key_fingerprint,
			authenticator_mode = EXCLUDED.authenticator_mode,
			credential_id = EXCLUDED.credential_id
	`, p.PrincipalID, p.Email, p.DisplayName, p.Role, p.KeyID, p.Alg, p.PublicKeyB64, p.KeyFingerprint, p.AuthenticatorMode, p.CredentialID)
	return err
}

// ListPrincipals returns all registered principals with live revocation status.
func (s *Store) ListPrincipals(ctx context.Context) ([]models.Principal, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.principal_id, p.email, p.display_name, p.role, p.key_id, p.alg,
		       p.public_key_b64, p.key_fingerprint, p.authenticator_mode, p.credential_id, p.created_at,
		       COALESCE(r.reason_code, '') AS revoke_reason,
		       (r.revocation_id IS NOT NULL) AS is_revoked
		FROM principals p
		LEFT JOIN LATERAL (
			SELECT revocation_id, reason_code
			FROM principal_revocations pr
			WHERE pr.principal_id = p.principal_id OR lower(pr.key_fingerprint) = lower(p.key_fingerprint)
			ORDER BY pr.revoked_at DESC
			LIMIT 1
		) r ON TRUE
		ORDER BY p.principal_id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Principal{}
	for rows.Next() {
		var p models.Principal
		if err := rows.Scan(
			&p.PrincipalID, &p.Email, &p.DisplayName, &p.Role, &p.KeyID, &p.Alg,
			&p.PublicKeyB64, &p.KeyFingerprint, &p.AuthenticatorMode, &p.CredentialID, &p.CreatedAt,
			&p.RevokeReason, &p.Revoked,
		); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RevokePrincipal inserts a live revocation into principal_revocations.
func (s *Store) RevokePrincipal(ctx context.Context, rev models.PrincipalRevocation) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO principal_revocations (revocation_id, principal_id, key_fingerprint, reason_code, revoked_by, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, rev.RevocationID, rev.PrincipalID, rev.KeyFingerprint, rev.ReasonCode, rev.RevokedBy, rev.RevokedAt)
	return err
}

// ListRevocations lists all active principal/key revocations.
func (s *Store) ListRevocations(ctx context.Context) ([]models.PrincipalRevocation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT revocation_id, principal_id, key_fingerprint, reason_code, revoked_by, revoked_at
		FROM principal_revocations ORDER BY revoked_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.PrincipalRevocation{}
	for rows.Next() {
		var r models.PrincipalRevocation
		if err := rows.Scan(&r.RevocationID, &r.PrincipalID, &r.KeyFingerprint, &r.ReasonCode, &r.RevokedBy, &r.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// KeyResolverContext binds a Store to a context for crypto.KeyResolver lookups.
type StoreKeyResolver struct {
	Store *Store
	Ctx   context.Context
}

// ResolveKey resolves keyID against principals + live principal_revocations.
func (r StoreKeyResolver) ResolveKey(keyID string) (*crypto.PrincipalKey, error) {
	var p models.Principal
	err := r.Store.pool.QueryRow(r.Ctx, `
		SELECT p.principal_id, p.email, p.display_name, p.role, p.key_id, p.alg,
		       p.public_key_b64, p.key_fingerprint,
		       COALESCE(rev.reason_code, ''),
		       (rev.revocation_id IS NOT NULL)
		FROM principals p
		LEFT JOIN LATERAL (
			SELECT revocation_id, reason_code
			FROM principal_revocations pr
			WHERE pr.principal_id = p.principal_id OR lower(pr.key_fingerprint) = lower(p.key_fingerprint)
			ORDER BY pr.revoked_at DESC
			LIMIT 1
		) rev ON TRUE
		WHERE p.key_id = $1
	`, keyID).Scan(
		&p.PrincipalID, &p.Email, &p.DisplayName, &p.Role, &p.KeyID, &p.Alg,
		&p.PublicKeyB64, &p.KeyFingerprint, &p.RevokeReason, &p.Revoked,
	)
	if err != nil {
		return nil, fmt.Errorf("lookup key %q: %w", keyID, err)
	}
	pubBytes, err := crypto.DecodeBase64Any(p.PublicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode public key for %q: %w", keyID, err)
	}
	return &crypto.PrincipalKey{
		PrincipalID:    p.PrincipalID,
		Email:          p.Email,
		DisplayName:    p.DisplayName,
		Role:           p.Role,
		KeyID:          p.KeyID,
		Alg:            p.Alg,
		PublicKeyBytes: pubBytes,
		KeyFingerprint: p.KeyFingerprint,
		Revoked:        p.Revoked,
		RevokeReason:   p.RevokeReason,
	}, nil
}

// ComputeWarrantEntryHash computes the deterministic SHA-256 chain link for warrant_envelopes.
func ComputeWarrantEntryHash(prevHash, warrantID, warrantClass, s1ID, s1FP, s2ID, s2FP string, env crypto.Envelope) (string, error) {
	canonEnv, err := crypto.CanonicalizeStruct(env)
	if err != nil {
		return "", err
	}
	material := strings.Join([]string{
		"warrant_envelopes",
		prevHash,
		warrantID,
		warrantClass,
		s1ID,
		strings.ToLower(s1FP),
		s2ID,
		strings.ToLower(s2FP),
		string(canonEnv),
	}, "|")
	return crypto.SHA256Hex([]byte(material)), nil
}

// ComputeAgentActionEntryHash computes the deterministic SHA-256 chain link for agent_action_ledger.
func ComputeAgentActionEntryHash(prevHash string, e models.AgentLedgerEntry) string {
	material := strings.Join([]string{
		"agent_action_ledger",
		prevHash,
		e.ActionID,
		e.TaskTokenID,
		e.WarrantID,
		e.WorkerName,
		e.TargetAsset,
		e.ActionType,
		e.RawInputSHA256,
		e.ExtractorDigest,
		e.TypedOutputSHA256,
		e.Status,
	}, "|")
	return crypto.SHA256Hex([]byte(material))
}

// ComputeAttestationEntryHash computes the deterministic SHA-256 chain link for attestation_records.
func ComputeAttestationEntryHash(prevHash string, a models.AttestationRecord) (string, error) {
	canonEnv, err := crypto.CanonicalizeStruct(a.DSSEEnvelope)
	if err != nil {
		return "", err
	}
	material := strings.Join([]string{
		"attestation_records",
		prevHash,
		a.AttestationID,
		a.RemediationID,
		a.ServiceID,
		a.CVEID,
		a.WarrantID,
		a.TwinTranscriptSHA256,
		a.LockoutPolicyID,
		string(canonEnv),
	}, "|")
	return crypto.SHA256Hex([]byte(material)), nil
}

// AppendWarrantEnvelope appends a dual-signed Standing Warrant to warrant_envelopes with serialized hash chaining.
func (s *Store) AppendWarrantEnvelope(ctx context.Context, w *models.WarrantRecord) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockWarrantChain); err != nil {
		return err
	}
	prevHash := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM warrant_envelopes ORDER BY seq_no DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	entryHash, err := ComputeWarrantEntryHash(
		prevHash, w.WarrantID, w.WarrantClass,
		w.Slot1PrincipalID, w.Slot1KeyFP,
		w.Slot2PrincipalID, w.Slot2KeyFP,
		w.DSSEEnvelope,
	)
	if err != nil {
		return err
	}
	w.PrevHash = prevHash
	w.EntryHash = entryHash
	if w.CreatedAt.IsZero() {
		w.CreatedAt = time.Now().UTC()
	}

	scopeJSON, err := json.Marshal(w.ScopeServices)
	if err != nil {
		return err
	}
	envJSON, err := crypto.CanonicalizeStruct(w.DSSEEnvelope)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO warrant_envelopes (
			warrant_id, warrant_class, scope_services, max_cvss, kev_eligible,
			max_blast_radius_replicas, allow_stateful_patches, sla_bridge_minutes, max_p99_latency_ms,
			issued_at, expires_at, dsse_envelope,
			slot1_principal_id, slot1_email, slot1_key_fp, slot1_role,
			slot2_principal_id, slot2_email, slot2_key_fp, slot2_role,
			prev_hash, entry_hash, created_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
			$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23
		)
	`,
		w.WarrantID, w.WarrantClass, scopeJSON, w.MaxCVSS, w.KEVEligible,
		w.MaxBlastRadiusReplicas, w.AllowStatefulPatches, w.SLABridgeMinutes, w.MaxP99LatencyMs,
		w.IssuedAt, w.ExpiresAt, envJSON,
		w.Slot1PrincipalID, w.Slot1Email, w.Slot1KeyFP, w.Slot1Role,
		w.Slot2PrincipalID, w.Slot2Email, w.Slot2KeyFP, w.Slot2Role,
		w.PrevHash, w.EntryHash, w.CreatedAt,
	)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AppendAgentAction appends an entry to agent_action_ledger with serialized hash chaining.
func (s *Store) AppendAgentAction(ctx context.Context, entry *models.AgentLedgerEntry) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockAgentActionChain); err != nil {
		return err
	}
	prevHash := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM agent_action_ledger ORDER BY seq_no DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	entry.PrevHash = prevHash
	entry.EntryHash = ComputeAgentActionEntryHash(prevHash, *entry)
	if entry.ExecutedAt.IsZero() {
		entry.ExecutedAt = time.Now().UTC()
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO agent_action_ledger (
			action_id, task_token_id, warrant_id, remediation_id, worker_name, target_asset, action_type,
			slot1_principal_id, slot2_principal_id, egress_profile,
			raw_input_sha256, extractor_digest, typed_output_sha256,
			token_ttl_sec, status, violation_code, prev_hash, entry_hash, executed_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
		)
	`,
		entry.ActionID, entry.TaskTokenID, entry.WarrantID, entry.RemediationID, entry.WorkerName,
		entry.TargetAsset, entry.ActionType, entry.Slot1PrincipalID, entry.Slot2PrincipalID, entry.EgressProfile,
		entry.RawInputSHA256, entry.ExtractorDigest, entry.TypedOutputSHA256,
		entry.TokenTTLSec, entry.Status, entry.ViolationCode, entry.PrevHash, entry.EntryHash, entry.ExecutedAt,
	)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AppendAttestation appends a DSSE-signed OSCAL POA&M attestation to attestation_records with serialized hash chaining.
func (s *Store) AppendAttestation(ctx context.Context, att *models.AttestationRecord) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockAttestationChain); err != nil {
		return err
	}
	prevHash := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM attestation_records ORDER BY seq_no DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	entryHash, err := ComputeAttestationEntryHash(prevHash, *att)
	if err != nil {
		return err
	}
	att.PrevHash = prevHash
	att.EntryHash = entryHash
	if att.MintedAt.IsZero() {
		att.MintedAt = time.Now().UTC()
	}

	manifestJSON, err := json.Marshal(att.FleetDigestManifest)
	if err != nil {
		return err
	}
	envJSON, err := crypto.CanonicalizeStruct(att.DSSEEnvelope)
	if err != nil {
		return err
	}
	oscalJSON, err := crypto.CanonicalizeStruct(att.OSCALPOAM)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO attestation_records (
			attestation_id, remediation_id, service_id, cve_id, is_kev, warrant_id,
			slot1_principal_id, slot1_email, slot2_principal_id, slot2_email,
			twin_transcript_sha256, fleet_digest_manifest, lockout_policy_id, reverify_expires_at,
			dsse_envelope, oscal_poam_json, ttvr_seconds, prev_hash, entry_hash, minted_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
		)
	`,
		att.AttestationID, att.RemediationID, att.ServiceID, att.CVEID, att.IsKEV, att.WarrantID,
		att.Slot1PrincipalID, att.Slot1Email, att.Slot2PrincipalID, att.Slot2Email,
		att.TwinTranscriptSHA256, manifestJSON, att.LockoutPolicyID, att.ReverifyExpiresAt,
		envJSON, oscalJSON, att.TTVRSeconds, att.PrevHash, att.EntryHash, att.MintedAt,
	)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// VerifyAllLedgerChains walks every row in warrant_envelopes, agent_action_ledger, and attestation_records
// and verifies both prev_hash continuity and recomputed entry_hash integrity.
func (s *Store) VerifyAllLedgerChains(ctx context.Context) (*models.LedgerVerificationReport, error) {
	wStatus, err := s.verifyWarrantChain(ctx)
	if err != nil {
		return nil, err
	}
	aStatus, err := s.verifyAgentChain(ctx)
	if err != nil {
		return nil, err
	}
	attStatus, err := s.verifyAttestationChain(ctx)
	if err != nil {
		return nil, err
	}
	allValid := wStatus.Valid && aStatus.Valid && attStatus.Valid
	return &models.LedgerVerificationReport{
		AllValid:   allValid,
		VerifiedAt: time.Now().UTC(),
		Tables:     []models.ChainTableStatus{wStatus, aStatus, attStatus},
	}, nil
}

func (s *Store) verifyWarrantChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT warrant_id, warrant_class, slot1_principal_id, slot1_key_fp, slot2_principal_id, slot2_key_fp,
		       dsse_envelope, prev_hash, entry_hash
		FROM warrant_envelopes ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var wID, wClass, s1ID, s1FP, s2ID, s2FP, prevHash, entryHash string
		var envRaw []byte
		if err := rows.Scan(&wID, &wClass, &s1ID, &s1FP, &s2ID, &s2FP, &envRaw, &prevHash, &entryHash); err != nil {
			return models.ChainTableStatus{}, err
		}
		var env crypto.Envelope
		if err := json.Unmarshal(envRaw, &env); err != nil {
			return models.ChainTableStatus{
				TableName: "warrant_envelopes", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: "invalid dsse json",
			}, nil
		}
		if prevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "warrant_envelopes", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s: got %s want %s", wID, prevHash, expectedPrev),
			}, nil
		}
		recomputed, err := ComputeWarrantEntryHash(prevHash, wID, wClass, s1ID, s1FP, s2ID, s2FP, env)
		if err != nil || recomputed != entryHash {
			return models.ChainTableStatus{
				TableName: "warrant_envelopes", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", wID),
			}, nil
		}
		expectedPrev = entryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "warrant_envelopes", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}

func (s *Store) verifyAgentChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT action_id, task_token_id, warrant_id, worker_name, target_asset, action_type,
		       raw_input_sha256, extractor_digest, typed_output_sha256, status, prev_hash, entry_hash
		FROM agent_action_ledger ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var e models.AgentLedgerEntry
		if err := rows.Scan(
			&e.ActionID, &e.TaskTokenID, &e.WarrantID, &e.WorkerName, &e.TargetAsset, &e.ActionType,
			&e.RawInputSHA256, &e.ExtractorDigest, &e.TypedOutputSHA256, &e.Status, &e.PrevHash, &e.EntryHash,
		); err != nil {
			return models.ChainTableStatus{}, err
		}
		if e.PrevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "agent_action_ledger", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s", e.ActionID),
			}, nil
		}
		recomputed := ComputeAgentActionEntryHash(e.PrevHash, e)
		if recomputed != e.EntryHash {
			return models.ChainTableStatus{
				TableName: "agent_action_ledger", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", e.ActionID),
			}, nil
		}
		expectedPrev = e.EntryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "agent_action_ledger", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}

func (s *Store) verifyAttestationChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT attestation_id, remediation_id, service_id, cve_id, warrant_id,
		       twin_transcript_sha256, lockout_policy_id, dsse_envelope, prev_hash, entry_hash
		FROM attestation_records ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var a models.AttestationRecord
		var envRaw []byte
		if err := rows.Scan(
			&a.AttestationID, &a.RemediationID, &a.ServiceID, &a.CVEID, &a.WarrantID,
			&a.TwinTranscriptSHA256, &a.LockoutPolicyID, &envRaw, &a.PrevHash, &a.EntryHash,
		); err != nil {
			return models.ChainTableStatus{}, err
		}
		if err := json.Unmarshal(envRaw, &a.DSSEEnvelope); err != nil {
			return models.ChainTableStatus{
				TableName: "attestation_records", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: "invalid dsse json",
			}, nil
		}
		if a.PrevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "attestation_records", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s", a.AttestationID),
			}, nil
		}
		recomputed, err := ComputeAttestationEntryHash(a.PrevHash, a)
		if err != nil || recomputed != a.EntryHash {
			return models.ChainTableStatus{
				TableName: "attestation_records", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", a.AttestationID),
			}, nil
		}
		expectedPrev = a.EntryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "attestation_records", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}
