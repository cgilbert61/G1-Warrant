package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/db/migrations"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

const (
	lockWarrantChain     int64 = 1001001
	lockAgentActionChain int64 = 1001002
	lockAttestationChain int64 = 1001003
	lockPrincipalChain   int64 = 1001004
	lockRevocationChain  int64 = 1001005
	lockKernelKeyChain   int64 = 1001006
	lockBootstrapSeal    int64 = 1001007
)

// Store manages PostgreSQL persistence, append-only hash chains, and LISTEN/NOTIFY streams.
type Store struct {
	pool         *pgxpool.Pool
	webauthnCfg  crypto.WebAuthnConfig
	sealAnchorFn func(ctx context.Context) (*models.LedgerCheckpoint, error)
}

// SetBootstrapSealAnchorFunc wires the N5 TransparencyAnchor checkpoint callback so SealBootstrap
// externally anchors Checkpoint #0 the instant genesis bootstrap sealing completes.
func (s *Store) SetBootstrapSealAnchorFunc(fn func(ctx context.Context) (*models.LedgerCheckpoint, error)) {
	s.sealAnchorFn = fn
}

// SetWebAuthnConfig binds the control-plane WebAuthn relying-party configuration for lineage replay verification.
func (s *Store) SetWebAuthnConfig(cfg crypto.WebAuthnConfig) {
	s.webauthnCfg = cfg
}

// WebAuthnConfig returns the configured WebAuthnConfig or DefaultWebAuthnConfig.
func (s *Store) WebAuthnConfig() crypto.WebAuthnConfig {
	if s.webauthnCfg.RPID == "" && len(s.webauthnCfg.AllowedOrigins) == 0 {
		return crypto.DefaultWebAuthnConfig()
	}
	return s.webauthnCfg
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

// ComputePrincipalEntryHash computes the deterministic SHA-256 chain link for principals.
func ComputePrincipalEntryHash(prevHash string, p models.Principal) string {
	material := strings.Join([]string{
		"principals",
		prevHash,
		p.PrincipalID,
		strings.ToLower(p.Email),
		p.Role,
		p.KeyID,
		p.Alg,
		p.PublicKeyB64,
		strings.ToLower(p.KeyFingerprint),
	}, "|")
	return crypto.SHA256Hex([]byte(material))
}

// ComputeRevocationEntryHash computes the deterministic SHA-256 chain link for principal_revocations.
func ComputeRevocationEntryHash(prevHash string, r models.PrincipalRevocation) string {
	material := strings.Join([]string{
		"principal_revocations",
		prevHash,
		r.RevocationID,
		r.PrincipalID,
		strings.ToLower(r.KeyFingerprint),
		r.ReasonCode,
		r.RevokedBy,
	}, "|")
	return crypto.SHA256Hex([]byte(material))
}

// ComputeKernelKeyEntryHash computes the deterministic SHA-256 chain link for kernel_public_keys.
func ComputeKernelKeyEntryHash(prevHash, keyID, alg, pubB64, keyFP, backendMode string) string {
	material := strings.Join([]string{
		"kernel_public_keys",
		prevHash,
		keyID,
		alg,
		pubB64,
		strings.ToLower(keyFP),
		backendMode,
	}, "|")
	return crypto.SHA256Hex([]byte(material))
}

// AppendPrincipal enrolls a new genesis principal in the append-only, hash-chained principals registry prior to bootstrap sealing.
func (s *Store) AppendPrincipal(ctx context.Context, p *models.Principal) error {
	return s.insertPrincipalTx(ctx, p, false, models.LineageModeGenesisSealed, nil)
}

// AppendPrincipalWithLineage enrolls a new principal with an explicit lineage mode and authorizing 2-of-2 DSSE Governance Envelope.
func (s *Store) AppendPrincipalWithLineage(ctx context.Context, p *models.Principal, lineageMode string, govDSSE *crypto.Envelope) error {
	if lineageMode == "" {
		if govDSSE != nil {
			lineageMode = models.LineageModePostSeal2Of2
		} else {
			lineageMode = models.LineageModeGenesisSealed
		}
	}
	return s.insertPrincipalTx(ctx, p, false, lineageMode, govDSSE)
}

// UpsertPrincipal inserts a principal if absent (idempotent only when identical public key material is already enrolled;
// never mutates existing rows on the append-only principals chain).
func (s *Store) UpsertPrincipal(ctx context.Context, p models.Principal) error {
	return s.insertPrincipalTx(ctx, &p, true, models.LineageModeGenesisSealed, nil)
}

func (s *Store) insertPrincipalTx(ctx context.Context, p *models.Principal, allowIdenticalIdempotent bool, lineageMode string, govDSSE *crypto.Envelope) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockPrincipalChain); err != nil {
		return err
	}

	// Block re-enrollment of any revoked principal_id or key_fingerprint
	var revReason string
	revErr := tx.QueryRow(ctx, `
		SELECT reason_code FROM principal_revocations
		WHERE principal_id = $1 OR lower(key_fingerprint) = lower($2)
		LIMIT 1
	`, p.PrincipalID, p.KeyFingerprint).Scan(&revReason)
	if revErr == nil {
		return fmt.Errorf("AC5_REVOKED_KEY_REENROLLMENT_FORBIDDEN: principal or key fingerprint %s was previously revoked (%s)", p.KeyFingerprint, revReason)
	}
	if !errors.Is(revErr, pgx.ErrNoRows) {
		return revErr
	}

	// Check for existing principal_id, key_id, public_key_b64, key_fingerprint, or active unrevoked email
	var existID, existEmail, existRole, existKeyID, existPubB64, existFP, existPrev, existEntry string
	var existCreated time.Time
	dupErr := tx.QueryRow(ctx, `
		SELECT p.principal_id, p.email, p.role, p.key_id, p.public_key_b64, p.key_fingerprint, p.prev_hash, p.entry_hash, p.created_at
		FROM principals p
		WHERE p.principal_id = $1
		   OR p.key_id = $2
		   OR p.public_key_b64 = $3
		   OR lower(p.key_fingerprint) = lower($4)
		   OR (
		       lower(p.email) = lower($5)
		       AND NOT EXISTS (
		           SELECT 1 FROM principal_revocations pr
		           WHERE pr.principal_id = p.principal_id OR lower(pr.key_fingerprint) = lower(p.key_fingerprint)
		       )
		   )
		LIMIT 1
	`, p.PrincipalID, p.KeyID, p.PublicKeyB64, p.KeyFingerprint, p.Email).Scan(
		&existID, &existEmail, &existRole, &existKeyID, &existPubB64, &existFP, &existPrev, &existEntry, &existCreated,
	)
	if dupErr == nil {
		if allowIdenticalIdempotent &&
			existID == p.PrincipalID &&
			strings.EqualFold(existEmail, p.Email) &&
			existRole == p.Role &&
			existKeyID == p.KeyID &&
			existPubB64 == p.PublicKeyB64 &&
			strings.EqualFold(existFP, p.KeyFingerprint) {
			p.PrevHash = existPrev
			p.EntryHash = existEntry
			p.CreatedAt = existCreated
			return nil
		}
		return fmt.Errorf("AC5_DUPLICATE_PRINCIPAL_OR_KEY: principal_id, email, or public key fingerprint %s is already enrolled", p.KeyFingerprint)
	}
	if !errors.Is(dupErr, pgx.ErrNoRows) {
		return dupErr
	}

	var sealed bool
	if err := tx.QueryRow(ctx, `SELECT sealed FROM bootstrap_state WHERE singleton_id = 1`).Scan(&sealed); err != nil {
		return err
	}
	if sealed && govDSSE == nil {
		return errors.New("BOOTSTRAP_SEALED_REQUIRES_DUAL_KEY_DSSE: post-seal principal enrollment requires a 2-of-2 DSSE governance envelope")
	}
	if sealed {
		lineageMode = models.LineageModePostSeal2Of2
	} else if lineageMode == "" {
		lineageMode = models.LineageModeGenesisSealed
	}

	prevHash := GenesisHash
	err = tx.QueryRow(ctx, `SELECT entry_hash FROM principals ORDER BY seq_no DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	p.LineageMode = lineageMode
	p.GovernanceDSSE = govDSSE
	p.PrevHash = prevHash
	p.EntryHash = ComputePrincipalEntryHash(prevHash, *p)

	var dsseRaw []byte
	if govDSSE != nil {
		dsseRaw, err = crypto.CanonicalizeStruct(govDSSE)
		if err != nil {
			return err
		}
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO principals (
			principal_id, email, display_name, role, key_id, alg, public_key_b64, key_fingerprint,
			authenticator_mode, credential_id, lineage_mode, governance_dsse, prev_hash, entry_hash, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
	`,
		p.PrincipalID, p.Email, p.DisplayName, p.Role, p.KeyID, p.Alg, p.PublicKeyB64, p.KeyFingerprint,
		p.AuthenticatorMode, p.CredentialID, p.LineageMode, dsseRaw, p.PrevHash, p.EntryHash, p.CreatedAt,
	)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListPrincipals returns all registered principals with live revocation status, lineage mode, and hash-chain links.
func (s *Store) ListPrincipals(ctx context.Context) ([]models.Principal, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.principal_id, p.email, p.display_name, p.role, p.key_id, p.alg,
		       p.public_key_b64, p.key_fingerprint, p.authenticator_mode, p.credential_id,
		       p.lineage_mode, p.governance_dsse,
		       p.prev_hash, p.entry_hash, p.created_at,
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
		ORDER BY p.seq_no ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Principal{}
	for rows.Next() {
		var p models.Principal
		var dsseRaw []byte
		if err := rows.Scan(
			&p.PrincipalID, &p.Email, &p.DisplayName, &p.Role, &p.KeyID, &p.Alg,
			&p.PublicKeyB64, &p.KeyFingerprint, &p.AuthenticatorMode, &p.CredentialID,
			&p.LineageMode, &dsseRaw,
			&p.PrevHash, &p.EntryHash, &p.CreatedAt,
			&p.RevokeReason, &p.Revoked,
		); err != nil {
			return nil, err
		}
		if len(dsseRaw) > 0 {
			var env crypto.Envelope
			if json.Unmarshal(dsseRaw, &env) == nil {
				p.GovernanceDSSE = &env
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RevokePrincipal appends a revocation into principal_revocations while enforcing survivor floor and post-seal DSSE requirements.
func (s *Store) RevokePrincipal(ctx context.Context, rev models.PrincipalRevocation) error {
	_, err := s.RevokePrincipalEnforced(ctx, rev, rev.PrincipalID, "", models.LineageModeGenesisSealed, false, rev.GovernanceDSSE)
	return err
}

// ListRevocations lists all active principal/key revocations with lineage metadata.
func (s *Store) ListRevocations(ctx context.Context) ([]models.PrincipalRevocation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT revocation_id, principal_id, key_fingerprint, reason_code, revoked_by,
		       lineage_mode, governance_dsse, prev_hash, entry_hash, revoked_at
		FROM principal_revocations ORDER BY seq_no DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.PrincipalRevocation{}
	for rows.Next() {
		var r models.PrincipalRevocation
		var dsseRaw []byte
		if err := rows.Scan(
			&r.RevocationID, &r.PrincipalID, &r.KeyFingerprint, &r.ReasonCode, &r.RevokedBy,
			&r.LineageMode, &dsseRaw, &r.PrevHash, &r.EntryHash, &r.RevokedAt,
		); err != nil {
			return nil, err
		}
		if len(dsseRaw) > 0 {
			var env crypto.Envelope
			if json.Unmarshal(dsseRaw, &env) == nil {
				r.GovernanceDSSE = &env
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetBootstrapState returns whether one-shot genesis bootstrap enrollment has been sealed along with its Genesis Seal Manifest.
func (s *Store) GetBootstrapState(ctx context.Context) (models.BootstrapState, error) {
	var st models.BootstrapState
	var sealRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT sealed, sealed_by, sealed_reason, sealed_at,
		       genesis_principal_max_seq, genesis_revocation_max_seq, genesis_manifest_sha256, genesis_seal_dsse
		FROM bootstrap_state WHERE singleton_id = 1
	`).Scan(
		&st.Sealed, &st.SealedBy, &st.SealedReason, &st.SealedAt,
		&st.GenesisPrincipalMaxSeq, &st.GenesisRevocationMaxSeq, &st.GenesisManifestSHA256, &sealRaw,
	)
	if err != nil {
		return models.BootstrapState{}, err
	}
	if len(sealRaw) > 0 {
		var env crypto.Envelope
		if json.Unmarshal(sealRaw, &env) == nil {
			st.GenesisSealDSSE = &env
		}
	}
	return st, nil
}

// CountActiveAC5Principals counts currently unrevoked SERVICE_OWNER and AUTHORIZING_OFFICIAL principals.
func (s *Store) CountActiveAC5Principals(ctx context.Context) (soCount int, aoCount int, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE p.role = 'SERVICE_OWNER'),
			COUNT(*) FILTER (WHERE p.role = 'AUTHORIZING_OFFICIAL')
		FROM principals p
		WHERE NOT EXISTS (
			SELECT 1 FROM principal_revocations pr
			WHERE pr.principal_id = p.principal_id OR lower(pr.key_fingerprint) = lower(p.key_fingerprint)
		)
	`).Scan(&soCount, &aoCount)
	return soCount, aoCount, err
}

// SealBootstrap permanently transitions bootstrap_state.sealed = TRUE once >= 1 active SERVICE_OWNER
// and >= 1 active AUTHORIZING_OFFICIAL are enrolled, recording a kernel-signed Genesis Seal Manifest digest.
func (s *Store) SealBootstrap(ctx context.Context, actor, reason string, kernelSigner ...crypto.EnvelopeSigner) (models.BootstrapState, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return models.BootstrapState{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, lk := range []int64{lockPrincipalChain, lockRevocationChain, lockBootstrapSeal} {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lk); err != nil {
			return models.BootstrapState{}, err
		}
	}

	var cur models.BootstrapState
	var curSealRaw []byte
	if err := tx.QueryRow(ctx, `
		SELECT sealed, sealed_by, sealed_reason, sealed_at,
		       genesis_principal_max_seq, genesis_revocation_max_seq, genesis_manifest_sha256, genesis_seal_dsse
		FROM bootstrap_state WHERE singleton_id = 1
	`).Scan(
		&cur.Sealed, &cur.SealedBy, &cur.SealedReason, &cur.SealedAt,
		&cur.GenesisPrincipalMaxSeq, &cur.GenesisRevocationMaxSeq, &cur.GenesisManifestSHA256, &curSealRaw,
	); err != nil {
		return models.BootstrapState{}, err
	}
	if cur.Sealed {
		if len(curSealRaw) > 0 {
			var env crypto.Envelope
			if json.Unmarshal(curSealRaw, &env) == nil {
				cur.GenesisSealDSSE = &env
			}
		}
		return cur, nil
	}

	var soCount, aoCount int
	if err := tx.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE p.role = 'SERVICE_OWNER'),
			COUNT(*) FILTER (WHERE p.role = 'AUTHORIZING_OFFICIAL')
		FROM principals p
		WHERE NOT EXISTS (
			SELECT 1 FROM principal_revocations pr
			WHERE pr.principal_id = p.principal_id OR lower(pr.key_fingerprint) = lower(p.key_fingerprint)
		)
	`).Scan(&soCount, &aoCount); err != nil {
		return models.BootstrapState{}, err
	}
	minPerRole := 1
	isLiveOrK8s := strings.EqualFold(strings.TrimSpace(os.Getenv("WARRANT_CLUSTER_DRIVER")), "kubernetes") ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("WARRANT_FEED_MODE")), "live")
	if !isLiveOrK8s {
		var dbFeedMode string
		if fErr := s.pool.QueryRow(ctx, `SELECT mode FROM feed_runtime_config WHERE singleton_id = 1`).Scan(&dbFeedMode); fErr == nil && strings.EqualFold(dbFeedMode, models.FeedModeLive) {
			isLiveOrK8s = true
		}
	}
	if isLiveOrK8s {
		minPerRole = 2
	}
	if soCount < minPerRole || aoCount < minPerRole {
		return models.BootstrapState{}, fmt.Errorf(
			"BOOTSTRAP_SEAL_PRECONDITION_FAILED: at least %d active SERVICE_OWNER (have %d) and %d active AUTHORIZING_OFFICIAL (have %d) must be enrolled before sealing",
			minPerRole, soCount, minPerRole, aoCount,
		)
	}

	maxPSeq, maxRSeq, manifestSHA, err := collectGenesisManifestTx(ctx, tx, 0, 0)
	if err != nil {
		return models.BootstrapState{}, err
	}

	now := time.Now().UTC()
	var sealEnv *crypto.Envelope
	var sealEnvJSON []byte
	if len(kernelSigner) > 0 && kernelSigner[0] != nil {
		sealPayload := map[string]any{
			"sealed_by":                  actor,
			"sealed_reason":              reason,
			"sealed_at":                  now.Format(time.RFC3339),
			"genesis_principal_max_seq":  maxPSeq,
			"genesis_revocation_max_seq": maxRSeq,
			"genesis_manifest_sha256":    manifestSHA,
		}
		env, _, sErr := crypto.NewUnsignedEnvelope(crypto.PayloadTypeGenesisSeal, sealPayload)
		if sErr != nil {
			return models.BootstrapState{}, sErr
		}
		if sErr := kernelSigner[0].SignEnvelope(ctx, 1, env); sErr != nil {
			return models.BootstrapState{}, sErr
		}
		sealEnvJSON, sErr = crypto.CanonicalizeStruct(env)
		if sErr != nil {
			return models.BootstrapState{}, sErr
		}
		sealEnv = env
	}

	if _, err := tx.Exec(ctx, `
		UPDATE bootstrap_state
		SET sealed = TRUE,
		    sealed_by = $1,
		    sealed_reason = $2,
		    sealed_at = $3,
		    genesis_principal_max_seq = $4,
		    genesis_revocation_max_seq = $5,
		    genesis_manifest_sha256 = $6,
		    genesis_seal_dsse = $7
		WHERE singleton_id = 1
	`, actor, reason, now, maxPSeq, maxRSeq, manifestSHA, sealEnvJSON); err != nil {
		return models.BootstrapState{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.BootstrapState{}, err
	}
	// Trigger immediate External Merkle Checkpoint #0 the instant genesis bootstrap sealing completes
	if s.sealAnchorFn != nil {
		if _, aErr := s.sealAnchorFn(ctx); aErr != nil {
			return models.BootstrapState{}, fmt.Errorf("anchor genesis seal checkpoint #0: %w", aErr)
		}
	}
	return models.BootstrapState{
		Sealed:                  true,
		SealedBy:                actor,
		SealedReason:            reason,
		SealedAt:                &now,
		GenesisPrincipalMaxSeq:  maxPSeq,
		GenesisRevocationMaxSeq: maxRSeq,
		GenesisManifestSHA256:   manifestSHA,
		GenesisSealDSSE:         sealEnv,
	}, nil
}

// ConsumeGovernanceEnvelopeNonce enforces single-use replay protection on Principal Governance DSSE envelopes.
func (s *Store) ConsumeGovernanceEnvelopeNonce(ctx context.Context, envelopeID, actionType, payloadSHA256, signerSummary string, expiresAt time.Time) error {
	if strings.TrimSpace(envelopeID) == "" {
		return errors.New("GOVERNANCE_MISSING_ENVELOPE_ID: single-use envelope_id is required")
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO governance_envelope_nonces (envelope_id, action_type, payload_sha256, signer_summary, expires_at, consumed_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (envelope_id) DO NOTHING
	`, envelopeID, actionType, payloadSHA256, signerSummary, expiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("GOVERNANCE_ENVELOPE_REPLAY_DETECTED: envelope_id %q has already been consumed", envelopeID)
	}
	return nil
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
		WHERE p.key_id = $1 OR (p.credential_id <> '' AND p.credential_id = $1)
		LIMIT 1
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
// Preserves exact hash continuity for legacy v1.0.x rows (where AuthorityMode, CommissioningFunctionID, and AgentID are empty)
// while binding authority_mode, commissioning_function_id, agent_id, and delegation_depth on all v1.1.0+ rows.
func ComputeAgentActionEntryHash(prevHash string, e models.AgentLedgerEntry) string {
	parts := []string{
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
	}
	if e.AuthorityMode != "" || e.CommissioningFunctionID != "" || e.AgentID != "" || e.DelegationDepth > 0 {
		parts = append(parts, e.AuthorityMode, e.CommissioningFunctionID, e.AgentID, strconv.Itoa(e.DelegationDepth))
	}
	return crypto.SHA256Hex([]byte(strings.Join(parts, "|")))
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
	scopeAssetsJSON, _ := json.Marshal(w.ScopeAssets)
	if len(w.ScopeAssets) == 0 {
		scopeAssetsJSON = []byte("[]")
	}
	authVendorDetJSON, _ := json.Marshal(w.AuthorizedVendorDetections)
	if len(w.AuthorizedVendorDetections) == 0 {
		authVendorDetJSON = []byte("[]")
	}
	cwesJSON, _ := json.Marshal(w.AutoRemediateCWEs)
	if len(w.AutoRemediateCWEs) == 0 {
		cwesJSON = []byte("[]")
	}
	envJSON, err := crypto.CanonicalizeStruct(w.DSSEEnvelope)
	if err != nil {
		return err
	}

	if w.MinCanarySamples <= 0 {
		w.MinCanarySamples = 500
	}
	if w.StageDwellSeconds <= 0 {
		w.StageDwellSeconds = 300
	}
	if w.WarrantClass == models.WarrantClassSecretRotation {
		w.AllowSecretRotation = true
	}
	cloneSourcesJSON, _ := json.Marshal(w.CloneSources)
	if len(w.CloneSources) == 0 {
		cloneSourcesJSON = []byte("[]")
	}
	driftPolicy := strings.TrimSpace(w.EstateDriftPolicy)
	if driftPolicy == "" {
		driftPolicy = models.EstateDriftPolicyRecordOnly
	}
	driftTol := w.EstateDriftTolerancePct
	if driftTol <= 0 {
		driftTol = models.DefaultEstateDriftTolPct
	}
	cloneTwinCnt := w.CloneTwinCount
	if cloneTwinCnt <= 0 {
		cloneTwinCnt = models.DefaultCloneTwinCount
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO warrant_envelopes (
			warrant_id, warrant_class, scope_services, scope_assets, authorized_vendor_detections, max_cvss, kev_eligible,
			max_blast_radius_replicas, allow_stateful_patches, allow_guarded_canary,
			allow_secret_rotation, auto_remediate_cwes, min_canary_samples, stage_dwell_seconds,
			clone_twin_count, clone_sources_json, estate_snapshot_sha256, estate_drift_policy, estate_drift_tolerance_pct, max_estate_staleness_seconds,
			sla_bridge_minutes, max_p99_latency_ms,
			issued_at, expires_at, dsse_envelope,
			slot1_principal_id, slot1_email, slot1_key_fp, slot1_role,
			slot2_principal_id, slot2_email, slot2_key_fp, slot2_role,
			prev_hash, entry_hash, created_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
			$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,
			$31,$32,$33,$34,$35,$36
		)
	`,
		w.WarrantID, w.WarrantClass, scopeJSON, scopeAssetsJSON, authVendorDetJSON, w.MaxCVSS, w.KEVEligible,
		w.MaxBlastRadiusReplicas, w.AllowStatefulPatches, w.AllowGuardedCanary,
		w.AllowSecretRotation, cwesJSON, w.MinCanarySamples, w.StageDwellSeconds,
		cloneTwinCnt, cloneSourcesJSON, w.EstateSnapshotSHA256, driftPolicy, driftTol, w.MaxEstateStalenessSec,
		w.SLABridgeMinutes, w.MaxP99LatencyMs,
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
	var actChainRaw []byte
	if entry.ActChain != nil {
		actChainRaw, _ = crypto.CanonicalizeStruct(entry.ActChain)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO agent_action_ledger (
			action_id, task_token_id, warrant_id, remediation_id,
			authority_mode, commissioning_function_id, agent_id, delegation_depth, act_chain_json,
			worker_name, target_asset, action_type,
			slot1_principal_id, slot2_principal_id, egress_profile,
			raw_input_sha256, extractor_digest, typed_output_sha256,
			token_ttl_sec, status, violation_code, prev_hash, entry_hash, executed_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24
		)
	`,
		entry.ActionID, entry.TaskTokenID, entry.WarrantID, entry.RemediationID,
		entry.AuthorityMode, entry.CommissioningFunctionID, entry.AgentID, entry.DelegationDepth, actChainRaw,
		entry.WorkerName, entry.TargetAsset, entry.ActionType,
		entry.Slot1PrincipalID, entry.Slot2PrincipalID, entry.EgressProfile,
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

	if att.AssuranceTier == "" {
		att.AssuranceTier = models.AssuranceTier1PassiveDigestSBOM
	}
	if att.SignerBackend == "" {
		att.SignerBackend = "EPHEMERAL_MEMORY_ED25519"
	}
	if att.ClosureCompleteness == "" {
		att.ClosureCompleteness = models.ClosureCompletenessFull
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO attestation_records (
			attestation_id, remediation_id, service_id, cve_id, is_kev, warrant_id,
			slot1_principal_id, slot1_email, slot2_principal_id, slot2_email,
			twin_transcript_sha256, assurance_tier,
			closure_completeness, targeted_asset_count, landed_asset_count, failed_asset_count, pending_asset_count, reboot_waiting_count,
			distributor_id, distributor_order_id, distributor_report_sha256,
			signer_backend, fleet_digest_manifest, lockout_policy_id, reverify_expires_at,
			dsse_envelope, oscal_poam_json, ttvr_seconds, prev_hash, entry_hash, minted_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
			$13,$14,$15,$16,$17,$18,$19,$20,$21,
			$22,$23,$24,$25,$26,$27,$28,$29,$30,$31
		)
	`,
		att.AttestationID, att.RemediationID, att.ServiceID, att.CVEID, att.IsKEV, att.WarrantID,
		att.Slot1PrincipalID, att.Slot1Email, att.Slot2PrincipalID, att.Slot2Email,
		att.TwinTranscriptSHA256, att.AssuranceTier,
		att.ClosureCompleteness, att.TargetedAssetCount, att.LandedAssetCount, att.FailedAssetCount, att.PendingAssetCount, att.RebootWaitingCount,
		att.DistributorID, att.DistributorOrderID, att.DistributorReportSHA256,
		att.SignerBackend, manifestJSON, att.LockoutPolicyID, att.ReverifyExpiresAt,
		envJSON, oscalJSON, att.TTVRSeconds, att.PrevHash, att.EntryHash, att.MintedAt,
	)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// VerifyAllLedgerChains walks every row in all 9 immutable hash-chained tables
// (6 core chains: warrant_envelopes, agent_action_ledger, attestation_records, principals, principal_revocations, kernel_public_keys;
// plus 3 v1.1.0 agent-authority chains: commissioning_functions, agent_identities, agent_lifecycle_events)
// and verifies prev_hash continuity, recomputed entry_hash integrity, and external Merkle checkpoint consistency.
func (s *Store) VerifyAllLedgerChains(ctx context.Context, externalWitnesses ...[]models.LedgerCheckpoint) (*models.LedgerVerificationReport, error) {
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
	pStatus, err := s.verifyPrincipalChain(ctx)
	if err != nil {
		return nil, err
	}
	revStatus, err := s.verifyRevocationChain(ctx)
	if err != nil {
		return nil, err
	}
	kStatus, err := s.verifyKernelKeyChain(ctx)
	if err != nil {
		return nil, err
	}
	cfStatus, err := s.verifyCommissioningFunctionChain(ctx)
	if err != nil {
		return nil, err
	}
	aiStatus, err := s.verifyAgentIdentityChain(ctx)
	if err != nil {
		return nil, err
	}
	aleStatus, err := s.verifyAgentLifecycleChain(ctx)
	if err != nil {
		return nil, err
	}
	estStatus, err := s.verifyEstateReadEvidenceChain(ctx)
	if err != nil {
		return nil, err
	}
	var witnessSlice []models.LedgerCheckpoint
	if len(externalWitnesses) > 0 {
		witnessSlice = externalWitnesses[0]
	}
	anchorOK, cpID, merkleRoot, tamperDetail := s.VerifyHistoricalCheckpointConsistency(ctx, witnessSlice)

	lineageOK := true
	if badTable, lineageErr := s.VerifyAuthorityLineageAttestations(ctx); lineageErr != nil {
		lineageOK = false
		if tamperDetail == "" {
			tamperDetail = lineageErr.Error()
		} else {
			tamperDetail = tamperDetail + "; " + lineageErr.Error()
		}
		switch badTable {
		case "principals":
			pStatus.Valid = false
			pStatus.FailureDetail = lineageErr.Error()
		case "principal_revocations":
			revStatus.Valid = false
			revStatus.FailureDetail = lineageErr.Error()
		case "kernel_public_keys":
			kStatus.Valid = false
			kStatus.FailureDetail = lineageErr.Error()
		case "commissioning_functions":
			cfStatus.Valid = false
			cfStatus.FailureDetail = lineageErr.Error()
		case "agent_identities":
			aiStatus.Valid = false
			aiStatus.FailureDetail = lineageErr.Error()
		case "agent_lifecycle_events":
			aleStatus.Valid = false
			aleStatus.FailureDetail = lineageErr.Error()
		}
	}

	allValid := wStatus.Valid && aStatus.Valid && attStatus.Valid &&
		pStatus.Valid && revStatus.Valid && kStatus.Valid &&
		cfStatus.Valid && aiStatus.Valid && aleStatus.Valid &&
		estStatus.Valid && anchorOK && lineageOK
	return &models.LedgerVerificationReport{
		AllValid:                allValid,
		ExternalAnchorVerified:  anchorOK,
		LatestCheckpointID:      cpID,
		LatestCombinedMerkleHex: merkleRoot,
		SuperuserTamperDetail:   tamperDetail,
		VerifiedAt:              time.Now().UTC(),
		Tables:                  []models.ChainTableStatus{wStatus, aStatus, attStatus, pStatus, revStatus, kStatus},
		AgentAuthorityTables:    []models.ChainTableStatus{cfStatus, aiStatus, aleStatus},
		EstateEvidenceTables:    []models.ChainTableStatus{estStatus},
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
		SELECT action_id, task_token_id, warrant_id,
		       authority_mode, commissioning_function_id, agent_id, delegation_depth,
		       worker_name, target_asset, action_type,
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
			&e.ActionID, &e.TaskTokenID, &e.WarrantID,
			&e.AuthorityMode, &e.CommissioningFunctionID, &e.AgentID, &e.DelegationDepth,
			&e.WorkerName, &e.TargetAsset, &e.ActionType,
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

func (s *Store) verifyPrincipalChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT principal_id, email, role, key_id, alg, public_key_b64, key_fingerprint, prev_hash, entry_hash
		FROM principals ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var p models.Principal
		if err := rows.Scan(
			&p.PrincipalID, &p.Email, &p.Role, &p.KeyID, &p.Alg, &p.PublicKeyB64, &p.KeyFingerprint, &p.PrevHash, &p.EntryHash,
		); err != nil {
			return models.ChainTableStatus{}, err
		}
		if p.PrevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "principals", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s: got %s want %s", p.PrincipalID, p.PrevHash, expectedPrev),
			}, nil
		}
		recomputed := ComputePrincipalEntryHash(p.PrevHash, p)
		if recomputed != p.EntryHash {
			return models.ChainTableStatus{
				TableName: "principals", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", p.PrincipalID),
			}, nil
		}
		expectedPrev = p.EntryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "principals", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}

func (s *Store) verifyRevocationChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT revocation_id, principal_id, key_fingerprint, reason_code, revoked_by, prev_hash, entry_hash
		FROM principal_revocations ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var r models.PrincipalRevocation
		if err := rows.Scan(
			&r.RevocationID, &r.PrincipalID, &r.KeyFingerprint, &r.ReasonCode, &r.RevokedBy, &r.PrevHash, &r.EntryHash,
		); err != nil {
			return models.ChainTableStatus{}, err
		}
		if r.PrevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "principal_revocations", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s", r.RevocationID),
			}, nil
		}
		recomputed := ComputeRevocationEntryHash(r.PrevHash, r)
		if recomputed != r.EntryHash {
			return models.ChainTableStatus{
				TableName: "principal_revocations", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", r.RevocationID),
			}, nil
		}
		expectedPrev = r.EntryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "principal_revocations", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}

func (s *Store) verifyKernelKeyChain(ctx context.Context) (models.ChainTableStatus, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT key_id, alg, public_key_b64, key_fingerprint, backend_mode, prev_hash, entry_hash
		FROM kernel_public_keys ORDER BY seq_no ASC
	`)
	if err != nil {
		return models.ChainTableStatus{}, err
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	idx := 0
	for rows.Next() {
		var r models.KernelPublicKeyRecord
		if err := rows.Scan(&r.KeyID, &r.Alg, &r.PublicKeyB64, &r.KeyFingerprint, &r.BackendMode, &r.PrevHash, &r.EntryHash); err != nil {
			return models.ChainTableStatus{}, err
		}
		if r.PrevHash != expectedPrev {
			return models.ChainTableStatus{
				TableName: "kernel_public_keys", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("prev_hash mismatch at %s", r.KeyID),
			}, nil
		}
		recomputed := ComputeKernelKeyEntryHash(r.PrevHash, r.KeyID, r.Alg, r.PublicKeyB64, r.KeyFingerprint, r.BackendMode)
		if recomputed != r.EntryHash {
			return models.ChainTableStatus{
				TableName: "kernel_public_keys", RowCount: idx + 1, Valid: false,
				BrokenAtRowIndex: idx, FailureDetail: fmt.Sprintf("entry_hash tamper detected at %s", r.KeyID),
			}, nil
		}
		expectedPrev = r.EntryHash
		idx++
	}
	return models.ChainTableStatus{
		TableName: "kernel_public_keys", RowCount: idx, Valid: true,
		TerminalHash: expectedPrev, BrokenAtRowIndex: -1,
	}, rows.Err()
}
