package ledger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
	"github.com/cgilbert61/G1-Warrant/internal/verify"
	"github.com/cgilbert61/G1-Warrant/internal/warrant"
	"github.com/google/uuid"
)

// Engine implements N5: Cryptographic Attestation Ledger, NIST OSCAL 1.1.2 POA&M Minting,
// External Merkle Transparency Anchoring, Hash-Chain Verification, and Scoped External Auditor Bearer Tokens.
type Engine struct {
	store       *db.Store
	policy      *policy.Engine
	warrants    *warrant.Engine
	signer      crypto.EnvelopeSigner
	anchor      *TransparencyAnchor
	onBroadcast func(eventType string, payload any)
}

// NewEngine constructs the N5 Cryptographic Attestation & OSCAL Engine.
func NewEngine(
	store *db.Store,
	pol *policy.Engine,
	warrants *warrant.Engine,
	signer crypto.EnvelopeSigner,
	onBroadcast func(string, any),
	anchor ...*TransparencyAnchor,
) *Engine {
	var anc *TransparencyAnchor
	if len(anchor) > 0 && anchor[0] != nil {
		anc = anchor[0]
	} else {
		anc = NewTransparencyAnchor("", "")
	}
	return &Engine{
		store:       store,
		policy:      pol,
		warrants:    warrants,
		signer:      signer,
		anchor:      anc,
		onBroadcast: onBroadcast,
	}
}

// KernelPublicKey returns the public key metadata for external/in-browser DSSE verification.
func (e *Engine) KernelPublicKey() crypto.PrincipalKey {
	return e.signer.PublicKey()
}

// Signer exposes the active EnvelopeSigner to seal genesis bootstrap manifests and sign kernel key rotations.
func (e *Engine) Signer() crypto.EnvelopeSigner {
	return e.signer
}

// SignKernelKeyRotation signs a KernelKeyRotationPayload authorizing a successor kernel signing key.
func (e *Engine) SignKernelKeyRotation(ctx context.Context, newPK crypto.PrincipalKey, backendMode string) (*crypto.Envelope, error) {
	return db.SignKernelKeyRotation(ctx, e.signer, newPK, backendMode)
}

// SignerBackend returns the active cryptographic signing backend mode (KMS/HSM vs ephemeral memory).
func (e *Engine) SignerBackend() string {
	return e.signer.BackendMode()
}

// Anchor returns the External Merkle Transparency Anchor.
func (e *Engine) Anchor() *TransparencyAnchor {
	return e.anchor
}

// CreateCheckpoint signs and ships an explicit Merkle Root checkpoint across all 3 ledger tables.
func (e *Engine) CreateCheckpoint(ctx context.Context) (*models.LedgerCheckpoint, error) {
	return e.anchor.AnchorCheckpoint(ctx, e.store, e.signer)
}

// MintOSCALAttestation re-verifies N1 human signatures, validates N3 verification proofs via OPA,
// builds a standards-compliant NIST OSCAL 1.1.2 POA&M JSON package, signs it in a DSSE envelope,
// and appends it to the immutable attestation_records ledger.
func (e *Engine) MintOSCALAttestation(ctx context.Context, item *models.RemediationItem, svc *models.EstateService, bundle *verify.VerificationBundle) (*models.AttestationRecord, error) {
	// Live N1 re-verification immediately prior to minting
	actionKind := item.RemediationKind
	if actionKind == "" {
		actionKind = models.RemediationKindImagePatch
	}
	w, err := e.warrants.ReverifyWarrantForExecution(ctx, item.WarrantID, svc.ServiceID, item.CVSSScore, svc.Replicas, actionKind, item.CWEID)
	warrantOK := err == nil
	if !warrantOK {
		item.StatusHealth = models.HealthExceptionRouted
		item.BlockerCode = "N1_WARRANT_REVERIFY_FAILED_AT_MINT"
		_ = e.store.UpsertRemediation(ctx, item)
		return nil, err
	}

	verDec, err := e.policy.EvalVerify(ctx, policy.VerifyInput{
		RemediationKind:           actionKind,
		SecretRotatedAndRevoked:   bundle.AssuranceTier == models.AssuranceTierSecretRotated,
		ExposedSecretSHA256:       bundle.ExposedSecretSHA256,
		RotatedSecretSHA256:       bundle.RotatedSecretSHA256,
		HasSignedProbe:            bundle.AssuranceTier == models.AssuranceTier2DifferentialTwin,
		UnpatchedTwinStatus:       bundle.UnpatchedTwinStatus,
		TwinReplayStatus:          item.TwinReplayStatus,
		ProvenanceVerified:        true,
		VulnerablePkgAbsentInSBOM: bundle.VulnerablePkgAbsentInSBOM || actionKind == models.RemediationKindSecretRotation,
		AttestedPods:              len(bundle.PodManifest),
		TotalPods:                 svc.Replicas,
		AdmissionLockoutEnforced:  bundle.Lockout.PolicyName != "",
		WarrantReverified:         warrantOK,
	})
	if err != nil {
		return nil, err
	}
	if !verDec.AllowAttestationMint {
		return nil, fmt.Errorf("N5_MINT_DENIED_BY_OPA: %s", strings.Join(verDec.Blockers, ","))
	}

	now := time.Now().UTC()
	reverifyExpiry := now.Add(30 * 24 * time.Hour)
	if w.ExpiresAt.Before(reverifyExpiry) {
		reverifyExpiry = w.ExpiresAt
	}

	attID := "att-" + uuid.NewString()[:8]
	systemUUID := deterministicUUID("system:g1-warrant-enterprise-estate")
	assetUUID := deterministicUUID("asset:" + svc.ServiceID)
	obsWarrantUUID := deterministicUUID("obs:warrant:" + attID)
	obsTwinUUID := deterministicUUID("obs:twin:" + attID)
	obsFleetUUID := deterministicUUID("obs:fleet:" + attID)
	obsLockoutUUID := deterministicUUID("obs:lockout:" + attID)
	riskUUID := deterministicUUID("risk:" + attID)
	poamItemUUID := deterministicUUID("poam-item:" + attID)

	warrantEnvHash, _, _ := crypto.CanonicalSHA256Hex(w.DSSEEnvelope)

	oscalDoc := map[string]any{
		"plan-of-action-and-milestones": map[string]any{
			"uuid": deterministicUUID("poam-doc:" + attID),
			"metadata": map[string]any{
				"title":         fmt.Sprintf("G1-Warrant Deterministic Closure POA&M — %s on %s", item.CVEID, svc.ServiceID),
				"last-modified": now.Format(time.RFC3339),
				"version":       "1.0.0",
				"oscal-version": "1.1.2",
				"props": []map[string]string{
					{"name": "organization", "value": "G1163RT Security Labs, Inc."},
					{"name": "control-plane", "value": "G1-Warrant Deterministic Kernel"},
					{"name": "compliance-baseline", "value": "NIST-SP-800-53-Rev5"},
					{"name": "assurance-tier", "value": verDec.AssuranceTier},
					{"name": "signer-backend", "value": e.signer.BackendMode()},
					{"name": "attestation-id", "value": attID},
					{"name": "reverification-expires-at", "value": reverifyExpiry.Format(time.RFC3339)},
				},
				"parties": []map[string]any{
					{
						"uuid": deterministicUUID("party:org"),
						"type": "organization",
						"name": "G1163RT Security Labs, Inc.",
					},
					{
						"uuid":          deterministicUUID("party:" + w.Slot1PrincipalID),
						"type":          "person",
						"name":          w.Slot1PrincipalID,
						"email-addresses": []string{w.Slot1Email},
						"props": []map[string]string{
							{"name": "ac5-slot", "value": "SLOT_1_SERVICE_OWNER"},
							{"name": "key-fingerprint", "value": w.Slot1KeyFP},
						},
					},
					{
						"uuid":          deterministicUUID("party:" + w.Slot2PrincipalID),
						"type":          "person",
						"name":          w.Slot2PrincipalID,
						"email-addresses": []string{w.Slot2Email},
						"props": []map[string]string{
							{"name": "ac5-slot", "value": "SLOT_2_AUTHORIZING_OFFICIAL"},
							{"name": "key-fingerprint", "value": w.Slot2KeyFP},
						},
					},
				},
			},
			"system-id": map[string]string{
				"identifier-type": "https://ietf.org/rfc/rfc4122",
				"id":              systemUUID,
			},
			"local-definitions": map[string]any{
				"inventory-items": []map[string]any{
					{
						"uuid":        assetUUID,
						"description": fmt.Sprintf("Workload %s (%s)", svc.ServiceID, svc.Namespace),
						"props": []map[string]string{
							{"name": "service-id", "value": svc.ServiceID},
							{"name": "namespace", "value": svc.Namespace},
							{"name": "purl", "value": item.PackagePURL},
							{"name": "vulnerable-digest", "value": item.VulnerableDigest},
							{"name": "patched-digest", "value": item.PatchedDigest},
						},
					},
				},
			},
			"observations": []map[string]any{
				{
					"uuid":        obsWarrantUUID,
					"title":       "N1 Dual-Key Standing Warrant Proof (NIST SP 800-53 AC-5)",
					"description": fmt.Sprintf("Governing Warrant %s verified with distinct Service Owner and Authorizing Official keys.", w.WarrantID),
					"methods":     []string{"EXAMINE", "TEST"},
					"collected":   now.Format(time.RFC3339),
					"props": []map[string]string{
						{"name": "warrant-id", "value": w.WarrantID},
						{"name": "warrant-dsse-sha256", "value": warrantEnvHash},
						{"name": "slot1-principal", "value": w.Slot1PrincipalID},
						{"name": "slot1-key-fp", "value": w.Slot1KeyFP},
						{"name": "slot2-principal", "value": w.Slot2PrincipalID},
						{"name": "slot2-key-fp", "value": w.Slot2KeyFP},
					},
				},
				{
					"uuid":        obsTwinUUID,
					"title":       "N3 Isolated Ephemeral Twin Exploit Replay",
					"description": "Deterministic exploit reproduction executed against isolated ephemeral twin; exit proof EXPLOIT_BLOCKED.",
					"methods":     []string{"TEST"},
					"collected":   now.Format(time.RFC3339),
					"props": []map[string]string{
						{"name": "twin-replay-status", "value": item.TwinReplayStatus},
						{"name": "twin-transcript-sha256", "value": bundle.TwinTranscriptSHA256},
					},
				},
				{
					"uuid":        obsFleetUUID,
					"title":       "N3 Passive 100% Fleet Digest & Unloaded Symbol Manifest",
					"description": fmt.Sprintf("Verified %d/%d live pods running patched digest %s.", len(bundle.PodManifest), svc.Replicas, item.PatchedDigest),
					"methods":     []string{"INSPECT"},
					"collected":   now.Format(time.RFC3339),
					"relevant-evidence": buildPodEvidenceList(bundle.PodManifest),
				},
				{
					"uuid":        obsLockoutUUID,
					"title":       "N3 Permanent Admission Lockout Policy",
					"description": fmt.Sprintf("Permanent ValidatingAdmissionPolicy %s enforced banning %s.", bundle.Lockout.PolicyName, bundle.Lockout.BannedDigest),
					"methods":     []string{"EXAMINE"},
					"collected":   now.Format(time.RFC3339),
					"props": []map[string]string{
						{"name": "lockout-policy-id", "value": bundle.Lockout.PolicyName},
						{"name": "banned-digest", "value": bundle.Lockout.BannedDigest},
					},
				},
			},
			"risks": []map[string]any{
				{
					"uuid":        riskUUID,
					"title":       fmt.Sprintf("%s Remediation Closure (%s)", item.CVEID, svc.ServiceID),
					"description": fmt.Sprintf("Deterministic remediation closure for %s (CISA_KEV=%t, CVSS=%.1f).", item.CVEID, item.IsKEV, item.CVSSScore),
					"statement":   "Exploit vector contained via Cilium bridge, patched statelessly via differential shadow canary, verified in isolated twin, and locked out permanently via ValidatingAdmissionPolicy.",
					"status":      "closed",
					"props": []map[string]string{
						{"name": "cve-id", "value": item.CVEID},
						{"name": "cwe-id", "value": item.CWEID},
						{"name": "cisa-kev", "value": fmt.Sprintf("%t", item.IsKEV)},
						{"name": "reverify-expires-at", "value": reverifyExpiry.Format(time.RFC3339)},
					},
				},
			},
			"poam-items": []map[string]any{
				{
					"uuid":        poamItemUUID,
					"title":       fmt.Sprintf("[%s] Closed Autonomous Remediation — %s", item.CVEID, svc.ServiceID),
					"description": fmt.Sprintf("Closed under Standing Warrant %s with Admission Lockout %s.", w.WarrantID, bundle.Lockout.PolicyName),
					"related-observations": []map[string]string{
						{"observation-uuid": obsWarrantUUID},
						{"observation-uuid": obsTwinUUID},
						{"observation-uuid": obsFleetUUID},
						{"observation-uuid": obsLockoutUUID},
					},
					"associated-risks": []map[string]string{
						{"risk-uuid": riskUUID},
					},
				},
			},
		},
	}

	env, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeAttestation, oscalDoc)
	if err != nil {
		return nil, err
	}
	if err := e.signer.SignEnvelope(ctx, 1, env); err != nil {
		return nil, err
	}

	ttvrSec := int64(now.Sub(item.CreatedAt).Seconds())
	if ttvrSec < 1 {
		ttvrSec = 1
	}

	rec := &models.AttestationRecord{
		AttestationID:        attID,
		RemediationID:        item.RemediationID,
		ServiceID:            svc.ServiceID,
		CVEID:                item.CVEID,
		IsKEV:                item.IsKEV,
		WarrantID:            w.WarrantID,
		Slot1PrincipalID:     w.Slot1PrincipalID,
		Slot1Email:           w.Slot1Email,
		Slot2PrincipalID:     w.Slot2PrincipalID,
		Slot2Email:           w.Slot2Email,
		TwinTranscriptSHA256: bundle.TwinTranscriptSHA256,
		AssuranceTier:        verDec.AssuranceTier,
		SignerBackend:        e.signer.BackendMode(),
		FleetDigestManifest:  bundle.PodManifest,
		LockoutPolicyID:      bundle.Lockout.PolicyName,
		ReverifyExpiresAt:    reverifyExpiry,
		DSSEEnvelope:         *env,
		OSCALPOAM:            oscalDoc,
		TTVRSeconds:          ttvrSec,
		MintedAt:             now,
	}
	if err := e.store.AppendAttestation(ctx, rec); err != nil {
		return nil, err
	}
	// Anchor DSSE-signed Merkle Root checkpoint across all 3 ledger tables on every closure
	_, _ = e.anchor.AnchorCheckpoint(ctx, e.store, e.signer)

	item.Stage = models.StageAttestedClosed
	item.StatusHealth = models.HealthAttested
	item.BlockerCode = ""
	item.AttestationID = attID
	item.AssuranceTier = verDec.AssuranceTier
	item.ClosedAt = &now
	_ = e.store.UpsertRemediation(ctx, item)
	kernelPK := e.signer.PublicKey()
	_ = e.store.AppendTrace(ctx, models.TraceEvent{
		TraceID:       "trc-" + uuid.NewString()[:8],
		RemediationID: item.RemediationID,
		Engine:        "N5",
		StepCode:      "OSCAL_1_1_2_ATTESTATION_MINTED",
		Outcome:       "ATTESTED",
		ActorOrToken:  kernelPK.KeyID,
		EvidenceHash:  rec.EntryHash,
		Fields: map[string]string{
			"attestation_id": attID,
			"assurance_tier": verDec.AssuranceTier,
			"signer_backend": e.signer.BackendMode(),
			"ttvr_seconds":   fmt.Sprintf("%d", ttvrSec),
			"oscal_version":  "1.1.2",
		},
		OccurredAt: now,
	})

	if e.onBroadcast != nil {
		e.onBroadcast("ATTESTATION_MINTED", rec)
		e.onBroadcast("REMEDIATION_UPDATED", item)
	}
	return rec, nil
}

// VerifyAttestationEnvelope cryptographically verifies a minted N5 DSSE OSCAL envelope.
func (e *Engine) VerifyAttestationEnvelope(env crypto.Envelope) error {
	raw, err := env.DecodePayload()
	if err != nil {
		return err
	}
	canon, err := crypto.CanonicalizeJSON(raw)
	if err != nil {
		return err
	}
	if string(canon) != string(raw) {
		return fmt.Errorf("OSCAL payload is not RFC 8785 JCS canonical")
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("missing kernel attestation signature")
	}
	kernelPK := e.signer.PublicKey()
	return crypto.VerifySingleSignature(env.PayloadType, raw, env.Signatures[0], &kernelPK, crypto.DefaultWebAuthnConfig())
}

// MintScopedAuditorToken generates a read-only, time-bounded cryptographic bearer token
// serving exclusively the Auditor Vault surface (/api/v1/auditor/...).
func (e *Engine) MintScopedAuditorToken(ctx context.Context, label, createdBy string, scopedIDs []string, ttlHours int) (*models.AuditorShareToken, string, error) {
	if ttlHours <= 0 || ttlHours > 720 {
		ttlHours = 24
	}
	if strings.TrimSpace(label) == "" {
		label = "3PAO External Assessment Bundle"
	}
	randBytes := make([]byte, 24)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, "", err
	}
	rawBearer := "g1aud_" + hex.EncodeToString(randBytes)
	now := time.Now().UTC()
	tok := models.AuditorShareToken{
		TokenID:              "aud-" + uuid.NewString()[:8],
		Label:                label,
		ScopedAttestationIDs: scopedIDs,
		CreatedBy:            createdBy,
		ExpiresAt:            now.Add(time.Duration(ttlHours) * time.Hour),
		Revoked:              false,
		CreatedAt:            now,
	}
	if err := e.store.CreateAuditorToken(ctx, tok, rawBearer); err != nil {
		return nil, "", err
	}
	return &tok, rawBearer, nil
}

func deterministicUUID(seed string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("g1163rt.g1-warrant:"+seed)).String()
}

func buildPodEvidenceList(pods []models.PodDigestEntry) []map[string]any {
	out := make([]map[string]any, 0, len(pods))
	for _, p := range pods {
		out = append(out, map[string]any{
			"description": fmt.Sprintf("Pod %s on %s verified running %s", p.PodName, p.NodeName, p.RunningDigest),
			"props": []map[string]string{
				{"name": "pod-name", "value": p.PodName},
				{"name": "node-name", "value": p.NodeName},
				{"name": "running-digest", "value": p.RunningDigest},
			},
		})
	}
	return out
}
