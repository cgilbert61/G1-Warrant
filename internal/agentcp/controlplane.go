package agentcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/db"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
	"github.com/google/uuid"
)

type internalWorkerKey struct {
	identity models.AgentIdentity
	priv     ed25519.PrivateKey
}

// ControlPlane implements N4: Governed Agent Control Plane, Commissioning Health + OPA Permission Intersection,
// RFC 8693 Composite Token Exchange (cnf + act), Wire-Level PoP signing, and hash-chained agent_action_ledger logging.
type ControlPlane struct {
	store           *db.Store
	policy          *policy.Engine
	signer          crypto.EnvelopeSigner
	extractorURL    string
	httpClient      *http.Client
	onBroadcast     func(eventType string, payload any)
	internalWorkers map[string]*internalWorkerKey
	workerManifests []models.AgentIdentity
}

// NewControlPlane initializes the N4 Agent Control Plane backed by an EnvelopeSigner (KMS/HSM or ephemeral)
// and generates dedicated holder-of-key identities for internal control-plane workers.
func NewControlPlane(store *db.Store, signer crypto.EnvelopeSigner, extractorURL string, onBroadcast func(string, any)) *ControlPlane {
	cp := &ControlPlane{
		store:        store,
		signer:       signer,
		extractorURL: strings.TrimRight(extractorURL, "/"),
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
		onBroadcast:     onBroadcast,
		internalWorkers: map[string]*internalWorkerKey{},
	}
	cp.initInternalWorkers()
	return cp
}

// SetPolicyEngine wires the precompiled OPA Engine (data.warrant.agent) into N4.
func (cp *ControlPlane) SetPolicyEngine(pol *policy.Engine) {
	cp.policy = pol
}

func (cp *ControlPlane) initInternalWorkers() {
	bPub, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	bPubB64 := base64.StdEncoding.EncodeToString(bPub)
	bFP := crypto.SHA256Hex(bPub)
	now := time.Now().UTC()

	specs := []struct {
		alias        string
		agentID      string
		displayName  string
		actions      []string
		egress       string
		allowIntake  bool
	}{
		{
			alias:       "warrant-extractor",
			agentID:     "agt-warrant-extractor",
			displayName: "Isolated Zero-Prose Extractor Worker",
			actions:     []string{"EXTRACT_SARIF_2_1_0", "EXTRACT_PATCH_DIFF", "EXTRACT_SECRET_EXPOSURE", "EXTRACT_ADVISORY"},
			egress:      models.EgressProfileZeroIsolated,
			allowIntake: true,
		},
		{
			alias:       "feed-poller",
			agentID:     "agt-feed-poller",
			displayName: "Autonomous Threat Feed Sanitizer (KEV/OSV)",
			actions:     []string{"EXTRACT_CISA_KEV_CATALOG", "EXTRACT_OSV_BATCH"},
			egress:      models.EgressProfileZeroIsolated,
			allowIntake: true,
		},
		{
			alias:       "k8s-rollout",
			agentID:     "agt-k8s-rollout",
			displayName: "Governed Kubernetes Canary Rollout Worker",
			actions:     []string{"*"},
			egress:      models.EgressProfileInternalCluster,
			allowIntake: false,
		},
		{
			alias:       "cilium-shield",
			agentID:     "agt-cilium-shield",
			displayName: "Cilium eBPF & Admission Lockout Enforcer",
			actions:     []string{"*"},
			egress:      models.EgressProfileInternalCluster,
			allowIntake: false,
		},
		{
			alias:       "twin-runner",
			agentID:     "agt-twin-runner",
			displayName: "Isolated Ephemeral Differential Twin Runner",
			actions:     []string{"*"},
			egress:      models.EgressProfileZeroIsolated,
			allowIntake: false,
		},
		{
			alias:       "secret-rotator",
			agentID:     "agt-secret-rotator",
			displayName: "Stateless Credential Rotation Worker",
			actions:     []string{"*"},
			egress:      models.EgressProfileInternalCluster,
			allowIntake: false,
		},
	}

	for _, sp := range specs {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		pubB64 := base64.StdEncoding.EncodeToString(pub)
		fp := crypto.SHA256Hex(pub)
		artDigest := "sha256:" + crypto.SHA256Hex([]byte("g1-internal-worker:"+sp.agentID))
		provSig, _ := crypto.SignAgentBuilderProvenance(sp.agentID, artDigest, pubB64, bPriv)
		manifest := models.AgentIdentity{
			AgentID:                   sp.agentID,
			DisplayName:               sp.displayName,
			AgentKind:                 models.AgentKindInternalWorker,
			CommissioningFunctionID:   models.SystemCommissioningFunctionID,
			KeyID:                     fmt.Sprintf("ed25519-%s-%s", sp.agentID, fp[:10]),
			Alg:                       crypto.AlgEd25519,
			PublicKeyB64:              pubB64,
			KeyFingerprint:            fp,
			SPIFFEID:                  "spiffe://g1-warrant.internal/ns/g1-system/sa/" + sp.agentID,
			ArtifactDigest:            artDigest,
			BuilderPrincipalID:        "bld-g1-kernel-release-pipeline",
			BuilderPublicKeyB64:       bPubB64,
			BuilderKeyFingerprint:     bFP,
			BuilderProvenanceSigB64:   provSig,
			AllowedActions:            sp.actions,
			AllowedServices:           []string{"*"},
			AllowedEgressProfile:      sp.egress,
			MaxTTLSeconds:             300,
			MaxDelegationDepth:        1,
			AllowAutonomousIntake:     sp.allowIntake,
			RecertifyExpiresAt:        now.Add(89 * 24 * time.Hour),
			CommissionerSOPrincipalID: "sys-kernel-so-anchor",
			CommissionerAOPrincipalID: "sys-kernel-ao-anchor",
			SponsorshipState:          models.SponsorshipActive,
			LineageMode:               models.LineageModeKernelSystemBoot,
			EnrolledAt:                now,
		}
		wk := &internalWorkerKey{identity: manifest, priv: priv}
		cp.internalWorkers[sp.alias] = wk
		cp.internalWorkers[sp.agentID] = wk
		cp.workerManifests = append(cp.workerManifests, manifest)
	}
}

// InternalWorkerManifests returns the public AgentIdentity manifests for startup registration in agent_identities.
func (cp *ControlPlane) InternalWorkerManifests() []models.AgentIdentity {
	out := make([]models.AgentIdentity, len(cp.workerManifests))
	copy(out, cp.workerManifests)
	return out
}

func (cp *ControlPlane) resolveInternalWorker(workerName, actionType string) *internalWorkerKey {
	if actionType == "EXTRACT_CISA_KEV_CATALOG" || actionType == "EXTRACT_OSV_BATCH" {
		if wk, ok := cp.internalWorkers["feed-poller"]; ok {
			return wk
		}
	}
	low := strings.ToLower(strings.TrimSpace(workerName))
	switch {
	case strings.Contains(low, "cilium") || strings.Contains(low, "shield") || strings.Contains(low, "lockout"):
		if wk, ok := cp.internalWorkers["cilium-shield"]; ok {
			return wk
		}
	case strings.Contains(low, "twin"):
		if wk, ok := cp.internalWorkers["twin-runner"]; ok {
			return wk
		}
	case strings.Contains(low, "secret"):
		if wk, ok := cp.internalWorkers["secret-rotator"]; ok {
			return wk
		}
	case strings.Contains(low, "rollout") || strings.Contains(low, "k8s"):
		if wk, ok := cp.internalWorkers["k8s-rollout"]; ok {
			return wk
		}
	}
	if wk, ok := cp.internalWorkers[low]; ok {
		return wk
	}
	return cp.internalWorkers["warrant-extractor"]
}

func resolveAuthorityModeAndSlots(warrantID, s1ID, s2ID string) (authMode, normWarrantID, normS1, normS2 string) {
	switch warrantID {
	case models.AuthorityModeAutonomousSponsored, "AUTONOMOUS_SPONSORED_INTAKE", "BOOTSTRAP_INTAKE", "BOOTSTRAP_SECRET_INTAKE", "BOOTSTRAP_FEED_SYNC":
		return models.AuthorityModeAutonomousSponsored, "AUTONOMOUS_SPONSORED_INTAKE", "NONE", "NONE"
	default:
		if strings.HasPrefix(s1ID, "sys-") || s1ID == "" {
			s1ID = "NONE"
		}
		if strings.HasPrefix(s2ID, "sys-") || s2ID == "" {
			s2ID = "NONE"
		}
		return models.AuthorityModeWarrantComposite, warrantID, s1ID, s2ID
	}
}

// MintTaskWarrant mints a short-lived (TTL <= 300s) Ed25519 DSSE-signed Ephemeral Task Warrant
// carrying RFC 8693 act + cnf holder-of-key claims.
func (cp *ControlPlane) MintTaskWarrant(warrantID, remediationID, workerName, targetAsset, allowedAction, slot1ID, slot2ID string, ttlSec int) (*crypto.Envelope, *models.EphemeralTaskWarrantPayload, error) {
	if ttlSec <= 0 || ttlSec > 300 {
		return nil, nil, fmt.Errorf("N4_TTL_CEILING_EXCEEDED: ttl_seconds=%d must be in (0, 300]", ttlSec)
	}
	if warrantID == "" || targetAsset == "" || allowedAction == "" {
		return nil, nil, errors.New("N4_UNATTRIBUTED_TASK: warrant_id, target_asset, and allowed_action are mandatory")
	}
	wk := cp.resolveInternalWorker(workerName, allowedAction)
	authMode, normWarrantID, normS1, normS2 := resolveAuthorityModeAndSlots(warrantID, slot1ID, slot2ID)
	now := time.Now().UTC()

	var act *models.ActorClaim
	var cnf *models.ConfirmationClaim
	fnID := models.SystemCommissioningFunctionID
	sub := workerName
	egress := models.EgressProfileZeroIsolated
	if wk != nil {
		sub = wk.identity.AgentID
		egress = wk.identity.AllowedEgressProfile
		act = &models.ActorClaim{
			AgentID:                 wk.identity.AgentID,
			KeyID:                   wk.identity.KeyID,
			KeyFingerprint:          wk.identity.KeyFingerprint,
			CommissioningFunctionID: fnID,
			SponsorshipState:        models.SponsorshipActive,
		}
		cnf = &models.ConfirmationClaim{
			Alg:            crypto.AlgEd25519,
			KeyID:          wk.identity.KeyID,
			PublicKeyB64:   wk.identity.PublicKeyB64,
			KeyFingerprint: wk.identity.KeyFingerprint,
		}
	}

	payload := models.EphemeralTaskWarrantPayload{
		TaskTokenID:             "tsk-" + uuid.NewString()[:8],
		WarrantID:               normWarrantID,
		RemediationID:           remediationID,
		AuthorityMode:           authMode,
		CommissioningFunctionID: fnID,
		Sub:                     sub,
		WorkerName:              workerName,
		TargetAsset:             targetAsset,
		AllowedAction:           allowedAction,
		EgressProfile:           egress,
		ForbiddenPathPrefixes:   models.DefaultForbiddenDiffPrefixes,
		Slot1PrincipalID:        normS1,
		Slot2PrincipalID:        normS2,
		Act:                     act,
		Cnf:                     cnf,
		DelegationDepth:         0,
		MaxDelegationDepth:      1,
		TTLSeconds:              ttlSec,
		IssuedUnix:              now.Unix(),
		ExpiresUnix:             now.Add(time.Duration(ttlSec) * time.Second).Unix(),
	}
	env, _, err := crypto.NewUnsignedEnvelope(crypto.PayloadTypeTaskWarrant, payload)
	if err != nil {
		return nil, nil, err
	}
	if err := cp.signer.SignEnvelope(context.Background(), 1, env); err != nil {
		return nil, nil, err
	}
	return env, &payload, nil
}

// AttachWireTaskAndPoPHeaders attaches X-Warrant-Task-DSSE and X-Warrant-Agent-PoP to an outbound HTTP request.
func AttachWireTaskAndPoPHeaders(req *http.Request, body []byte, env *crypto.Envelope, taskTokenID string, holderPriv ed25519.PrivateKey) error {
	if req == nil || env == nil {
		return errors.New("nil request or task warrant envelope")
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}
	req.Header.Set(crypto.HeaderTaskDSSE, base64.StdEncoding.EncodeToString(envBytes))
	if len(holderPriv) == ed25519.PrivateKeySize {
		popHdr, err := crypto.BuildAgentPoPHeader(req.Method, req.URL.Path, body, taskTokenID, holderPriv, time.Now().UTC())
		if err != nil {
			return err
		}
		req.Header.Set(crypto.HeaderAgentPoP, popHdr)
	}
	return nil
}

type governedAdapterTransport struct {
	cp          *ControlPlane
	workerAlias string
	base        http.RoundTripper
}

func (t *governedAdapterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if req.Method == http.MethodGet || req.Method == http.MethodHead || req.Header.Get(crypto.HeaderTaskDSSE) != "" {
		return base.RoundTrip(req)
	}
	var bodyBytes []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		bodyBytes = b
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
	}
	wk := t.cp.resolveInternalWorker(t.workerAlias, "CLUSTER_MUTATION")
	if wk != nil {
		env, tok, err := t.cp.MintTaskWarrant("KERNEL_CLUSTER_ADAPTER", "", wk.identity.AgentID, "*", "*", "NONE", "NONE", 60)
		if err == nil {
			_ = AttachWireTaskAndPoPHeaders(req, bodyBytes, env, tok.TaskTokenID, wk.priv)
		}
	}
	return base.RoundTrip(req)
}

// NewGovernedRoundTripper wraps an HTTP RoundTripper so mutating outbound adapter requests (e.g. to fleet-sim)
// carry kernel-signed X-Warrant-Task-DSSE + Ed25519 holder-of-key X-Warrant-Agent-PoP wire headers.
func (cp *ControlPlane) NewGovernedRoundTripper(workerAlias string, base http.RoundTripper) http.RoundTripper {
	return &governedAdapterTransport{
		cp:          cp,
		workerAlias: workerAlias,
		base:        base,
	}
}

func (cp *ControlPlane) doGovernedExtractorPost(
	ctx context.Context,
	endpoint string,
	body []byte,
	env *crypto.Envelope,
	tok *models.EphemeralTaskWarrantPayload,
	wk *internalWorkerKey,
) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if wk != nil {
		if err := AttachWireTaskAndPoPHeaders(req, body, env, tok.TaskTokenID, wk.priv); err != nil {
			return nil, 0, err
		}
	}
	resp, err := cp.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return respBody, resp.StatusCode, nil
}

// VerifyAndConsumeTaskWarrant validates an Ephemeral Task Warrant against asset, action, sponsorship health, and TTL.
// Any unattributed, forged, wrong-asset, quarantined, or expired call is logged as SECURITY_VIOLATION in agent_action_ledger.
func (cp *ControlPlane) VerifyAndConsumeTaskWarrant(ctx context.Context, env *crypto.Envelope, requestedAsset, requestedAction string) (*models.EphemeralTaskWarrantPayload, error) {
	recordViolation := func(code string, p models.EphemeralTaskWarrantPayload) error {
		if cp.store != nil {
			entry := &models.AgentLedgerEntry{
				ActionID:                "act-" + uuid.NewString()[:8],
				TaskTokenID:             nonEmpty(p.TaskTokenID, "UNATTRIBUTED"),
				WarrantID:               nonEmpty(p.WarrantID, "NONE"),
				RemediationID:           p.RemediationID,
				AuthorityMode:           p.AuthorityMode,
				CommissioningFunctionID: p.CommissioningFunctionID,
				AgentID:                 p.Sub,
				DelegationDepth:         p.DelegationDepth,
				ActChain:                p.Act,
				WorkerName:              nonEmpty(p.WorkerName, "UNKNOWN_WORKER"),
				TargetAsset:             nonEmpty(requestedAsset, "UNKNOWN_ASSET"),
				ActionType:              nonEmpty(requestedAction, "UNKNOWN_ACTION"),
				Slot1PrincipalID:        nonEmpty(p.Slot1PrincipalID, "NONE"),
				Slot2PrincipalID:        nonEmpty(p.Slot2PrincipalID, "NONE"),
				EgressProfile:           "BLOCKED_BY_KERNEL",
				RawInputSHA256:          db.GenesisHash,
				ExtractorDigest:         "NONE",
				TypedOutputSHA256:       db.GenesisHash,
				TokenTTLSec:             clampTTL(p.TTLSeconds),
				Status:                  "SECURITY_VIOLATION",
				ViolationCode:           code,
				ExecutedAt:              time.Now().UTC(),
			}
			_ = cp.store.AppendAgentAction(ctx, entry)
			if cp.onBroadcast != nil {
				cp.onBroadcast("AGENT_SECURITY_VIOLATION", entry)
			}
		}
		return fmt.Errorf("N4_SECURITY_VIOLATION (%s)", code)
	}

	if env == nil || len(env.Signatures) == 0 {
		return nil, recordViolation("MISSING_TASK_WARRANT", models.EphemeralTaskWarrantPayload{})
	}
	rawPayload, err := env.DecodePayload()
	if err != nil {
		return nil, recordViolation("CORRUPT_TASK_PAYLOAD", models.EphemeralTaskWarrantPayload{})
	}
	var p models.EphemeralTaskWarrantPayload
	if err := json.Unmarshal(rawPayload, &p); err != nil {
		return nil, recordViolation("INVALID_TASK_JSON", models.EphemeralTaskWarrantPayload{})
	}
	kernelPK := cp.signer.PublicKey()
	if err := crypto.VerifySingleSignature(env.PayloadType, rawPayload, env.Signatures[0], &kernelPK, crypto.DefaultWebAuthnConfig()); err != nil {
		return nil, recordViolation("FORGED_TASK_SIGNATURE", p)
	}
	nowUnix := time.Now().UTC().Unix()
	if nowUnix >= p.ExpiresUnix {
		return nil, recordViolation("EXPIRED_TASK_WARRANT", p)
	}
	if p.TTLSeconds <= 0 || p.TTLSeconds > 300 {
		return nil, recordViolation("TTL_CEILING_VIOLATION", p)
	}
	if p.TargetAsset != requestedAsset && p.TargetAsset != "*" {
		return nil, recordViolation("ASSET_SCOPE_VIOLATION", p)
	}
	if p.AllowedAction != requestedAction && p.AllowedAction != "*" {
		return nil, recordViolation("ACTION_SCOPE_VIOLATION", p)
	}
	if p.Act != nil {
		switch p.Act.SponsorshipState {
		case models.SponsorshipOrphanQuarantined, models.SponsorshipLeaseExpired, models.SponsorshipRevokedCompromise, models.SponsorshipRevokedKillSwitch:
			return nil, recordViolation("GHOST_OR_REVOKED_AGENT_BLOCKED:"+p.Act.SponsorshipState, p)
		}
	}
	return &p, nil
}

// RecordGovernedAdapterAction mints, verifies, and logs a governed adapter execution into agent_action_ledger.
func (cp *ControlPlane) RecordGovernedAdapterAction(ctx context.Context, warrantID, remediationID, workerName, targetAsset, actionType, s1ID, s2ID, egressProfile, inputSHA, outSHA string) error {
	env, _, err := cp.MintTaskWarrant(warrantID, remediationID, workerName, targetAsset, actionType, s1ID, s2ID, 120)
	if err != nil {
		return err
	}
	tok, err := cp.VerifyAndConsumeTaskWarrant(ctx, env, targetAsset, actionType)
	if err != nil {
		return err
	}
	entry := &models.AgentLedgerEntry{
		ActionID:                "act-" + uuid.NewString()[:8],
		TaskTokenID:             tok.TaskTokenID,
		WarrantID:               tok.WarrantID,
		RemediationID:           remediationID,
		AuthorityMode:           tok.AuthorityMode,
		CommissioningFunctionID: tok.CommissioningFunctionID,
		AgentID:                 tok.Sub,
		DelegationDepth:         tok.DelegationDepth,
		ActChain:                tok.Act,
		WorkerName:              tok.Sub,
		TargetAsset:             targetAsset,
		ActionType:              actionType,
		Slot1PrincipalID:        tok.Slot1PrincipalID,
		Slot2PrincipalID:        tok.Slot2PrincipalID,
		EgressProfile:           egressProfile,
		RawInputSHA256:          inputSHA,
		ExtractorDigest:         "KERNEL_ADAPTER_DIRECT",
		TypedOutputSHA256:       outSHA,
		TokenTTLSec:             tok.TTLSeconds,
		Status:                  "EXECUTED",
		ExecutedAt:              time.Now().UTC(),
	}
	if err := cp.store.AppendAgentAction(ctx, entry); err != nil {
		return err
	}
	if cp.onBroadcast != nil {
		cp.onBroadcast("AGENT_ACTION_LOGGED", entry)
	}
	return nil
}

// ExtractSARIFGoverned invokes the isolated warrant-extractor over internal HTTP and records the cryptographic proof in agent_action_ledger.
func (cp *ControlPlane) ExtractSARIFGoverned(ctx context.Context, warrantID, remediationID, targetAsset, s1ID, s2ID string, rawSARIF []byte) (*models.ExtractedFindingSet, error) {
	return cp.ExtractSARIFWithOptionsGoverned(ctx, warrantID, remediationID, targetAsset, s1ID, s2ID, rawSARIF, "", "", 0)
}

// ExtractSARIFWithOptionsGoverned invokes warrant-extractor /extract/sarif with wire-level X-Warrant-Task-DSSE + X-Warrant-Agent-PoP.
func (cp *ControlPlane) ExtractSARIFWithOptionsGoverned(ctx context.Context, warrantID, remediationID, targetAsset, s1ID, s2ID string, rawSARIF []byte, targetService, vulnDigest string, maxFindings int) (*models.ExtractedFindingSet, error) {
	wk := cp.resolveInternalWorker("warrant-extractor", "EXTRACT_SARIF_2_1_0")
	env, _, err := cp.MintTaskWarrant(warrantID, remediationID, wk.identity.AgentID, targetAsset, "EXTRACT_SARIF_2_1_0", s1ID, s2ID, 60)
	if err != nil {
		return nil, err
	}
	tok, err := cp.VerifyAndConsumeTaskWarrant(ctx, env, targetAsset, "EXTRACT_SARIF_2_1_0")
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	if targetService != "" {
		q.Set("target_service", targetService)
	}
	if vulnDigest != "" {
		q.Set("vulnerable_digest", vulnDigest)
	}
	if maxFindings > 0 {
		q.Set("max_findings", strconv.Itoa(maxFindings))
	}
	endpoint := cp.extractorURL + "/extract/sarif"
	if encoded := q.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}

	respBody, status, err := cp.doGovernedExtractorPost(ctx, endpoint, rawSARIF, env, tok, wk)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/sarif unreachable: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected SARIF (HTTP %d): %s", status, string(respBody))
	}

	var out models.ExtractedFindingSet
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode ExtractedFindingSet: %w", err)
	}

	entry := &models.AgentLedgerEntry{
		ActionID:                "act-" + uuid.NewString()[:8],
		TaskTokenID:             tok.TaskTokenID,
		WarrantID:               tok.WarrantID,
		RemediationID:           remediationID,
		AuthorityMode:           tok.AuthorityMode,
		CommissioningFunctionID: tok.CommissioningFunctionID,
		AgentID:                 tok.Sub,
		DelegationDepth:         tok.DelegationDepth,
		ActChain:                tok.Act,
		WorkerName:              wk.identity.AgentID,
		TargetAsset:             targetAsset,
		ActionType:              "EXTRACT_SARIF_2_1_0",
		Slot1PrincipalID:        tok.Slot1PrincipalID,
		Slot2PrincipalID:        tok.Slot2PrincipalID,
		EgressProfile:           models.EgressProfileZeroIsolated,
		RawInputSHA256:          out.RawInputSHA256,
		ExtractorDigest:         out.ExtractorDigest,
		TypedOutputSHA256:       out.TypedOutputSHA256,
		TokenTTLSec:             tok.TTLSeconds,
		Status:                  "EXECUTED",
		ExecutedAt:              time.Now().UTC(),
	}
	if err := cp.store.AppendAgentAction(ctx, entry); err != nil {
		return nil, err
	}
	if cp.onBroadcast != nil {
		cp.onBroadcast("AGENT_ACTION_LOGGED", entry)
	}
	return &out, nil
}

// ExtractCISAKEVGoverned pipes raw untrusted CISA KEV catalog JSON through warrant-extractor using agt-feed-poller (AUTONOMOUS_WORKLOAD_SPONSORED).
func (cp *ControlPlane) ExtractCISAKEVGoverned(ctx context.Context, rawKEV []byte) (*models.ExtractedKEVCatalog, error) {
	wk := cp.resolveInternalWorker("feed-poller", "EXTRACT_CISA_KEV_CATALOG")
	env, _, err := cp.MintTaskWarrant(models.AuthorityModeAutonomousSponsored, "", wk.identity.AgentID, "cisa-kev-feed", "EXTRACT_CISA_KEV_CATALOG", "NONE", "NONE", 120)
	if err != nil {
		return nil, err
	}
	tok, err := cp.VerifyAndConsumeTaskWarrant(ctx, env, "cisa-kev-feed", "EXTRACT_CISA_KEV_CATALOG")
	if err != nil {
		return nil, err
	}

	respBody, status, err := cp.doGovernedExtractorPost(ctx, cp.extractorURL+"/extract/cisa-kev", rawKEV, env, tok, wk)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/cisa-kev unreachable: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected CISA KEV (HTTP %d): %s", status, string(respBody))
	}

	var out models.ExtractedKEVCatalog
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode ExtractedKEVCatalog: %w", err)
	}

	entry := &models.AgentLedgerEntry{
		ActionID:                "act-" + uuid.NewString()[:8],
		TaskTokenID:             tok.TaskTokenID,
		WarrantID:               tok.WarrantID,
		AuthorityMode:           tok.AuthorityMode,
		CommissioningFunctionID: tok.CommissioningFunctionID,
		AgentID:                 tok.Sub,
		DelegationDepth:         tok.DelegationDepth,
		ActChain:                tok.Act,
		WorkerName:              wk.identity.AgentID,
		TargetAsset:             "cisa-kev-feed",
		ActionType:              "EXTRACT_CISA_KEV_CATALOG",
		Slot1PrincipalID:        "NONE",
		Slot2PrincipalID:        "NONE",
		EgressProfile:           models.EgressProfileZeroIsolated,
		RawInputSHA256:          out.RawInputSHA256,
		ExtractorDigest:         out.ExtractorDigest,
		TypedOutputSHA256:       out.TypedOutputSHA256,
		TokenTTLSec:             tok.TTLSeconds,
		Status:                  "EXECUTED",
		ExecutedAt:              time.Now().UTC(),
	}
	if err := cp.store.AppendAgentAction(ctx, entry); err != nil {
		return nil, err
	}
	if cp.onBroadcast != nil {
		cp.onBroadcast("AGENT_ACTION_LOGGED", entry)
	}
	return &out, nil
}

// ExtractOSVBundleGoverned pipes untrusted Google OSV.dev responses through warrant-extractor using agt-feed-poller (AUTONOMOUS_WORKLOAD_SPONSORED).
func (cp *ControlPlane) ExtractOSVBundleGoverned(ctx context.Context, rawBundle []byte) (*models.ExtractedOSVReport, error) {
	wk := cp.resolveInternalWorker("feed-poller", "EXTRACT_OSV_BATCH")
	env, _, err := cp.MintTaskWarrant(models.AuthorityModeAutonomousSponsored, "", wk.identity.AgentID, "google-osv-sbom", "EXTRACT_OSV_BATCH", "NONE", "NONE", 120)
	if err != nil {
		return nil, err
	}
	tok, err := cp.VerifyAndConsumeTaskWarrant(ctx, env, "google-osv-sbom", "EXTRACT_OSV_BATCH")
	if err != nil {
		return nil, err
	}

	respBody, status, err := cp.doGovernedExtractorPost(ctx, cp.extractorURL+"/extract/osv", rawBundle, env, tok, wk)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/osv unreachable: %w", err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected OSV bundle (HTTP %d): %s", status, string(respBody))
	}

	var out models.ExtractedOSVReport
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode ExtractedOSVReport: %w", err)
	}

	entry := &models.AgentLedgerEntry{
		ActionID:                "act-" + uuid.NewString()[:8],
		TaskTokenID:             tok.TaskTokenID,
		WarrantID:               tok.WarrantID,
		AuthorityMode:           tok.AuthorityMode,
		CommissioningFunctionID: tok.CommissioningFunctionID,
		AgentID:                 tok.Sub,
		DelegationDepth:         tok.DelegationDepth,
		ActChain:                tok.Act,
		WorkerName:              wk.identity.AgentID,
		TargetAsset:             "google-osv-sbom",
		ActionType:              "EXTRACT_OSV_BATCH",
		Slot1PrincipalID:        "NONE",
		Slot2PrincipalID:        "NONE",
		EgressProfile:           models.EgressProfileZeroIsolated,
		RawInputSHA256:          out.RawInputSHA256,
		ExtractorDigest:         out.ExtractorDigest,
		TypedOutputSHA256:       out.TypedOutputSHA256,
		TokenTTLSec:             tok.TTLSeconds,
		Status:                  "EXECUTED",
		ExecutedAt:              time.Now().UTC(),
	}
	if err := cp.store.AppendAgentAction(ctx, entry); err != nil {
		return nil, err
	}
	if cp.onBroadcast != nil {
		cp.onBroadcast("AGENT_ACTION_LOGGED", entry)
	}
	return &out, nil
}

// ExtractDiffGoverned invokes warrant-extractor /extract/diff with wire-level X-Warrant-Task-DSSE + X-Warrant-Agent-PoP.
func (cp *ControlPlane) ExtractDiffGoverned(ctx context.Context, warrantID, remediationID, targetAsset, s1ID, s2ID, patchedDigest, unifiedDiff string) (*models.ExtractedPatchMetadata, error) {
	wk := cp.resolveInternalWorker("warrant-extractor", "EXTRACT_PATCH_DIFF")
	env, _, err := cp.MintTaskWarrant(warrantID, remediationID, wk.identity.AgentID, targetAsset, "EXTRACT_PATCH_DIFF", s1ID, s2ID, 60)
	if err != nil {
		return nil, err
	}
	tok, err := cp.VerifyAndConsumeTaskWarrant(ctx, env, targetAsset, "EXTRACT_PATCH_DIFF")
	if err != nil {
		return nil, err
	}

	rawBody, _ := json.Marshal(map[string]string{
		"patched_digest": patchedDigest,
		"unified_diff":   unifiedDiff,
	})
	respBytes, statusCode, err := cp.doGovernedExtractorPost(ctx, cp.extractorURL+"/extract/diff", rawBody, env, tok, wk)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/diff unreachable: %w", err)
	}
	if statusCode >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected diff (HTTP %d): %s", statusCode, string(respBytes))
	}

	var meta models.ExtractedPatchMetadata
	if err := json.Unmarshal(respBytes, &meta); err != nil {
		return nil, fmt.Errorf("decode ExtractedPatchMetadata: %w", err)
	}

	if n4Violations := InspectDiffForForbiddenPaths(unifiedDiff, meta.TouchedFiles); len(n4Violations) > 0 {
		merged := map[string]bool{}
		for _, v := range meta.ForbiddenConfigTouches {
			merged[v] = true
		}
		for _, v := range n4Violations {
			merged[v] = true
		}
		meta.ForbiddenConfigTouches = make([]string, 0, len(merged))
		for v := range merged {
			meta.ForbiddenConfigTouches = append(meta.ForbiddenConfigTouches, v)
		}
		sort.Strings(meta.ForbiddenConfigTouches)
		meta.StatelessEligible = false
	}

	status := "EXECUTED"
	violationCode := ""
	if len(meta.ForbiddenConfigTouches) > 0 {
		status = "SECURITY_VIOLATION"
		violationCode = "FORBIDDEN_BUILD_OR_AGENT_CONFIG_MUTATION:" + strings.Join(meta.ForbiddenConfigTouches, ",")
	}

	entry := &models.AgentLedgerEntry{
		ActionID:                "act-" + uuid.NewString()[:8],
		TaskTokenID:             tok.TaskTokenID,
		WarrantID:               tok.WarrantID,
		RemediationID:           remediationID,
		AuthorityMode:           tok.AuthorityMode,
		CommissioningFunctionID: tok.CommissioningFunctionID,
		AgentID:                 tok.Sub,
		DelegationDepth:         tok.DelegationDepth,
		ActChain:                tok.Act,
		WorkerName:              wk.identity.AgentID,
		TargetAsset:             targetAsset,
		ActionType:              "EXTRACT_PATCH_DIFF",
		Slot1PrincipalID:        tok.Slot1PrincipalID,
		Slot2PrincipalID:        tok.Slot2PrincipalID,
		EgressProfile:           models.EgressProfileZeroIsolated,
		RawInputSHA256:          meta.RawInputSHA256,
		ExtractorDigest:         meta.ExtractorDigest,
		TypedOutputSHA256:       meta.TypedOutputSHA256,
		TokenTTLSec:             tok.TTLSeconds,
		Status:                  status,
		ViolationCode:           violationCode,
		ExecutedAt:              time.Now().UTC(),
	}
	if err := cp.store.AppendAgentAction(ctx, entry); err != nil {
		return nil, err
	}
	if cp.onBroadcast != nil {
		if status == "SECURITY_VIOLATION" {
			cp.onBroadcast("AGENT_SECURITY_VIOLATION", entry)
		} else {
			cp.onBroadcast("AGENT_ACTION_LOGGED", entry)
		}
	}
	if status == "SECURITY_VIOLATION" {
		return &meta, fmt.Errorf("N4_FORBIDDEN_CONFIG_POISONING_BLOCKED (%s)", violationCode)
	}
	return &meta, nil
}

// ExtractSecretFindingsGoverned pipes Gitleaks/GitGuardian/cloud secret-exposure scan JSON through warrant-extractor
// with wire-level X-Warrant-Task-DSSE + X-Warrant-Agent-PoP.
func (cp *ControlPlane) ExtractSecretFindingsGoverned(ctx context.Context, warrantID, remediationID, targetAsset, s1ID, s2ID string, rawSecrets []byte) (*models.ExtractedSecretFindingSet, error) {
	wk := cp.resolveInternalWorker("warrant-extractor", "EXTRACT_SECRET_EXPOSURE")
	env, _, err := cp.MintTaskWarrant(warrantID, remediationID, wk.identity.AgentID, targetAsset, "EXTRACT_SECRET_EXPOSURE", s1ID, s2ID, 60)
	if err != nil {
		return nil, err
	}
	tok, err := cp.VerifyAndConsumeTaskWarrant(ctx, env, targetAsset, "EXTRACT_SECRET_EXPOSURE")
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	if targetAsset != "" && targetAsset != "secret-intake-stream" {
		q.Set("target_service", targetAsset)
	}
	endpoint := cp.extractorURL + "/extract/secrets"
	if enc := q.Encode(); enc != "" {
		endpoint += "?" + enc
	}

	respBytes, statusCode, err := cp.doGovernedExtractorPost(ctx, endpoint, rawSecrets, env, tok, wk)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/secrets unreachable: %w", err)
	}
	if statusCode >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected secret scan (HTTP %d): %s", statusCode, string(respBytes))
	}

	var out models.ExtractedSecretFindingSet
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("decode ExtractedSecretFindingSet: %w", err)
	}

	entry := &models.AgentLedgerEntry{
		ActionID:                "act-" + uuid.NewString()[:8],
		TaskTokenID:             tok.TaskTokenID,
		WarrantID:               tok.WarrantID,
		RemediationID:           remediationID,
		AuthorityMode:           tok.AuthorityMode,
		CommissioningFunctionID: tok.CommissioningFunctionID,
		AgentID:                 tok.Sub,
		DelegationDepth:         tok.DelegationDepth,
		ActChain:                tok.Act,
		WorkerName:              wk.identity.AgentID,
		TargetAsset:             targetAsset,
		ActionType:              "EXTRACT_SECRET_EXPOSURE",
		Slot1PrincipalID:        tok.Slot1PrincipalID,
		Slot2PrincipalID:        tok.Slot2PrincipalID,
		EgressProfile:           models.EgressProfileZeroIsolated,
		RawInputSHA256:          out.RawInputSHA256,
		ExtractorDigest:         out.ExtractorDigest,
		TypedOutputSHA256:       out.TypedOutputSHA256,
		TokenTTLSec:             tok.TTLSeconds,
		Status:                  "EXECUTED",
		ExecutedAt:              time.Now().UTC(),
	}
	if err := cp.store.AppendAgentAction(ctx, entry); err != nil {
		return nil, err
	}
	if cp.onBroadcast != nil {
		cp.onBroadcast("AGENT_ACTION_LOGGED", entry)
	}
	return &out, nil
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func clampTTL(v int) int {
	if v < 0 {
		return 0
	}
	if v > 300 {
		return 300
	}
	return v
}

// InspectDiffForForbiddenPaths normalizes every diff path (path.Clean), rejects '..' traversal and
// git 120000 symlinks, and blocks protected build/agent files (Dockerfile*, Makefile, GNUmakefile,
// AGENTS.md, CLAUDE.md, .github/, .gitlab-ci*, .cursor/, .gemini/) at ANY directory depth.
func InspectDiffForForbiddenPaths(unifiedDiff string, extraPaths []string) []string {
	violations := map[string]bool{}
	currentFile := ""

	inspectPath := func(raw string) {
		trimmed := strings.Trim(strings.TrimSpace(raw), `"`)
		trimmed = strings.ReplaceAll(trimmed, `\`, "/")
		if trimmed == "" || trimmed == "/dev/null" || trimmed == "dev/null" {
			currentFile = ""
			return
		}
		for _, seg := range strings.Split(trimmed, "/") {
			if seg == ".." {
				violations["PATH_TRAVERSAL:"+trimmed] = true
				currentFile = trimmed
				return
			}
		}
		cleaned := path.Clean(strings.TrimPrefix(strings.TrimPrefix(trimmed, "./"), "/"))
		if cleaned == "." || cleaned == "dev/null" {
			currentFile = ""
			return
		}
		if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
			violations["PATH_TRAVERSAL:"+trimmed] = true
			currentFile = trimmed
			return
		}
		currentFile = cleaned
		if isProtectedPathAnyDepth(cleaned) {
			violations[cleaned] = true
		}
	}

	for _, p := range extraPaths {
		inspectPath(p)
	}
	for _, line := range strings.Split(unifiedDiff, "\n") {
		tl := strings.TrimSpace(line)
		if strings.HasPrefix(tl, "new file mode 120000") ||
			strings.HasPrefix(tl, "old mode 120000") ||
			strings.HasPrefix(tl, "new mode 120000") ||
			(strings.HasPrefix(tl, "index ") && strings.HasSuffix(tl, " 120000")) {
			lbl := currentFile
			if lbl == "" {
				lbl = "git-symlink"
			}
			violations["SYMLINK_MODE_120000:"+lbl] = true
			continue
		}
		if strings.HasPrefix(line, "diff --git ") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				inspectPath(strings.TrimPrefix(parts[2], "a/"))
				inspectPath(strings.TrimPrefix(parts[3], "b/"))
			}
			continue
		}
		if strings.HasPrefix(line, "--- ") {
			src := strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, "--- ")), "a/")
			inspectPath(src)
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			dst := strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, "+++ ")), "b/")
			inspectPath(dst)
			continue
		}
	}

	out := make([]string, 0, len(violations))
	for v := range violations {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func isProtectedPathAnyDepth(clean string) bool {
	for _, seg := range strings.Split(clean, "/") {
		sLow := strings.ToLower(strings.TrimSpace(seg))
		switch sLow {
		case "..", ".github", ".cursor", ".gemini", ".windsurf", ".copilot", ".vscode", ".git":
			return true
		}
		if strings.HasPrefix(sLow, ".gitlab-ci") || strings.HasPrefix(sLow, ".cursor") {
			return true
		}
	}
	base := strings.ToLower(path.Base(clean))
	if strings.HasPrefix(base, "dockerfile") || strings.HasSuffix(base, ".dockerfile") {
		return true
	}
	switch base {
	case "makefile", "gnumakefile", "agents.md", "claude.md":
		return true
	}
	return strings.HasPrefix(base, ".gitlab-ci") || strings.HasPrefix(base, ".cursor")
}
