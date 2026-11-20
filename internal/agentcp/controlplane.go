package agentcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/db"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
	"github.com/google/uuid"
)

// ControlPlane implements N4: Governed Agent Control Plane, Ephemeral Task Warrants (TTL <= 300s),
// isolated warrant-extractor socket invocations, and hash-chained agent_action_ledger logging.
type ControlPlane struct {
	store        *db.Store
	signer       crypto.EnvelopeSigner
	extractorURL string
	httpClient   *http.Client
	onBroadcast  func(eventType string, payload any)
}

// NewControlPlane initializes the N4 Agent Control Plane backed by an EnvelopeSigner (KMS/HSM or ephemeral).
func NewControlPlane(store *db.Store, signer crypto.EnvelopeSigner, extractorURL string, onBroadcast func(string, any)) *ControlPlane {
	return &ControlPlane{
		store:        store,
		signer:       signer,
		extractorURL: strings.TrimRight(extractorURL, "/"),
		httpClient: &http.Client{
			Timeout: 12 * time.Second,
		},
		onBroadcast: onBroadcast,
	}
}

// MintTaskWarrant mints a short-lived (TTL <= 300s) Ed25519 DSSE-signed Ephemeral Task Warrant.
func (cp *ControlPlane) MintTaskWarrant(warrantID, remediationID, workerName, targetAsset, allowedAction, slot1ID, slot2ID string, ttlSec int) (*crypto.Envelope, *models.EphemeralTaskWarrantPayload, error) {
	if ttlSec <= 0 || ttlSec > 300 {
		return nil, nil, fmt.Errorf("N4_TTL_CEILING_EXCEEDED: ttl_seconds=%d must be in (0, 300]", ttlSec)
	}
	if warrantID == "" || targetAsset == "" || allowedAction == "" {
		return nil, nil, errors.New("N4_UNATTRIBUTED_TASK: warrant_id, target_asset, and allowed_action are mandatory")
	}
	now := time.Now().UTC()
	payload := models.EphemeralTaskWarrantPayload{
		TaskTokenID:           "tsk-" + uuid.NewString()[:8],
		WarrantID:             warrantID,
		RemediationID:         remediationID,
		WorkerName:            workerName,
		TargetAsset:           targetAsset,
		AllowedAction:         allowedAction,
		ForbiddenPathPrefixes: models.DefaultForbiddenDiffPrefixes,
		Slot1PrincipalID:      slot1ID,
		Slot2PrincipalID:      slot2ID,
		TTLSeconds:            ttlSec,
		IssuedUnix:            now.Unix(),
		ExpiresUnix:           now.Add(time.Duration(ttlSec) * time.Second).Unix(),
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

// VerifyAndConsumeTaskWarrant validates an Ephemeral Task Warrant against asset, action, and TTL.
// Any unattributed, forged, wrong-asset, or expired call is logged as SECURITY_VIOLATION in agent_action_ledger.
func (cp *ControlPlane) VerifyAndConsumeTaskWarrant(ctx context.Context, env *crypto.Envelope, requestedAsset, requestedAction string) (*models.EphemeralTaskWarrantPayload, error) {
	recordViolation := func(code, tokenID, warrantID, remID, worker, s1, s2 string, ttl int) error {
		entry := &models.AgentLedgerEntry{
			ActionID:          "act-" + uuid.NewString()[:8],
			TaskTokenID:       nonEmpty(tokenID, "UNATTRIBUTED"),
			WarrantID:         nonEmpty(warrantID, "NONE"),
			RemediationID:     remID,
			WorkerName:        nonEmpty(worker, "UNKNOWN_WORKER"),
			TargetAsset:       nonEmpty(requestedAsset, "UNKNOWN_ASSET"),
			ActionType:        nonEmpty(requestedAction, "UNKNOWN_ACTION"),
			Slot1PrincipalID:  nonEmpty(s1, "NONE"),
			Slot2PrincipalID:  nonEmpty(s2, "NONE"),
			EgressProfile:     "BLOCKED_BY_KERNEL",
			RawInputSHA256:    db.GenesisHash,
			ExtractorDigest:   "NONE",
			TypedOutputSHA256: db.GenesisHash,
			TokenTTLSec:       clampTTL(ttl),
			Status:            "SECURITY_VIOLATION",
			ViolationCode:     code,
			ExecutedAt:        time.Now().UTC(),
		}
		_ = cp.store.AppendAgentAction(ctx, entry)
		if cp.onBroadcast != nil {
			cp.onBroadcast("AGENT_SECURITY_VIOLATION", entry)
		}
		return fmt.Errorf("N4_SECURITY_VIOLATION (%s)", code)
	}

	if env == nil || len(env.Signatures) == 0 {
		return nil, recordViolation("MISSING_TASK_WARRANT", "", "", "", "", "", "", 0)
	}
	rawPayload, err := env.DecodePayload()
	if err != nil {
		return nil, recordViolation("CORRUPT_TASK_PAYLOAD", "", "", "", "", "", "", 0)
	}
	var p models.EphemeralTaskWarrantPayload
	if err := json.Unmarshal(rawPayload, &p); err != nil {
		return nil, recordViolation("INVALID_TASK_JSON", "", "", "", "", "", "", 0)
	}
	kernelPK := cp.signer.PublicKey()
	if err := crypto.VerifySingleSignature(env.PayloadType, rawPayload, env.Signatures[0], &kernelPK, crypto.DefaultWebAuthnConfig()); err != nil {
		return nil, recordViolation("FORGED_TASK_SIGNATURE", p.TaskTokenID, p.WarrantID, p.RemediationID, p.WorkerName, p.Slot1PrincipalID, p.Slot2PrincipalID, p.TTLSeconds)
	}
	nowUnix := time.Now().UTC().Unix()
	if nowUnix >= p.ExpiresUnix {
		return nil, recordViolation("EXPIRED_TASK_WARRANT", p.TaskTokenID, p.WarrantID, p.RemediationID, p.WorkerName, p.Slot1PrincipalID, p.Slot2PrincipalID, p.TTLSeconds)
	}
	if p.TTLSeconds <= 0 || p.TTLSeconds > 300 {
		return nil, recordViolation("TTL_CEILING_VIOLATION", p.TaskTokenID, p.WarrantID, p.RemediationID, p.WorkerName, p.Slot1PrincipalID, p.Slot2PrincipalID, p.TTLSeconds)
	}
	if p.TargetAsset != requestedAsset {
		return nil, recordViolation("ASSET_SCOPE_VIOLATION", p.TaskTokenID, p.WarrantID, p.RemediationID, p.WorkerName, p.Slot1PrincipalID, p.Slot2PrincipalID, p.TTLSeconds)
	}
	if p.AllowedAction != requestedAction {
		return nil, recordViolation("ACTION_SCOPE_VIOLATION", p.TaskTokenID, p.WarrantID, p.RemediationID, p.WorkerName, p.Slot1PrincipalID, p.Slot2PrincipalID, p.TTLSeconds)
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
		ActionID:          "act-" + uuid.NewString()[:8],
		TaskTokenID:       tok.TaskTokenID,
		WarrantID:         tok.WarrantID,
		RemediationID:     remediationID,
		WorkerName:        workerName,
		TargetAsset:       targetAsset,
		ActionType:        actionType,
		Slot1PrincipalID:  s1ID,
		Slot2PrincipalID:  s2ID,
		EgressProfile:     egressProfile,
		RawInputSHA256:    inputSHA,
		ExtractorDigest:   "KERNEL_ADAPTER_DIRECT",
		TypedOutputSHA256: outSHA,
		TokenTTLSec:       tok.TTLSeconds,
		Status:            "EXECUTED",
		ExecutedAt:        time.Now().UTC(),
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

// ExtractSARIFWithOptionsGoverned invokes warrant-extractor /extract/sarif with optional default service/digest/maxFindings parameters.
func (cp *ControlPlane) ExtractSARIFWithOptionsGoverned(ctx context.Context, warrantID, remediationID, targetAsset, s1ID, s2ID string, rawSARIF []byte, targetService, vulnDigest string, maxFindings int) (*models.ExtractedFindingSet, error) {
	env, _, err := cp.MintTaskWarrant(warrantID, remediationID, "warrant-extractor", targetAsset, "EXTRACT_SARIF_2_1_0", s1ID, s2ID, 60)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(rawSARIF))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/sarif unreachable: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected SARIF (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var out models.ExtractedFindingSet
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode ExtractedFindingSet: %w", err)
	}

	entry := &models.AgentLedgerEntry{
		ActionID:          "act-" + uuid.NewString()[:8],
		TaskTokenID:       tok.TaskTokenID,
		WarrantID:         warrantID,
		RemediationID:     remediationID,
		WorkerName:        "warrant-extractor",
		TargetAsset:       targetAsset,
		ActionType:        "EXTRACT_SARIF_2_1_0",
		Slot1PrincipalID:  s1ID,
		Slot2PrincipalID:  s2ID,
		EgressProfile:     "ZERO_EGRESS_ISOLATED",
		RawInputSHA256:    out.RawInputSHA256,
		ExtractorDigest:   out.ExtractorDigest,
		TypedOutputSHA256: out.TypedOutputSHA256,
		TokenTTLSec:       tok.TTLSeconds,
		Status:            "EXECUTED",
		ExecutedAt:        time.Now().UTC(),
	}
	if err := cp.store.AppendAgentAction(ctx, entry); err != nil {
		return nil, err
	}
	if cp.onBroadcast != nil {
		cp.onBroadcast("AGENT_ACTION_LOGGED", entry)
	}
	return &out, nil
}

// ExtractCISAKEVGoverned pipes raw untrusted CISA KEV catalog JSON through warrant-extractor and logs the SHA-256 lineage in agent_action_ledger.
func (cp *ControlPlane) ExtractCISAKEVGoverned(ctx context.Context, rawKEV []byte) (*models.ExtractedKEVCatalog, error) {
	env, _, err := cp.MintTaskWarrant("BOOTSTRAP_FEED_SYNC", "", "warrant-extractor", "cisa-kev-feed", "EXTRACT_CISA_KEV_CATALOG", "sys-feed-poller", "sys-feed-poller", 120)
	if err != nil {
		return nil, err
	}
	tok, err := cp.VerifyAndConsumeTaskWarrant(ctx, env, "cisa-kev-feed", "EXTRACT_CISA_KEV_CATALOG")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cp.extractorURL+"/extract/cisa-kev", bytes.NewReader(rawKEV))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/cisa-kev unreachable: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected CISA KEV (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var out models.ExtractedKEVCatalog
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode ExtractedKEVCatalog: %w", err)
	}

	entry := &models.AgentLedgerEntry{
		ActionID:          "act-" + uuid.NewString()[:8],
		TaskTokenID:       tok.TaskTokenID,
		WarrantID:         "BOOTSTRAP_FEED_SYNC",
		WorkerName:        "warrant-extractor",
		TargetAsset:       "cisa-kev-feed",
		ActionType:        "EXTRACT_CISA_KEV_CATALOG",
		Slot1PrincipalID:  "sys-feed-poller",
		Slot2PrincipalID:  "sys-feed-poller",
		EgressProfile:     "ZERO_EGRESS_ISOLATED",
		RawInputSHA256:    out.RawInputSHA256,
		ExtractorDigest:   out.ExtractorDigest,
		TypedOutputSHA256: out.TypedOutputSHA256,
		TokenTTLSec:       tok.TTLSeconds,
		Status:            "EXECUTED",
		ExecutedAt:        time.Now().UTC(),
	}
	if err := cp.store.AppendAgentAction(ctx, entry); err != nil {
		return nil, err
	}
	if cp.onBroadcast != nil {
		cp.onBroadcast("AGENT_ACTION_LOGGED", entry)
	}
	return &out, nil
}

// ExtractOSVBundleGoverned pipes untrusted Google OSV.dev responses through warrant-extractor and logs the SHA-256 lineage in agent_action_ledger.
func (cp *ControlPlane) ExtractOSVBundleGoverned(ctx context.Context, rawBundle []byte) (*models.ExtractedOSVReport, error) {
	env, _, err := cp.MintTaskWarrant("BOOTSTRAP_FEED_SYNC", "", "warrant-extractor", "google-osv-sbom", "EXTRACT_OSV_BATCH", "sys-feed-poller", "sys-feed-poller", 120)
	if err != nil {
		return nil, err
	}
	tok, err := cp.VerifyAndConsumeTaskWarrant(ctx, env, "google-osv-sbom", "EXTRACT_OSV_BATCH")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cp.extractorURL+"/extract/osv", bytes.NewReader(rawBundle))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/osv unreachable: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected OSV bundle (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var out models.ExtractedOSVReport
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode ExtractedOSVReport: %w", err)
	}

	entry := &models.AgentLedgerEntry{
		ActionID:          "act-" + uuid.NewString()[:8],
		TaskTokenID:       tok.TaskTokenID,
		WarrantID:         "BOOTSTRAP_FEED_SYNC",
		WorkerName:        "warrant-extractor",
		TargetAsset:       "google-osv-sbom",
		ActionType:        "EXTRACT_OSV_BATCH",
		Slot1PrincipalID:  "sys-feed-poller",
		Slot2PrincipalID:  "sys-feed-poller",
		EgressProfile:     "ZERO_EGRESS_ISOLATED",
		RawInputSHA256:    out.RawInputSHA256,
		ExtractorDigest:   out.ExtractorDigest,
		TypedOutputSHA256: out.TypedOutputSHA256,
		TokenTTLSec:       tok.TTLSeconds,
		Status:            "EXECUTED",
		ExecutedAt:        time.Now().UTC(),
	}
	if err := cp.store.AppendAgentAction(ctx, entry); err != nil {
		return nil, err
	}
	if cp.onBroadcast != nil {
		cp.onBroadcast("AGENT_ACTION_LOGGED", entry)
	}
	return &out, nil
}

// ExtractDiffGoverned invokes warrant-extractor /extract/diff over the isolated socket and records the proof in agent_action_ledger.
func (cp *ControlPlane) ExtractDiffGoverned(ctx context.Context, warrantID, remediationID, targetAsset, s1ID, s2ID, patchedDigest, unifiedDiff string) (*models.ExtractedPatchMetadata, error) {
	env, _, err := cp.MintTaskWarrant(warrantID, remediationID, "warrant-extractor", targetAsset, "EXTRACT_PATCH_DIFF", s1ID, s2ID, 60)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cp.extractorURL+"/extract/diff", bytes.NewReader(rawBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/diff unreachable: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected diff (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	var meta models.ExtractedPatchMetadata
	if err := json.Unmarshal(respBytes, &meta); err != nil {
		return nil, fmt.Errorf("decode ExtractedPatchMetadata: %w", err)
	}

	status := "EXECUTED"
	violationCode := ""
	if len(meta.ForbiddenConfigTouches) > 0 {
		status = "SECURITY_VIOLATION"
		violationCode = "FORBIDDEN_BUILD_OR_AGENT_CONFIG_MUTATION:" + strings.Join(meta.ForbiddenConfigTouches, ",")
	}

	entry := &models.AgentLedgerEntry{
		ActionID:          "act-" + uuid.NewString()[:8],
		TaskTokenID:       tok.TaskTokenID,
		WarrantID:         warrantID,
		RemediationID:     remediationID,
		WorkerName:        "warrant-extractor",
		TargetAsset:       targetAsset,
		ActionType:        "EXTRACT_PATCH_DIFF",
		Slot1PrincipalID:  s1ID,
		Slot2PrincipalID:  s2ID,
		EgressProfile:     "ZERO_EGRESS_ISOLATED",
		RawInputSHA256:    meta.RawInputSHA256,
		ExtractorDigest:   meta.ExtractorDigest,
		TypedOutputSHA256: meta.TypedOutputSHA256,
		TokenTTLSec:       tok.TTLSeconds,
		Status:            status,
		ViolationCode:     violationCode,
		ExecutedAt:        time.Now().UTC(),
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
// (hashing and stripping raw credentials) and records the cryptographic lineage in agent_action_ledger.
func (cp *ControlPlane) ExtractSecretFindingsGoverned(ctx context.Context, warrantID, remediationID, targetAsset, s1ID, s2ID string, rawSecrets []byte) (*models.ExtractedSecretFindingSet, error) {
	env, _, err := cp.MintTaskWarrant(warrantID, remediationID, "warrant-extractor", targetAsset, "EXTRACT_SECRET_EXPOSURE", s1ID, s2ID, 60)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(rawSecrets))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/secrets unreachable: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected secret scan (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	var out models.ExtractedSecretFindingSet
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("decode ExtractedSecretFindingSet: %w", err)
	}

	entry := &models.AgentLedgerEntry{
		ActionID:          "act-" + uuid.NewString()[:8],
		TaskTokenID:       tok.TaskTokenID,
		WarrantID:         warrantID,
		RemediationID:     remediationID,
		WorkerName:        "warrant-extractor",
		TargetAsset:       targetAsset,
		ActionType:        "EXTRACT_SECRET_EXPOSURE",
		Slot1PrincipalID:  s1ID,
		Slot2PrincipalID:  s2ID,
		EgressProfile:     "ZERO_EGRESS_ISOLATED",
		RawInputSHA256:    out.RawInputSHA256,
		ExtractorDigest:   out.ExtractorDigest,
		TypedOutputSHA256: out.TypedOutputSHA256,
		TokenTTLSec:       tok.TTLSeconds,
		Status:            "EXECUTED",
		ExecutedAt:        time.Now().UTC(),
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
