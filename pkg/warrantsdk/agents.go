package warrantsdk

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/agentcp"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/google/uuid"
)

// AgentKeyBundle holds an Ed25519 workload/agent or builder keypair in portable JSON format.
type AgentKeyBundle struct {
	AgentID        string `json:"agent_id"`
	DisplayName    string `json:"display_name"`
	KeyID          string `json:"key_id"`
	Alg            string `json:"alg"`
	PublicKeyB64   string `json:"public_key_b64"`
	PrivateKeyB64  string `json:"private_key_b64"`
	KeyFingerprint string `json:"key_fingerprint"`
	CreatedAt      string `json:"created_at"`
}

// GenerateAgentKeyBundle generates a new Ed25519 workload/agent or builder keypair.
func GenerateAgentKeyBundle(agentOrBuilderID, displayName string) (*AgentKeyBundle, error) {
	id := strings.TrimSpace(agentOrBuilderID)
	if id == "" {
		return nil, errors.New("agent_id or builder_id is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	fp := crypto.SHA256Hex(pub)
	return &AgentKeyBundle{
		AgentID:        id,
		DisplayName:    nonEmptySDK(displayName, id),
		KeyID:          fmt.Sprintf("ed25519-%s-%s", id, fp[:10]),
		Alg:            crypto.AlgEd25519,
		PublicKeyB64:   base64.StdEncoding.EncodeToString(pub),
		PrivateKeyB64:  base64.StdEncoding.EncodeToString(priv),
		KeyFingerprint: fp,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// PrivateKey decodes the 64-byte Ed25519 private key from the AgentKeyBundle.
func (b *AgentKeyBundle) PrivateKey() (ed25519.PrivateKey, error) {
	if b == nil {
		return nil, errors.New("nil AgentKeyBundle")
	}
	raw, err := crypto.DecodeBase64Any(b.PrivateKeyB64)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private_key_b64")
	}
	return ed25519.PrivateKey(raw), nil
}

// SignEnvelope signs a DSSE envelope in slot 1 using the agent's Ed25519 private key.
func (b *AgentKeyBundle) SignEnvelope(env *Envelope) error {
	priv, err := b.PrivateKey()
	if err != nil {
		return err
	}
	pub, err := crypto.DecodeBase64Any(b.PublicKeyB64)
	if err != nil {
		return err
	}
	pk := PrincipalKey{
		PrincipalID:    b.AgentID,
		DisplayName:    b.DisplayName,
		KeyID:          b.KeyID,
		Alg:            crypto.AlgEd25519,
		PublicKeyBytes: pub,
		KeyFingerprint: b.KeyFingerprint,
	}
	return env.SignEd25519(1, pk, priv)
}

// SignBuilderProvenance signs canonical builder provenance over (agent_id, artifact_digest, agent_public_key_b64)
// using an Ed25519 SignerKeyBundle or AgentKeyBundle private key.
func SignBuilderProvenance(agentID, artifactDigest, agentPublicKeyB64, builderPrivateKeyB64 string) (string, error) {
	privBytes, err := crypto.DecodeBase64Any(strings.TrimSpace(builderPrivateKeyB64))
	if err != nil {
		return "", err
	}
	if len(privBytes) == ed25519.SeedSize {
		privBytes = ed25519.NewKeyFromSeed(privBytes)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return "", errors.New("expected 32-byte seed or 64-byte Ed25519 private key")
	}
	return crypto.SignAgentBuilderProvenance(agentID, artifactDigest, agentPublicKeyB64, ed25519.PrivateKey(privBytes))
}

// DraftCommissioningFunctionEnvelope creates an unsigned 2-of-2 DSSE envelope for UPSERT_COMMISSIONING_FUNCTION or TRANSFER_COMMISSIONING_SPONSOR.
func DraftCommissioningFunctionEnvelope(cf CommissioningFunction, isTransfer bool, reasonCode string) (*Envelope, error) {
	action := GovActionUpsertCommissioningFunction
	if isTransfer {
		action = GovActionTransferCommissioningSponsor
	}
	grace := cf.OrphanGraceHours
	now := time.Now().UTC()
	payload := PrincipalGovernancePayload{
		EnvelopeID:             "gov-" + uuid.NewString(),
		Action:                 action,
		IssuedAt:               now.Format(time.RFC3339),
		ExpiresAt:              now.Add(5 * time.Minute).Format(time.RFC3339),
		FunctionID:             cf.FunctionID,
		DisplayName:            cf.DisplayName,
		OwningOrgUnit:          cf.OwningOrgUnit,
		CostCenter:             cf.CostCenter,
		PrimarySOPrincipalID:   cf.PrimarySOPrincipalID,
		SecondarySOPrincipalID: cf.SecondarySOPrincipalID,
		PrimaryAOPrincipalID:   cf.PrimaryAOPrincipalID,
		SecondaryAOPrincipalID: cf.SecondaryAOPrincipalID,
		EscalationContact:      cf.EscalationContact,
		OrphanGraceHours:       &grace,
		ReasonCode:             reasonCode,
	}
	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypePrincipalGovernance, payload)
	return env, err
}

// AgentEnrollDraftOptions specifies parameters for drafting a 2-of-2 ENROLL_AGENT_IDENTITY DSSE envelope.
type AgentEnrollDraftOptions struct {
	AgentID                 string
	DisplayName             string
	AgentKind               string
	CommissioningFunctionID string
	KeyID                   string
	PublicKeyB64            string
	SPIFFEID                string
	ArtifactDigest          string
	BuilderPrincipalID      string
	BuilderPublicKeyB64     string
	BuilderKeyFingerprint   string
	BuilderProvenanceSigB64 string
	AllowedActions          []string
	AllowedServices         []string
	AllowedEgressProfile    string
	MaxTTLSeconds           int
	MaxDelegationDepth      int
	AllowAutonomousIntake   bool
	RecertifyDays           int
	RecertifyExpiresAt      string
}

// DraftAgentEnrollEnvelope creates an unsigned 2-of-2 ENROLL_AGENT_IDENTITY DSSE envelope.
func DraftAgentEnrollEnvelope(opts AgentEnrollDraftOptions) (*Envelope, error) {
	now := time.Now().UTC()
	if opts.AgentKind == "" {
		opts.AgentKind = AgentKindExternalAutonomous
	}
	if opts.AllowedEgressProfile == "" {
		opts.AllowedEgressProfile = EgressProfileZeroIsolated
	}
	if opts.MaxTTLSeconds <= 0 {
		opts.MaxTTLSeconds = 120
	}
	if opts.RecertifyDays <= 0 && opts.RecertifyExpiresAt == "" {
		opts.RecertifyDays = 30
	}
	payload := PrincipalGovernancePayload{
		EnvelopeID:              "gov-" + uuid.NewString(),
		Action:                  GovActionEnrollAgentIdentity,
		IssuedAt:                now.Format(time.RFC3339),
		ExpiresAt:               now.Add(5 * time.Minute).Format(time.RFC3339),
		AgentID:                 opts.AgentID,
		DisplayName:             nonEmptySDK(opts.DisplayName, opts.AgentID),
		AgentKind:               opts.AgentKind,
		CommissioningFunctionID: opts.CommissioningFunctionID,
		KeyID:                   opts.KeyID,
		Alg:                     crypto.AlgEd25519,
		PublicKeyB64:            opts.PublicKeyB64,
		SPIFFEID:                opts.SPIFFEID,
		ArtifactDigest:          opts.ArtifactDigest,
		BuilderPrincipalID:      opts.BuilderPrincipalID,
		BuilderPublicKeyB64:     opts.BuilderPublicKeyB64,
		BuilderKeyFingerprint:   opts.BuilderKeyFingerprint,
		BuilderProvenanceSigB64: opts.BuilderProvenanceSigB64,
		AllowedActions:          opts.AllowedActions,
		AllowedServices:         opts.AllowedServices,
		AllowedEgressProfile:    opts.AllowedEgressProfile,
		MaxTTLSeconds:           opts.MaxTTLSeconds,
		MaxDelegationDepth:      opts.MaxDelegationDepth,
		AllowAutonomousIntake:   opts.AllowAutonomousIntake,
		RecertifyDays:           opts.RecertifyDays,
		RecertifyExpiresAt:      opts.RecertifyExpiresAt,
	}
	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypePrincipalGovernance, payload)
	return env, err
}

// DraftAgentRecertifyEnvelope creates an unsigned 2-of-2 RECERTIFY_AGENT_IDENTITY DSSE envelope.
func DraftAgentRecertifyEnvelope(agentID string, recertifyDays int, reasonCode string) (*Envelope, error) {
	if recertifyDays <= 0 || recertifyDays > 90 {
		recertifyDays = 90
	}
	now := time.Now().UTC()
	payload := PrincipalGovernancePayload{
		EnvelopeID:    "gov-" + uuid.NewString(),
		Action:        GovActionRecertifyAgentIdentity,
		IssuedAt:      now.Format(time.RFC3339),
		ExpiresAt:     now.Add(5 * time.Minute).Format(time.RFC3339),
		AgentID:       agentID,
		RecertifyDays: recertifyDays,
		ReasonCode:    nonEmptySDK(reasonCode, "DUAL_KEY_RECERTIFICATION_RENEWAL"),
	}
	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypePrincipalGovernance, payload)
	return env, err
}

// DraftAgentRevokeEnvelope creates an unsigned 1-of-2 (or self-signed) REVOKE_AGENT_IDENTITY DSSE envelope.
func DraftAgentRevokeEnvelope(agentID, reasonCode string) (*Envelope, error) {
	now := time.Now().UTC()
	payload := PrincipalGovernancePayload{
		EnvelopeID: "gov-" + uuid.NewString(),
		Action:     GovActionRevokeAgentIdentity,
		IssuedAt:   now.Format(time.RFC3339),
		ExpiresAt:  now.Add(5 * time.Minute).Format(time.RFC3339),
		AgentID:    agentID,
		ReasonCode: nonEmptySDK(reasonCode, "SDK_AGENT_KILL_SWITCH"),
	}
	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypePrincipalGovernance, payload)
	return env, err
}

// SignTokenExchangeRequest builds and signs an RFC 8693 AgentTokenExchangePayload DSSE PoP request (<= 60s TTL).
// When parentTaskWarrant and parentHolderBundle are supplied, signs ParentHolderPoPSigB64 for sub-agent attenuation.
func SignTokenExchangeRequest(
	caller *AgentKeyBundle,
	req AgentTokenExchangePayload,
	parentHolder *AgentKeyBundle,
) (*Envelope, error) {
	if caller == nil {
		return nil, errors.New("caller AgentKeyBundle is required")
	}
	now := time.Now().UTC()
	if req.EnvelopeID == "" {
		req.EnvelopeID = "xch-" + uuid.NewString()
	}
	if req.AgentID == "" {
		req.AgentID = caller.AgentID
	}
	if req.RequestedTTLSeconds <= 0 {
		req.RequestedTTLSeconds = 60
	}
	req.IssuedAt = now.Format(time.RFC3339)
	req.ExpiresAt = now.Add(45 * time.Second).Format(time.RFC3339)

	if req.ParentTaskWarrant != nil && parentHolder != nil && req.ParentHolderPoPSigB64 == "" {
		rawP, err := req.ParentTaskWarrant.DecodePayload()
		if err != nil {
			return nil, err
		}
		var pt EphemeralTaskWarrantPayload
		if err := json.Unmarshal(rawP, &pt); err != nil {
			return nil, err
		}
		parentPriv, err := parentHolder.PrivateKey()
		if err != nil {
			return nil, err
		}
		sig := ed25519.Sign(parentPriv, agentcp.ParentDelegationPoPPreimage(pt.TaskTokenID, req.AgentID, req.EnvelopeID))
		req.ParentHolderPoPSigB64 = base64.StdEncoding.EncodeToString(sig)
	}

	env, _, err := crypto.NewUnsignedEnvelope(PayloadTypeAgentTokenExchange, req)
	if err != nil {
		return nil, err
	}
	if err := caller.SignEnvelope(env); err != nil {
		return nil, err
	}
	return env, nil
}

// SignAgentHTTPRequest attaches wire-level X-Warrant-Task-DSSE and X-Warrant-Agent-PoP headers to an outbound HTTP request.
func SignAgentHTTPRequest(req *http.Request, body []byte, taskWarrant *Envelope, holder *AgentKeyBundle) error {
	if req == nil || taskWarrant == nil || holder == nil {
		return errors.New("req, taskWarrant, and holder are required")
	}
	rawP, err := taskWarrant.DecodePayload()
	if err != nil {
		return err
	}
	var p EphemeralTaskWarrantPayload
	if err := json.Unmarshal(rawP, &p); err != nil {
		return err
	}
	priv, err := holder.PrivateKey()
	if err != nil {
		return err
	}
	return agentcp.AttachWireTaskAndPoPHeaders(req, body, taskWarrant, p.TaskTokenID, priv)
}

// ListCommissioningFunctions lists all registered CommissioningFunctions and their live continuity status.
func (c *Client) ListCommissioningFunctions(ctx context.Context) ([]CommissioningFunction, error) {
	var out []CommissioningFunction
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/commissioning-functions", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListPendingSponsorTransfers lists CommissioningFunctions awaiting 2-of-2 sponsor succession in the Action Inbox.
func (c *Client) ListPendingSponsorTransfers(ctx context.Context) ([]PendingSponsorTransfer, error) {
	var out []PendingSponsorTransfer
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/commissioning-functions/pending-transfers", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SubmitCommissioningFunction submits a 2-of-2 signed UPSERT_COMMISSIONING_FUNCTION DSSE envelope.
func (c *Client) SubmitCommissioningFunction(ctx context.Context, env Envelope) (*CommissioningFunction, error) {
	var out CommissioningFunction
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/commissioning-functions", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TransferCommissioningSponsor submits a 2-of-2 TRANSFER_COMMISSIONING_SPONSOR DSSE envelope.
func (c *Client) TransferCommissioningSponsor(ctx context.Context, functionID string, env Envelope) (*CommissioningFunction, error) {
	var out CommissioningFunction
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/commissioning-functions/"+url.PathEscape(functionID)+"/transfer", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAgents lists all enrolled AgentIdentities and their live IGA sponsorship health.
func (c *Client) ListAgents(ctx context.Context) ([]AgentIdentity, error) {
	var out []AgentIdentity
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/agents", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// EnrollAgent submits a 2-of-2 signed ENROLL_AGENT_IDENTITY DSSE envelope.
func (c *Client) EnrollAgent(ctx context.Context, env Envelope) (*AgentIdentity, error) {
	var out AgentIdentity
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/enroll", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RecertifyAgent submits a 2-of-2 signed RECERTIFY_AGENT_IDENTITY DSSE envelope.
func (c *Client) RecertifyAgent(ctx context.Context, env Envelope) (*AgentIdentity, error) {
	var out AgentIdentity
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/recertify", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeAgent submits a 1-of-2 human principal or agent self-revocation REVOKE_AGENT_IDENTITY DSSE envelope.
func (c *Client) RevokeAgent(ctx context.Context, env Envelope) (*AgentIdentity, error) {
	var out AgentIdentity
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/revoke", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ExchangeAgentToken submits an RFC 8693 DSSE PoP request to POST /api/v1/agents/token-exchange.
func (c *Client) ExchangeAgentToken(ctx context.Context, env Envelope) (*AgentTokenExchangeResponse, error) {
	var out AgentTokenExchangeResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/token-exchange", env, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListIGAEvents lists all recorded WORM agent_lifecycle_events.
func (c *Client) ListIGAEvents(ctx context.Context) ([]AgentLifecycleEvent, error) {
	var out []AgentLifecycleEvent
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/iga/events", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// EmitIGAEvent submits an HR/IAM lifecycle event to POST /api/v1/iga/events using either 1-of-2 DSSE (when c.signerBundle is set),
// HMAC-SHA256 webhook signature (hmacSecret), or dedicated IGA token (igaToken).
func (c *Client) EmitIGAEvent(ctx context.Context, req IGAEventRequest, igaToken, hmacSecret string) (map[string]any, error) {
	var out map[string]any
	if c.signerBundle != nil && igaToken == "" && hmacSecret == "" {
		err := c.doActionJSON(ctx, http.MethodPost, "/api/v1/iga/events", GovActionEmitIGAEvent, PrincipalGovernancePayload{
			TargetPrincipalID: req.PrincipalID,
			IGAEventType:      req.EventType,
			ReasonCode:        req.ReasonCode,
		}, req, &out)
		return out, err
	}
	rawBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/iga/events", strings.NewReader(string(rawBody)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if hmacSecret != "" {
		mac := hmac.New(sha256.New, []byte(hmacSecret))
		_, _ = mac.Write(rawBody)
		httpReq.Header.Set("X-Warrant-IGA-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	if igaToken != "" {
		httpReq.Header.Set("X-Warrant-IGA-Token", igaToken)
	}
	if c.operatorToken != "" && igaToken == "" && hmacSecret == "" {
		httpReq.Header.Set("X-Warrant-Operator-Token", c.operatorToken)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var errDoc map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&errDoc)
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Method:     http.MethodPost,
			Endpoint:   "/api/v1/iga/events",
			Message:    errDoc["error"],
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func nonEmptySDK(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(b)
}
