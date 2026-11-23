package agentcp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
)

// ExtractEstateFindingsGoverned pipes raw untrusted Qualys VMDR, Tenable.io/sc, or Rapid7 InsightVM payloads
// through zero-egress warrant-extractor (/extract/qualys, /extract/tenable, /extract/rapid7) with wire-level PoP.
func (cp *ControlPlane) ExtractEstateFindingsGoverned(
	ctx context.Context,
	vendor string,
	rawPayload []byte,
	targetService string,
	vulnDigest string,
	patchedDigest string,
	maxFindings int,
	aliasToService map[string]string,
	aliasToAssetKey map[string]string,
) (*models.ExtractedFindingSet, error) {
	routeSlug := ""
	switch strings.ToLower(strings.TrimSpace(vendor)) {
	case "qualys", "qualys_vmdr", "qualys-vmdr":
		routeSlug = "qualys"
	case "tenable", "tenable_io", "tenable_sc", "tenable_io_sc", "tenable-io-sc":
		routeSlug = "tenable"
	case "rapid7", "insightvm", "rapid7_insightvm", "rapid7-insightvm":
		routeSlug = "rapid7"
	default:
		return nil, fmt.Errorf("UNSUPPORTED_FINDER_VENDOR: %q", vendor)
	}

	wk := cp.resolveInternalWorker("warrant-extractor", "EXTRACT_ESTATE_FINDINGS")
	targetAsset := routeSlug + "-intake-stream"
	env, _, err := cp.MintTaskWarrant(models.AuthorityModeAutonomousSponsored, "", wk.identity.AgentID, targetAsset, "EXTRACT_ESTATE_FINDINGS", "NONE", "NONE", 60)
	if err != nil {
		return nil, err
	}
	tok, err := cp.VerifyAndConsumeTaskWarrant(ctx, env, targetAsset, "EXTRACT_ESTATE_FINDINGS")
	if err != nil {
		return nil, err
	}

	wireWrap := map[string]any{
		"g1_finder_envelope":        true,
		"raw_payload_b64":           base64.StdEncoding.EncodeToString(rawPayload),
		"default_service_id":        targetService,
		"default_vulnerable_digest": vulnDigest,
		"default_patched_digest":    patchedDigest,
		"max_findings":              maxFindings,
		"alias_to_service":          aliasToService,
		"alias_to_asset_key":         aliasToAssetKey,
	}
	wireBytes, err := json.Marshal(wireWrap)
	if err != nil {
		return nil, err
	}

	endpoint := cp.extractorURL + "/extract/" + routeSlug
	respBody, status, err := cp.doGovernedExtractorPost(ctx, endpoint, wireBytes, env, tok, wk)
	if err != nil {
		return nil, fmt.Errorf("warrant-extractor /extract/%s unreachable: %w", routeSlug, err)
	}
	if status >= 300 {
		return nil, fmt.Errorf("warrant-extractor rejected %s payload (HTTP %d): %s", routeSlug, status, string(respBody))
	}

	var out models.ExtractedFindingSet
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode ExtractedFindingSet from %s: %w", routeSlug, err)
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
		TargetAsset:             targetAsset,
		ActionType:              "EXTRACT_ESTATE_FINDINGS",
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

// MintGovernedDistributorWarrant mints and validates a WARRANT_DELEGATED_COMPOSITE EphemeralTaskWarrant
// for agt-distributor-gateway strictly bound to a live Standing Warrant, target service, and distributor action.
func (cp *ControlPlane) MintGovernedDistributorWarrant(
	ctx context.Context,
	warrantID, remediationID, distributorID, targetService, actionType, s1ID, s2ID string,
) (*crypto.Envelope, *models.EphemeralTaskWarrantPayload, ed25519.PrivateKey, error) {
	if strings.TrimSpace(warrantID) == "" || strings.HasPrefix(warrantID, "AUTONOMOUS") || strings.HasPrefix(warrantID, "BOOTSTRAP") {
		return nil, nil, nil, errors.New("N4_DISTRIBUTOR_REQUIRES_STANDING_WARRANT: DeploymentOrder mutations cannot execute without a live 2-of-2 Standing Warrant")
	}
	wk := cp.resolveInternalWorker("distributor-gateway", actionType)
	env, _, err := cp.MintTaskWarrant(warrantID, remediationID, wk.identity.AgentID, targetService, actionType, s1ID, s2ID, 120)
	if err != nil {
		return nil, nil, nil, err
	}
	tok, err := cp.VerifyAndConsumeTaskWarrant(ctx, env, targetService, actionType)
	if err != nil {
		return nil, nil, nil, err
	}
	return env, tok, wk.priv, nil
}

// NewDistributorBoundRoundTripper returns a per-execution HTTP RoundTripper attaching an explicit
// WARRANT_DELEGATED_COMPOSITE EphemeralTaskWarrant + Ed25519 X-Warrant-Agent-PoP header to outbound distributor calls.
func NewDistributorBoundRoundTripper(env *crypto.Envelope, taskTokenID string, holderPriv ed25519.PrivateKey, base http.RoundTripper) http.RoundTripper {
	return &distributorBoundTransport{
		env:         env,
		taskTokenID: taskTokenID,
		holderPriv:  holderPriv,
		base:        base,
	}
}

type distributorBoundTransport struct {
	env         *crypto.Envelope
	taskTokenID string
	holderPriv  ed25519.PrivateKey
	base        http.RoundTripper
}

func (t *distributorBoundTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if t.env != nil {
		var bodyBytes []byte
		if req.Body != nil {
			b, err := readAllAndRewind(req)
			if err != nil {
				return nil, err
			}
			bodyBytes = b
		}
		_ = AttachWireTaskAndPoPHeaders(req, bodyBytes, t.env, t.taskTokenID, t.holderPriv)
	}
	return base.RoundTrip(req)
}

func readAllAndRewind(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, err := req.Body.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	_ = req.Body.Close()
	out := []byte(buf.String())
	req.Body = http.NoBody
	if len(out) > 0 {
		req.Body = &bytesReadCloser{r: strings.NewReader(string(out))}
	}
	req.ContentLength = int64(len(out))
	return out, nil
}

type bytesReadCloser struct {
	r *strings.Reader
}

func (b *bytesReadCloser) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *bytesReadCloser) Close() error               { return nil }
