package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters/distributors"
	"github.com/cgilbert61/G1-Warrant/internal/adapters/estatereader"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

const govActionConfigureVendorConnector = "CONFIGURE_VENDOR_CONNECTOR"

func dispatchEnvKeysForSystem(sourceSystem, readEnvPrefix string) (dispPrefix, urlKey, tokKey string, supportsWN8 bool) {
	switch sourceSystem {
	case "qualys_vmdr", "tenable", "rapid7_insightvm", "osquery-fleet":
		return "", "", "", false
	case "k8s-cilium-native":
		return "WARRANT_KUBE_API", "WARRANT_KUBE_API_URL", "WARRANT_KUBE_API_TOKEN", true
	default:
		return readEnvPrefix, readEnvPrefix + "_URL", readEnvPrefix + "_TOKEN", true
	}
}

func (o *ControlPlaneOrchestrator) effectiveConnectorValLocked(overrides map[string]string, key string) string {
	if key == "" {
		return ""
	}
	if overrides != nil {
		if v, exists := overrides[key]; exists {
			return v
		}
	}
	return os.Getenv(key)
}

func (o *ControlPlaneOrchestrator) reloadConnectorsLocked() error {
	lookup := func(k string) string {
		return o.effectiveConnectorValLocked(o.connectorOverrides, k)
	}
	if o.Distributors != nil && o.N4AgentCP != nil {
		distributors.RegisterAllBuiltinDistributors(
			o.Distributors,
			o.Deploy,
			o.N4AgentCP.NewGovernedRoundTripper("distributor-gateway", nil),
			lookup,
		)
	}
	if o.EstateReaders != nil && o.N4AgentCP != nil {
		if err := estatereader.RegisterAllBuiltinEstateReaders(
			o.EstateReaders,
			o.localK8sReader,
			o.N4AgentCP.NewGovernedRoundTripper("estate-reader", nil),
			lookup,
		); err != nil {
			return err
		}
	}
	if o.connectorPersistPath != "" {
		if dir := filepath.Dir(o.connectorPersistPath); dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0700)
		}
		if raw, err := json.MarshalIndent(o.connectorOverrides, "", "  "); err == nil {
			_ = os.WriteFile(o.connectorPersistPath, raw, 0600)
		}
	}
	return nil
}

// VerifyConnectorMutationAuth authenticates runtime vendor connector updates:
//   - Unconditionally rejects read-only credentials, intake tokens, automation tokens, auditor tokens, and sensor tokens.
//   - Requires 2-of-2 DSSE Principal Governance (CONFIGURE_VENDOR_CONNECTOR) in live or Kubernetes posture.
//   - Accepts DSSE governance, X-Warrant-Operator-Token (if configured), or interactive local Console session in sandbox/demo mode.
func (o *ControlPlaneOrchestrator) VerifyConnectorMutationAuth(ctx context.Context, r *http.Request, rawBody []byte) (int, error) {
	if code, sepErr := o.RejectEstateReadCredentialOnMutation(r); sepErr != nil {
		return code, sepErr
	}
	if strings.TrimSpace(r.Header.Get("X-Warrant-Intake-Token")) != "" {
		return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: X-Warrant-Intake-Token cannot modify vendor connectors")
	}
	if strings.TrimSpace(r.Header.Get("X-Warrant-Automation-Token")) != "" {
		return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: X-Warrant-Automation-Token cannot modify vendor connectors")
	}

	bearer := ""
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		bearer = strings.TrimSpace(auth[7:])
	}
	opHdr := strings.TrimSpace(r.Header.Get("X-Warrant-Operator-Token"))
	for _, cand := range []string{bearer, opHdr} {
		if cand == "" {
			continue
		}
		if strings.HasPrefix(cand, "g1aud_") || strings.HasPrefix(cand, "g1tet_") {
			return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: auditor and sensor tokens cannot modify vendor connectors")
		}
		if o.intakeToken != "" && subtle.ConstantTimeCompare([]byte(cand), []byte(o.intakeToken)) == 1 {
			return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: WARRANT_INTAKE_TOKEN cannot modify vendor connectors")
		}
		if o.automationToken != "" && subtle.ConstantTimeCompare([]byte(cand), []byte(o.automationToken)) == 1 {
			return http.StatusForbidden, fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: WARRANT_AUTOMATION_TOKEN cannot modify vendor connectors")
		}
	}

	if hdrB64 := strings.TrimSpace(r.Header.Get("X-Warrant-Governance-DSSE")); hdrB64 != "" {
		envRaw, err := crypto.DecodeBase64Any(hdrB64)
		if err != nil {
			return http.StatusUnauthorized, fmt.Errorf("INVALID_GOVERNANCE_DSSE_HEADER: %w", err)
		}
		var env crypto.Envelope
		if err := json.Unmarshal(envRaw, &env); err != nil {
			return http.StatusUnauthorized, fmt.Errorf("INVALID_GOVERNANCE_DSSE_JSON: %w", err)
		}
		if _, _, dErr := o.N1Warrant.VerifyDualGovernanceEnvelope(ctx, env, govActionConfigureVendorConnector); dErr == nil {
			return http.StatusOK, nil
		} else if o.IsProductionOrLivePosture(ctx) {
			return http.StatusUnauthorized, dErr
		}
		bodyHash := crypto.SHA256Hex(rawBody)
		if _, _, sErr := o.N1Warrant.VerifyRequestScopedSingleGovernanceEnvelope(ctx, env, govActionConfigureVendorConnector, r.Method, r.URL.Path, bodyHash, false); sErr != nil {
			return http.StatusUnauthorized, sErr
		}
		return http.StatusOK, nil
	}

	if o.IsProductionOrLivePosture(ctx) {
		return http.StatusUnauthorized, fmt.Errorf("DUAL_KEY_GOVERNANCE_REQUIRED: configuring vendor connectors in live/Kubernetes posture requires a 2-of-2 X-Warrant-Governance-DSSE envelope (%s)", govActionConfigureVendorConnector)
	}

	tok := opHdr
	if tok == "" {
		tok = bearer
	}
	if o.operatorToken != "" {
		if tok == "" {
			return http.StatusUnauthorized, fmt.Errorf("MISSING_OPERATOR_TOKEN: provide X-Warrant-Operator-Token or X-Warrant-Governance-DSSE")
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(o.operatorToken)) != 1 {
			return http.StatusForbidden, fmt.Errorf("INVALID_OPERATOR_CREDENTIAL")
		}
	}
	return http.StatusOK, nil
}

// ListVendorConnectorStatuses returns masked Read & Dispatch configuration state for all registered connected systems.
func (o *ControlPlaneOrchestrator) ListVendorConnectorStatuses(ctx context.Context) []models.VendorConnectorConfigStatus {
	if o.EstateReaders == nil {
		return []models.VendorConnectorConfigStatus{}
	}
	simAllowed, _ := o.IsSimulationAllowed(ctx)
	demoAvail := simAllowed && o.fleetURL != ""

	descs := o.EstateReaders.ListDescriptors()
	o.connectorMu.RLock()
	defer o.connectorMu.RUnlock()

	out := make([]models.VendorConnectorConfigStatus, 0, len(descs))
	for _, d := range descs {
		readURL := strings.TrimSpace(o.effectiveConnectorValLocked(o.connectorOverrides, d.ReadEnvPrefix+"_READ_URL"))
		readTok := strings.TrimSpace(o.effectiveConnectorValLocked(o.connectorOverrides, d.ReadEnvPrefix+"_READ_TOKEN"))
		dispPrefix, dispURLKey, dispTokKey, supportsWN8 := dispatchEnvKeysForSystem(d.SourceSystem, d.ReadEnvPrefix)
		dispURL := ""
		dispTok := ""
		if supportsWN8 {
			dispURL = strings.TrimSpace(o.effectiveConnectorValLocked(o.connectorOverrides, dispURLKey))
			dispTok = strings.TrimSpace(o.effectiveConnectorValLocked(o.connectorOverrides, dispTokKey))
		}

		mode := "UNCONFIGURED"
		switch {
		case readURL != "" && strings.Contains(readURL, "/mock-estate/"):
			mode = "DEMO_MOCK"
		case readURL != "":
			mode = "LIVE_CUSTOM"
		case d.SourceSystem == "k8s-cilium-native" && d.ReadConfigured:
			mode = "LOCAL_CLUSTER"
		}

		dispConfigured := false
		if supportsWN8 {
			dispConfigured = dispURL != "" || (d.SourceSystem == "k8s-cilium-native" && d.ReadConfigured)
		}

		out = append(out, models.VendorConnectorConfigStatus{
			SourceSystem:           d.SourceSystem,
			DisplayName:            d.DisplayName,
			SourceTier:             d.SourceTier,
			HandlerFamily:          d.HandlerFamily,
			CanProposeCloneSources: d.CanProposeCloneSources,
			SupportsWN8Dispatch:    supportsWN8,
			ConnectionMode:         mode,
			ReadEnvPrefix:          d.ReadEnvPrefix,
			ReadURL:                readURL,
			ReadTokenConfigured:    readTok != "",
			ReadTokenMasked:        estatereader.MaskConnectorSecret(readTok),
			ReadConfigured:         d.ReadConfigured,
			DispatchEnvPrefix:      dispPrefix,
			DispatchURL:            dispURL,
			DispatchTokenSet:       dispTok != "",
			DispatchTokenMasked:    estatereader.MaskConnectorSecret(dispTok),
			DispatchConfigured:     dispConfigured,
			DemoMockAvailable:      demoAvail,
		})
	}
	return out
}

func (o *ControlPlaneOrchestrator) validateProspectiveConnectorTokensLocked(descs []models.EstateSourceDescriptor, candidate map[string]string) error {
	readTokens := map[string]string{}
	dispTokens := map[string]string{}

	for _, d := range descs {
		rt := strings.TrimSpace(o.effectiveConnectorValLocked(candidate, d.ReadEnvPrefix+"_READ_TOKEN"))
		if rt != "" {
			if o.intakeToken != "" && subtle.ConstantTimeCompare([]byte(rt), []byte(o.intakeToken)) == 1 {
				return fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION (%s): read_token cannot match WARRANT_INTAKE_TOKEN", d.SourceSystem)
			}
			if o.automationToken != "" && subtle.ConstantTimeCompare([]byte(rt), []byte(o.automationToken)) == 1 {
				return fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION (%s): read_token cannot match WARRANT_AUTOMATION_TOKEN", d.SourceSystem)
			}
			readTokens[d.SourceSystem] = rt
		}
		_, _, dispTokKey, supportsWN8 := dispatchEnvKeysForSystem(d.SourceSystem, d.ReadEnvPrefix)
		if supportsWN8 {
			dt := strings.TrimSpace(o.effectiveConnectorValLocked(candidate, dispTokKey))
			if dt != "" {
				if o.estateReadToken != "" && subtle.ConstantTimeCompare([]byte(dt), []byte(o.estateReadToken)) == 1 {
					return fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION (%s): dispatch_token cannot match WARRANT_ESTATE_READ_TOKEN", d.SourceSystem)
				}
				dispTokens[d.SourceSystem] = dt
			}
		}
	}

	for rSys, rTok := range readTokens {
		for dSys, dTok := range dispTokens {
			if subtle.ConstantTimeCompare([]byte(rTok), []byte(dTok)) == 1 {
				return fmt.Errorf("CREDENTIAL_SEPARATION_VIOLATION: %s read_token must be strictly distinct from %s WN-8 dispatch_token", rSys, dSys)
			}
		}
	}
	return nil
}

// UpdateVendorConnector updates read and/or dispatch URLs & tokens for a single system at runtime, enforcing Rule 2 separation.
func (o *ControlPlaneOrchestrator) UpdateVendorConnector(
	ctx context.Context,
	systemID string,
	req models.VendorConnectorUpdateRequest,
) (*models.VendorConnectorConfigStatus, error) {
	if o.EstateReaders == nil {
		return nil, fmt.Errorf("ESTATE_READER_REGISTRY_UNINITIALIZED")
	}
	er, err := o.EstateReaders.Get(systemID)
	if err != nil {
		return nil, err
	}
	canonSys := er.SourceSystem()
	readPrefix := er.ReadEnvPrefix()
	_, dispURLKey, dispTokKey, supportsWN8 := dispatchEnvKeysForSystem(canonSys, readPrefix)

	descs := o.EstateReaders.ListDescriptors()

	o.connectorMu.Lock()
	candidate := make(map[string]string, len(o.connectorOverrides)+4)
	for k, v := range o.connectorOverrides {
		candidate[k] = v
	}

	candidate[readPrefix+"_READ_URL"] = strings.TrimSpace(req.ReadURL)
	if req.ClearReadToken {
		candidate[readPrefix+"_READ_TOKEN"] = ""
	} else if strings.TrimSpace(req.ReadToken) != "" {
		candidate[readPrefix+"_READ_TOKEN"] = strings.TrimSpace(req.ReadToken)
	}

	if supportsWN8 {
		candidate[dispURLKey] = strings.TrimSpace(req.DispatchURL)
		if req.ClearDispatchToken {
			candidate[dispTokKey] = ""
		} else if strings.TrimSpace(req.DispatchToken) != "" {
			candidate[dispTokKey] = strings.TrimSpace(req.DispatchToken)
		}
	}

	if vErr := o.validateProspectiveConnectorTokensLocked(descs, candidate); vErr != nil {
		o.connectorMu.Unlock()
		return nil, vErr
	}

	o.connectorOverrides = candidate
	if rErr := o.reloadConnectorsLocked(); rErr != nil {
		o.connectorMu.Unlock()
		return nil, rErr
	}
	o.connectorMu.Unlock()

	for _, st := range o.ListVendorConnectorStatuses(ctx) {
		if st.SourceSystem == canonSys {
			cp := st
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("connector %s not found after update", canonSys)
}

// ConnectDemoEstateMock wires one or all ("*" / "all") registered systems to fleet-sim's wire-accurate Demo Estate mock endpoints.
func (o *ControlPlaneOrchestrator) ConnectDemoEstateMock(ctx context.Context, systemID string) ([]models.VendorConnectorConfigStatus, error) {
	if o.EstateReaders == nil {
		return nil, fmt.Errorf("ESTATE_READER_REGISTRY_UNINITIALIZED")
	}
	if o.fleetURL == "" {
		return nil, fmt.Errorf("DEMO_MOCK_UNAVAILABLE: FLEET_SIM_URL is not configured on warrantd")
	}
	target := strings.ToLower(strings.TrimSpace(systemID))
	connectAll := target == "" || target == "*" || target == "all"

	var matched bool
	descs := o.EstateReaders.ListDescriptors()
	var targetCanon string
	if !connectAll {
		er, err := o.EstateReaders.Get(target)
		if err != nil {
			return nil, err
		}
		targetCanon = er.SourceSystem()
	}

	o.connectorMu.Lock()
	candidate := make(map[string]string, len(o.connectorOverrides)+len(descs)*4)
	for k, v := range o.connectorOverrides {
		candidate[k] = v
	}

	for _, d := range descs {
		if !connectAll && d.SourceSystem != targetCanon {
			continue
		}
		matched = true
		candidate[d.ReadEnvPrefix+"_READ_URL"] = fmt.Sprintf("%s/mock-estate/%s", o.fleetURL, d.SourceSystem)
		candidate[d.ReadEnvPrefix+"_READ_TOKEN"] = fmt.Sprintf("demo-read-%s-token-v1", d.SourceSystem)
		_, dispURLKey, dispTokKey, supportsWN8 := dispatchEnvKeysForSystem(d.SourceSystem, d.ReadEnvPrefix)
		if supportsWN8 {
			candidate[dispURLKey] = fmt.Sprintf("%s/mock-distributor/%s", o.fleetURL, d.SourceSystem)
			candidate[dispTokKey] = fmt.Sprintf("demo-disp-%s-token-v1", d.SourceSystem)
		}
	}
	if !matched {
		o.connectorMu.Unlock()
		return nil, fmt.Errorf("UNKNOWN_ESTATE_SOURCE_SYSTEM: %q", systemID)
	}
	if vErr := o.validateProspectiveConnectorTokensLocked(descs, candidate); vErr != nil {
		o.connectorMu.Unlock()
		return nil, vErr
	}
	o.connectorOverrides = candidate
	if rErr := o.reloadConnectorsLocked(); rErr != nil {
		o.connectorMu.Unlock()
		return nil, rErr
	}
	o.connectorMu.Unlock()

	return o.ListVendorConnectorStatuses(ctx), nil
}

// TestVendorConnectorRead executes an ephemeral, zero-persistence read check against a connected system and returns selectable servers.
func (o *ControlPlaneOrchestrator) TestVendorConnectorRead(
	ctx context.Context,
	systemID, warrantClass string,
	scopeServices []string,
) (*models.VendorConnectorTestResult, error) {
	if o.EstateReaders == nil {
		return nil, fmt.Errorf("ESTATE_READER_REGISTRY_UNINITIALIZED")
	}
	er, err := o.EstateReaders.Get(systemID)
	if err != nil {
		return nil, err
	}
	if len(scopeServices) == 0 {
		scopeServices = []string{"payments-ledger-api", "identity-sso-gateway"}
	}
	if strings.TrimSpace(warrantClass) == "" {
		warrantClass = "KEV-TIER1-STATELESS"
	}
	snap, err := er.ReadEstateSnapshot(ctx, estatereader.EstateReadQuery{
		WarrantClass:  warrantClass,
		ScopeServices: scopeServices,
	})
	if err != nil {
		return nil, err
	}
	mode := "LIVE_CUSTOM"
	for _, st := range o.ListVendorConnectorStatuses(ctx) {
		if st.SourceSystem == er.SourceSystem() {
			mode = st.ConnectionMode
			break
		}
	}
	return &models.VendorConnectorTestResult{
		SourceSystem:         er.SourceSystem(),
		Reachable:            true,
		ConnectionMode:       mode,
		ClassMembershipCount: snap.ClassMembershipCount,
		CandidateSourceCount: len(snap.CandidateCloneSources),
		SelectableServers:    snap.EphemeralServers,
		FreshnessAgeSeconds:  snap.SourceFreshnessAgeSeconds,
		SnapshotSHA256:       snap.SnapshotSHA256,
		TestedAt:             time.Now().UTC(),
	}, nil
}
