package server

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/g1163rt-labs/g1-warrant/internal/adapters"
	"github.com/g1163rt-labs/g1-warrant/internal/agentcp"
	"github.com/g1163rt-labs/g1-warrant/internal/crypto"
	"github.com/g1163rt-labs/g1-warrant/internal/db"
	"github.com/g1163rt-labs/g1-warrant/internal/feeds"
	"github.com/g1163rt-labs/g1-warrant/internal/gate"
	"github.com/g1163rt-labs/g1-warrant/internal/ledger"
	"github.com/g1163rt-labs/g1-warrant/internal/models"
	"github.com/g1163rt-labs/g1-warrant/internal/policy"
	"github.com/g1163rt-labs/g1-warrant/internal/verify"
	"github.com/g1163rt-labs/g1-warrant/internal/warrant"
	"github.com/google/uuid"
)

// ControlPlaneOrchestrator wires N1-N5, Live Threat Feeds, and the Kubernetes/Cilium/SARIF Adapter Pack.
type ControlPlaneOrchestrator struct {
	Store       *db.Store
	Policy      *policy.Engine
	N1Warrant   *warrant.Engine
	N2Gate      *gate.Engine
	N3Verify    *verify.Engine
	N4AgentCP   *agentcp.ControlPlane
	N5Ledger    *ledger.Engine
	Feeds       *feeds.Manager
	SARIFIntake adapters.ScannerIntake
	FixProvider adapters.FixProvider
	Shield      adapters.ShieldEnforcer
	Deploy      adapters.DeploymentTarget
	Twin        adapters.TwinRunner
	Broker      *SSEBroker
	WebAuthnCfg crypto.WebAuthnConfig
}

// NewOrchestrator initializes all five control-plane engines (N1-N5), Live Feed Manager, and production adapters.
func NewOrchestrator(ctx context.Context, store *db.Store, extractorURL, fleetURL, kernelSeed string, webauthnCfg crypto.WebAuthnConfig) (*ControlPlaneOrchestrator, error) {
	pol, err := policy.NewEngine(ctx)
	if err != nil {
		return nil, err
	}
	broker := NewSSEBroker()

	var signer crypto.EnvelopeSigner
	if kmsURL := strings.TrimSpace(os.Getenv("WARRANT_KMS_SIGN_URL")); kmsURL != "" {
		kmsSigner, kErr := crypto.NewRemoteKMSSigner(
			kmsURL,
			os.Getenv("WARRANT_KMS_BEARER_TOKEN"),
			os.Getenv("WARRANT_KMS_KEY_ID"),
			os.Getenv("WARRANT_KMS_PUBLIC_KEY_B64"),
		)
		if kErr != nil {
			return nil, fmt.Errorf("configure RemoteKMSSigner: %w", kErr)
		}
		signer = kmsSigner
	} else if strings.TrimSpace(kernelSeed) != "" {
		signer = crypto.NewSeededDevEd25519Signer(kernelSeed)
	} else {
		ephSigner, eErr := crypto.NewEphemeralEd25519Signer()
		if eErr != nil {
			return nil, fmt.Errorf("generate ephemeral Ed25519 kernel signer: %w", eErr)
		}
		signer = ephSigner
	}

	n1, err := warrant.NewEngine(ctx, store, pol, webauthnCfg, broker.Broadcast)
	if err != nil {
		return nil, err
	}
	n4 := agentcp.NewControlPlane(store, signer, extractorURL, broker.Broadcast)
	feedMgr, err := feeds.NewManager(ctx, store, n4, broker.Broadcast)
	if err != nil {
		return nil, err
	}

	rulepacks := adapters.NewDefaultRulepackRegistry()
	var shield adapters.ShieldEnforcer
	var deploy adapters.DeploymentTarget
	var twin adapters.TwinRunner

	if strings.EqualFold(strings.TrimSpace(os.Getenv("WARRANT_CLUSTER_DRIVER")), "kubernetes") {
		liveK8s, kErr := adapters.NewLiveKubernetesAdapterFromEnv(rulepacks)
		if kErr != nil {
			return nil, fmt.Errorf("initialize LiveKubernetesAdapter: %w", kErr)
		}
		shield = liveK8s
		deploy = liveK8s
		twin = liveK8s
	} else {
		shield = adapters.NewCiliumShieldAdapter(fleetURL, rulepacks)
		simK8s := adapters.NewK8sRolloutAdapter(fleetURL)
		deploy = simK8s
		twin = simK8s
	}

	fixProv := adapters.NewDeterministicFixProvider()
	sarifIn := adapters.NewSARIFIntakeAdapter(n4)

	n2 := gate.NewEngine(store, pol, n1, n4, deploy, broker.Broadcast)
	n3 := verify.NewEngine(store, pol, n1, n4, shield, deploy, twin, broker.Broadcast, rulepacks)
	n5 := ledger.NewEngine(store, pol, n1, signer, broker.Broadcast)

	return &ControlPlaneOrchestrator{
		Store:       store,
		Policy:      pol,
		N1Warrant:   n1,
		N2Gate:      n2,
		N3Verify:    n3,
		N4AgentCP:   n4,
		N5Ledger:    n5,
		Feeds:       feedMgr,
		SARIFIntake: sarifIn,
		FixProvider: fixProv,
		Shield:      shield,
		Deploy:      deploy,
		Twin:        twin,
		Broker:      broker,
		WebAuthnCfg: webauthnCfg,
	}, nil
}

// ExecuteSARIFRemediation runs the deterministic 5-stage Race Pipeline for an incoming SARIF 2.1.0 report.
func (o *ControlPlaneOrchestrator) ExecuteSARIFRemediation(ctx context.Context, rawSARIF []byte, patchProfile string) ([]models.RemediationItem, error) {
	return o.ExecuteSARIFRemediationWithOptions(ctx, rawSARIF, patchProfile, "", "", 0)
}

// ExecuteSARIFRemediationWithOptions ingests Wiz/GitHub/Tenable or native aquasec/trivy SARIF 2.1.0 reports,
// cross-references findings against the synced CISA KEV catalog, and drives the 5-stage Race Pipeline.
func (o *ControlPlaneOrchestrator) ExecuteSARIFRemediationWithOptions(
	ctx context.Context,
	rawSARIF []byte,
	patchProfile string,
	targetService string,
	vulnDigest string,
	maxFindings int,
) ([]models.RemediationItem, error) {
	if patchProfile == "" {
		patchProfile = "STATELESS_CLEAN"
	}

	// If targetService was passed (e.g., from Trivy sidecar) without an explicit digest, default to service's current digest
	if targetService != "" && vulnDigest == "" {
		if svc, err := o.Store.GetEstateService(ctx, targetService); err == nil {
			vulnDigest = svc.CurrentDigest
		}
	}

	// Stage 1: Zero-privilege SARIF extraction via N4 -> warrant-extractor
	findingSet, err := o.N4AgentCP.ExtractSARIFWithOptionsGoverned(
		ctx, "BOOTSTRAP_INTAKE", "", "sarif-intake-stream", "sys-intake", "sys-intake",
		rawSARIF, targetService, vulnDigest, maxFindings,
	)
	if err != nil {
		return nil, err
	}

	// Live CISA KEV Catalog Cross-Check
	kevCatalog, _ := o.Store.LookupCISAKEVSet(ctx)
	kevMatchCount := 0
	for i := range findingSet.Findings {
		if _, inKEV := kevCatalog[strings.ToUpper(findingSet.Findings[i].CVEID)]; inKEV {
			findingSet.Findings[i].IsKEV = true
		}
		if findingSet.Findings[i].IsKEV {
			kevMatchCount++
		}
	}
	if strings.EqualFold(findingSet.ScannerToolID, "Trivy") && o.Feeds != nil {
		o.Feeds.RecordTrivyIntake(ctx, findingSet, kevMatchCount)
	}

	// Avoid duplicating identical (service_id, cve_id) items when periodic Trivy scanner loops run
	existingByKey := map[string]models.RemediationItem{}
	if maxFindings > 0 {
		if existingList, lErr := o.Store.ListRemediations(ctx); lErr == nil {
			for _, ex := range existingList {
				existingByKey[ex.ServiceID+"|"+strings.ToUpper(ex.CVEID)] = ex
			}
		}
	}

	results := make([]models.RemediationItem, 0, len(findingSet.Findings))
	for _, f := range findingSet.Findings {
		if maxFindings > 0 {
			if prev, exists := existingByKey[f.TargetServiceID+"|"+strings.ToUpper(f.CVEID)]; exists {
				results = append(results, prev)
				continue
			}
		}
		svc, err := o.Store.GetEstateService(ctx, f.TargetServiceID)
		if err != nil {
			return nil, fmt.Errorf("unknown target service %q: %w", f.TargetServiceID, err)
		}

		remID := "rem-" + uuid.NewString()[:8]
		now := time.Now().UTC()
		item := models.RemediationItem{
			RemediationID:    remID,
			CVEID:            f.CVEID,
			CWEID:            f.CWEID,
			IsKEV:            f.IsKEV,
			CVSSScore:        f.CVSSScore,
			ServiceID:        svc.ServiceID,
			VulnerableDigest: f.VulnerableDigest,
			PatchedDigest:    f.PatchedDigest,
			PackagePURL:      f.PackagePURL,
			VulnerableSymbol: f.VulnerableSymbol,
			ExploitVector:    f.ExploitVector,
			Stage:            models.StageIntakeRepro,
			StatusHealth:     models.HealthNormal,
			PodSweepTotal:    svc.Replicas,
			BridgeSLAMIN:     60,
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		// Match governing active N1 Standing Warrant
		matchedWarrant, wErr := o.Store.FindMatchingWarrant(ctx, svc.ServiceID, f.CVSSScore)
		s1ID, s2ID := "UNBOUND", "UNBOUND"
		if wErr == nil {
			item.WarrantID = matchedWarrant.WarrantID
			item.BridgeSLAMIN = matchedWarrant.SLABridgeMinutes
			s1ID = matchedWarrant.Slot1PrincipalID
			s2ID = matchedWarrant.Slot2PrincipalID
		}

		if err := o.Store.UpsertRemediation(ctx, &item); err != nil {
			return nil, err
		}
		_ = o.Store.AppendTrace(ctx, models.TraceEvent{
			TraceID:       "trc-" + uuid.NewString()[:8],
			RemediationID: remID,
			Engine:        "N4",
			StepCode:      "SARIF_EXTRACTED_TYPED_SCHEMA",
			Outcome:       "PASS",
			ActorOrToken:  "warrant-extractor",
			EvidenceHash:  findingSet.TypedOutputSHA256,
			Fields: map[string]string{
				"cve_id":           f.CVEID,
				"raw_input_sha256": findingSet.RawInputSHA256,
				"scanner":          findingSet.ScannerToolID,
			},
			OccurredAt: now,
		})

		// Stage 2: Bridge Before Patch — deploy CiliumNetworkPolicy + K8s NetPol + Envoy mTLS containment bridge immediately
		bridgeID := "brg-" + uuid.NewString()[:8]
		blockerReason := "AUTONOMOUS_CANARY_IN_PROGRESS"
		if patchProfile == "UPSTREAM_VENDOR_PENDING" {
			blockerReason = "AWAITING_UPSTREAM_VENDOR_PATCH"
		} else if wErr != nil {
			blockerReason = "NO_VALID_STANDING_WARRANT_FAIL_CLOSED"
		}
		bridge, err := o.Shield.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
			BridgeID:          bridgeID,
			RemediationID:     remID,
			ServiceID:         svc.ServiceID,
			Namespace:         svc.Namespace,
			CVEID:             f.CVEID,
			CWEID:             f.CWEID,
			ExploitVector:     f.ExploitVector,
			AffectedPort:      f.AffectedPort,
			BlockedPaths:      f.BlockedPaths,
			SLABridgeMinutes:  item.BridgeSLAMIN,
			BlockerReasonCode: blockerReason,
		})
		if err != nil {
			return nil, err
		}
		if err := o.Store.UpsertBridge(ctx, *bridge); err != nil {
			return nil, err
		}
		if item.WarrantID != "" {
			_ = o.N4AgentCP.RecordGovernedAdapterAction(
				ctx, item.WarrantID, remID, "cilium_shield", svc.ServiceID,
				"APPLY_CILIUM_CONTAINMENT_BRIDGE", s1ID, s2ID, "INTERNAL_CLUSTER_ONLY",
				findingSet.TypedOutputSHA256, crypto.SHA256Hex([]byte(bridge.CiliumManifestYAML)),
			)
		}

		bridgedTime := time.Now().UTC()
		item.Stage = models.StageBridgedContained
		item.StatusHealth = models.HealthBridged
		item.BridgeID = bridge.BridgeID
		item.BridgedAt = &bridgedTime
		_ = o.Store.UpsertRemediation(ctx, &item)
		_ = o.Store.AppendTrace(ctx, models.TraceEvent{
			TraceID:       "trc-" + uuid.NewString()[:8],
			RemediationID: remID,
			Engine:        "ADAPTER",
			StepCode:      "CILIUM_SHIELD_BRIDGE_ARMED",
			Outcome:       "PASS",
			ActorOrToken:  bridge.BridgeID,
			EvidenceHash:  crypto.SHA256Hex([]byte(bridge.CiliumManifestYAML)),
			Fields: map[string]string{
				"bridge_type": bridge.BridgeType,
				"sla_minutes": fmt.Sprintf("%d", bridge.SLABridgeMinutes),
			},
			OccurredAt: bridgedTime,
		})
		o.Broker.Broadcast("BRIDGE_ARMED", bridge)
		o.Broker.Broadcast("REMEDIATION_UPDATED", item)

		// Fail closed if no active warrant covers this service/CVSS
		if wErr != nil {
			item.StatusHealth = models.HealthExceptionRouted
			item.BlockerCode = "NO_ACTIVE_WARRANT_FAIL_CLOSED"
			_ = o.Store.UpsertRemediation(ctx, &item)
			_ = o.Store.AppendTrace(ctx, models.TraceEvent{
				TraceID:       "trc-" + uuid.NewString()[:8],
				RemediationID: remID,
				Engine:        "N1",
				StepCode:      "WARRANT_LOOKUP",
				Outcome:       "BLOCK",
				ActorOrToken:  "n1-kernel",
				EvidenceHash:  crypto.SHA256Hex([]byte(wErr.Error())),
				Fields:        map[string]string{"reason": wErr.Error()},
			})
			results = append(results, item)
			continue
		}

		// Hold safely at Bridged / Contained if upstream vendor patch is not yet available
		if patchProfile == "UPSTREAM_VENDOR_PENDING" {
			item.BlockerCode = "AWAITING_UPSTREAM_VENDOR_PATCH"
			_ = o.Store.UpsertRemediation(ctx, &item)
			results = append(results, item)
			continue
		}

		// Resolve & verify cryptographic publisher provenance on patch artifact
		signedArt, err := o.FixProvider.ResolveSignedPatch(ctx, f, patchProfile)
		if err != nil {
			return nil, err
		}
		if err := o.FixProvider.VerifyProvenance(*signedArt); err != nil {
			item.StatusHealth = models.HealthRollbackFailed
			item.BlockerCode = err.Error()
			_ = o.Store.UpsertRemediation(ctx, &item)
			results = append(results, item)
			continue
		}
		item.PatchedDigest = signedArt.PatchedDigest
		_ = o.Store.AppendTrace(ctx, models.TraceEvent{
			TraceID:       "trc-" + uuid.NewString()[:8],
			RemediationID: remID,
			Engine:        "N4",
			StepCode:      "ARTIFACT_PROVENANCE_VERIFIED",
			Outcome:       "PASS",
			ActorOrToken:  signedArt.PublisherKeyID,
			EvidenceHash:  crypto.SHA256Hex([]byte(signedArt.ProvenanceSigB64)),
			Fields: map[string]string{
				"patched_digest": signedArt.PatchedDigest,
				"publisher_id":   signedArt.PublisherID,
			},
		})

		// Extract untrusted unified diff through isolated warrant-extractor
		patchMeta, err := o.N4AgentCP.ExtractDiffGoverned(
			ctx, item.WarrantID, remID, svc.ServiceID, s1ID, s2ID, signedArt.PatchedDigest, signedArt.UnifiedDiff,
		)
		if err != nil {
			return nil, err
		}

		// Stage 3: N2 Gate + Differential Shadow Canary
		if err := o.N2Gate.EvaluateAndRollout(ctx, &item, svc, patchMeta, false); err != nil {
			// Routed to Four-Eyes Exception Queue, Frozen, or Rolled Back safely with Bridge still armed
			results = append(results, item)
			continue
		}

		// Stage 4: N3 Twin Replay + Passive Fleet Attestation + Permanent Admission Lockout + Bridge Retirement
		verBundle, err := o.N3Verify.VerifyLockAndRetireBridge(ctx, &item, svc)
		if err != nil {
			results = append(results, item)
			continue
		}

		// Stage 5: N5 OSCAL 1.1.2 POA&M Minting & DSSE Attestation Closure
		if _, err := o.N5Ledger.MintOSCALAttestation(ctx, &item, svc, verBundle); err != nil {
			results = append(results, item)
			continue
		}
		results = append(results, item)
	}

	return results, nil
}

// ApproveOrRejectException processes a 2-of-2 Four-Eyes Exception decision and resumes rollout if APPROVED.
func (o *ControlPlaneOrchestrator) ApproveOrRejectException(ctx context.Context, exceptionID, decision string, env crypto.Envelope) (*models.CeilingException, *models.RemediationItem, error) {
	ex, err := o.N1Warrant.ResolveCeilingException(ctx, exceptionID, decision, env)
	if err != nil {
		return nil, nil, err
	}
	rem, err := o.Store.GetRemediation(ctx, ex.RemediationID)
	if err != nil {
		return ex, nil, err
	}
	if decision == "REJECTED" {
		rem.BlockerCode = "FOUR_EYES_EXCEPTION_REJECTED_HOLDING_BRIDGE"
		_ = o.Store.UpsertRemediation(ctx, rem)
		return ex, rem, nil
	}

	svc, err := o.Store.GetEstateService(ctx, rem.ServiceID)
	if err != nil {
		return ex, rem, err
	}
	patchMeta := rem.PatchMetadata
	if patchMeta == nil {
		patchMeta = &models.ExtractedPatchMetadata{
			PatchedDigest:         rem.PatchedDigest,
			APIBackwardCompatible: true,
			StatelessEligible:     true,
		}
	}
	_ = o.Store.AppendTrace(ctx, models.TraceEvent{
		TraceID:       "trc-" + uuid.NewString()[:8],
		RemediationID: rem.RemediationID,
		Engine:        "N1",
		StepCode:      "FOUR_EYES_EXCEPTION_APPROVED",
		Outcome:       "PASS",
		ActorOrToken:  exceptionID,
		EvidenceHash:  crypto.SHA256Hex([]byte(exceptionID)),
		Fields:        map[string]string{"decision": "APPROVED"},
	})
	if err := o.N2Gate.EvaluateAndRollout(ctx, rem, svc, patchMeta, true); err != nil {
		return ex, rem, err
	}
	verBundle, err := o.N3Verify.VerifyLockAndRetireBridge(ctx, rem, svc)
	if err != nil {
		return ex, rem, err
	}
	if _, err := o.N5Ledger.MintOSCALAttestation(ctx, rem, svc, verBundle); err != nil {
		return ex, rem, err
	}
	return ex, rem, nil
}

// IngestOSVAdvisoryToPipeline routes a sanitized OSV.dev SBOM advisory into the 5-stage Race Pipeline.
func (o *ControlPlaneOrchestrator) IngestOSVAdvisoryToPipeline(ctx context.Context, osvID, serviceID string) ([]models.RemediationItem, error) {
	advisories, err := o.Store.ListOSVAdvisories(ctx)
	if err != nil {
		return nil, err
	}
	for _, adv := range advisories {
		if strings.EqualFold(adv.OSVID, osvID) && (serviceID == "" || adv.ServiceID == serviceID) {
			svc, err := o.Store.GetEstateService(ctx, adv.ServiceID)
			if err != nil {
				return nil, err
			}
			cve := adv.CVEID
			if cve == "" || cve == "CVE-0000-0000" {
				cve = "CVE-2023-44487"
			}
			patchedDigest := "sha256:" + crypto.SHA256Hex([]byte(svc.ServiceID+"|"+adv.OSVID+"|"+adv.FixedVersion))
			sarif := BuildDeterministicSARIF(
				cve, adv.CWEID, adv.CVSSScore, adv.IsKEV, svc.ServiceID,
				svc.CurrentDigest, patchedDigest, "", "HTTP2_RAPID_RESET", 8080,
			)
			return o.ExecuteSARIFRemediationWithOptions(ctx, sarif, "STATELESS_CLEAN", svc.ServiceID, svc.CurrentDigest, 1)
		}
	}
	return nil, fmt.Errorf("OSV advisory %q not found", osvID)
}
