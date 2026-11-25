package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/fleetsim"
	"github.com/cgilbert61/G1-Warrant/internal/gate"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/google/uuid"
)

// DistributorDispatchAPIRequest invokes governed WN-8 patch deployment for an existing remediation item.
type DistributorDispatchAPIRequest struct {
	RemediationID        string                    `json:"remediation_id"`
	DistributorID        string                    `json:"distributor_id"`
	PlatformFamily       string                    `json:"platform_family,omitempty"`
	FixIdentity          *models.FixIdentity       `json:"fix_identity,omitempty"`
	TargetAssets         []models.AssetTarget      `json:"target_assets,omitempty"`
	WavePercentages      []int                     `json:"wave_percentages,omitempty"`
	MaxFailureRatePct    float64                   `json:"max_failure_rate_pct,omitempty"`
	StageDwellSeconds    int                       `json:"stage_dwell_seconds,omitempty"`
	MaintenanceWindowUTC string                    `json:"maintenance_window_utc,omitempty"`
	RollbackInstruction  models.NativeRollbackSpec `json:"rollback_instruction"`
}

func (o *ControlPlaneOrchestrator) registerFinderAndDistributorRoutes(mux *http.ServeMux) {
	// WN-7 Estate Scanner Finder Intake Routes (Qualys VMDR, Tenable.io/sc, Rapid7 InsightVM)
	registerFinderIntake := func(vendorSlug string) {
		mux.HandleFunc("POST /api/v1/intake/"+vendorSlug, func(w http.ResponseWriter, r *http.Request) {
			if code, authErr := o.VerifyIntakeAuth(r); authErr != nil {
				writeAPIError(w, code, authErr)
				return
			}
			raw, err := readBoundedBody(w, r, 16<<20)
			if err != nil {
				writeAPIError(w, statusForBodyReadError(err), err)
				return
			}
			profile := r.URL.Query().Get("patch_profile")
			targetSvc := r.URL.Query().Get("target_service")
			distID := r.URL.Query().Get("distributor_id")
			maxFindings := 0
			if mf := r.URL.Query().Get("max_findings"); mf != "" {
				if parsed, pErr := strconv.Atoi(mf); pErr == nil && parsed > 0 {
					maxFindings = parsed
				}
			}
			items, err := o.ExecuteFinderIntakeRemediation(r.Context(), vendorSlug, raw, profile, targetSvc, distID, maxFindings)
			if err != nil {
				writeAPIError(w, http.StatusUnprocessableEntity, err)
				return
			}
			writeAPIJSON(w, http.StatusCreated, items)
		})
	}
	registerFinderIntake("qualys")
	registerFinderIntake("tenable")
	registerFinderIntake("rapid7")

	// Asset Identity Alias Registry (WN-7 Scanner Asset -> Warrant EstateService / AssetKey Mapping)
	mux.HandleFunc("GET /api/v1/finders/aliases", func(w http.ResponseWriter, r *http.Request) {
		aliases, err := o.Store.ListAssetIdentityAliases(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, aliases)
	})

	mux.HandleFunc("POST /api/v1/finders/aliases", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if _, _, code, authErr := o.VerifyAutomationOrPrincipalAuth(ctx, r, models.GovActionFeedMutation, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var alias models.AssetIdentityAlias
		if err := json.Unmarshal(rawBody, &alias); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		if err := o.Store.UpsertAssetIdentityAlias(ctx, alias); err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusCreated, alias)
	})

	// WN-8 Distributor Catalog, Orders, Results & Governed Dispatch/Rollback Routes
	mux.HandleFunc("GET /api/v1/distributors", func(w http.ResponseWriter, r *http.Request) {
		if o.Distributors == nil {
			writeAPIJSON(w, http.StatusOK, []models.DistributorDescriptor{})
			return
		}
		writeAPIJSON(w, http.StatusOK, o.Distributors.ListDescriptors())
	})

	mux.HandleFunc("GET /api/v1/distributors/orders", func(w http.ResponseWriter, r *http.Request) {
		remID := r.URL.Query().Get("remediation_id")
		orders, err := o.Store.ListDeploymentOrders(r.Context(), remID)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, orders)
	})

	mux.HandleFunc("GET /api/v1/distributors/results", func(w http.ResponseWriter, r *http.Request) {
		orderID := r.URL.Query().Get("order_id")
		results, err := o.Store.ListDeploymentResults(r.Context(), orderID)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, results)
	})

	mux.HandleFunc("POST /api/v1/distributors/dispatch", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 2<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		if _, _, code, authErr := o.VerifyAutomationOrPrincipalAuth(ctx, r, models.GovActionFeedMutation, rawBody); authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		var req DistributorDispatchAPIRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
			return
		}
		resp, err := o.ExecuteGovernedDistributorDispatch(ctx, req)
		if err != nil {
			status := http.StatusUnprocessableEntity
			if strings.Contains(err.Error(), "OUTSIDE_WARRANT_SCOPE") || strings.Contains(err.Error(), "NO_WARRANT") || strings.Contains(err.Error(), "NO_PROOF") {
				status = http.StatusForbidden
			}
			writeAPIError(w, status, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, resp)
	})

	mux.HandleFunc("POST /api/v1/distributors/orders/{order_id}/rollback", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rawBody, err := readBoundedBody(w, r, 1<<20)
		if err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		actor, gp, code, authErr := o.VerifyOperatorOrSinglePrincipalAuth(ctx, r, models.GovActionEmergencyRollback, rawBody)
		if authErr != nil {
			writeAPIError(w, code, authErr)
			return
		}
		orderID := r.PathValue("order_id")
		reason := "OPERATOR_DISTRIBUTOR_ROLLBACK"
		if gp != nil && gp.ReasonCode != "" {
			reason = gp.ReasonCode
		} else if len(bytesTrimSpace(rawBody)) > 0 {
			var body struct {
				ReasonCode string `json:"reason_code"`
			}
			if json.Unmarshal(rawBody, &body) == nil && body.ReasonCode != "" {
				reason = body.ReasonCode
			}
		}
		res, err := o.ExecuteManualDistributorOrderRollback(ctx, orderID, actor, reason)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, res)
	})

	// v1.3.0 Item 1 Decoupled Class-Binding Route:
	// Binds an unbound/unmapped ingested RemediationItem to an active 2-of-2 Standing Warrant class
	// (either submitting a new 2-of-2 Warrant DSSE envelope or referencing an active 2-of-2 Warrant ID),
	// strictly decoupling class authorization from X-Warrant-Intake-Token arrival.
	mux.HandleFunc("POST /api/v1/remediations/{id}/bind-class", func(w http.ResponseWriter, r *http.Request) {
		if code, sepErr := o.RejectEstateReadCredentialOnMutation(r); sepErr != nil {
			writeAPIError(w, code, sepErr)
			return
		}
		ctx := r.Context()
		remID := strings.TrimSpace(r.PathValue("id"))
		var req struct {
			WarrantID       string           `json:"warrant_id,omitempty"`
			WarrantEnvelope *crypto.Envelope `json:"warrant_envelope,omitempty"`
			DistributorID   string           `json:"distributor_id,omitempty"`
			AutoExecute     bool             `json:"auto_execute,omitempty"`
		}
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeAPIError(w, statusForBodyReadError(err), err)
			return
		}
		updated, err := o.BindRemediationToWarrantClass(ctx, remID, req.WarrantID, req.WarrantEnvelope, req.DistributorID, req.AutoExecute)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeAPIJSON(w, http.StatusOK, updated)
	})
}

// BindRemediationToWarrantClass binds an ingested unbound/unmapped finding to a verified 2-of-2 Standing Warrant class
// (strictly decoupled from ingest) and optionally drives Clone-Twin Proving + rollout.
func (o *ControlPlaneOrchestrator) BindRemediationToWarrantClass(
	ctx context.Context,
	remediationID string,
	warrantID string,
	warrantEnvelope *crypto.Envelope,
	distributorID string,
	autoExecute bool,
) (*models.RemediationItem, error) {
	item, err := o.Store.GetRemediation(ctx, remediationID)
	if err != nil {
		return nil, err
	}
	svc, err := o.Store.GetEstateService(ctx, item.ServiceID)
	if err != nil {
		return nil, err
	}

	var wRec *models.WarrantRecord
	if warrantEnvelope != nil {
		minted, mErr := o.N1Warrant.SubmitDualSignedWarrant(ctx, *warrantEnvelope)
		if mErr != nil {
			return nil, fmt.Errorf("CLASS_BINDING_DUAL_KEY_WARRANT_INVALID: %w", mErr)
		}
		wRec = minted
	} else if strings.TrimSpace(warrantID) != "" {
		reverified, rErr := o.N1Warrant.ReverifyWarrantForExecution(ctx, strings.TrimSpace(warrantID), svc.ServiceID, item.CVSSScore, svc.Replicas, item.RemediationKind, item.CWEID)
		if rErr != nil {
			return nil, fmt.Errorf("CLASS_BINDING_WARRANT_REVERIFY_FAILED: %w", rErr)
		}
		wRec = reverified
	} else {
		return nil, fmt.Errorf("CLASS_BINDING_REQUIRES_2OF2_WARRANT: provide warrant_envelope (2-of-2 DSSE) or active warrant_id")
	}

	// Verify unmapped vendor detections are explicitly authorized on the Standing Warrant class
	if item.CVEMappingStatus == models.CVEMappingStatusUnmappedVendor || item.CVEMappingStatus == models.CVEMappingStatusAbsent {
		authorized := false
		for _, authDet := range wRec.AuthorizedVendorDetections {
			if strings.EqualFold(strings.TrimSpace(authDet), item.VendorDetectionID) || authDet == "*" {
				authorized = true
				break
			}
		}
		if !authorized {
			return nil, fmt.Errorf("UNMAPPED_FINDING_NOT_IN_AUTHORIZED_DETECTIONS: warrant %s does not authorize %s", wRec.WarrantID, item.VendorDetectionID)
		}
	}

	item.WarrantID = wRec.WarrantID
	item.ClassBindingStatus = models.ClassBindingStatusBound
	item.BridgeSLAMIN = wRec.SLABridgeMinutes
	if item.BlockerCode == "UNMAPPED_FINDING_REQUIRES_CLASS_BINDING" || item.BlockerCode == "NO_ACTIVE_WARRANT_FAIL_CLOSED" {
		item.BlockerCode = ""
	}
	if err := o.Store.UpsertRemediation(ctx, item); err != nil {
		return nil, err
	}
	_ = o.Store.AppendTrace(ctx, models.TraceEvent{
		TraceID:       "trc-" + uuid.NewString()[:8],
		RemediationID: item.RemediationID,
		Engine:        "N1",
		StepCode:      "DECOUPLED_WARRANT_CLASS_BOUND",
		Outcome:       "PASS",
		ActorOrToken:  wRec.WarrantID,
		EvidenceHash:  wRec.EntryHash,
		Fields: map[string]string{
			"warrant_id":           wRec.WarrantID,
			"warrant_class":        wRec.WarrantClass,
			"class_binding_status": models.ClassBindingStatusBound,
		},
		OccurredAt: time.Now().UTC(),
	})
	o.Broker.Broadcast("REMEDIATION_UPDATED", item)

	if autoExecute {
		dist := strings.TrimSpace(distributorID)
		if dist == "" {
			dist = strings.TrimSpace(item.DistributorID)
		}
		if dist != "" {
			resp, dErr := o.ExecuteGovernedDistributorDispatch(ctx, DistributorDispatchAPIRequest{
				RemediationID: item.RemediationID,
				DistributorID: dist,
			})
			if dErr != nil {
				return item, dErr
			}
			return &resp.Remediation, nil
		}
	}
	return item, nil
}

// ExecuteFinderIntakeRemediation ingests Qualys VMDR, Tenable.io/sc, or Rapid7 InsightVM scan payloads via
// zero-egress warrant-extractor, enforces the WN-7 Fail-Visible Unmapped Vendor Advisory rule, arms immediate
// containment bridges, and optionally executes governed WN-8 distributor rollout (or standard K8s pipeline).
func (o *ControlPlaneOrchestrator) ExecuteFinderIntakeRemediation(
	ctx context.Context,
	vendor string,
	rawPayload []byte,
	patchProfile string,
	targetService string,
	distributorID string,
	maxFindings int,
) ([]models.RemediationItem, error) {
	if patchProfile == "" {
		patchProfile = "STATELESS_CLEAN"
	}
	aliasToSvc, aliasToAsset := o.Store.BuildFinderAliasMaps(ctx)
	var vulnDigest string
	if targetService != "" {
		if svc, err := o.Store.GetEstateService(ctx, targetService); err == nil {
			vulnDigest = svc.CurrentDigest
		}
	}

	findingSet, err := o.N4AgentCP.ExtractEstateFindingsGoverned(
		ctx, vendor, rawPayload, targetService, vulnDigest, "", maxFindings, aliasToSvc, aliasToAsset,
	)
	if err != nil {
		return nil, err
	}

	kevCatalog, _ := o.Store.LookupCISAKEVSet(ctx)
	for i := range findingSet.Findings {
		if _, inKEV := kevCatalog[strings.ToUpper(findingSet.Findings[i].CVEID)]; inKEV {
			findingSet.Findings[i].IsKEV = true
		}
	}

	results := make([]models.RemediationItem, 0, len(findingSet.Findings))
	for _, f := range findingSet.Findings {
		svc, err := o.Store.GetEstateService(ctx, f.TargetServiceID)
		if err != nil {
			return nil, fmt.Errorf("UNMAPPED_TARGET_SERVICE %q: register service or asset_identity_alias first: %w", f.TargetServiceID, err)
		}

		remID := "rem-" + uuid.NewString()[:8]
		now := time.Now().UTC()
		var firstSeenPtr, lastSeenPtr *time.Time
		if ts, tErr := time.Parse(time.RFC3339, f.FirstSeenAt); tErr == nil {
			firstSeenPtr = &ts
		}
		if ts, tErr := time.Parse(time.RFC3339, f.LastSeenAt); tErr == nil {
			lastSeenPtr = &ts
		}

		item := models.RemediationItem{
			RemediationID:            remID,
			RemediationKind:          models.RemediationKindImagePatch,
			CVEID:                    f.CVEID,
			CWEID:                    f.CWEID,
			IsKEV:                    f.IsKEV,
			ChainedExploitEnabler:    f.ChainedExploitEnabler,
			CVSSScore:                f.CVSSScore,
			ServiceID:                svc.ServiceID,
			VulnerableDigest:         firstNonEmptyStr(f.VulnerableDigest, svc.CurrentDigest),
			PatchedDigest:            f.PatchedDigest,
			PackagePURL:              f.PackagePURL,
			VulnerableSymbol:         f.VulnerableSymbol,
			ExploitVector:            f.ExploitVector,
			Stage:                    models.StageIntakeRepro,
			StatusHealth:             models.HealthNormal,
			PodSweepTotal:            svc.Replicas,
			BridgeSLAMIN:             60,
			FinderVendor:             f.FinderVendor,
			VendorDetectionID:        f.VendorDetectionID,
			CVEMappingStatus:         f.CVEMappingStatus,
			NormalizedDetectionState: f.NormalizedDetectionState,
			AssetIdentity:            f.AssetIdentity,
			FirstSeenAt:              firstSeenPtr,
			LastSeenAt:               lastSeenPtr,
			DistributorID:            strings.TrimSpace(distributorID),
			CreatedAt:                now,
			UpdatedAt:                now,
		}

		matchedWarrant, wErr := o.Store.FindMatchingWarrantForFinding(ctx, svc.ServiceID, f)
		s1ID, s2ID := "UNBOUND", "UNBOUND"
		if wErr == nil {
			item.WarrantID = matchedWarrant.WarrantID
			item.ClassBindingStatus = models.ClassBindingStatusBound
			item.BridgeSLAMIN = matchedWarrant.SLABridgeMinutes
			s1ID = matchedWarrant.Slot1PrincipalID
			s2ID = matchedWarrant.Slot2PrincipalID
		} else {
			item.ClassBindingStatus = models.ClassBindingStatusUnbound
		}

		if err := o.Store.UpsertRemediation(ctx, &item); err != nil {
			return nil, err
		}
		_ = o.Store.AppendTrace(ctx, models.TraceEvent{
			TraceID:       "trc-" + uuid.NewString()[:8],
			RemediationID: remID,
			Engine:        "N4",
			StepCode:      "FINDER_EXTRACTED_TYPED_SCHEMA",
			Outcome:       "PASS",
			ActorOrToken:  "agt-warrant-extractor",
			EvidenceHash:  findingSet.TypedOutputSHA256,
			Fields: map[string]string{
				"finder_vendor":       f.FinderVendor,
				"vendor_detection_id": f.VendorDetectionID,
				"cve_id":              f.CVEID,
				"cve_mapping_status":  f.CVEMappingStatus,
				"raw_input_sha256":    findingSet.RawInputSHA256,
			},
			OccurredAt: now,
		})

		// Stage 2: Bridge Before Patch — immediately arm containment bridge across K8s/Cloud/Linux/Windows even for unmapped/unwarranted findings!
		bridgeID := "brg-" + uuid.NewString()[:8]
		blockerReason := "AUTONOMOUS_CANARY_IN_PROGRESS"
		if f.CVEMappingStatus == models.CVEMappingStatusUnmappedVendor && wErr != nil {
			blockerReason = "UNMAPPED_FINDING_REQUIRES_CLASS_BINDING"
		} else if wErr != nil {
			blockerReason = "NO_VALID_STANDING_WARRANT_FAIL_CLOSED"
		} else if patchProfile == "UPSTREAM_VENDOR_PENDING" {
			blockerReason = "AWAITING_UPSTREAM_VENDOR_PATCH"
		} else if strings.TrimSpace(distributorID) == "" {
			blockerReason = "CONTAINED_AWAITING_DISTRIBUTOR_DISPATCH"
		}
		bridge, err := o.Shield.CompileAndApplyBridge(ctx, adapters.BridgeApplyRequest{
			BridgeID:                 bridgeID,
			RemediationID:            remID,
			ServiceID:                svc.ServiceID,
			Namespace:                svc.Namespace,
			CVEID:                    f.CVEID,
			CWEID:                    f.CWEID,
			ExploitVector:            f.ExploitVector,
			AffectedPort:             f.AffectedPort,
			BlockedPaths:             f.BlockedPaths,
			AllowedEgressServices:    svc.AllowedEgressServices,
			AllowKubeAPIServerEgress: svc.AllowKubeAPIServerEgress,
			SLABridgeMinutes:         item.BridgeSLAMIN,
			BlockerReasonCode:        blockerReason,
			DistributorID:            strings.TrimSpace(distributorID),
			AssetIdentity:            f.AssetIdentity,
		})
		if err != nil {
			return nil, err
		}
		if err := o.Store.UpsertBridge(ctx, *bridge); err != nil {
			return nil, err
		}
		if item.WarrantID != "" {
			_ = o.N4AgentCP.RecordGovernedAdapterAction(
				ctx, item.WarrantID, remID, "cilium-shield", svc.ServiceID,
				"APPLY_CILIUM_CONTAINMENT_BRIDGE", s1ID, s2ID, models.EgressProfileInternalCluster,
				findingSet.TypedOutputSHA256, crypto.SHA256Hex([]byte(bridge.CiliumManifestYAML)),
			)
		}

		bridgedTime := time.Now().UTC()
		item.Stage = models.StageBridgedContained
		item.StatusHealth = models.HealthBridged
		item.BridgeID = bridge.BridgeID
		item.BridgedAt = &bridgedTime
		_ = o.Store.UpsertRemediation(ctx, &item)
		o.Broker.Broadcast("BRIDGE_ARMED", bridge)

		// v1.3.0 Item 1 Zero-Signature Intake Doctrine:
		// Unmapped vendor advisories and unbound findings NEVER demand dual-key at ingest, NEVER set StatusHealth=EXCEPTION_ROUTED,
		// and NEVER create rows in ceiling_exceptions / Four-Eyes Queue. Containment is armed autonomously (StatusHealth=BRIDGED,
		// ClassBindingStatus=UNBOUND) while the typed record waits passively for a separate, decoupled 2-of-2 class-binding act.
		if wErr != nil {
			item.StatusHealth = models.HealthBridged
			item.ClassBindingStatus = models.ClassBindingStatusUnbound
			if f.CVEMappingStatus == models.CVEMappingStatusUnmappedVendor || f.CVEMappingStatus == models.CVEMappingStatusAbsent {
				item.BlockerCode = "UNMAPPED_FINDING_REQUIRES_CLASS_BINDING"
			} else {
				item.BlockerCode = "NO_ACTIVE_WARRANT_FAIL_CLOSED"
			}
			_ = o.Store.UpsertRemediation(ctx, &item)
			o.Broker.Broadcast("REMEDIATION_UPDATED", item)
			results = append(results, item)
			continue
		}

		if patchProfile == "UPSTREAM_VENDOR_PENDING" {
			item.BlockerCode = "AWAITING_UPSTREAM_VENDOR_PATCH"
			_ = o.Store.UpsertRemediation(ctx, &item)
			o.Broker.Broadcast("REMEDIATION_UPDATED", item)
			results = append(results, item)
			continue
		}

		// If caller specified a WN-8 DistributorID on intake, drive governed distributor rollout; otherwise hold at Bridged ready for dispatch (or run K8s rollout when k8s-cilium-native).
		if strings.TrimSpace(distributorID) != "" {
			var targets []models.AssetTarget
			if f.AssetIdentity != nil {
				targets = append(targets, models.AssetTarget{
					AssetKey:       f.AssetIdentity.AssetKey,
					ServiceID:      svc.ServiceID,
					Hostname:       f.AssetIdentity.Hostname,
					IPv4:           f.AssetIdentity.IPv4,
					NativeDeviceID: firstNonEmptyStr(f.AssetIdentity.CloudInstanceID, f.AssetIdentity.ScannerAssetID, f.AssetIdentity.AssetKey),
					PlatformFamily: f.AssetIdentity.PlatformFamily,
				})
			} else {
				targets = append(targets, models.AssetTarget{AssetKey: svc.ServiceID, ServiceID: svc.ServiceID})
			}
			dispatchResp, dErr := o.ExecuteGovernedDistributorDispatch(ctx, DistributorDispatchAPIRequest{
				RemediationID: item.RemediationID,
				DistributorID: distributorID,
				FixIdentity: &models.FixIdentity{
					CVEID:        f.CVEID,
					KBArticleID:  f.KBArticleID,
					PackageNEVRA: f.PackageNEVRA,
					TargetDigest: item.PatchedDigest,
				},
				TargetAssets: targets,
				RollbackInstruction: models.NativeRollbackSpec{
					UninstallKB:          f.KBArticleID,
					PreviousDigest:       item.VulnerableDigest,
					PreviousPackageNEVRA: "prev-" + f.PackageNEVRA,
				},
			})
			if dErr != nil {
				return nil, dErr
			}
			results = append(results, dispatchResp.Remediation)
			continue
		}

		o.Broker.Broadcast("REMEDIATION_UPDATED", item)
		results = append(results, item)
	}
	return results, nil
}

// DistributorDispatchAPIResponse summarizes the complete governed WN-8 execution & N5 attestation result.
type DistributorDispatchAPIResponse struct {
	Remediation models.RemediationItem         `json:"remediation"`
	Rollout     gate.DistributorExecutionOutcome `json:"rollout"`
	Attestation *models.AttestationRecord      `json:"attestation,omitempty"`
}

// ExecuteGovernedDistributorDispatch verifies N1 Standing Warrant + N3 Twin/Provenance proof BEFORE creating
// a DeploymentOrder, executes progressive waves via N2 WaveSequencer, handles automatic symmetric rollback on
// wave failure/stall, or mints an honest FULL / PARTIAL / DISPATCH_ONLY OSCAL 1.1.2 attestation.
func (o *ControlPlaneOrchestrator) ExecuteGovernedDistributorDispatch(
	ctx context.Context,
	req DistributorDispatchAPIRequest,
) (*DistributorDispatchAPIResponse, error) {
	item, err := o.Store.GetRemediation(ctx, req.RemediationID)
	if err != nil {
		return nil, err
	}
	svc, err := o.Store.GetEstateService(ctx, item.ServiceID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(item.WarrantID) == "" {
		return nil, fmt.Errorf("NO_WARRANT_NO_DEPLOYMENT_ORDER: remediation %s has no bound Standing Warrant", item.RemediationID)
	}

	// Verify publisher patch provenance + N3 Isolated Twin Exploit Replay BEFORE creating any DeploymentOrder!
	finding := models.ExtractedFinding{
		CVEID:            item.CVEID,
		CWEID:            item.CWEID,
		CVSSScore:        item.CVSSScore,
		TargetServiceID:  svc.ServiceID,
		VulnerableDigest: item.VulnerableDigest,
		PatchedDigest:    item.PatchedDigest,
		VulnerableSymbol: item.VulnerableSymbol,
		ExploitVector:    item.ExploitVector,
	}
	signedArt, err := o.FixProvider.ResolveSignedPatch(ctx, finding, "STATELESS_CLEAN")
	if err != nil {
		return nil, fmt.Errorf("NO_PROOF_NO_DEPLOYMENT_ORDER (resolve patch): %w", err)
	}
	if err := o.FixProvider.VerifyProvenance(*signedArt); err != nil {
		return nil, fmt.Errorf("NO_PROOF_NO_DEPLOYMENT_ORDER (provenance failed): %w", err)
	}
	item.PatchedDigest = signedArt.PatchedDigest
	_ = o.Store.AppendTrace(ctx, models.TraceEvent{
		TraceID:       "trc-" + uuid.NewString()[:8],
		RemediationID: item.RemediationID,
		Engine:        "N4",
		StepCode:      "ARTIFACT_PROVENANCE_VERIFIED",
		Outcome:       "PASS",
		ActorOrToken:  signedArt.PublisherKeyID,
		EvidenceHash:  crypto.SHA256Hex([]byte(signedArt.ProvenanceSigB64)),
		Fields: map[string]string{
			"patched_digest": signedArt.PatchedDigest,
			"publisher_id":   signedArt.PublisherID,
		},
		OccurredAt: time.Now().UTC(),
	})

	// Register patched digest profile in simulator so K8s/Twin runner has clean baseline metrics when needed
	_ = o.Deploy.RegisterImageProfile(ctx, serverCleanImageProfile(svc, signedArt.PatchedDigest))

	twinResp, hasSignedProbe, err := o.N3Verify.RunPreDispatchTwinProof(ctx, item, svc)
	if err != nil {
		return nil, fmt.Errorf("NO_PROOF_NO_DEPLOYMENT_ORDER: %w", err)
	}

	fixIdent := models.FixIdentity{
		CVEID:        item.CVEID,
		TargetDigest: item.PatchedDigest,
	}
	if req.FixIdentity != nil {
		fixIdent = *req.FixIdentity
		if fixIdent.CVEID == "" {
			fixIdent.CVEID = item.CVEID
		}
		if fixIdent.TargetDigest == "" {
			fixIdent.TargetDigest = item.PatchedDigest
		}
	}

	// v1.3.0 Item 2: Execute 3-Clone Proving Ground + Runtime-Follows-Patch BEFORE dispatching any WN-8 DeploymentOrder!
	if _, cErr := o.N3Verify.RunCloneTwinProving(ctx, item, svc, &fixIdent, item.PatchMetadata); cErr != nil {
		return nil, fmt.Errorf("NO_PROOF_NO_DEPLOYMENT_ORDER: %w", cErr)
	}

	targets := req.TargetAssets
	if len(targets) == 0 {
		if item.AssetIdentity != nil && item.AssetIdentity.AssetKey != "" {
			targets = []models.AssetTarget{
				{
					AssetKey:       item.AssetIdentity.AssetKey,
					ServiceID:      svc.ServiceID,
					Hostname:       item.AssetIdentity.Hostname,
					IPv4:           item.AssetIdentity.IPv4,
					PlatformFamily: item.AssetIdentity.PlatformFamily,
				},
			}
		} else {
			targets = []models.AssetTarget{{AssetKey: svc.ServiceID, ServiceID: svc.ServiceID}}
		}
	}

	rbInst := req.RollbackInstruction
	if rbInst.PreviousDigest == "" {
		rbInst.PreviousDigest = item.VulnerableDigest
	}

	item.Stage = models.StageShadowCanary
	item.DistributorID = req.DistributorID
	_ = o.Store.UpsertRemediation(ctx, item)

	outcome, err := o.N2Gate.ExecuteDistributorRollout(ctx, o.Distributors, gate.DistributorExecutionRequest{
		Remediation:          item,
		Service:              svc,
		DistributorID:        req.DistributorID,
		PlatformFamily:       req.PlatformFamily,
		FixIdentity:          fixIdent,
		TargetAssets:         targets,
		WavePercentages:      req.WavePercentages,
		MaxFailureRatePct:    req.MaxFailureRatePct,
		StageDwellSeconds:    req.StageDwellSeconds,
		MaintenanceWindowUTC: req.MaintenanceWindowUTC,
		RollbackInstruction:  rbInst,
		ProofVerified:        true,
		TwinReplayStatus:     twinResp.Status,
	})
	if err != nil {
		return nil, err
	}

	if outcome.RolledBack {
		// Keep / re-arm containment bridge and mark QUARANTINED_ROLLBACK
		if item.BridgeID != "" {
			if b, bErr := o.Store.GetBridge(ctx, item.BridgeID); bErr == nil && b != nil {
				b.Status = "ARMED"
				b.RetiredAt = nil
				b.RearmedCount++
				b.BlockerReasonCode = "DISTRIBUTOR_WAVE_ROLLBACK_" + outcome.RollbackReasonCode
				_ = o.Store.UpsertBridge(ctx, *b)
				o.Broker.Broadcast("BRIDGE_ARMED", b)
			}
		}
		item.Stage = models.StageBridgedContained
		item.StatusHealth = models.HealthQuarantinedRollback
		item.LatestOrderID = outcome.PrimaryOrder.OrderID
		item.BlockerCode = "DISTRIBUTOR_NATIVE_ROLLBACK:" + outcome.RollbackReasonCode
		if outcome.RollbackResult != nil {
			item.RolledBackAssetCount = outcome.RollbackResult.RolledBackCount
		}
		_ = o.Store.UpsertRemediation(ctx, item)
		o.Broker.Broadcast("REMEDIATION_UPDATED", item)
		return &DistributorDispatchAPIResponse{
			Remediation: *item,
			Rollout:     *outcome,
		}, nil
	}

	// Evaluate honest closure tiering (FULL vs PARTIAL vs DISPATCH_ONLY) & bridge retirement
	verBundle, verDec, err := o.N3Verify.EvaluateDistributorClosureAndBridge(
		ctx, item, svc, twinResp, hasSignedProbe, outcome.PrimaryOrder, outcome.AggregatedResult,
	)
	if err != nil {
		return nil, err
	}

	var att *models.AttestationRecord
	if verDec.AllowAttestationMint || verDec.AllowPartialAttestationMint || verDec.AllowDispatchOnlyRecord {
		minted, mErr := o.N5Ledger.MintOSCALAttestation(ctx, item, svc, verBundle)
		if mErr != nil {
			return nil, mErr
		}
		att = minted
	}

	return &DistributorDispatchAPIResponse{
		Remediation: *item,
		Rollout:     *outcome,
		Attestation: att,
	}, nil
}

// ExecuteManualDistributorOrderRollback invokes DistributorTranslator.ExecuteRollback using the immutable pre-recorded
// RollbackInstruction on order_id and re-arms the active containment bridge.
func (o *ControlPlaneOrchestrator) ExecuteManualDistributorOrderRollback(
	ctx context.Context,
	orderID string,
	actor string,
	reason string,
) (*models.DeploymentResult, error) {
	order, err := o.Store.GetDeploymentOrder(ctx, orderID)
	if err != nil {
		return nil, err
	}
	tr, err := o.Distributors.Get(order.DistributorID)
	if err != nil {
		return nil, err
	}
	rbRes, err := tr.ExecuteRollback(ctx, *order, order.NativeJobRef, reason)
	if err != nil {
		return nil, err
	}
	rbRes.OrderID = order.OrderID
	rbRes.RemediationID = order.RemediationID
	rbRes.IsRollback = true
	rbRes.RollbackReason = reason
	rbRes.RecomputeCounts()
	if err := o.Store.AppendDeploymentResult(ctx, rbRes); err != nil {
		return nil, err
	}

	if item, gErr := o.Store.GetRemediation(ctx, order.RemediationID); gErr == nil && item != nil {
		if item.BridgeID != "" {
			if b, bErr := o.Store.GetBridge(ctx, item.BridgeID); bErr == nil && b != nil {
				b.Status = "ARMED"
				b.RetiredAt = nil
				b.RearmedCount++
				b.BlockerReasonCode = "MANUAL_DISTRIBUTOR_ROLLBACK:" + reason
				_ = o.Store.UpsertBridge(ctx, *b)
				o.Broker.Broadcast("BRIDGE_ARMED", b)
			}
		}
		item.Stage = models.StageBridgedContained
		item.StatusHealth = models.HealthQuarantinedRollback
		item.BlockerCode = "MANUAL_DISTRIBUTOR_ROLLBACK:" + reason
		item.RolledBackAssetCount = rbRes.RolledBackCount
		_ = o.Store.UpsertRemediation(ctx, item)
		o.Broker.Broadcast("REMEDIATION_UPDATED", item)
	}
	_ = actor
	return rbRes, nil
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func serverCleanImageProfile(_ *models.EstateService, patchedDigest string) fleetsim.ImageBehaviorProfile {
	samples := 1000
	dwell := 600
	return fleetsim.ImageBehaviorProfile{
		Digest:               patchedDigest,
		P99LatencyMs:         18.5,
		ExploitStillWorks:    false,
		ObservedSamples:      &samples,
		ObservedDwellSeconds: &dwell,
	}
}
