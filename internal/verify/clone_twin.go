package verify

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/adapters/estatereader"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
	"github.com/google/uuid"
)

// ClassifyPatchTargetLayer classifies whether a candidate patch mutates USERSPACE_SOFTWARE, KERNEL, or BOOT_LAYER.
// Container twins share the host kernel and cannot prove a kernel or bootloader they never boot.
func ClassifyPatchTargetLayer(explicitLayer, packagePURL, packageNEVRA, kbArticleID string, touchedFiles []string) string {
	switch strings.ToUpper(strings.TrimSpace(explicitLayer)) {
	case models.PatchTargetLayerKernel:
		return models.PatchTargetLayerKernel
	case models.PatchTargetLayerBoot:
		return models.PatchTargetLayerBoot
	}

	combined := strings.ToLower(strings.Join([]string{packagePURL, packageNEVRA, kbArticleID, strings.Join(touchedFiles, " ")}, " "))
	bootTokens := []string{
		"grub2", "shim-x64", "shim-aa64", "systemd-boot", "dracut-boot",
		"initramfs", "efibootmgr", "/boot/efi", "/boot/grub", "uefi-dbx",
	}
	for _, tok := range bootTokens {
		if strings.Contains(combined, tok) {
			return models.PatchTargetLayerBoot
		}
	}

	kernelTokens := []string{
		"linux-image-", "linux-headers-", "kernel-core", "kernel-modules",
		"pkg:rpm/redhat/kernel@", "pkg:rpm/fedora/kernel@", "pkg:deb/ubuntu/linux-image",
		"pkg:deb/debian/linux-image", "vmlinuz", "kmod-", "kernel-lt-", "kernel-ml-",
	}
	for _, tok := range kernelTokens {
		if strings.Contains(combined, tok) {
			return models.PatchTargetLayerKernel
		}
	}

	return models.PatchTargetLayerUserspace
}

// SetVMTwinProvider registers a full-VM / microVM hypervisor twin backend for KERNEL and BOOT_LAYER patches.
func (e *Engine) SetVMTwinProvider(vm adapters.VMTwinProvider) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.vmTwin = vm
}

// SetEstateReaders registers the v1.4.0 EstateReader registry for proving-time estate re-reads and drift gating.
func (e *Engine) SetEstateReaders(reg *estatereader.Registry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.estateReaders = reg
}

type provingEstateMetadata struct {
	ResolutionPath        string
	SourceSystem          string
	QueryIdentity         string
	SigningReadAt         *time.Time
	ProvingReadAt         *time.Time
	SigningSnapshotSHA256 string
	ProvingSnapshotSHA256 string
	DriftPolicy           string
	DriftTolerancePct     float64
	ObservedDriftPct      float64
	DriftExceeded         bool
	DriftDeltaSummary     string
	ResolvedSources       []models.ResolvedCloneSourceEvidence
	BaseCloneImage        string
}

func stampEstateMetadataOnManifest(m *models.CloneTwinProvingManifest, meta provingEstateMetadata) {
	if m == nil {
		return
	}
	m.CloneSourceResolutionPath = meta.ResolutionPath
	m.EstateSourceSystem = meta.SourceSystem
	m.EstateQueryIdentity = meta.QueryIdentity
	m.SigningReadAt = meta.SigningReadAt
	m.ProvingReadAt = meta.ProvingReadAt
	m.SigningSnapshotSHA256 = meta.SigningSnapshotSHA256
	m.ProvingSnapshotSHA256 = meta.ProvingSnapshotSHA256
	m.EstateDriftPolicy = meta.DriftPolicy
	m.EstateDriftTolerancePct = meta.DriftTolerancePct
	m.ObservedDriftPct = meta.ObservedDriftPct
	m.DriftExceeded = meta.DriftExceeded
	m.DriftDeltaSummary = meta.DriftDeltaSummary
	m.ResolvedCloneSources = meta.ResolvedSources
	if meta.ResolutionPath != "" {
		m.TranscriptSHA256 = crypto.SHA256Hex([]byte(fmt.Sprintf("%s|res=%s|sig_sha=%s|prv_sha=%s|drift=%.2f|exc=%t",
			m.TranscriptSHA256, meta.ResolutionPath, meta.SigningSnapshotSHA256, meta.ProvingSnapshotSHA256, meta.ObservedDriftPct, meta.DriftExceeded)))
	}
}

// resolveCloneSourcesAndEvaluateDrift enforces Item 2, Item 4, and Item 5:
//  1. Resolves clone sources from signed Standing Warrant class (`SIGNED_CLASS` or `SIGNED_CLASS_MANUAL`) first,
//     falling back to env/deployment defaults (`ENV_BOOTSTRAP_FALLBACK`) only when `clone_sources[]` is empty.
//  2. Re-runs the bounded estate query at proving time for `ESTATE_LOADER` sources, appends WORM `PROVING_REREAD` evidence,
//     computes estate drift, and enforces `RECORD_ONLY` vs. `FAIL_CLOSED` (defaulting `KERNEL`/`BOOT_LAYER` to `FAIL_CLOSED` on unavailability).
func (e *Engine) resolveCloneSourcesAndEvaluateDrift(
	ctx context.Context,
	item *models.RemediationItem,
	svc *models.EstateService,
	w *models.WarrantRecord,
	layer string,
	cloneCount int,
) (provingEstateMetadata, *models.CloneTwinProvingManifest, error) {
	now := time.Now().UTC()
	isKernelOrBoot := layer == models.PatchTargetLayerKernel || layer == models.PatchTargetLayerBoot

	effPolicy := strings.ToUpper(strings.TrimSpace(w.EstateDriftPolicy))
	if effPolicy == "" {
		if isKernelOrBoot {
			effPolicy = models.EstateDriftPolicyFailClosed
		} else {
			effPolicy = models.EstateDriftPolicyRecordOnly
		}
	}
	tolPct := w.EstateDriftTolerancePct
	if tolPct <= 0 {
		tolPct = models.DefaultEstateDriftTolPct
	}

	if len(w.CloneSources) == 0 {
		return provingEstateMetadata{
			ResolutionPath:    models.CloneSourceResolutionEnvFallback,
			DriftPolicy:       effPolicy,
			DriftTolerancePct: tolPct,
		}, nil, nil
	}

	primary := w.CloneSources[0]
	mode := strings.ToUpper(strings.TrimSpace(primary.SourceMode))
	if mode == "" {
		mode = models.CloneSourceModeEstateLoader
	}

	// Case A: Explicit Operator Manual Override (`SIGNED_CLASS_MANUAL`)
	if mode == models.CloneSourceModeManual {
		resolved := make([]models.ResolvedCloneSourceEvidence, 0, len(w.CloneSources))
		for _, cs := range w.CloneSources {
			age := cs.ImageAgeSecondsAtSign
			if cs.ImageCreatedAt != "" {
				if ts, err := time.Parse(time.RFC3339, cs.ImageCreatedAt); err == nil {
					if calc := int64(now.Sub(ts.UTC()).Seconds()); calc >= 0 {
						age = calc
					}
				}
			}
			resolved = append(resolved, models.ResolvedCloneSourceEvidence{
				SourceSystem:    cs.SourceSystem,
				ImageIdentity:   cs.ImageIdentity,
				SourceMode:      models.CloneSourceModeManual,
				ImageCreatedAt:  cs.ImageCreatedAt,
				ImageAgeSeconds: age,
			})
		}
		return provingEstateMetadata{
			ResolutionPath:    models.CloneSourceResolutionSignedClassManual,
			SourceSystem:      primary.SourceSystem,
			QueryIdentity:     primary.QueryIdentity,
			DriftPolicy:       effPolicy,
			DriftTolerancePct: tolPct,
			DriftDeltaSummary: "MANUAL_CLONE_SOURCE_DECLARED_AT_SIGNING",
			ResolvedSources:   resolved,
			BaseCloneImage:    primary.ImageIdentity,
		}, nil, nil
	}

	// Case B: `ESTATE_LOADER` Signed Class Clone Source (`SIGNED_CLASS`) -> Proving-Time Re-Read & Drift Gate
	sigSnapSHA := firstNonEmptyLayer(primary.SnapshotSHA256, w.EstateSnapshotSHA256)
	var signingEv *models.EstateReadEvidenceRecord
	var signingReadAt *time.Time
	if sigEv, fErr := e.store.FindEstateReadEvidenceBySnapshot(ctx, primary.SourceSystem, sigSnapSHA); fErr == nil && sigEv != nil {
		signingEv = sigEv
		ts := sigEv.ObservedAt.UTC()
		signingReadAt = &ts
	} else if !w.IssuedAt.IsZero() {
		ts := w.IssuedAt.UTC()
		signingReadAt = &ts
	}

	e.mu.Lock()
	erReg := e.estateReaders
	e.mu.Unlock()

	buildBlockedManifest := func(reasonCode, errMsg string, meta provingEstateMetadata) (*models.CloneTwinProvingManifest, error) {
		twinRT := models.TwinRuntimeContainer
		if isKernelOrBoot {
			twinRT = models.TwinRuntimeVM
		}
		failManifest := &models.CloneTwinProvingManifest{
			ProvingRunID:         "prv-estate-blocked-" + crypto.SHA256Hex([]byte(item.RemediationID+"|"+reasonCode))[:8],
			RemediationID:        item.RemediationID,
			ServiceID:            svc.ServiceID,
			WarrantID:            w.WarrantID,
			WarrantClass:         w.WarrantClass,
			CVEID:                item.CVEID,
			CandidateDigest:      item.PatchedDigest,
			PatchTargetLayer:     layer,
			TwinRuntime:          twinRT,
			ProvingNamespace:     "g1-twin-proving",
			ZeroProductionEgress: true,
			CloneCount:           cloneCount,
			AllPassed:            false,
			FailureReasonCode:    reasonCode,
			TranscriptSHA256:     crypto.SHA256Hex([]byte(reasonCode + "|" + errMsg)),
			ProvedAt:             now,
		}
		stampEstateMetadataOnManifest(failManifest, meta)
		item.CloneTwinProving = failManifest
		item.BlockerCode = reasonCode
		_ = e.store.UpsertRemediation(ctx, item)
		_ = e.recordTrace(ctx, item.RemediationID, "N3", "ESTATE_DRIFT_OR_REREAD_BLOCKED", "BLOCK", "agt-estate-reader", failManifest.TranscriptSHA256, map[string]string{
			"source_system": primary.SourceSystem,
			"drift_policy":  effPolicy,
			"reason_code":   reasonCode,
			"detail":        errMsg,
		})
		e.emit("REMEDIATION_UPDATED", item)
		return failManifest, fmt.Errorf("%s: %s", reasonCode, errMsg)
	}

	var reader estatereader.EstateReader
	var lookupErr error
	if erReg == nil {
		lookupErr = fmt.Errorf("estate reader registry not configured")
	} else {
		reader, lookupErr = erReg.Get(primary.SourceSystem)
	}

	var provSnap *models.EstateSnapshot
	var readErr error
	if lookupErr != nil {
		readErr = lookupErr
	} else {
		provSnap, readErr = reader.ReadEstateSnapshot(ctx, estatereader.EstateReadQuery{
			WarrantClass:  w.WarrantClass,
			ScopeServices: w.ScopeServices,
		})
	}

	if readErr != nil {
		meta := provingEstateMetadata{
			ResolutionPath:        models.CloneSourceResolutionSignedClass,
			SourceSystem:          primary.SourceSystem,
			QueryIdentity:         primary.QueryIdentity,
			SigningReadAt:         signingReadAt,
			SigningSnapshotSHA256: sigSnapSHA,
			DriftPolicy:           effPolicy,
			DriftTolerancePct:     tolPct,
			ObservedDriftPct:      100.0,
			DriftExceeded:         true,
			DriftDeltaSummary:     "ESTATE_REREAD_UNAVAILABLE: " + readErr.Error(),
			BaseCloneImage:        primary.ImageIdentity,
		}
		// Item 5: Unavailable at Proving follows class's estate_drift_policy, defaulting strictly to FAIL_CLOSED on KERNEL / BOOT_LAYER
		if effPolicy == models.EstateDriftPolicyFailClosed {
			return meta, nil, func() error {
				_, bErr := buildBlockedManifest("ESTATE_REREAD_UNAVAILABLE_FAIL_CLOSED", readErr.Error(), meta)
				return bErr
			}()
		}
		resolved := make([]models.ResolvedCloneSourceEvidence, 0, len(w.CloneSources))
		for _, cs := range w.CloneSources {
			resolved = append(resolved, models.ResolvedCloneSourceEvidence{
				SourceSystem:    cs.SourceSystem,
				ImageIdentity:   cs.ImageIdentity,
				SourceMode:      models.CloneSourceModeEstateLoader,
				ImageCreatedAt:  cs.ImageCreatedAt,
				ImageAgeSeconds: cs.ImageAgeSecondsAtSign,
			})
		}
		meta.ResolvedSources = resolved
		return meta, nil, nil
	}

	provTime := provSnap.ObservedAt.UTC()
	evRec := &models.EstateReadEvidenceRecord{
		EvidenceID:            "ere-prv-" + uuid.NewString()[:8],
		SourceSystem:          provSnap.SourceSystem,
		SourceTier:            provSnap.SourceTier,
		HandlerFamily:         provSnap.HandlerFamily,
		Phase:                 models.EstateReadPhaseProvingReread,
		WarrantID:             w.WarrantID,
		RemediationID:         item.RemediationID,
		QueryIdentity:         provSnap.QueryIdentity,
		ClassMembershipCount:  provSnap.ClassMembershipCount,
		OSDistSummary:         provSnap.OSBuildKernelDistribution,
		SWDistSummary:         provSnap.SoftwareVersionDistribution,
		CandidateSources:      provSnap.CandidateCloneSources,
		SourceFreshnessAt:     provSnap.SourceInventoryFreshnessAt,
		SourceFreshnessAgeSec: provSnap.SourceFreshnessAgeSeconds,
		ObservedAt:            provTime,
		SnapshotSHA256:        provSnap.SnapshotSHA256,
	}
	_ = e.store.AppendEstateReadEvidence(ctx, evRec)
	if e.agentCP != nil {
		_ = e.agentCP.RecordGovernedAdapterAction(
			ctx, w.WarrantID, item.RemediationID, "agt-estate-reader", provSnap.SourceSystem,
			models.AgentActionReadEstateSnapshot, w.Slot1PrincipalID, w.Slot2PrincipalID,
			models.EgressProfileInternalCluster, crypto.SHA256Hex([]byte(provSnap.QueryIdentity)), provSnap.SnapshotSHA256,
		)
	}

	obsDriftPct, driftExc, driftSummary := estatereader.ComputeEstateDriftDelta(
		signingEv, provSnap, w.CloneSources, tolPct, w.MaxEstateStalenessSec,
	)

	candAgeByID := map[string]models.CloneSourceCandidate{}
	for _, c := range provSnap.CandidateCloneSources {
		candAgeByID[c.ImageIdentity] = c
	}
	resolved := make([]models.ResolvedCloneSourceEvidence, 0, len(w.CloneSources))
	for _, cs := range w.CloneSources {
		imgAge := cs.ImageAgeSecondsAtSign
		createdAt := cs.ImageCreatedAt
		if liveCand, ok := candAgeByID[cs.ImageIdentity]; ok {
			imgAge = liveCand.ImageAgeSeconds
			if liveCand.CreatedAt != "" {
				createdAt = liveCand.CreatedAt
			}
		} else if createdAt != "" {
			if ts, err := time.Parse(time.RFC3339, createdAt); err == nil {
				if calc := int64(provTime.Sub(ts.UTC()).Seconds()); calc >= 0 {
					imgAge = calc
				}
			}
		}
		resolved = append(resolved, models.ResolvedCloneSourceEvidence{
			SourceSystem:    cs.SourceSystem,
			ImageIdentity:   cs.ImageIdentity,
			SourceMode:      models.CloneSourceModeEstateLoader,
			ImageCreatedAt:  createdAt,
			ImageAgeSeconds: imgAge,
		})
	}

	meta := provingEstateMetadata{
		ResolutionPath:        models.CloneSourceResolutionSignedClass,
		SourceSystem:          provSnap.SourceSystem,
		QueryIdentity:         provSnap.QueryIdentity,
		SigningReadAt:         signingReadAt,
		ProvingReadAt:         &provTime,
		SigningSnapshotSHA256: sigSnapSHA,
		ProvingSnapshotSHA256: provSnap.SnapshotSHA256,
		DriftPolicy:           effPolicy,
		DriftTolerancePct:     tolPct,
		ObservedDriftPct:      obsDriftPct,
		DriftExceeded:         driftExc,
		DriftDeltaSummary:     driftSummary,
		ResolvedSources:       resolved,
		BaseCloneImage:        primary.ImageIdentity,
	}

	if driftExc && effPolicy == models.EstateDriftPolicyFailClosed {
		failedM, bErr := buildBlockedManifest("ESTATE_DRIFT_TOLERANCE_EXCEEDED", driftSummary, meta)
		return meta, failedM, bErr
	}

	return meta, nil, nil
}

// RunCloneTwinProving executes the 3-Clone Proving Ground BEFORE promoting a patch through N2 canary waves or WN-8 distributors.
// Enforces Runtime-Follows-Patch: KERNEL and BOOT_LAYER patches fail closed (KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME) on CONTAINER_TWIN.
func (e *Engine) RunCloneTwinProving(
	ctx context.Context,
	item *models.RemediationItem,
	svc *models.EstateService,
	fixIdent *models.FixIdentity,
	patchMeta *models.ExtractedPatchMetadata,
) (*models.CloneTwinProvingManifest, error) {
	w, err := e.warrants.ReverifyWarrantForExecution(ctx, item.WarrantID, svc.ServiceID, item.CVSSScore, svc.Replicas, item.RemediationKind, item.CWEID)
	if err != nil {
		return nil, err
	}

	var pkgNEVRA, kbID, explicitLayer string
	if fixIdent != nil {
		pkgNEVRA = fixIdent.PackageNEVRA
		kbID = fixIdent.KBArticleID
	}
	var touched []string
	if patchMeta != nil {
		touched = patchMeta.TouchedFiles
	}
	layer := ClassifyPatchTargetLayer(firstNonEmptyLayer(explicitLayer, item.PatchTargetLayer), item.PackagePURL, pkgNEVRA, kbID, touched)
	item.PatchTargetLayer = layer

	cloneCount := w.CloneTwinCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	maxP99 := w.MaxP99LatencyMs
	if maxP99 <= 0 {
		maxP99 = 120.0
	}

	estateMeta, blockedManifest, driftErr := e.resolveCloneSourcesAndEvaluateDrift(ctx, item, svc, w, layer, cloneCount)
	if driftErr != nil {
		return blockedManifest, driftErr
	}

	req := adapters.CloneTwinProvingRequest{
		RemediationID:          item.RemediationID,
		ServiceID:              svc.ServiceID,
		Namespace:              svc.Namespace,
		WarrantID:              w.WarrantID,
		WarrantClass:           w.WarrantClass,
		CVEID:                  item.CVEID,
		CWEID:                  item.CWEID,
		VulnerableDigest:       item.VulnerableDigest,
		CandidateDigest:        item.PatchedDigest,
		BaseCloneImageIdentity: estateMeta.BaseCloneImage,
		KBArticleID:            kbID,
		PackageNEVRA:           pkgNEVRA,
		PatchTargetLayer:       layer,
		CloneCount:             cloneCount,
		MaxP99LatencyMs:        maxP99,
	}

	e.mu.Lock()
	vmBackend := e.vmTwin
	e.mu.Unlock()

	assetKey := ""
	if item.AssetIdentity != nil {
		assetKey = item.AssetIdentity.AssetKey
	}
	hasVMClassSource := false
	for _, cs := range w.CloneSources {
		switch strings.ToLower(cs.SourceSystem) {
		case "k8s-cilium-native", "argocd", "flux":
		default:
			if cs.SourceSystem != "" {
				hasVMClassSource = true
			}
		}
	}
	preferVMTwin := vmBackend != nil && (isVMTwinPreferredService(svc.ServiceID, assetKey) || hasVMClassSource)

	if layer == models.PatchTargetLayerKernel || layer == models.PatchTargetLayerBoot || preferVMTwin {
		if vmBackend == nil {
			failManifest := &models.CloneTwinProvingManifest{
				ProvingRunID:         "prv-blocked-" + crypto.SHA256Hex([]byte(item.RemediationID+"|"+layer))[:8],
				RemediationID:        item.RemediationID,
				ServiceID:            svc.ServiceID,
				WarrantID:            w.WarrantID,
				WarrantClass:         w.WarrantClass,
				CVEID:                item.CVEID,
				CandidateDigest:      item.PatchedDigest,
				PatchTargetLayer:     layer,
				TwinRuntime:          models.TwinRuntimeContainer,
				ProvingNamespace:     "g1-twin-proving",
				ZeroProductionEgress: true,
				CloneCount:           cloneCount,
				AllPassed:            false,
				FailureReasonCode:    "KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME",
				TranscriptSHA256:     crypto.SHA256Hex([]byte("KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME|" + item.RemediationID + "|" + layer)),
				ProvedAt:             time.Now().UTC(),
			}
			stampEstateMetadataOnManifest(failManifest, estateMeta)
			item.CloneTwinProving = failManifest
			item.BlockerCode = "KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME"
			_ = e.store.UpsertRemediation(ctx, item)
			_ = e.recordTrace(ctx, item.RemediationID, "N3", "CLONE_TWIN_PROVING_BLOCKED", "BLOCK", "clone-twin-prover", failManifest.TranscriptSHA256, map[string]string{
				"patch_target_layer": layer,
				"twin_runtime":       models.TwinRuntimeContainer,
				"reason":             "KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME",
			})
			e.emit("REMEDIATION_UPDATED", item)
			return nil, fmt.Errorf("KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME: patch targets %s layer; container twins share the host kernel and cannot prove a kernel or boot layer they never boot", layer)
		}

		vmManifest, vErr := vmBackend.RunVMTwinProving(ctx, req)
		if vErr != nil {
			if vmManifest != nil {
				vmManifest.PatchTargetLayer = layer
				vmManifest.TwinRuntime = models.TwinRuntimeVM
				stampEstateMetadataOnManifest(vmManifest, estateMeta)
				item.CloneTwinProving = vmManifest
			}
			item.BlockerCode = vErr.Error()
			_ = e.store.UpsertRemediation(ctx, item)
			_ = e.recordTrace(ctx, item.RemediationID, "N3", "CLONE_TWIN_PROVING_BLOCKED", "BLOCK", "vm-twin-prover", crypto.SHA256Hex([]byte(vErr.Error())), map[string]string{
				"patch_target_layer": layer,
				"twin_runtime":       models.TwinRuntimeVM,
				"error":              vErr.Error(),
			})
			e.emit("REMEDIATION_UPDATED", item)
			return nil, vErr
		}
		vmManifest.PatchTargetLayer = layer
		vmManifest.TwinRuntime = models.TwinRuntimeVM
		stampEstateMetadataOnManifest(vmManifest, estateMeta)
		return e.finalizeCloneTwinManifest(ctx, item, svc, w, vmManifest)
	}

	prover, ok := e.twin.(adapters.CloneTwinProver)
	if !ok {
		prover, ok = e.deploy.(adapters.CloneTwinProver)
	}
	if !ok {
		return nil, fmt.Errorf("CLONE_TWIN_PROVER_UNAVAILABLE: configured cluster adapter does not implement CloneTwinProver")
	}

	manifest, err := prover.RunCloneTwinProving(ctx, req)
	if err != nil {
		item.BlockerCode = err.Error()
		_ = e.store.UpsertRemediation(ctx, item)
		_ = e.recordTrace(ctx, item.RemediationID, "N3", "CLONE_TWIN_PROVING_BLOCKED", "BLOCK", "clone-twin-prover", crypto.SHA256Hex([]byte(err.Error())), map[string]string{
			"patch_target_layer": layer,
			"twin_runtime":       models.TwinRuntimeContainer,
			"error":              err.Error(),
		})
		e.emit("REMEDIATION_UPDATED", item)
		return nil, err
	}
	stampEstateMetadataOnManifest(manifest, estateMeta)
	return e.finalizeCloneTwinManifest(ctx, item, svc, w, manifest)
}

func (e *Engine) finalizeCloneTwinManifest(
	ctx context.Context,
	item *models.RemediationItem,
	svc *models.EstateService,
	w *models.WarrantRecord,
	manifest *models.CloneTwinProvingManifest,
) (*models.CloneTwinProvingManifest, error) {
	item.CloneTwinProving = manifest
	_ = e.agentCP.RecordGovernedAdapterAction(
		ctx, w.WarrantID, item.RemediationID, "twin_runner", svc.ServiceID,
		"ISOLATED_TWIN_EXPLOIT_REPLAY", w.Slot1PrincipalID, w.Slot2PrincipalID,
		models.EgressProfileZeroIsolated, crypto.SHA256Hex([]byte(item.PatchedDigest)), manifest.TranscriptSHA256,
	)

	outcome := "PASS"
	if !manifest.AllPassed {
		outcome = "BLOCK"
	}
	_ = e.recordTrace(ctx, item.RemediationID, "N3", "CLONE_TWIN_PROVING_VERIFIED", outcome, manifest.ProvingNamespace, manifest.TranscriptSHA256, map[string]string{
		"proving_run_id":               manifest.ProvingRunID,
		"clone_count":                  fmt.Sprintf("%d", manifest.CloneCount),
		"services_up_count":            fmt.Sprintf("%d", manifest.ServicesUpCount),
		"smoke_passed_count":           fmt.Sprintf("%d", manifest.SmokePassedCount),
		"acceptance_passed_count":      fmt.Sprintf("%d", manifest.AcceptancePassedCount),
		"patch_target_layer":           manifest.PatchTargetLayer,
		"twin_runtime":                 manifest.TwinRuntime,
		"clone_source_resolution_path": manifest.CloneSourceResolutionPath,
		"signing_snapshot_sha256":      manifest.SigningSnapshotSHA256,
		"proving_snapshot_sha256":      manifest.ProvingSnapshotSHA256,
		"observed_drift_pct":           fmt.Sprintf("%.2f", manifest.ObservedDriftPct),
		"drift_exceeded":               fmt.Sprintf("%t", manifest.DriftExceeded),
		"all_passed":                   fmt.Sprintf("%t", manifest.AllPassed),
	})
	_ = e.store.UpsertRemediation(ctx, item)
	e.emit("REMEDIATION_UPDATED", item)

	if !manifest.AllPassed {
		reason := manifest.FailureReasonCode
		if reason == "" {
			reason = "CLONE_TWIN_PROVING_FAILED"
		}
		item.BlockerCode = reason
		_ = e.store.UpsertRemediation(ctx, item)
		return manifest, fmt.Errorf("%s: %d/%d clones passed in %s (%s)",
			reason, manifest.AcceptancePassedCount, manifest.CloneCount, manifest.ProvingNamespace, manifest.TwinRuntime)
	}
	return manifest, nil
}

func populateVerifyCloneTwinFields(in *policy.VerifyInput, item *models.RemediationItem, ctp *models.CloneTwinProvingManifest) {
	if item != nil && item.PatchTargetLayer != "" {
		in.PatchTargetLayer = item.PatchTargetLayer
	}
	if ctp == nil && item != nil {
		ctp = item.CloneTwinProving
	}
	if ctp != nil {
		in.CloneTwinProvingPresent = true
		in.PatchTargetLayer = ctp.PatchTargetLayer
		in.TwinRuntime = ctp.TwinRuntime
		in.CloneTwinCount = ctp.CloneCount
		in.CloneTwinAllPassed = ctp.AllPassed
		in.EstateDriftPolicy = ctp.EstateDriftPolicy
		in.EstateDriftExceeded = ctp.DriftExceeded
	}
}

func firstNonEmptyLayer(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func isVMTwinPreferredService(serviceID, assetKey string) bool {
	raw := strings.TrimSpace(os.Getenv("WARRANT_VM_TWIN_SERVICES"))
	if raw == "" {
		return false
	}
	for _, tok := range strings.Split(raw, ",") {
		t := strings.TrimSpace(tok)
		if t == "*" || strings.EqualFold(t, serviceID) || (assetKey != "" && strings.EqualFold(t, assetKey)) {
			return true
		}
	}
	return false
}
