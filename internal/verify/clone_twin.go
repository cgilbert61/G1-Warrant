package verify

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
	"github.com/cgilbert61/G1-Warrant/internal/policy"
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

	req := adapters.CloneTwinProvingRequest{
		RemediationID:    item.RemediationID,
		ServiceID:        svc.ServiceID,
		Namespace:        svc.Namespace,
		WarrantID:        w.WarrantID,
		WarrantClass:     w.WarrantClass,
		CVEID:            item.CVEID,
		CWEID:            item.CWEID,
		VulnerableDigest: item.VulnerableDigest,
		CandidateDigest:  item.PatchedDigest,
		KBArticleID:      kbID,
		PackageNEVRA:     pkgNEVRA,
		PatchTargetLayer: layer,
		CloneCount:       cloneCount,
		MaxP99LatencyMs:  maxP99,
	}

	e.mu.Lock()
	vmBackend := e.vmTwin
	e.mu.Unlock()

	assetKey := ""
	if item.AssetIdentity != nil {
		assetKey = item.AssetIdentity.AssetKey
	}
	preferVMTwin := vmBackend != nil && isVMTwinPreferredService(svc.ServiceID, assetKey)

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
		"proving_run_id":          manifest.ProvingRunID,
		"clone_count":             fmt.Sprintf("%d", manifest.CloneCount),
		"services_up_count":       fmt.Sprintf("%d", manifest.ServicesUpCount),
		"smoke_passed_count":      fmt.Sprintf("%d", manifest.SmokePassedCount),
		"acceptance_passed_count": fmt.Sprintf("%d", manifest.AcceptancePassedCount),
		"patch_target_layer":      manifest.PatchTargetLayer,
		"twin_runtime":            manifest.TwinRuntime,
		"all_passed":              fmt.Sprintf("%t", manifest.AllPassed),
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
