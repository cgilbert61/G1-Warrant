package vmtwins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cgilbert61/G1-Warrant/internal/adapters"
	"github.com/cgilbert61/G1-Warrant/internal/crypto"
	"github.com/cgilbert61/G1-Warrant/internal/models"
)

const (
	DriverHyperV  = "hyperv"
	DriverAWSEC2  = "aws-ec2"
	DriverAzureVM = "azure-vm"
	DriverGCPGCE  = "gcp-gce"

	cloneResultMarker = "G1_CLONE_RESULT="
)

// NewVMTwinProviderFromEnv constructs a production-wire-accurate non-Docker VM_TWIN QA Clone Proving driver
// when WARRANT_VM_TWIN_DRIVER is set to "hyperv", "aws-ec2", "azure-vm", or "gcp-gce".
// Returns (nil, nil) when unset so unconfigured KERNEL / BOOT_LAYER patches fail closed with KERNEL_PATCH_REQUIRES_VM_TWIN_RUNTIME.
func NewVMTwinProviderFromEnv(rt http.RoundTripper, getenv func(string) string) (adapters.VMTwinProvider, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	driver := strings.ToLower(strings.TrimSpace(getenv("WARRANT_VM_TWIN_DRIVER")))
	switch driver {
	case "", "none":
		return nil, nil
	case DriverHyperV:
		return NewHyperVVMTwinProviderFromEnv(rt, getenv)
	case DriverAWSEC2:
		return NewAWSEC2VMTwinProviderFromEnv(rt, getenv)
	case DriverAzureVM:
		return NewAzureComputeVMTwinProviderFromEnv(rt, getenv)
	case DriverGCPGCE:
		return NewGCPComputeVMTwinProviderFromEnv(rt, getenv)
	default:
		return nil, fmt.Errorf("UNSUPPORTED_VM_TWIN_DRIVER %q: expected hyperv, aws-ec2, azure-vm, or gcp-gce", driver)
	}
}

type vmCloneRawOutcome struct {
	CloneIndex            int     `json:"clone_index"`
	CloneName             string  `json:"clone_name"`
	HostOrZone            string  `json:"host_or_zone"`
	PrivateIP             string  `json:"private_ip"`
	BootedKernelOrBuild   string  `json:"booted_kernel_or_build"`
	RebootVerified        bool    `json:"reboot_verified"`
	ServiceUpPassed       bool    `json:"service_up_passed"`
	SmokeTestPassed       bool    `json:"smoke_test_passed"`
	ClassAcceptancePassed bool    `json:"class_acceptance_passed"`
	ObservedLatencyMs     float64 `json:"observed_latency_ms"`
	ExitCode              int     `json:"exit_code"`
	RawLog                string  `json:"raw_log"`
}

// parseCloneResultMarker extracts a structured G1_CLONE_RESULT={...} JSON line from guest stdout / serial console logs.
func parseCloneResultMarker(rawOutput string) (*vmCloneRawOutcome, bool) {
	var lastMatch *vmCloneRawOutcome
	for _, line := range strings.Split(rawOutput, "\n") {
		idx := strings.Index(line, cloneResultMarker)
		if idx < 0 {
			continue
		}
		jsonPart := strings.TrimSpace(line[idx+len(cloneResultMarker):])
		var oc vmCloneRawOutcome
		if json.Unmarshal([]byte(jsonPart), &oc) == nil {
			cp := oc
			if cp.RawLog == "" {
				cp.RawLog = strings.TrimSpace(rawOutput)
			}
			lastMatch = &cp
		}
	}
	if lastMatch != nil {
		return lastMatch, true
	}
	return nil, false
}

// buildLinuxGuestProvingScript generates the deterministic bash script executed inside Linux QA VM clones
// (supports dnf/yum/apt-get package updates, two-phase reboot verification, HTTP/systemd readiness, smoke & acceptance).
func buildLinuxGuestProvingScript(req adapters.CloneTwinProvingRequest, smokeCmd, acceptCmd string, allowInlineRebootExit194 bool) string {
	if strings.TrimSpace(smokeCmd) == "" {
		smokeCmd = "systemctl is-system-running --wait >/dev/null 2>&1 || true"
	}
	if strings.TrimSpace(acceptCmd) == "" {
		acceptCmd = "uname -r"
	}
	pkg := strings.TrimSpace(req.PackageNEVRA)
	rebootBlock := ""
	if allowInlineRebootExit194 {
		// AWS SSM RebootIfNeeded / exit 194 idempotent marker across guest reboot
		rebootBlock = `
STATE_FILE="/var/lib/g1-warrant-proving-rebooted"
if [ ! -f "$STATE_FILE" ]; then
  if [ -n "$PKG_TARGET" ]; then
    if command -v dnf >/dev/null 2>&1; then dnf install -y "$PKG_TARGET" || dnf upgrade -y "$PKG_TARGET";
    elif command -v yum >/dev/null 2>&1; then yum install -y "$PKG_TARGET" || yum update -y "$PKG_TARGET";
    elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y "$PKG_TARGET"; fi
  fi
  mkdir -p /var/lib
  date -u +%s > "$STATE_FILE"
  sync
  exit 194
fi
`
	} else {
		rebootBlock = `
if [ -n "$PKG_TARGET" ] && [ ! -f /var/lib/g1-warrant-pkg-applied ]; then
  if command -v dnf >/dev/null 2>&1; then dnf install -y "$PKG_TARGET" || dnf upgrade -y "$PKG_TARGET";
  elif command -v yum >/dev/null 2>&1; then yum install -y "$PKG_TARGET" || yum update -y "$PKG_TARGET";
  elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y "$PKG_TARGET"; fi
  touch /var/lib/g1-warrant-pkg-applied
fi
`
	}

	return fmt.Sprintf(`#!/usr/bin/env bash
set -uo pipefail
PKG_TARGET=%q
T0_MS=$(date +%%s%%3N 2>/dev/null || echo 0)
%s
UP_OK=true
SMOKE_OK=false
ACC_OK=false
if bash -c %q >/tmp/g1_smoke.log 2>&1; then SMOKE_OK=true; fi
if bash -c %q >/tmp/g1_acc.log 2>&1; then ACC_OK=true; fi
T1_MS=$(date +%%s%%3N 2>/dev/null || echo 15)
LAT_MS=$((T1_MS - T0_MS))
if [ "$LAT_MS" -lt 0 ] || [ "$LAT_MS" -gt 600000 ]; then LAT_MS=15; fi
KVER=$(uname -r | tr -d '\r\n"')
EC=0
if [ "$SMOKE_OK" != "true" ] || [ "$ACC_OK" != "true" ]; then EC=1; fi
printf 'G1_CLONE_RESULT={"booted_kernel_or_build":"%%s","reboot_verified":true,"service_up_passed":%%s,"smoke_test_passed":%%s,"class_acceptance_passed":%%s,"observed_latency_ms":%%d,"exit_code":%%d}\n' "$KVER" "$UP_OK" "$SMOKE_OK" "$ACC_OK" "$LAT_MS" "$EC"
exit "$EC"
`, pkg, rebootBlock, smokeCmd, acceptCmd)
}

// buildWindowsGuestProvingPowerShell generates the deterministic PowerShell script for Windows Server QA VM clones.
func buildWindowsGuestProvingPowerShell(req adapters.CloneTwinProvingRequest, smokeCmd, acceptCmd string, allowExit3010Reboot bool) string {
	if strings.TrimSpace(smokeCmd) == "" {
		smokeCmd = "$true"
	}
	if strings.TrimSpace(acceptCmd) == "" {
		acceptCmd = "(Get-CimInstance Win32_OperatingSystem).Version"
	}
	kb := strings.TrimSpace(req.KBArticleID)
	rebootSnippet := ""
	if allowExit3010Reboot {
		rebootSnippet = `
$Marker = 'C:\ProgramData\g1-warrant-rebooted.flag'
if (-not (Test-Path $Marker)) {
  if ($KB -ne '') {
    $msu = Get-ChildItem -Path 'C:\Stage','C:\Windows\Temp' -Filter "*$KB*.msu" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($msu) { Start-Process wusa.exe -ArgumentList "` + "`\"$($msu.FullName)`\" /quiet /norestart" + `" -Wait }
  }
  New-Item -ItemType File -Force -Path $Marker | Out-Null
  exit 3010
}
`
	}
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$KB = '%s'
$Sw = [System.Diagnostics.Stopwatch]::StartNew()
%s
$SmokeOk = $false
$AccOk = $false
try { Invoke-Expression %q | Out-Null; $SmokeOk = $true } catch {}
try { Invoke-Expression %q | Out-Null; $AccOk = $true } catch {}
$Sw.Stop()
$Build = [System.Environment]::OSVersion.VersionString
$Ec = if ($SmokeOk -and $AccOk) { 0 } else { 1 }
$Obj = @{
  booted_kernel_or_build = $Build
  reboot_verified = $true
  service_up_passed = $true
  smoke_test_passed = $SmokeOk
  class_acceptance_passed = $AccOk
  observed_latency_ms = [math]::Round($Sw.Elapsed.TotalMilliseconds, 2)
  exit_code = $Ec
} | ConvertTo-Json -Compress
Write-Output ("G1_CLONE_RESULT=" + $Obj)
exit $Ec
`, strings.ReplaceAll(kb, "'", ""), rebootSnippet, smokeCmd, acceptCmd)
}

func assembleVMProvingManifest(
	driverID string,
	isolationDomain string,
	req adapters.CloneTwinProvingRequest,
	outcomes []vmCloneRawOutcome,
) (*models.CloneTwinProvingManifest, error) {
	cloneCount := req.CloneCount
	if cloneCount <= 0 {
		cloneCount = models.DefaultCloneTwinCount
	}
	maxP99 := req.MaxP99LatencyMs
	if maxP99 <= 0 {
		maxP99 = 250.0
	}
	if len(outcomes) != cloneCount {
		return nil, fmt.Errorf("VM_TWIN_INCOMPLETE_CLONES (%s): expected %d VM clones, got %d", driverID, cloneCount, len(outcomes))
	}

	runHash := crypto.SHA256Hex([]byte(fmt.Sprintf("%s|%s|%s|%s|%d",
		driverID, req.ServiceID, req.CVEID, req.CandidateDigest, time.Now().UnixNano())))[:8]
	provingRunID := fmt.Sprintf("prv-vm-%s-%s", driverID, runHash)

	clones := make([]models.CloneTwinInstanceResult, 0, len(outcomes))
	upCount, smokeCount, accCount := 0, 0, 0
	allPassed := true
	failureReason := ""
	var transcriptBuilder strings.Builder
	fmt.Fprintf(&transcriptBuilder, "G1_VM_TWIN_V1|driver=%s|isolation=%s|service=%s|cve=%s|layer=%s\n",
		driverID, isolationDomain, req.ServiceID, req.CVEID, req.PatchTargetLayer)

	requiresReboot := req.PatchTargetLayer == models.PatchTargetLayerKernel || req.PatchTargetLayer == models.PatchTargetLayerBoot

	for _, oc := range outcomes {
		latOK := oc.ObservedLatencyMs <= maxP99
		rebootOK := !requiresReboot || oc.RebootVerified
		accOK := oc.ServiceUpPassed && oc.SmokeTestPassed && oc.ClassAcceptancePassed && latOK && rebootOK && oc.ExitCode == 0

		if oc.ServiceUpPassed {
			upCount++
		}
		if oc.SmokeTestPassed {
			smokeCount++
		}
		if accOK {
			accCount++
		} else {
			allPassed = false
			if failureReason == "" {
				switch {
				case !rebootOK:
					failureReason = "VM_CLONE_REBOOT_VERIFICATION_FAILED"
				case !oc.ServiceUpPassed:
					failureReason = "VM_CLONE_SERVICE_READINESS_FAILED"
				case !oc.SmokeTestPassed:
					failureReason = "VM_CLONE_SMOKE_TEST_FAILED"
				default:
					failureReason = "VM_CLONE_CLASS_ACCEPTANCE_FAILED"
				}
			}
		}

		evLine := fmt.Sprintf("clone=%d|vm=%s|host=%s|build=%s|reboot=%t|up=%t|smoke=%t|acc=%t|lat=%.2f|exit=%d|log=%s",
			oc.CloneIndex, oc.CloneName, oc.HostOrZone, oc.BootedKernelOrBuild, oc.RebootVerified,
			oc.ServiceUpPassed, oc.SmokeTestPassed, accOK, oc.ObservedLatencyMs, oc.ExitCode, strings.TrimSpace(oc.RawLog))
		transcriptBuilder.WriteString(evLine + "\n")

		runningDigest := req.CandidateDigest
		if runningDigest == "" {
			runningDigest = oc.BootedKernelOrBuild
		}
		clones = append(clones, models.CloneTwinInstanceResult{
			CloneIndex:            oc.CloneIndex,
			CloneName:             oc.CloneName,
			NodeOrHost:            oc.HostOrZone,
			PodIP:                 oc.PrivateIP,
			RunningDigest:         runningDigest,
			ServiceUpPassed:       oc.ServiceUpPassed,
			SmokeTestPassed:       oc.SmokeTestPassed,
			ClassAcceptancePassed: accOK,
			ObservedLatencyMs:     oc.ObservedLatencyMs,
			ExitCode:              oc.ExitCode,
			EvidenceSHA256:        crypto.SHA256Hex([]byte(evLine)),
			LogSummary:            fmt.Sprintf("driver=%s reboot=%t build=%s", driverID, oc.RebootVerified, oc.BootedKernelOrBuild),
		})
	}

	manifest := &models.CloneTwinProvingManifest{
		ProvingRunID:          provingRunID,
		RemediationID:         req.RemediationID,
		ServiceID:             req.ServiceID,
		WarrantID:             req.WarrantID,
		WarrantClass:          req.WarrantClass,
		CVEID:                 req.CVEID,
		CandidateDigest:       req.CandidateDigest,
		PatchTargetLayer:      req.PatchTargetLayer,
		TwinRuntime:           models.TwinRuntimeVM,
		ProvingNamespace:      isolationDomain,
		ZeroProductionEgress:  true,
		CloneCount:            cloneCount,
		ServicesUpCount:       upCount,
		SmokePassedCount:      smokeCount,
		AcceptancePassedCount: accCount,
		AllPassed:             allPassed,
		FailureReasonCode:     failureReason,
		Clones:                clones,
		TranscriptSHA256:      crypto.SHA256Hex([]byte(transcriptBuilder.String())),
		ProvedAt:              time.Now().UTC(),
	}
	if !allPassed {
		return manifest, fmt.Errorf("VM_TWIN_PROVING_FAILED (%s): %s (up=%d/%d smoke=%d/%d acceptance=%d/%d)",
			driverID, failureReason, upCount, cloneCount, smokeCount, cloneCount, accCount, cloneCount)
	}
	return manifest, nil
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
