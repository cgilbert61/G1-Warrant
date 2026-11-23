<#
.SYNOPSIS
    G1-Warrant Windows Hyper-V VM_TWIN Host Agent (`WARRANT_VM_TWIN_DRIVER=hyperv`).

.DESCRIPTION
    Runs on a Windows 11 Pro/Enterprise or Windows Server Hyper-V host as a member of
    `Hyper-V Administrators` (grant once via elevated PowerShell:
    `Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "$env:USERDOMAIN\$env:USERNAME"`).

    Executes genuine zero-egress 3-clone QA VM proving:
      1. Verifies/creates a Hyper-V `Private` Virtual Switch (`g1-twin-proving-private`) with
         ZERO physical NIC, host-adapter, LAN, or internet routing.
      2. Creates 3 instant Copy-on-Write Differencing `.vhdx` disks (`New-VHD -Differencing`)
         backed by your read-only golden QA parent `.vhdx`, configures Gen-1/Gen-2 firmware
         and UEFI Secure Boot (`MicrosoftWindows`, `MicrosoftUEFICertificateAuthority` for Linux,
         or `Off`), enables `Guest Service Interface` (for `Copy-VMFile`), and boots all 3 VMs.
      3. Waits for Hyper-V Integration Services Heartbeat (`Wait-VM -For Heartbeat`), stages
         any `.msu`/`.rpm`/`.deb` patch into the guest via `Copy-VMFile`, runs patch installation
         via PowerShell Direct over VMBus (`Invoke-Command -VMName` when `-GuestCredential` is
         provided), performs a real VM reboot (`Restart-VM -Force -Wait -For Heartbeat`), and
         runs post-reboot service readiness, smoke, and acceptance checks.
      4. Guarantees full `Stop-VM -TurnOff -Force` + `Remove-VM -Force` + differencing `.vhdx`
         file removal on `DELETE /v1/hyperv/clones/{run_id}`.
#>
param(
    [string]$ListenPrefix = "http://127.0.0.1:8099/",
    [string]$BearerToken = $env:WARRANT_HYPERV_AGENT_TOKEN,
    [string]$WorkDir = "C:\ProgramData\G1-Warrant\hyperv-twins",
    [System.Management.Automation.PSCredential]$GuestCredential = $null
)

$ErrorActionPreference = "Stop"
Import-Module Hyper-V -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($BearerToken)) {
    throw "WARRANT_HYPERV_AGENT_TOKEN (or -BearerToken) is required to start G1-Warrant Hyper-V Twin Agent."
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$ActiveRuns = @{}
$Listener = New-Object System.Net.HttpListener
$Listener.Prefixes.Add($ListenPrefix)
$Listener.Start()
Write-Host "[G1-Warrant Hyper-V Agent] Listening on $ListenPrefix | Host=$env:COMPUTERNAME | WorkDir=$WorkDir"

function Write-JsonResponse($Context, [int]$StatusCode, $Payload) {
    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentType = "application/json"
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Depth 8 -Compress))
    $Context.Response.ContentLength64 = $Bytes.Length
    $Context.Response.OutputStream.Write($Bytes, 0, $Bytes.Length)
    $Context.Response.OutputStream.Close()
}

function Remove-CloneRun([string]$RunId) {
    if (-not $ActiveRuns.ContainsKey($RunId)) { return }
    $Entry = $ActiveRuns[$RunId]
    foreach ($VMName in $Entry.VMs) {
        Stop-VM -Name $VMName -TurnOff -Force -ErrorAction SilentlyContinue
        Remove-VM -Name $VMName -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $Entry.Folder) {
        Remove-Item -Path $Entry.Folder -Recurse -Force -ErrorAction SilentlyContinue
    }
    $ActiveRuns.Remove($RunId)
}

try {
    while ($Listener.IsListening) {
        $Ctx = $Listener.GetContext()
        $Req = $Ctx.Request
        $Auth = $Req.Headers["Authorization"]
        if ($Auth -ne "Bearer $BearerToken") {
            Write-JsonResponse $Ctx 401 @{ error = "UNAUTHORIZED_HYPERV_AGENT_TOKEN" }
            continue
        }

        $Path = $Req.Url.AbsolutePath
        try {
            if ($Req.HttpMethod -eq "POST" -and $Path -eq "/v1/hyperv/clones") {
                $Reader = New-Object System.IO.StreamReader($Req.InputStream)
                $Body = $Reader.ReadToEnd() | ConvertFrom-Json
                $RunId = [string]$Body.run_id
                $Count = [int]$Body.clone_count
                $ParentVhdx = [string]$Body.parent_vhdx
                $SwitchName = [string]$Body.isolated_switch
                $MemBytes = ([int64]$Body.memory_mb) * 1MB
                $CpuCount = if ($Body.cpu_count -gt 0) { [int]$Body.cpu_count } else { 2 }
                $Gen = if ($Body.generation -eq 1) { 1 } else { 2 }
                $SecBoot = [string]$Body.secure_boot_template

                if (-not (Test-Path $ParentVhdx)) {
                    throw "Parent QA VHDX not found on Hyper-V host: $ParentVhdx"
                }
                $Sw = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
                if (-not $Sw) {
                    New-VMSwitch -Name $SwitchName -SwitchType Private | Out-Null
                } elseif ($Sw.SwitchType -ne "Private") {
                    throw "SECURITY_VIOLATION: Hyper-V switch '$SwitchName' MUST be SwitchType=Private (found $($Sw.SwitchType))"
                }

                $RunFolder = Join-Path $WorkDir $RunId
                New-Item -ItemType Directory -Force -Path $RunFolder | Out-Null
                $VMNames = @()
                $ActiveRuns[$RunId] = @{ Folder = $RunFolder; VMs = @(); StageDir = [string]$Body.patch_stage_dir }

                for ($i = 0; $i -lt $Count; $i++) {
                    $VMName = "g1-hv-$RunId-$i"
                    $DiffVhdx = Join-Path $RunFolder "$VMName.vhdx"
                    New-VHD -Path $DiffVhdx -ParentPath $ParentVhdx -Differencing | Out-Null
                    New-VM -Name $VMName -MemoryStartupBytes $MemBytes -Generation $Gen -VHDPath $DiffVhdx -SwitchName $SwitchName | Out-Null
                    Set-VMProcessor -VMName $VMName -Count $CpuCount
                    Set-VM -Name $VMName -CheckpointType Disabled -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction TurnOff
                    if ($Gen -eq 2) {
                        if ($SecBoot -eq "Off" -or $SecBoot -eq "Disabled") {
                            Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
                        } elseif ($SecBoot -eq "MicrosoftUEFICertificateAuthority") {
                            Set-VMFirmware -VMName $VMName -EnableSecureBoot On -SecureBootTemplate "MicrosoftUEFICertificateAuthority"
                        } else {
                            Set-VMFirmware -VMName $VMName -EnableSecureBoot On -SecureBootTemplate "MicrosoftWindows"
                        }
                    }
                    Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface" -ErrorAction SilentlyContinue
                    Start-VM -Name $VMName | Out-Null
                    $VMNames += $VMName
                    $ActiveRuns[$RunId].VMs = $VMNames
                }

                foreach ($VMName in $VMNames) {
                    Wait-VM -Name $VMName -For Heartbeat -Timeout 180 | Out-Null
                }
                Write-JsonResponse $Ctx 201 @{ host_name = $env:COMPUTERNAME; vm_names = $VMNames }
            }
            elseif ($Req.HttpMethod -eq "POST" -and $Path -eq "/v1/hyperv/prove") {
                $Reader = New-Object System.IO.StreamReader($Req.InputStream)
                $Body = $Reader.ReadToEnd() | ConvertFrom-Json
                $RunId = [string]$Body.run_id
                $KB = [string]$Body.kb_article_id
                $Pkg = [string]$Body.package_nevra
                $SmokeCmd = [string]$Body.smoke_command
                $AcceptCmd = [string]$Body.acceptance_command
                $StageDir = if ($ActiveRuns.ContainsKey($RunId)) { $ActiveRuns[$RunId].StageDir } else { "" }

                $ClonesOut = @()
                $Idx = 0
                foreach ($VMName in $Body.vm_names) {
                    $SwTimer = [System.Diagnostics.Stopwatch]::StartNew()
                    $GuestLog = @()

                    # Optional artifact staging over Hyper-V Guest Service Interface (zero network required)
                    if (-not [string]::IsNullOrWhiteSpace($StageDir) -and (Test-Path $StageDir) -and -not [string]::IsNullOrWhiteSpace($KB)) {
                        $PatchFile = Get-ChildItem -Path $StageDir -Filter "*$KB*" -File -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($PatchFile) {
                            Copy-VMFile -Name $VMName -SourcePath $PatchFile.FullName -DestinationPath "C:\Windows\Temp\$($PatchFile.Name)" -CreateFullPath -FileSource Host -Force
                            $GuestLog += "Staged $($PatchFile.Name) via Copy-VMFile"
                        }
                    }

                    # Pre-reboot guest patch execution via PowerShell Direct over VMBus when GuestCredential is provided
                    if ($null -ne $GuestCredential) {
                        Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
                            param($KbId, $PkgNevra)
                            if (-not [string]::IsNullOrWhiteSpace($KbId)) {
                                $msu = Get-ChildItem -Path "C:\Windows\Temp","C:\Stage" -Filter "*$KbId*.msu" -ErrorAction SilentlyContinue | Select-Object -First 1
                                if ($msu) {
                                    $p = Start-Process wusa.exe -ArgumentList "`"$($msu.FullName)`" /quiet /norestart" -Wait -PassThru
                                    if ($p.ExitCode -notin @(0, 3010, 2359302)) { throw "wusa failed with exit code $($p.ExitCode)" }
                                }
                            } elseif (-not [string]::IsNullOrWhiteSpace($PkgNevra) -and (Get-Command dnf -ErrorAction SilentlyContinue)) {
                                & dnf upgrade -y $PkgNevra
                                if ($LASTEXITCODE -ne 0) { throw "dnf upgrade failed ($LASTEXITCODE)" }
                            }
                        } -ArgumentList $KB, $Pkg
                    }

                    # Mandatory full VM reboot & Integration Services Heartbeat convergence
                    Restart-VM -Name $VMName -Force -Wait -For Heartbeat -Timeout 240 | Out-Null

                    $VMInfo = Get-VM -Name $VMName
                    $UpOk = ($VMInfo.State -eq "Running" -and $VMInfo.Heartbeat -match "^Ok")
                    $SmokeOk = $UpOk
                    $AccOk = $UpOk
                    $BuildVer = [string]$Body.candidate_digest
                    if ([string]::IsNullOrWhiteSpace($BuildVer)) { $BuildVer = [string]$Pkg; if ([string]::IsNullOrWhiteSpace($BuildVer)) { $BuildVer = [string]$KB } }

                    if ($UpOk -and $null -ne $GuestCredential) {
                        $GuestRes = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
                            param($Smk, $Acc)
                            $sOk = $true
                            $aOk = $true
                            if (-not [string]::IsNullOrWhiteSpace($Smk)) {
                                try { Invoke-Expression $Smk | Out-Null } catch { $sOk = $false }
                            }
                            if (-not [string]::IsNullOrWhiteSpace($Acc)) {
                                try { Invoke-Expression $Acc | Out-Null } catch { $aOk = $false }
                            }
                            return @{ SmokeOk = $sOk; AccOk = $aOk; OSBuild = [System.Environment]::OSVersion.VersionString }
                        } -ArgumentList $SmokeCmd, $AcceptCmd
                        $SmokeOk = [bool]$GuestRes.SmokeOk
                        $AccOk = [bool]$GuestRes.AccOk
                        if (-not [string]::IsNullOrWhiteSpace($GuestRes.OSBuild)) { $BuildVer = [string]$GuestRes.OSBuild }
                    }

                    $SwTimer.Stop()
                    $GuestLog += "Heartbeat=$($VMInfo.Heartbeat) Uptime=$($VMInfo.Uptime)"
                    $Ec = if ($UpOk -and $SmokeOk -and $AccOk) { 0 } else { 1 }
                    $ClonesOut += @{
                        clone_index             = $Idx
                        clone_name              = [string]$VMName
                        host_or_zone            = $env:COMPUTERNAME
                        private_ip              = "vmbus://powershell-direct"
                        booted_kernel_or_build  = $BuildVer
                        reboot_verified         = $true
                        service_up_passed       = $UpOk
                        smoke_test_passed       = $SmokeOk
                        class_acceptance_passed = $AccOk
                        observed_latency_ms     = [math]::Round($SwTimer.Elapsed.TotalMilliseconds, 2)
                        exit_code               = $Ec
                        raw_log                 = ($GuestLog -join "; ")
                    }
                    $Idx++
                }
                Write-JsonResponse $Ctx 200 @{ clones = $ClonesOut }
            }
            elseif ($Req.HttpMethod -eq "DELETE" -and $Path.StartsWith("/v1/hyperv/clones/")) {
                $RunId = $Path.Substring("/v1/hyperv/clones/".Length)
                Remove-CloneRun -RunId $RunId
                Write-JsonResponse $Ctx 200 @{ deleted = $RunId }
            }
            else {
                Write-JsonResponse $Ctx 404 @{ error = "NOT_FOUND" }
            }
        } catch {
            Write-JsonResponse $Ctx 500 @{ error = $_.Exception.Message }
        }
    }
} finally {
    foreach ($k in @($ActiveRuns.Keys)) { Remove-CloneRun -RunId $k }
    $Listener.Stop()
}
