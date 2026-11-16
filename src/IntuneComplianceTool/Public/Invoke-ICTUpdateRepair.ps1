function Invoke-ICTUpdateRepair {
    <#
    .SYNOPSIS
        Repairs a broken Windows Update: re-enables its services, resets its components
        and starts a new scan.
    .DESCRIPTION
        Runs as SYSTEM in a temporary scheduled task (a dropped SSH session cannot stop it
        half-way): re-enables disabled update services, stops them, sets SoftwareDistribution
        and catroot2 aside (renamed, not deleted; only the newest copy is kept), starts the
        services again and starts a scan. With -Deep it also runs DISM /RestoreHealth and
        sfc /scannow, which can take an hour. Resetting clears the update history shown
        in Settings.
        Afterwards it waits for a successful scan. It refuses to start while Windows Update
        is installing or another repair of this tool runs.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [switch]$Deep,
        [string]$WorkDirectory,
        [ValidateRange(30, 14400)][int]$ScriptTimeoutSeconds = 900,
        [ValidateRange(0, 3600)][int]$ScanTimeoutSeconds = 300,
        [ValidateRange(1, 60)][int]$PollIntervalSeconds = 5,
        [scriptblock]$OnProgress
    )

    if (-not (Test-ICTIsWindows)) { throw 'Invoke-ICTUpdateRepair must run on Windows.' }
    if (-not (Test-ICTIsElevated)) { throw 'Invoke-ICTUpdateRepair must run as administrator.' }
    if (-not $WorkDirectory) { $WorkDirectory = Join-Path $env:ProgramData 'IntuneComplianceTool' }

    $steps = New-Object 'System.Collections.Generic.List[object]'
    $result = [pscustomobject]@{ Status = 'NotStarted'; Succeeded = $false; Deep = [bool]$Deep; Folder = $null; Message = $null; Steps = $null }
    $finish = {
        param([string]$Status, [string]$Message)
        $result.Status = $Status
        if ($Message) { $result.Message = $Message }
        $result.Steps = $steps.ToArray()
        return $result
    }

    try {
        $agent = Get-ICTWindowsUpdateState   # its dates stay empty while wuauserv is disabled: that is fine here
        $running = Test-ICTRepairRunning
        $policy = Get-ICTUpdatePolicy
    }
    catch {
        $steps.Add((New-ICTStep 'Update repair' Fail $_.Exception.Message))
        return (& $finish 'Failed' "Windows Update could not be checked: $($_.Exception.Message)")
    }
    if ($running) {
        $steps.Add((New-ICTStep 'Update repair' Fail 'another repair is running'))
        return (& $finish 'Blocked' 'Another repair of this tool is still running as SYSTEM. Wait until it has finished.')
    }
    if ($agent.InstallerBusy -eq $true) {
        $steps.Add((New-ICTStep 'Update repair' Fail 'Windows Update is installing right now'))
        return (& $finish 'Blocked' 'Windows Update is installing right now. Run the repair when it has finished.')
    }

    # DISM repairs from Windows Update, unless WSUS or a policy blocks that and no repair source is set.
    $noRepairSource = (-not $policy.RepairFromWindowsUpdate -and (($policy.WsusServer -and -not $policy.QualityFromWindowsUpdate) -or $policy.DisableAccess))
    $what = 'reset the Windows Update components (clears the update history in Settings)' + $(if ($Deep) { ', run DISM /RestoreHealth and sfc /scannow' } else { '' })
    if ($WhatIfPreference -or -not $PSCmdlet.ShouldProcess([System.Environment]::MachineName, ($what.Substring(0, 1).ToUpperInvariant() + $what.Substring(1)))) {
        $steps.Add((New-ICTStep 'Update repair' Info "would $what (as SYSTEM)"))
        $steps.Add((New-ICTStep 'Update scan' Info ('would start a scan and wait up to {0} s' -f $ScanTimeoutSeconds)))
        return (& $finish 'WhatIf' $null)
    }

    $started = [datetime]::UtcNow
    $stamp = [datetime]::Now.ToString('yyyyMMdd-HHmmss', $script:ICTInvariant)
    try {
        Protect-ICTDirectory -Path $WorkDirectory
        $folder = New-ICTPrivateDirectory -Parent (Join-Path $WorkDirectory 'Repair') -Prefix "update-$stamp"
        $result.Folder = $folder
        $statePath = Join-Path $folder 'repair-state.jsonl'
        $scriptPath = Join-Path $folder 'update-repair.ps1'
        Set-Content -LiteralPath $scriptPath -Encoding UTF8 -ErrorAction Stop -Value (New-ICTUpdateRepairScript -StatePath $statePath -Stamp $stamp -Deep:$Deep -NoRepairSource:$noRepairSource)
        Remove-ICTSystemTask   # finished leftovers of earlier runs
        $taskName = Start-ICTSystemScript -ScriptPath $scriptPath -TimeLimitMinutes ([int][math]::Ceiling($ScriptTimeoutSeconds / 60) + 10)
    }
    catch {
        $steps.Add((New-ICTStep 'Start repair as SYSTEM' Fail $_.Exception.Message))
        return (& $finish 'Failed' "The update repair could not be started, so nothing was changed: $($_.Exception.Message)")
    }

    $keepTask = $false
    # If the task was killed (time limit) its own cleanup did not run: start the update services again.
    $restartServices = { foreach ($name in 'CryptSvc', 'BITS', 'wuauserv', 'UsoSvc') { try { Start-ICTService -Name $name } catch { Write-ICTLog -Level Warning "Could not start ${name}: $($_.Exception.Message)" } } }
    $previousCtrlC = Set-ICTCtrlCAsInput -Enabled $true
    try {
        $wait = Wait-ICTSystemScript -TaskName $taskName -StatePath $statePath -TimeoutSeconds $ScriptTimeoutSeconds -PollIntervalSeconds $PollIntervalSeconds -Label 'update repair' -OnProgress $OnProgress
        $stageNames = [ordered]@{ services = 'Update services'; stop = 'Stop services'; reset = 'Reset components'; 'start-services' = 'Start services'; dism = 'DISM RestoreHealth'; sfc = 'System file check'; scan = 'Start scan' }
        foreach ($line in @($wait.Lines | Where-Object { $stageNames.Contains([string]$_.Stage) })) {
            $status = 'Pass'
            if ($line.Detail -like 'skipped*') { $status = 'Info' }
            elseif ($line.Detail -match 'kept|failed|0x|restart required') { $status = 'Warning' }
            $steps.Add((New-ICTStep $stageNames[[string]$line.Stage] $status $line.Detail))
        }
        if ($wait.Stopped) {
            $keepTask = $true
            $code = $(if ($null -ne $wait.Stopped.LastTaskResult) { '0x{0:X8}' -f [int64]$wait.Stopped.LastTaskResult } else { 'unknown' })
            $steps.Add((New-ICTStep 'Update repair' Fail "the task stopped without finishing (result $code)"))
            & $restartServices
            return (& $finish 'Failed' "The update repair task stopped without finishing (result $code). The update services were started again.")
        }
        if (-not $wait.Final) {
            $keepTask = $true
            $steps.Add((New-ICTStep 'Update repair' Warning ('still running after {0} s' -f $ScriptTimeoutSeconds)))
            return (& $finish 'Pending' "The update repair is still running as SYSTEM and finishes on its own. Progress: $statePath")
        }
        if ($wait.Final.Status -ne 'Succeeded') {
            $steps.Add((New-ICTStep 'Update repair' Fail $wait.Final.Detail))
            return (& $finish 'Failed' "The update repair stopped at $($wait.Final.Detail). The update services were started again.")
        }

        # The reset worked; now wait for Windows Update to find updates successfully again.
        $attempts = [int][math]::Ceiling($ScanTimeoutSeconds / $PollIntervalSeconds)
        for ($i = 1; $i -le $attempts; $i++) {
            Start-Sleep -Seconds $PollIntervalSeconds
            if ($OnProgress) { & $OnProgress ('waiting for a successful update scan ({0} s)' -f ($i * $PollIntervalSeconds)) }
            $scan = $null
            try { $scan = ConvertFrom-ICTDate (Get-ICTWindowsUpdateState).LastSearchSuccess } catch { Write-ICTLog "Update agent not ready yet: $($_.Exception.Message)" }
            if ($scan -and $scan -gt $started) {
                $result.Succeeded = $true
                $steps.Add((New-ICTStep 'Update scan' Pass ('succeeded after {0} s' -f [int]([datetime]::UtcNow - $started).TotalSeconds)))
                return (& $finish 'Succeeded' $null)
            }
        }
        # Not a failure: scans can take longer, and the reset itself worked.
        $result.Succeeded = $true
        $steps.Add((New-ICTStep 'Update scan' Warning ('no successful scan within {0} s yet' -f $ScanTimeoutSeconds)))
        return (& $finish 'Succeeded' 'The components were reset, but the new scan has not finished yet. Run the tool again later to confirm.')
    }
    catch {
        $keepTask = $true
        $steps.Add((New-ICTStep 'Monitor update repair' Fail $_.Exception.Message))
        return (& $finish 'Failed' "Monitoring the update repair failed: $($_.Exception.Message). It may still be running as SYSTEM.")
    }
    finally {
        if ($null -ne $previousCtrlC) { $null = Set-ICTCtrlCAsInput -Enabled $previousCtrlC }
        if (-not $keepTask) { Remove-ICTSystemTask -TaskName $taskName }
    }
}
