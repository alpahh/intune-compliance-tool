function Invoke-ICTRemediation {
    <#
    .SYNOPSIS
        Runs the repairs an evaluation recommends.
    .DESCRIPTION
        Order: TimeSync (w32tm resync), ServiceFix (re-enable / start MDM services),
        then the enrollment repair, then LapsRetry.
        Enrollment: a stale check-in gets a sync first; if the sync does not produce a
        successful check-in, it escalates to a re-enrollment (EscalateSyncToReEnroll).
        A broken enrollment goes straight to re-enrollment. Blockers stop the
        enrollment repair; -Force overrides them, but never the re-enrollment's own
        safety checks (Entra join, a usable signed-in user).

        Status: NothingToDo | WhatIf | Blocked | Succeeded | Failed
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][psobject]$Evaluation,
        [psobject]$Config,
        [ValidateSet('UserCredential', 'DeviceCredential')][string]$Method,
        [string[]]$ExcludeAccount = @(),
        [string]$WorkDirectory,
        [switch]$Force,
        [scriptblock]$OnProgress
    )

    if (-not $Config) { $Config = Get-ICTConfig }
    if (-not $Method) { $Method = $Config.EnrollmentMethod }
    $preview = [bool]$WhatIfPreference

    $steps = New-Object 'System.Collections.Generic.List[object]'
    $state = @{ Failed = $false; Blocked = $false; Changed = $false }
    $result = [pscustomobject]@{
        WhatIf = $preview; Status = 'NothingToDo'; Blockers = @(); ChangesMade = $false
        Sync = $null; ReEnrollment = $null; LapsRetry = $null; Steps = $null
    }
    # Runs one repair: records its steps, and a failure instead of throwing.
    $run = {
        param([string]$Name, [scriptblock]$Repair)
        try {
            $outcome = & $Repair
            if ($outcome -and $outcome.PSObject.Properties['Steps']) {
                foreach ($step in @($outcome.Steps)) { $steps.Add($step) }
                if (-not $preview -and $outcome.Status -ne 'Blocked' -and $outcome.Status -ne 'NoEnrollment') { $state.Changed = $true }
                if (-not $preview -and -not $outcome.Succeeded -and $outcome.Status -ne 'Blocked') { $state.Failed = $true }
            }
            return $outcome
        }
        catch {
            $steps.Add((New-ICTStep $Name Fail $_.Exception.Message))
            if (-not $preview) { $state.Failed = $true; $state.Changed = $true }   # it may have changed something before failing
        }
    }

    $actions = @($Evaluation.RecommendedActions)
    if ($actions.Count -eq 0) {
        $steps.Add((New-ICTStep 'Repair' Info 'nothing to repair'))
        $result.Steps = $steps.ToArray()
        return $result
    }

    $clockFixed = $true
    if ($actions -contains 'TimeSync') {
        $failedBefore = $state.Failed
        $null = & $run 'Time sync' {
            if ($preview) { return [pscustomobject]@{ Succeeded = $true; Status = 'WhatIf'; Steps = @(New-ICTStep 'Time sync' Info 'would resynchronise the clock (w32tm /resync)') } }
            Invoke-ICTTimeResync
            [pscustomobject]@{ Succeeded = $true; Status = 'Succeeded'; Steps = @(New-ICTStep 'Time sync' Pass 'clock resynchronised') }
        }
        $clockFixed = ($state.Failed -eq $failedBefore)
    }

    if ($actions -contains 'ServiceFix') {
        foreach ($finding in @($Evaluation.Results | Where-Object { $_.Action -eq 'ServiceFix' })) {
            $service = $finding.Id.Substring(4)
            $null = & $run "Service $service" {
                $startType = $(if ($service -eq 'IntuneManagementExtension') { 'Automatic' } else { 'Manual' })
                $what = $(if ($finding.Actual -eq 'disabled') { "set to $startType" + $(if ($startType -eq 'Automatic') { ' and start' } else { '' }) } else { 'start' })
                if ($preview) { return [pscustomobject]@{ Succeeded = $true; Status = 'WhatIf'; Steps = @(New-ICTStep "Service $service" Info "would $what") } }
                if ($finding.Actual -eq 'disabled') { Set-ICTServiceStartType -Name $service -StartupType $startType }
                if ($finding.Actual -ne 'disabled' -or $startType -eq 'Automatic') { Start-ICTService -Name $service }
                [pscustomobject]@{ Succeeded = $true; Status = 'Succeeded'; Steps = @(New-ICTStep "Service $service" Pass ($what -replace '^set', 'set' -replace '^start', 'started')) }
            }
        }
    }

    $enrollmentAction = @($actions | Where-Object { $_ -eq 'ReEnroll' -or $_ -eq 'Sync' }) | Select-Object -First 1
    if ($enrollmentAction -and -not $clockFixed) {
        # With a wrong clock, certificate checks fail: a sync or a new enrollment would fail too.
        $state.Blocked = $true
        $result.Blockers = @('Clock: could not be resynchronised')
        $steps.Add((New-ICTStep 'Enrollment repair' Fail 'skipped: the clock could not be fixed'))
        $enrollmentAction = $null
    }
    $reEnroll = {
        $blockers = @($Evaluation.ReEnrollBlockers)
        if ($blockers.Count -gt 0 -and -not $Force) {
            $state.Blocked = $true
            $result.Blockers = $blockers
            $steps.Add((New-ICTStep 'Re-enroll' Fail ('blocked: {0}' -f ($blockers -join '; '))))
            return
        }
        if ($blockers.Count -gt 0) { $steps.Add((New-ICTStep 'Blockers' Warning ('ignored (-Force): {0}' -f ($blockers -join '; ')))) }
        $result.ReEnrollment = & $run 'Re-enroll' {
            Invoke-ICTReEnrollment -Method $Method -WorkDirectory $WorkDirectory -ExcludeAccount $ExcludeAccount -ScriptTimeoutSeconds $Config.RepairScriptTimeoutSeconds `
                -TimeoutSeconds $Config.EnrollmentTimeoutSeconds -OnProgress $OnProgress -WhatIf:$preview -Confirm:$false
        }
        if ($result.ReEnrollment.Status -eq 'Blocked') {
            $state.Blocked = $true
            $result.Blockers = @($result.ReEnrollment.Message)
        }
    }

    if ($enrollmentAction -eq 'Sync') {
        $syncBlockers = @($Evaluation.SyncBlockers)
        if ($syncBlockers.Count -gt 0 -and -not $Force) {
            $state.Blocked = $true
            $result.Blockers = $syncBlockers
            $steps.Add((New-ICTStep 'Sync' Fail ('blocked: {0}' -f ($syncBlockers -join '; '))))
        }
        else {
            $failedBeforeSync = $state.Failed
            $result.Sync = & $run 'Sync' { Invoke-ICTSync -TimeoutSeconds $Config.SyncTimeoutSeconds -OnProgress $OnProgress -WhatIf:$preview -Confirm:$false }
            $escalate = [bool]$Config.EscalateSyncToReEnroll
            if ($preview -and $escalate) {
                $steps.Add((New-ICTStep 'Escalate' Info ('if no check-in within {0} s: remove and re-create the enrollment' -f $Config.SyncTimeoutSeconds)))
            }
            elseif (-not $preview -and -not ($result.Sync -and $result.Sync.Succeeded) -and $escalate) {
                $state.Failed = $failedBeforeSync   # the sync failure is superseded by the re-enrollment result
                $steps.Add((New-ICTStep 'Escalate' Info 'the sync did not help, re-enrolling'))
                & $reEnroll
            }
        }
    }
    elseif ($enrollmentAction -eq 'ReEnroll') { & $reEnroll }

    if ($actions -contains 'LapsRetry') { $result.LapsRetry = & $run 'LAPS retry' { Invoke-ICTLapsRetry -WhatIf:$preview -Confirm:$false } }

    $result.ChangesMade = $state.Changed
    $result.Status = $(if ($state.Failed) { 'Failed' } elseif ($state.Blocked) { 'Blocked' } elseif ($preview) { 'WhatIf' } else { 'Succeeded' })
    $result.Steps = $steps.ToArray()
    return $result
}
