function Invoke-ICTRemediation {
    <#
    .SYNOPSIS
        Runs the repairs an evaluation recommends, in escalating order.
    .DESCRIPTION
        Enrollment: Sync first when only the check-in is stale; if the sync does not
        produce a successful check-in, escalate to a full re-enrollment. A broken
        enrollment (missing/expired certificate, missing tasks, no enrollment) goes
        straight to re-enrollment. Blockers stop the enrollment repair unless -Force.
        LAPS: retries LAPS policy processing when the backup failed or rotation is overdue.

        Status: NothingToDo | WhatIf | Blocked | Succeeded | Failed
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][psobject]$Evaluation,
        [psobject]$Config,
        [ValidateSet('UserCredential', 'DeviceCredential')][string]$Method,
        [switch]$Force
    )

    if (-not $Config) { $Config = Get-ICTConfig }
    if (-not $Method) { $Method = $Config.EnrollmentMethod }
    $preview = [bool]$WhatIfPreference

    $steps = New-Object 'System.Collections.Generic.List[object]'
    $result = [pscustomobject]@{
        Requested    = $true
        WhatIf       = $preview
        Status       = 'NothingToDo'
        Blockers     = @()
        ChangesMade  = $false
        Sync         = $null
        ReEnrollment = $null
        LapsRetry    = $null
        Steps        = $null
    }

    $actions = @($Evaluation.RecommendedActions)
    if ($actions.Count -eq 0) {
        $steps.Add((New-ICTStep -Name 'Repair' -Status Info -Detail 'nothing to repair'))
        $result.Steps = $steps.ToArray()
        return $result
    }

    $failed = $false
    $blocked = $false
    $enrollmentAction = $null
    if ($actions -contains 'ReEnroll') { $enrollmentAction = 'ReEnroll' }
    elseif ($actions -contains 'Sync') { $enrollmentAction = 'Sync' }

    if ($enrollmentAction) {
        $blockers = @($Evaluation.Blockers)
        if ($blockers.Count -gt 0 -and -not $Force) {
            $blocked = $true
            $result.Blockers = $blockers
            $steps.Add((New-ICTStep -Name 'Enrollment repair' -Status Fail -Detail ('blocked: {0}' -f ($blockers -join '; '))))
        }
        else {
            if ($blockers.Count -gt 0) {
                $steps.Add((New-ICTStep -Name 'Blockers' -Status Warning -Detail ('ignored (-Force): {0}' -f ($blockers -join '; '))))
            }

            if ($enrollmentAction -eq 'Sync') {
                try {
                    $sync = Invoke-ICTSync -TimeoutSeconds $Config.SyncTimeoutSeconds -WhatIf:$preview -Confirm:$false
                    $result.Sync = $sync
                    foreach ($step in @($sync.Steps)) { $steps.Add($step) }
                    if (-not $preview) {
                        $result.ChangesMade = $true
                        if (-not $sync.Succeeded) {
                            $steps.Add((New-ICTStep -Name 'Escalate' -Status Info -Detail 'the sync did not help, re-enrolling'))
                            $enrollmentAction = 'ReEnroll'
                        }
                    }
                }
                catch {
                    $steps.Add((New-ICTStep -Name 'Sync' -Status Fail -Detail $_.Exception.Message))
                    $enrollmentAction = 'ReEnroll'
                }
            }

            if ($enrollmentAction -eq 'ReEnroll') {
                try {
                    $reEnrollment = Invoke-ICTReEnrollment -Method $Method -TimeoutSeconds $Config.EnrollmentTimeoutSeconds `
                        -SkipPrerequisiteCheck:$Force -WhatIf:$preview -Confirm:$false
                    $result.ReEnrollment = $reEnrollment
                    foreach ($step in @($reEnrollment.Steps)) { $steps.Add($step) }
                    if ($reEnrollment.Status -eq 'Blocked') { $blocked = $true; $result.Blockers = @($reEnrollment.Message) }
                    elseif (-not $preview) {
                        if ($reEnrollment.Status -ne 'Failed' -or $reEnrollment.BackupPath) { $result.ChangesMade = $true }
                        if (-not $reEnrollment.Succeeded) { $failed = $true }
                    }
                }
                catch {
                    $steps.Add((New-ICTStep -Name 'Re-enroll' -Status Fail -Detail $_.Exception.Message))
                    $failed = $true
                }
            }
        }
    }

    if ($actions -contains 'LapsRetry') {
        try {
            $laps = Invoke-ICTLapsRetry -WhatIf:$preview -Confirm:$false
            $result.LapsRetry = $laps
            foreach ($step in @($laps.Steps)) { $steps.Add($step) }
            if (-not $preview) {
                $result.ChangesMade = $true
                if (-not $laps.Succeeded) { $failed = $true }
            }
        }
        catch {
            $steps.Add((New-ICTStep -Name 'LAPS retry' -Status Fail -Detail $_.Exception.Message))
            $failed = $true
        }
    }

    if ($blocked) { $result.Status = 'Blocked' }
    elseif ($preview) { $result.Status = 'WhatIf' }
    elseif ($failed) { $result.Status = 'Failed' }
    else { $result.Status = 'Succeeded' }

    $result.Steps = $steps.ToArray()
    return $result
}
