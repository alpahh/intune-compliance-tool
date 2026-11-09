function Invoke-ICTSync {
    <#
    .SYNOPSIS
        Starts an Intune MDM sync and waits for a successful check-in.
    .DESCRIPTION
        Starts the PushLaunch task of every Intune enrollment, then polls until the
        last successful OMA-DM session moves forward. On devices that do not record
        that time, a newer successful run of the enrollment's tasks counts instead
        (the same fallback the Last check-in rule uses).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [ValidateRange(0, 3600)][int]$TimeoutSeconds = 180,
        [ValidateRange(1, 300)][int]$PollIntervalSeconds = 5,
        [scriptblock]$OnProgress
    )

    if (-not (Test-ICTIsWindows)) { throw 'Invoke-ICTSync must run on Windows.' }

    $steps = New-Object 'System.Collections.Generic.List[object]'
    $result = [pscustomobject]@{ Status = 'NotStarted'; Succeeded = $false; LastSuccessBefore = $null; LastSuccessAfter = $null; Message = $null; Steps = $null }
    $finish = {
        param([string]$Status, [string]$Message)
        $result.Status = $Status
        if ($Message) { $result.Message = $Message }
        $result.Steps = $steps.ToArray()
        return $result
    }

    $ids = @(Get-ICTEnrollmentRegistry | Where-Object { $_.IsIntune } | ForEach-Object { $_.EnrollmentId })
    if ($ids.Count -eq 0) {
        $steps.Add((New-ICTStep 'Sync' Fail 'no Intune enrollment'))
        return (& $finish 'NoEnrollment' 'No Intune enrollment exists, so there is nothing to sync.')
    }

    $before = Get-ICTLatestServerSuccess -EnrollmentId $ids
    $result.LastSuccessBefore = ConvertTo-ICTIsoDate $before

    if ($WhatIfPreference -or -not $PSCmdlet.ShouldProcess([System.Environment]::MachineName, 'Start an Intune sync (PushLaunch task)')) {
        $steps.Add((New-ICTStep 'Sync' Info ('would start PushLaunch and wait up to {0} s' -f $TimeoutSeconds)))
        return (& $finish 'WhatIf' $null)
    }

    $started = [datetime]::UtcNow
    $launched = @($ids | Where-Object { Start-ICTEnterpriseMgmtSyncTask -EnrollmentId $_ }).Count
    if ($launched -eq 0) {
        $steps.Add((New-ICTStep 'Start sync' Fail 'PushLaunch task not found'))
        return (& $finish 'Failed' 'The PushLaunch task does not exist, so a sync cannot be started.')
    }
    $steps.Add((New-ICTStep 'Start sync' Pass 'PushLaunch task started'))

    $attempts = [int][math]::Ceiling($TimeoutSeconds / $PollIntervalSeconds)
    for ($i = 1; $i -le $attempts; $i++) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $waited = $i * $PollIntervalSeconds
        if ($OnProgress) { & $OnProgress ('waiting for a successful check-in ({0} s)' -f $waited) }

        $after = Get-ICTLatestServerSuccess -EnrollmentId $ids
        $success = ($after -and ($null -eq $before -or $after -gt $before))
        if (-not $success -and $null -eq $before) {
            # No server success time on this device: accept a newer successful task run.
            $success = [bool](@(Get-ICTEnterpriseMgmtTask | Where-Object {
                        $ids -contains $_.EnrollmentId -and $_.TaskName -ne 'PushLaunch' -and $_.LastTaskResult -eq 0 -and (ConvertFrom-ICTDate $_.LastRunTime) -gt $started
                    }).Count)
        }
        if ($success) {
            $result.LastSuccessAfter = ConvertTo-ICTIsoDate $after
            $result.Succeeded = $true
            $steps.Add((New-ICTStep 'Check-in' Pass ('succeeded after {0} s' -f $waited)))
            return (& $finish 'Succeeded' $null)
        }
    }

    $steps.Add((New-ICTStep 'Check-in' Fail ('no successful check-in within {0} s' -f $TimeoutSeconds)))
    return (& $finish 'TimedOut' 'The sync was started, but no successful check-in was recorded in time.')
}
