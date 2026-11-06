function Invoke-ICTSync {
    <#
    .SYNOPSIS
        Starts an Intune MDM sync and waits for a successful check-in.
    .DESCRIPTION
        Starts the PushLaunch scheduled task of every Intune enrollment, then polls the
        OMA-DM "last successful session" time until it moves forward or the timeout
        passes. Changes nothing else; the lightest possible repair.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [ValidateRange(0, 3600)][int]$TimeoutSeconds = 180,
        [ValidateRange(1, 300)][int]$PollIntervalSeconds = 15
    )

    if (-not (Test-ICTIsWindows)) { throw 'Invoke-ICTSync must run on Windows.' }

    $steps = New-Object 'System.Collections.Generic.List[object]'
    $result = [pscustomobject]@{
        Action            = 'Sync'
        Status            = 'NotStarted'
        Succeeded         = $false
        EnrollmentIds     = @()
        LastSuccessBefore = $null
        LastSuccessAfter  = $null
        Message           = $null
        Steps             = $null
    }

    $ids = @(Get-ICTEnrollmentRegistry | Where-Object { $_.IsIntune } | ForEach-Object { $_.EnrollmentId })
    $result.EnrollmentIds = $ids
    if ($ids.Count -eq 0) {
        $result.Status = 'NoEnrollment'
        $result.Message = 'No Intune enrollment exists, so there is nothing to sync.'
        $steps.Add((New-ICTStep -Name 'Sync' -Status Fail -Detail 'no Intune enrollment'))
        $result.Steps = $steps.ToArray()
        return $result
    }

    $before = Get-ICTLatestServerSuccess -EnrollmentId $ids
    $result.LastSuccessBefore = ConvertTo-ICTIsoDate $before

    if (-not $PSCmdlet.ShouldProcess([System.Environment]::MachineName, 'Start an Intune sync (PushLaunch task)')) {
        $result.Status = 'WhatIf'
        $steps.Add((New-ICTStep -Name 'Sync' -Status Info -Detail ('would start PushLaunch and wait up to {0} s' -f $TimeoutSeconds)))
        $result.Steps = $steps.ToArray()
        return $result
    }

    $started = 0
    foreach ($id in $ids) {
        if (Start-ICTEnterpriseMgmtSyncTask -EnrollmentId $id) { $started++ }
    }
    if ($started -eq 0) {
        $result.Status = 'Failed'
        $result.Message = 'The PushLaunch task does not exist, so a sync cannot be started.'
        $steps.Add((New-ICTStep -Name 'Start sync' -Status Fail -Detail 'PushLaunch task not found'))
        $result.Steps = $steps.ToArray()
        return $result
    }
    $steps.Add((New-ICTStep -Name 'Start sync' -Status Pass -Detail 'PushLaunch task started'))

    $attempts = [int][math]::Ceiling($TimeoutSeconds / $PollIntervalSeconds)
    $waited = 0
    for ($i = 0; $i -lt $attempts; $i++) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $waited += $PollIntervalSeconds
        $after = Get-ICTLatestServerSuccess -EnrollmentId $ids
        if ($after -and ($null -eq $before -or $after -gt $before)) {
            $result.LastSuccessAfter = ConvertTo-ICTIsoDate $after
            $result.Status = 'Succeeded'
            $result.Succeeded = $true
            $steps.Add((New-ICTStep -Name 'Check-in' -Status Pass -Detail ('succeeded after {0} s' -f $waited)))
            $result.Steps = $steps.ToArray()
            return $result
        }
    }

    $result.Status = 'TimedOut'
    $result.Message = 'The sync was started, but no successful check-in was recorded in time.'
    $steps.Add((New-ICTStep -Name 'Check-in' -Status Fail -Detail ('no successful check-in within {0} s' -f $TimeoutSeconds)))
    $result.Steps = $steps.ToArray()
    return $result
}
