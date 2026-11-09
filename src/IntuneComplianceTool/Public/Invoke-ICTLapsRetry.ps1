function Invoke-ICTLapsRetry {
    <#
    .SYNOPSIS
        Runs Windows LAPS policy processing again and reports its real outcome.
    .DESCRIPTION
        Invoke-LapsPolicyProcessing does not report whether the cycle worked, so the
        result is read from the LAPS event log: 10004 = succeeded, 10005 = failed.
        It does not force a password rotation.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([ValidateRange(0, 300)][int]$TimeoutSeconds = 30, [ValidateRange(1, 30)][int]$PollIntervalSeconds = 2)

    if (-not (Test-ICTIsWindows)) { throw 'Invoke-ICTLapsRetry must run on Windows.' }

    $result = [pscustomobject]@{ Status = 'NotStarted'; Succeeded = $false; Message = $null; Steps = @() }
    if ($WhatIfPreference -or -not $PSCmdlet.ShouldProcess([System.Environment]::MachineName, 'Run LAPS policy processing')) {
        $result.Status = 'WhatIf'
        $result.Steps = @(New-ICTStep 'LAPS retry' Info 'would run Invoke-LapsPolicyProcessing')
        return $result
    }

    $started = [datetime]::UtcNow
    try { Invoke-ICTLapsPolicyProcessing }
    catch {
        $result.Status = 'Failed'
        $result.Message = $_.Exception.Message
        $result.Steps = @(New-ICTStep 'LAPS retry' Fail $_.Exception.Message)
        return $result
    }

    $outcome = $null
    $attempts = [int][math]::Ceiling($TimeoutSeconds / $PollIntervalSeconds)
    for ($i = 0; $i -le $attempts -and -not $outcome; $i++) {
        if ($i -gt 0) { Start-Sleep -Seconds $PollIntervalSeconds }
        $windowMs = [int64]([datetime]::UtcNow - $started).TotalMilliseconds + 5000
        $xpath = '*[System[(EventID=10004 or EventID=10005) and TimeCreated[timediff(@SystemTime) <= {0}]]]' -f $windowMs
        $outcome = @(Get-ICTWinEvent -LogName $script:ICTLapsLogName -XPath $xpath -MaxEvents 1) | Select-Object -First 1
    }

    if ($null -eq $outcome) {
        $result.Status = 'Pending'
        $result.Message = 'LAPS processing ran, but no result was logged yet. Check the LAPS event log.'
        $result.Steps = @(New-ICTStep 'LAPS retry' Warning 'no result logged yet')
    }
    elseif ($outcome.Id -eq 10004) {
        $result.Status = 'Succeeded'
        $result.Succeeded = $true
        $result.Steps = @(New-ICTStep 'LAPS retry' Pass 'LAPS processing succeeded (event 10004)')
    }
    else {
        $result.Status = 'Failed'
        $result.Message = "LAPS processing failed: $($outcome.Message)"
        $result.Steps = @(New-ICTStep 'LAPS retry' Fail "event 10005: $($outcome.Message)")
    }
    return $result
}
