function Invoke-ICTLapsRetry {
    <#
    .SYNOPSIS
        Runs Windows LAPS policy processing again (Invoke-LapsPolicyProcessing).
    .DESCRIPTION
        Retries the LAPS backup to Entra ID. It does not force a password rotation.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()

    if (-not (Test-ICTIsWindows)) { throw 'Invoke-ICTLapsRetry must run on Windows.' }

    $steps = New-Object 'System.Collections.Generic.List[object]'
    $result = [pscustomobject]@{ Action = 'LapsRetry'; Status = 'NotStarted'; Succeeded = $false; Message = $null; Steps = $null }

    if (-not $PSCmdlet.ShouldProcess([System.Environment]::MachineName, 'Run LAPS policy processing')) {
        $result.Status = 'WhatIf'
        $steps.Add((New-ICTStep -Name 'LAPS retry' -Status Info -Detail 'would run Invoke-LapsPolicyProcessing'))
    }
    else {
        try {
            Invoke-ICTLapsPolicyProcessing
            $result.Status = 'Succeeded'
            $result.Succeeded = $true
            $steps.Add((New-ICTStep -Name 'LAPS retry' -Status Pass -Detail 'LAPS policy processing ran'))
        }
        catch {
            $result.Status = 'Failed'
            $result.Message = $_.Exception.Message
            $steps.Add((New-ICTStep -Name 'LAPS retry' -Status Fail -Detail $_.Exception.Message))
        }
    }

    $result.Steps = $steps.ToArray()
    return $result
}
