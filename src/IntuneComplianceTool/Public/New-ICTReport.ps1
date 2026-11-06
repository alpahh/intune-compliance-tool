function New-ICTReport {
    <#
    .SYNOPSIS
        Combines device data, evaluation and (optional) repair results into one report
        object. This object is what -Json prints and what Export-ICTReport saves.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][psobject]$DeviceData,
        [Parameter(Mandatory)][psobject]$Evaluation,
        [psobject]$Remediation,
        [psobject]$PostRemediationEvaluation,
        [psobject]$PostRemediationDeviceData
    )

    $finalStatus = $Evaluation.OverallStatus
    if ($PostRemediationEvaluation) { $finalStatus = $PostRemediationEvaluation.OverallStatus }

    return [pscustomobject]@{
        Tool                      = 'IntuneComplianceTool'
        ToolVersion               = $script:ICTVersion
        GeneratedAt               = ConvertTo-ICTIsoDate ([datetime]::UtcNow)
        ComputerName              = $DeviceData.ComputerName
        OverallStatus             = $finalStatus
        Evaluation                = $Evaluation
        Remediation               = $Remediation
        PostRemediationEvaluation = $PostRemediationEvaluation
        DeviceData                = $DeviceData
        PostRemediationDeviceData = $PostRemediationDeviceData
    }
}
