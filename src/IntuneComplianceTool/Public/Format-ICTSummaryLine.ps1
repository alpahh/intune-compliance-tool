function Format-ICTSummaryLine {
    <#
    .SYNOPSIS
        One tab-separated line per device for batch runs (ict.sh with several hosts):
        computer, status, failed, warnings, recommended actions, failed checks.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][psobject]$Report)

    $evaluation = $(if ($Report.PostRemediationEvaluation) { $Report.PostRemediationEvaluation } else { $Report.Evaluation })
    $failed = @($evaluation.Results | Where-Object { $_.Status -eq 'Fail' } | ForEach-Object { $_.Name })
    $actions = @($evaluation.RecommendedActions)
    $fields = @(
        $Report.ComputerName
        $Report.OverallStatus
        $evaluation.Summary.Fail
        $evaluation.Summary.Warning
        $(if ($actions.Count) { $actions -join ',' } else { '-' })
        $(if ($failed.Count) { $failed -join '; ' } else { '-' })
    )
    return (($fields | ForEach-Object { "$_" -replace '\t', ' ' }) -join "`t")
}
