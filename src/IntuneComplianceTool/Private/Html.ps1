function ConvertTo-ICTHtml {
    <# Self-contained HTML page for a report. All values are HTML-encoded. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][psobject]$Report)

    $enc = { param($Value) [System.Net.WebUtility]::HtmlEncode("$Value") }

    $evaluation = $Report.Evaluation
    $data = $Report.DeviceData
    if ($Report.PostRemediationEvaluation) {
        $evaluation = $Report.PostRemediationEvaluation
        $data = $Report.PostRemediationDeviceData
    }

    $statusClass = @{ Compliant = 'pass'; NonCompliant = 'fail'; EnrollmentBroken = 'fail'; Indeterminate = 'warn' }[$evaluation.OverallStatus]
    $rowClass = @{ Pass = 'pass'; Fail = 'fail'; Warning = 'warn'; Unknown = 'unknown'; Info = 'info' }

    $device = $data.Device
    $deviceRows = @(
        , @('Computer', $data.ComputerName)
        , @('Model', $(if ($device) { '{0} {1}' -f $device.Manufacturer, $device.Model }))
        , @('Serial', $(if ($device) { $device.SerialNumber }))
        , @('OS', $(if ($device) { '{0} {1} ({2}.{3})' -f $device.OSCaption, $device.OSDisplayVersion, $device.OSBuild, $device.OSUpdateBuildRevision }))
        , @('Join', $(if ($data.Join) { '{0} - {1}' -f $data.Join.JoinType, $data.Join.TenantName }))
        , @('Signed-in user', $data.ConsoleUser)
        , @('Collected as', $data.RunAs)
        , @('Collected at (UTC)', $data.CollectedAt)
    ) | ForEach-Object { '<tr><th>{0}</th><td>{1}</td></tr>' -f (& $enc $_[0]), (& $enc $_[1]) }

    $recommended = (@($evaluation.RecommendedActions) -join ', ')
    if (-not $recommended) { $recommended = 'nothing' }

    $checkRows = foreach ($result in @($evaluation.Results)) {
        '<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f $rowClass[$result.Status],
        (& $enc $result.Status), (& $enc $result.Category), (& $enc $result.Name), (& $enc $result.Actual),
        (& $enc ((@($result.Message, $result.Remediation) | Where-Object { $_ }) -join ' Fix: '))
    }

    $repairRows = ''
    if ($Report.Remediation -and @($Report.Remediation.Steps).Count -gt 0) {
        $items = foreach ($step in @($Report.Remediation.Steps)) {
            '<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f $rowClass["$($step.Status)"], (& $enc $step.Status), (& $enc $step.Name), (& $enc $step.Detail)
        }
        $repairRows = '<h2>Repair</h2><table><tr><th>Status</th><th>Step</th><th>Detail</th></tr>' + ($items -join '') + '</table>'
    }

    $errorRows = ''
    $errors = @($data.CollectionErrors | Where-Object { $_ })
    if ($errors.Count -gt 0) {
        $items = foreach ($item in $errors) { '<li>{0}: {1}</li>' -f (& $enc $item.Section), (& $enc $item.Error) }
        $errorRows = '<h2>Could not read</h2><ul>' + ($items -join '') + '</ul>'
    }

    $title = 'Intune compliance - {0}' -f $data.ComputerName
    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(& $enc $title)</title>
<style>
:root { --bg:#ffffff; --fg:#1d1d1f; --muted:#6e6e73; --line:#e5e5ea; --pass:#1a7f37; --fail:#cf222e; --warn:#9a6700; --info:#0969da; }
@media (prefers-color-scheme: dark) { :root { --bg:#161618; --fg:#f2f2f7; --muted:#a1a1a6; --line:#2c2c2e; --pass:#3fb950; --fail:#f85149; --warn:#d29922; --info:#58a6ff; } }
body { background:var(--bg); color:var(--fg); font:14px/1.45 -apple-system, "Segoe UI", sans-serif; margin:24px; }
h1 { font-size:20px; margin:0 0 4px; } h2 { font-size:16px; margin:28px 0 8px; }
.badge { display:inline-block; padding:4px 12px; border-radius:6px; font-weight:600; color:#fff; }
.badge.pass { background:var(--pass); } .badge.fail { background:var(--fail); } .badge.warn { background:var(--warn); }
table { border-collapse:collapse; width:100%; } th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:500; }
tr.pass td:first-child { color:var(--pass); } tr.fail td:first-child { color:var(--fail); font-weight:600; }
tr.warn td:first-child { color:var(--warn); } tr.unknown td:first-child { color:var(--muted); } tr.info td:first-child { color:var(--info); }
.muted { color:var(--muted); }
</style>
</head>
<body>
<h1>$(& $enc $title)</h1>
<p><span class="badge $statusClass">$(& $enc $evaluation.OverallStatus)</span>
<span class="muted">Recommended: $(& $enc $recommended) - generated $(& $enc $Report.GeneratedAt) UTC by IntuneComplianceTool $(& $enc $Report.ToolVersion)</span></p>
<h2>Device</h2>
<table>$($deviceRows -join '')</table>
<h2>Checks</h2>
<table><tr><th>Status</th><th>Category</th><th>Check</th><th>Value</th><th>Details</th></tr>$($checkRows -join '')</table>
$repairRows
$errorRows
</body>
</html>
"@
}
