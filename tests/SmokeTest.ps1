<#
    Runs the finished single-file script on a real Windows machine in every output mode
    and checks the result. Used by CI; the machine does not need to be enrolled.
    Exit 0 = all good.
#>
param([Parameter(Mandatory)][string]$Bundle)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$failures = New-Object System.Collections.Generic.List[string]

function Invoke-Tool {
    param([string[]]$Arguments)
    $ErrorActionPreference = 'Continue'   # a stray stderr line must not abort the remaining checks
    $output = @(& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Bundle @Arguments 2>&1 | ForEach-Object { "$_" })
    [pscustomobject]@{ Code = $LASTEXITCODE; Output = $output; Text = ($output -join "`n") }
}
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail)
    if ($Condition) { Write-Host "ok    $Name" } else { Write-Host "FAIL  $Name  $Detail"; $failures.Add($Name) }
}

$json = Invoke-Tool @('-Json')
Assert-True '-Json: no script error' ($json.Code -ne 10) "exit $($json.Code)"
$report = $json.Text | ConvertFrom-Json
Assert-True '-Json: valid report' ($null -ne $report.Evaluation) ''
Assert-True '-Json: starts with {' ($json.Output[0].StartsWith('{')) $json.Output[0]
Assert-True '-Json: device data' ($report.DeviceData.Device.OSBuild -gt 10000) ''
Assert-True '-Json: join state' ($null -ne $report.DeviceData.Join.JoinType) ''
Assert-True '-Json: firewall profiles' (@($report.DeviceData.Security.Firewall).Count -eq 3) ''
Assert-True '-Json: endpoints tested' (@($report.DeviceData.Network.Endpoints).Count -ge 5) ''
Assert-True '-Json: clock measured' ($null -ne $report.DeviceData.Network.ClockOffsetSeconds) $report.DeviceData.Network.ClockError
Write-Host ('Could not read: ' + (@($report.DeviceData.CollectionErrors | ForEach-Object { "$($_.Section): $($_.Error)" }) -join ' | '))

$terminal = Invoke-Tool @('-NoColor', '-Detailed')
Assert-True 'terminal: no script error' ($terminal.Code -ne 10) "exit $($terminal.Code)"
Assert-True 'terminal: shows the checks' ($terminal.Text -match 'CHECKS') ''
Assert-True 'terminal: shows next steps' ($terminal.Text -match 'NEXT STEPS') ''

$color = Invoke-Tool @()
Assert-True 'colour: ANSI codes present' ($color.Text.Contains([string][char]27)) ''

$ascii = Invoke-Tool @('-NoColor', '-Ascii')
Assert-True '-Ascii: only ASCII' ($ascii.Code -ne 10 -and $ascii.Text -match 'CHECKS' -and $ascii.Text -cmatch '^[\x09\x0A\x20-\x7E]*$') "exit $($ascii.Code)"

$summary = Invoke-Tool @('-Summary')
Assert-True '-Summary: one line with 6 fields' ($summary.Code -ne 10 -and $summary.Output.Count -eq 1 -and $summary.Output[0].Split("`t").Count -eq 6 -and $summary.Output[0].Split("`t")[1] -ne 'ERROR') $summary.Text

$preview = Invoke-Tool @('-Remediate', '-WhatIf', '-Json')
Assert-True '-Remediate -WhatIf -Json: clean JSON' ($preview.Output[0].StartsWith('{') -and $preview.Text -notmatch 'What if:') $preview.Output[0]
$previewReport = $preview.Text | ConvertFrom-Json
Assert-True '-Remediate -WhatIf: nothing changed' ($previewReport.Remediation.WhatIf -eq $true -and $previewReport.Remediation.ChangesMade -eq $false) ''

if ($failures.Count) { Write-Host "$($failures.Count) smoke test(s) failed."; exit 1 }
Write-Host 'All smoke tests passed.'
exit 0
