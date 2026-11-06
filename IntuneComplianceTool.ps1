<#
.SYNOPSIS
    Checks Intune MDM enrollment, compliance and LAPS on this Windows device and can
    repair a broken enrollment. Built to be run over SSH.

.DESCRIPTION
    1. Collects device, Entra join, MDM enrollment, certificate, sync, service,
       security, LAPS, network and event log data (read-only).
    2. Evaluates it and shows the result in the terminal.
    3. With -Remediate: syncs, re-enrolls and/or retries LAPS as recommended, then
       checks the device again.

    Exit codes: 0 compliant, 1 not compliant or indeterminate, 2 enrollment broken
    (not repaired), 3 repair attempted but failed, 10 error.

.PARAMETER Remediate
    Repair what can be repaired. No confirmation prompt: passing this switch is the
    consent. Combine with -WhatIf to only see what would happen.
.PARAMETER Force
    Repair even when blockers were found (e.g. an unreachable endpoint).
.PARAMETER EnrollmentMethod
    UserCredential (default, needs a user signed in at the device) or DeviceCredential.
.PARAMETER Detailed
    Show the reason and fix for every finding, plus recent MDM errors.
.PARAMETER Json
    Print only the full report as JSON (for scripts: ssh ... -Json | jq).
.PARAMETER SaveReport
    Also save the report as JSON and HTML in -OutputDirectory.
.PARAMETER OutputDirectory
    Folder for the log, saved reports and enrollment backups.
    Default: C:\ProgramData\IntuneComplianceTool
.PARAMETER ConfigPath
    JSON file that overrides default settings (see README).
.PARAMETER NoColor
    No ANSI colours. Also set by the NO_COLOR environment variable.
.PARAMETER Ascii
    Plain ASCII symbols and boxes for terminals without Unicode.

.EXAMPLE
    .\IntuneComplianceTool.ps1
.EXAMPLE
    .\IntuneComplianceTool.ps1 -Remediate -WhatIf
.EXAMPLE
    .\IntuneComplianceTool.ps1 -Remediate -EnrollmentMethod DeviceCredential
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Remediate,
    [switch]$Force,
    [ValidateSet('UserCredential', 'DeviceCredential')][string]$EnrollmentMethod,
    [switch]$Detailed,
    [switch]$Json,
    [switch]$SaveReport,
    [ValidateSet('Json', 'Html', 'Both')][string]$ReportFormat = 'Both',
    [string]$OutputDirectory,
    [string]$ConfigPath,
    [switch]$NoColor,
    [switch]$Ascii,
    [string]$CommandHint = '.\IntuneComplianceTool.ps1'
)

# Registry paths differ for 32-bit processes (WOW64 redirection): restart in 64-bit PowerShell.
if ([System.Environment]::Is64BitOperatingSystem -and -not [System.Environment]::Is64BitProcess -and $env:windir) {
    $powershell64 = Join-Path $env:windir 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $powershell64) {
        $relaunchArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        foreach ($entry in $PSBoundParameters.GetEnumerator()) {
            if ($entry.Value -is [System.Management.Automation.SwitchParameter]) {
                if ($entry.Value.IsPresent) { $relaunchArgs += "-$($entry.Key)" }
            }
            else {
                $relaunchArgs += "-$($entry.Key)"
                $relaunchArgs += "$($entry.Value)"
            }
        }
        & $powershell64 @relaunchArgs
        exit $LASTEXITCODE
    }
}

# >>> ICT-MODULE-IMPORT (the build script replaces this block with the module code)
Import-Module -Name (Join-Path (Join-Path (Join-Path $PSScriptRoot 'src') 'IntuneComplianceTool') 'IntuneComplianceTool.psd1') -Force -ErrorAction Stop
# <<< ICT-MODULE-IMPORT

# -WhatIf only applies to the repair. Keep it from turning logging and report files
# into "What if" messages, then pass it on explicitly.
$preview = [bool]$WhatIfPreference
$WhatIfPreference = $false
$ErrorActionPreference = 'Stop'
if ($env:NO_COLOR) { $NoColor = [switch]$true }

$script:progressLength = 0
$writeLines = {
    param([string[]]$Lines)
    if ($Json) { return }
    foreach ($line in $Lines) { Write-Host $line }
}
$onProgress = {
    param([string]$Name, [bool]$Succeeded)
    if ($Json) { return }
    $itemLength = $Name.Length + 4
    if ($script:progressLength + $itemLength -gt 78) {
        Write-Host ''
        Write-Host -NoNewline (' ' * 14)
        $script:progressLength = 14
    }
    Write-Host -NoNewline ((Format-ICTProgressItem -Name $Name -Succeeded $Succeeded -NoColor:$NoColor -Ascii:$Ascii) + '  ')
    $script:progressLength += $itemLength
}
$collect = {
    param([string]$Label, [psobject]$Configuration)
    if (-not $Json) {
        Write-Host ''
        Write-Host -NoNewline ('  ' + $Label.PadRight(12))
        $script:progressLength = 14
    }
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $collected = Get-ICTDeviceData -Config $Configuration -OnProgress $onProgress
    $timer.Stop()
    if (-not $Json) { Write-Host ('({0:N1} s)' -f $timer.Elapsed.TotalSeconds) }
    return $collected
}

$exitCode = 10
try {
    try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { Write-Verbose 'Console encoding could not be changed.' }

    if (-not $OutputDirectory) {
        if ($env:ProgramData) { $OutputDirectory = Join-Path $env:ProgramData 'IntuneComplianceTool' }
        else { $OutputDirectory = Join-Path $PSScriptRoot 'output' }
    }
    try {
        Initialize-ICTLogging -Path (Join-Path $OutputDirectory 'ict.log')
    }
    catch {
        Write-Verbose "File logging disabled: $($_.Exception.Message)"
    }

    $config = $(if ($ConfigPath) { Get-ICTConfig -Path $ConfigPath } else { Get-ICTConfig })
    $method = $(if ($EnrollmentMethod) { $EnrollmentMethod } else { $config.EnrollmentMethod })

    & $writeLines (Format-ICTHeader -NoColor:$NoColor -Ascii:$Ascii)
    $data = & $collect 'Collecting' $config
    $evaluation = Test-ICTCompliance -DeviceData $data -Config $config

    $remediation = $null
    $postData = $null
    $postEvaluation = $null
    if ($Remediate) {
        $remediation = Invoke-ICTRemediation -Evaluation $evaluation -Config $config -Method $method -Force:$Force -WhatIf:$preview -Confirm:$false
        if ($remediation.ChangesMade) {
            $postData = & $collect 'Re-checking' $config
            $postEvaluation = Test-ICTCompliance -DeviceData $postData -Config $config
        }
    }

    $report = New-ICTReport -DeviceData $data -Evaluation $evaluation -Remediation $remediation `
        -PostRemediationEvaluation $postEvaluation -PostRemediationDeviceData $postData

    $savedFiles = @()
    if ($SaveReport) {
        $savedFiles = @(Export-ICTReport -Report $report -OutputDirectory (Join-Path $OutputDirectory 'Reports') -Format $ReportFormat)
    }

    if ($Json) {
        Write-Output ($report | ConvertTo-Json -Depth 12)
    }
    else {
        & $writeLines (Format-ICTReport -Report $report -NoColor:$NoColor -Ascii:$Ascii -Detailed:$Detailed -CommandHint $CommandHint -SavedFile $savedFiles)
    }

    $finalStatus = $report.OverallStatus
    if ($remediation -and $remediation.Status -eq 'Failed') { $exitCode = 3 }
    else {
        $exitCode = switch ($finalStatus) {
            'Compliant' { 0 }
            'EnrollmentBroken' { 2 }
            default { 1 }
        }
    }
}
catch {
    $message = $_.Exception.Message
    if ($Json) {
        Write-Output (@{ Tool = 'IntuneComplianceTool'; Error = $message } | ConvertTo-Json)
    }
    else {
        Write-Host ''
        Write-Host ('  ERROR: {0}' -f $message) -ForegroundColor Red
        Write-Host ('  {0}' -f $_.InvocationInfo.PositionMessage.Split("`n")[0]) -ForegroundColor DarkGray
        Write-Host ''
    }
    $exitCode = 10
}

exit $exitCode
