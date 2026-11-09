<#
.SYNOPSIS
    Checks Intune MDM enrollment, compliance and LAPS on this Windows device and can
    repair what is broken. Built to be run over SSH (see ict.sh).

.DESCRIPTION
    1. Collects device, Entra join, MDM enrollment, certificate, sync, service,
       security, LAPS, network, clock and event log data (read-only).
    2. Evaluates it and shows the result in the terminal.
    3. With -Remediate: resyncs the clock, fixes MDM services, syncs or re-enrolls,
       retries LAPS - whatever the evaluation recommends - then checks again.

    Exit codes: 0 compliant, 1 not compliant or indeterminate, 2 enrollment broken
    (not repaired), 3 repair attempted but failed, 10 error.

.PARAMETER Remediate
    Repair what can be repaired. There is no prompt: passing this switch is the
    consent. Combine with -WhatIf to see what would happen.
.PARAMETER Force
    Start the enrollment repair even when blockers were found (e.g. an unreachable
    endpoint). The re-enrollment's own safety checks still apply.
.PARAMETER EnrollmentMethod
    UserCredential (needs an Entra or domain user signed in at the console) or
    DeviceCredential. Default from the settings: UserCredential.
.PARAMETER Detailed
    Show the reason and fix for every finding, plus recent MDM errors.
.PARAMETER Json
    Print only the full report as JSON.
.PARAMETER Summary
    Print one tab-separated line (computer, status, failed, warnings, actions,
    failed checks). Used by ict.sh for several hosts.
.PARAMETER SaveReport
    Also save the report as JSON in <OutputDirectory>\Reports.
.PARAMETER CollectDiagnostics
    Also export MDM diagnostics (MdmDiagnosticsTool) to ict-diagnostics.zip in the
    profile of the account running the tool; ict.sh copies it to the Mac.
.PARAMETER OutputDirectory
    Folder for the log, reports and enrollment backups (protected: SYSTEM and
    Administrators only). Default: C:\ProgramData\IntuneComplianceTool
.PARAMETER ConfigPath
    JSON file that overrides default settings (see README).
.PARAMETER NoColor
    No ANSI colours. Also set by the NO_COLOR environment variable.
.PARAMETER Ascii
    Plain ASCII symbols and boxes for terminals without Unicode.

.EXAMPLE
    .\IntuneComplianceTool.ps1 -Remediate -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Remediate,
    [switch]$Force,
    [ValidateSet('UserCredential', 'DeviceCredential')][string]$EnrollmentMethod,
    [switch]$Detailed,
    [switch]$Json,
    [switch]$Summary,
    [switch]$SaveReport,
    [switch]$CollectDiagnostics,
    [string]$OutputDirectory,
    [string]$ConfigPath,
    [switch]$NoColor,
    [switch]$Ascii,
    [string]$CommandHint = '.\IntuneComplianceTool.ps1'
)

if ([System.Environment]::Is64BitOperatingSystem -and -not [System.Environment]::Is64BitProcess) {
    # 32-bit PowerShell sees redirected registry paths and would report wrong data.
    Write-Host '  ERROR: run this with 64-bit PowerShell.' -ForegroundColor Red
    exit 10
}

# >>> ICT-MODULE-IMPORT (the build script replaces this block with the module code)
Import-Module -Name (Join-Path (Join-Path (Join-Path $PSScriptRoot 'src') 'IntuneComplianceTool') 'IntuneComplianceTool.psd1') -Force -ErrorAction Stop
# <<< ICT-MODULE-IMPORT

# -WhatIf applies to the repair only: keep logging and report files out of it.
$preview = [bool]$WhatIfPreference
$WhatIfPreference = $false
$ErrorActionPreference = 'Stop'
if ($env:NO_COLOR) { $NoColor = [switch]$true }
$quiet = ($Json -or $Summary)

$script:progressLength = 0
$writeLines = { param([string[]]$Lines) if (-not $quiet) { foreach ($line in $Lines) { Write-Host $line } } }
$onProgress = {
    param([string]$Name, [bool]$Succeeded)
    if ($quiet) { return }
    if ($script:progressLength + $Name.Length + 4 -gt 78) {
        Write-Host ''
        Write-Host -NoNewline (' ' * 14)
        $script:progressLength = 14
    }
    Write-Host -NoNewline ((Format-ICTProgressItem -Name $Name -Succeeded $Succeeded -NoColor:$NoColor -Ascii:$Ascii) + '  ')
    $script:progressLength += $Name.Length + 4
}
$onRepairProgress = {
    param([string]$Text)
    if (-not $quiet) { Write-Host -NoNewline ("`r  Repairing   {0}" -f $Text).PadRight(78) }
}
$collect = {
    param([string]$Label, [psobject]$Configuration, [string[]]$Section, [psobject]$Previous)
    if (-not $quiet) {
        Write-Host ''
        Write-Host -NoNewline ('  ' + $Label.PadRight(12))
        $script:progressLength = 14
    }
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $arguments = @{ Config = $Configuration; OnProgress = $onProgress }
    if ($Section) { $arguments.Section = $Section; $arguments.Previous = $Previous }
    $collected = Get-ICTDeviceData @arguments
    if (-not $quiet) { Write-Host ('({0:N1} s)' -f $timer.Elapsed.TotalSeconds) }
    return $collected
}

$exitCode = 10
try {
    try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { Write-Verbose 'Console encoding could not be changed.' }

    if (-not $OutputDirectory) {
        $OutputDirectory = $(if ($env:ProgramData) { Join-Path $env:ProgramData 'IntuneComplianceTool' } else { Join-Path $PSScriptRoot 'output' })
    }
    try { Initialize-ICTLogging -Path (Join-Path $OutputDirectory 'ict.log') }
    catch { Write-Verbose "File logging disabled: $($_.Exception.Message)" }

    $warnings = $(if ($quiet) { 'SilentlyContinue' } else { 'Continue' })   # -Json/-Summary output must stay clean
    $config = $(if ($ConfigPath) { Get-ICTConfig -Path $ConfigPath -WarningAction $warnings } else { Get-ICTConfig })
    $method = $(if ($EnrollmentMethod) { $EnrollmentMethod } else { $config.EnrollmentMethod })

    & $writeLines (Format-ICTHeader -NoColor:$NoColor -Ascii:$Ascii)
    $data = & $collect 'Collecting' $config
    $evaluation = Test-ICTCompliance -DeviceData $data -Config $config

    $remediation = $null
    $postData = $null
    $postEvaluation = $null
    if ($Remediate) {
        # Accounts that can never provide the user token for UserCredential enrollment.
        $exclude = @($data.RunAs, $data.Laps.Account.Name, $config.LapsExpectedAccount | Where-Object { $_ })
        if (-not $quiet) { Write-Host '' }
        $remediation = Invoke-ICTRemediation -Evaluation $evaluation -Config $config -Method $method -ExcludeAccount $exclude `
            -Force:$Force -OnProgress $onRepairProgress -WhatIf:$preview -Confirm:$false
        if (-not $quiet) { Write-Host ("`r" + (' ' * 78) + "`r") -NoNewline }
        if ($remediation.ChangesMade) {
            $recheck = @('Enrollment', 'Services', 'LAPS', 'Event log')
            if (@($evaluation.RecommendedActions) -contains 'TimeSync') { $recheck += 'Network' }
            $postData = & $collect 'Re-checking' $config $recheck $data
            $postEvaluation = Test-ICTCompliance -DeviceData $postData -Config $config
        }
    }

    $report = New-ICTReport -DeviceData $data -Evaluation $evaluation -Remediation $remediation `
        -PostRemediationEvaluation $postEvaluation -PostRemediationDeviceData $postData

    $savedFiles = @()
    if ($SaveReport) { $savedFiles += Export-ICTReport -Report $report -OutputDirectory (Join-Path $OutputDirectory 'Reports') }
    if ($CollectDiagnostics) {
        $profileDirectory = $(if ($env:USERPROFILE) { $env:USERPROFILE } else { $OutputDirectory })
        $savedFiles += Export-ICTDiagnostics -Path (Join-Path $profileDirectory 'ict-diagnostics.zip')
    }

    if ($Json) { Write-Output ($report | ConvertTo-Json -Depth 12) }
    elseif ($Summary) { Write-Output (Format-ICTSummaryLine -Report $report) }
    else { & $writeLines (Format-ICTReport -Report $report -NoColor:$NoColor -Ascii:$Ascii -Detailed:$Detailed -CommandHint $CommandHint -SavedFile $savedFiles) }

    if ($remediation -and $remediation.Status -eq 'Failed') { $exitCode = 3 }
    else {
        $exitCode = switch ($report.OverallStatus) { 'Compliant' { 0 } 'EnrollmentBroken' { 2 } default { 1 } }
    }
}
catch {
    $message = $_.Exception.Message
    if ($Json) { Write-Output (@{ Tool = 'IntuneComplianceTool'; Error = $message } | ConvertTo-Json) }
    elseif ($Summary) { Write-Output ("{0}`tERROR`t-`t-`t-`t{1}" -f [System.Environment]::MachineName, ($message -replace '\s+', ' ')) }
    else {
        Write-Host ''
        Write-Host ('  ERROR: {0}' -f $message) -ForegroundColor Red
        Write-Host ('  {0}' -f $_.InvocationInfo.PositionMessage.Split("`n")[0]) -ForegroundColor DarkGray
        Write-Host ''
    }
    $exitCode = 10
}

exit $exitCode
