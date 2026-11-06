# Shared constants and helpers. Everything in this file is platform-neutral so it
# can be unit tested on any OS.

$script:ICTVersion = '0.1.0'
$script:ICTIntuneProviderId = 'MS DM Server'
$script:ICTGuidPattern = '^\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?$'
$script:ICTLogPath = $null

function Test-ICTIsWindows {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT)
}

function Test-ICTGuid {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    return ($Value -match $script:ICTGuidPattern)
}

function ConvertFrom-ICTDate {
    <#
        Converts a DateTime or a date string (ISO 8601 or the OMA-DM format
        yyyyMMddTHHmmssZ) to a UTC DateTime. Returns $null when the value is empty
        or cannot be parsed.
    #>
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }

    $text = ([string]$Value).Trim()
    if ($text -eq '') { return $null }

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $formats = [string[]]@("yyyyMMdd'T'HHmmss'Z'", "yyyyMMdd'T'HHmmss")
    $parsed = [datetime]::MinValue

    if ([datetime]::TryParseExact($text, $formats, $culture, $styles, [ref]$parsed)) { return $parsed }
    if ([datetime]::TryParse($text, $culture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}

function ConvertTo-ICTIsoDate {
    <#
        Formats a date as an ISO 8601 UTC string (yyyy-MM-ddTHH:mm:ssZ). Dates before
        the year 2000 are treated as "never" (Task Scheduler reports 1999-11-30 for
        tasks that have not run yet) and return $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Position = 0)][AllowNull()][object]$Value)

    $date = ConvertFrom-ICTDate -Value $Value
    if ($null -eq $date -or $date.Year -lt 2000) { return $null }
    return $date.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-ICTUriHost {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Uri)

    if ([string]::IsNullOrWhiteSpace($Uri)) { return $null }
    $parsed = $null
    if ([System.Uri]::TryCreate($Uri.Trim(), [System.UriKind]::Absolute, [ref]$parsed) -and $parsed.Host) {
        return $parsed.Host.ToLowerInvariant()
    }
    return $null
}

function ConvertFrom-ICTYesNo {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Value)

    if ($null -eq $Value) { return $null }
    switch ($Value.Trim().ToUpperInvariant()) {
        'YES' { return $true }
        'NO' { return $false }
    }
    return $null
}

function ConvertFrom-ICTWinHttpProxySetting {
    <#
        Parses the binary WinHttpSettings value stored under
        HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections.
        Layout: [0..3] struct version, [4..7] counter, [8..11] flags,
        [12..15] proxy length, proxy (ASCII), bypass length (DWORD), bypass (ASCII).
        Reading the registry avoids parsing localised "netsh winhttp" output.
    #>
    [CmdletBinding()]
    param([AllowNull()][byte[]]$Bytes)

    $direct = [pscustomobject]@{ ProxyConfigured = $false; ProxyServer = $null; BypassList = $null }
    if ($null -eq $Bytes -or $Bytes.Length -lt 16) { return $direct }

    $proxyLength = [System.BitConverter]::ToInt32($Bytes, 12)
    if ($proxyLength -le 0 -or (16 + $proxyLength) -gt $Bytes.Length) { return $direct }
    $proxy = [System.Text.Encoding]::ASCII.GetString($Bytes, 16, $proxyLength)

    $bypass = $null
    $bypassOffset = 16 + $proxyLength
    if (($bypassOffset + 4) -le $Bytes.Length) {
        $bypassLength = [System.BitConverter]::ToInt32($Bytes, $bypassOffset)
        if ($bypassLength -gt 0 -and ($bypassOffset + 4 + $bypassLength) -le $Bytes.Length) {
            $bypass = [System.Text.Encoding]::ASCII.GetString($Bytes, $bypassOffset + 4, $bypassLength)
        }
    }

    return [pscustomobject]@{ ProxyConfigured = $true; ProxyServer = $proxy; BypassList = $bypass }
}

function Write-ICTLog {
    <#
        Writes to the verbose stream and, when Initialize-ICTLogging was called, to
        the log file. It never writes to the warning stream: problems surface in the
        report itself, and -Json output must stay clean.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')][string]$Level = 'Info'
    )

    Write-Verbose ('[{0}] {1}' -f $Level, $Message)

    if ($script:ICTLogPath) {
        $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level.ToUpperInvariant(), $Message
        try {
            # Logging must happen even inside -WhatIf runs.
            Add-Content -LiteralPath $script:ICTLogPath -Value $line -Encoding UTF8 -ErrorAction Stop -WhatIf:$false -Confirm:$false
        }
        catch {
            Write-Verbose "Could not write to log file '$script:ICTLogPath': $($_.Exception.Message)"
        }
    }
}

function Invoke-ICTCollector {
    <#
        Runs one collection step. A failure is logged and recorded in ErrorList
        instead of aborting the whole collection. On failure nothing is written to
        the pipeline, so callers get $null (or an empty array when wrapped in @()).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$ErrorList
    )

    try {
        & $ScriptBlock
    }
    catch {
        Write-ICTLog -Level Warning -Message "Collecting '$Section' failed: $($_.Exception.Message)"
        $ErrorList.Add([pscustomobject]@{ Section = $Section; Error = $_.Exception.Message })
    }
}

function Get-ICTEnrollmentRegistryPath {
    <#
        Registry keys that make up one MDM enrollment. These are removed (after a
        backup) when an enrollment is reset.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$EnrollmentId)

    if (-not (Test-ICTGuid $EnrollmentId)) { throw "'$EnrollmentId' is not a valid enrollment ID." }

    return [string[]]@(
        "HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollmentId"
        "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$EnrollmentId"
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$EnrollmentId"
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$EnrollmentId"
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$EnrollmentId"
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$EnrollmentId"
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$EnrollmentId"
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$EnrollmentId"
    )
}

function Format-ICTRelativeTime {
    <# "just now", "25 min ago", "3 h ago", "12 days ago"; future dates as "in 5 days". #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Date, [datetime]$Now = [datetime]::UtcNow)

    $value = ConvertFrom-ICTDate $Date
    if ($null -eq $value) { return 'never' }
    $span = $Now.ToUniversalTime() - $value
    $future = $span.Ticks -lt 0
    if ($future) { $span = $span.Negate() }

    if ($span.TotalMinutes -lt 1) { return 'just now' }
    if ($span.TotalHours -lt 1) { $text = '{0} min' -f [int][math]::Floor($span.TotalMinutes) }
    elseif ($span.TotalDays -lt 2) { $text = '{0} h' -f [int][math]::Floor($span.TotalHours) }
    else { $text = '{0} days' -f [int][math]::Floor($span.TotalDays) }

    if ($future) { return "in $text" }
    return "$text ago"
}

function New-ICTStep {
    <# One line of a repair log. Status: Pass | Fail | Warning | Info | Skipped #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'Skipped')][string]$Status,
        [string]$Detail
    )
    $level = $(if ($Status -eq 'Fail') { 'Error' } elseif ($Status -eq 'Warning') { 'Warning' } else { 'Info' })
    Write-ICTLog -Level $level -Message ('{0} [{1}] {2}' -f $Name, $Status, $Detail)
    return [pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail }
}

function Get-ICTShortId {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Id)
    if ([string]::IsNullOrEmpty($Id)) { return '' }
    $clean = $Id.Trim('{', '}')
    if ($clean.Length -le 8) { return $clean }
    return $clean.Substring(0, 8) + '...'
}

function Get-ICTLatestServerSuccess {
    <# Most recent successful OMA-DM session across the given enrollments (UTC DateTime or $null). #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$EnrollmentId)

    $latest = $null
    foreach ($id in @($EnrollmentId)) {
        $info = Get-ICTOmadmConnectionInfo -EnrollmentId $id
        if ($null -eq $info) { continue }
        $date = ConvertFrom-ICTDate $info.ServerLastSuccessTime
        if ($null -ne $date -and ($null -eq $latest -or $date -gt $latest)) { $latest = $date }
    }
    return $latest
}
