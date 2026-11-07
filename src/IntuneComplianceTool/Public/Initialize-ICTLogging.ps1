function Initialize-ICTLogging {
    <#
    .SYNOPSIS
        Sets the log file that every step is appended to, in a folder only SYSTEM and
        Administrators can write to. The log is rotated to <name>.old above MaxSizeMB.
        An empty path turns file logging off.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Path, [ValidateRange(1, 100)][int]$MaxSizeMB = 5)

    $script:ICTLogPath = $null
    if ([string]::IsNullOrEmpty($Path)) { return }

    # Only an administrator can create the protected folder; a read-only run without rights just logs nothing.
    if ((Test-ICTIsWindows) -and -not (Test-ICTIsElevated)) { return }
    $directory = Split-Path -Path $Path -Parent
    if ($directory) { Protect-ICTDirectory -Path $directory }
    if ((Test-Path -LiteralPath $Path) -and (Get-Item -LiteralPath $Path).Length -gt ($MaxSizeMB * 1MB)) {
        Move-Item -LiteralPath $Path -Destination "$Path.old" -Force -ErrorAction SilentlyContinue
    }
    $script:ICTLogPath = $Path
}
