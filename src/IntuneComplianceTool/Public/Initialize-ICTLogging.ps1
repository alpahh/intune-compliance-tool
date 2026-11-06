function Initialize-ICTLogging {
    <#
    .SYNOPSIS
        Sets the log file that every IntuneComplianceTool step is appended to.
    .DESCRIPTION
        Creates the folder if needed. When the log grows past MaxSizeMB it is moved to
        <name>.old (one generation kept). Pass an empty path to turn file logging off.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Path,
        [ValidateRange(1, 100)][int]$MaxSizeMB = 5
    )

    if ([string]::IsNullOrEmpty($Path)) {
        $script:ICTLogPath = $null
        return
    }

    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop
    }

    if (Test-Path -LiteralPath $Path) {
        $size = (Get-Item -LiteralPath $Path).Length
        if ($size -gt ($MaxSizeMB * 1MB)) {
            Move-Item -LiteralPath $Path -Destination "$Path.old" -Force -ErrorAction SilentlyContinue
        }
    }

    $script:ICTLogPath = $Path
}
