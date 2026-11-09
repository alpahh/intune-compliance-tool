# Terminal theme: symbols, box characters and ANSI colours. Source files must stay
# ASCII (Windows PowerShell 5.1 reads BOM-less files as ANSI), so every non-ASCII
# character is built from its code point here.

function New-ICTTheme {
    [CmdletBinding()]
    param([switch]$NoColor, [switch]$Ascii)

    $c = { param([int]$CodePoint) [string][char]$CodePoint }

    if ($Ascii) {
        $symbols = @{
            Pass = '[OK]  '; Fail = '[FAIL]'; Warning = '[WARN]'; Unknown = '[ ?? ]'; Info = '[INFO]'
            Arrow = '->'; Dot = '-'; Ellipsis = '...'
            H = '-'; V = '|'; TL = '+'; TR = '+'; BL = '+'; BR = '+'
            HH = '='; HV = '|'; HTL = '+'; HTR = '+'; HBL = '+'; HBR = '+'
            Section = '-'
        }
    }
    else {
        $symbols = @{
            Pass = (& $c 0x2714); Fail = (& $c 0x2718); Warning = '!'; Unknown = '?'; Info = 'i'
            Arrow = (& $c 0x2192); Dot = (& $c 0x00B7); Ellipsis = (& $c 0x2026)
            H = (& $c 0x2500); V = (& $c 0x2502); TL = (& $c 0x256D); TR = (& $c 0x256E); BL = (& $c 0x2570); BR = (& $c 0x256F)
            HH = (& $c 0x2501); HV = (& $c 0x2503); HTL = (& $c 0x250F); HTR = (& $c 0x2513); HBL = (& $c 0x2517); HBR = (& $c 0x251B)
            Section = (& $c 0x2500)
        }
    }

    return [pscustomobject]@{
        UseColor = -not $NoColor
        Ascii    = [bool]$Ascii
        Symbols  = $symbols
        Codes    = @{
            Green = '32'; Red = '31'; Yellow = '33'; Cyan = '36'; Gray = '90'; Bold = '1'
            GreenBold = '1;32'; RedBold = '1;31'; YellowBold = '1;33'; CyanBold = '1;36'
        }
        StatusColor = @{ Pass = 'Green'; Fail = 'Red'; Warning = 'Yellow'; Unknown = 'Gray'; Info = 'Cyan' }
    }
}

function Format-ICTColor {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string]$Text, [string]$Color, [Parameter(Mandatory)][psobject]$Theme)

    if (-not $Theme.UseColor -or [string]::IsNullOrEmpty($Color) -or [string]::IsNullOrEmpty($Text)) { return $Text }
    $escape = [string][char]27
    return '{0}[{1}m{2}{0}[0m' -f $escape, $Theme.Codes[$Color], $Text
}

function Limit-ICTText {
    <# Truncates text to a display width, ending in an ellipsis. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$Width, [Parameter(Mandatory)][psobject]$Theme)

    if ($null -eq $Text) { return '' }
    $Text = ($Text -replace '\s+', ' ').Trim()
    if ($Width -le 0) { return '' }
    if ($Text.Length -le $Width) { return $Text }
    $ellipsis = $Theme.Symbols.Ellipsis
    if ($Width -le $ellipsis.Length) { return $Text.Substring(0, $Width) }
    return $Text.Substring(0, $Width - $ellipsis.Length) + $ellipsis
}

function Split-ICTText {
    <# Word-wraps text into lines of at most $Width characters. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$Width)

    if ([string]::IsNullOrWhiteSpace($Text)) { return [string[]]@() }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $current = ''
    foreach ($word in (($Text -replace '\s+', ' ').Trim() -split ' ')) {
        while ($word.Length -gt $Width) {
            if ($current) { $lines.Add($current); $current = '' }
            $lines.Add($word.Substring(0, $Width))
            $word = $word.Substring($Width)
        }
        if ($current -eq '') { $current = $word }
        elseif (($current.Length + 1 + $word.Length) -le $Width) { $current = "$current $word" }
        else { $lines.Add($current); $current = $word }
    }
    if ($current) { $lines.Add($current) }
    return [string[]]$lines.ToArray()
}

function Format-ICTSectionRule {
    <# "  -- Title -----------" #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Title, [int]$Width, [Parameter(Mandatory)][psobject]$Theme, [int]$Indent = 2)

    $h = $Theme.Symbols.Section
    $prefix = (' ' * $Indent) + ($h * 2) + ' ' + $Title + ' '
    $fill = [math]::Max(3, $Width - $prefix.Length)
    return (' ' * $Indent) + (Format-ICTColor -Text (($h * 2) + ' ') -Color 'Gray' -Theme $Theme) +
        (Format-ICTColor -Text $Title -Color 'Bold' -Theme $Theme) +
        (Format-ICTColor -Text (' ' + ($h * $fill)) -Color 'Gray' -Theme $Theme)
}
