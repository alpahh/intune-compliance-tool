function Format-ICTHeader {
    <#
    .SYNOPSIS
        Returns the title box shown at the top of the terminal output.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [string]$ComputerName = [System.Environment]::MachineName,
        [datetime]$Time = [datetime]::Now,
        [ValidateRange(60, 200)][int]$Width = 78,
        [switch]$NoColor,
        [switch]$Ascii
    )

    $theme = New-ICTTheme -NoColor:$NoColor -Ascii:$Ascii
    $s = $theme.Symbols
    $inner = $Width - 2

    $left = '  INTUNE COMPLIANCE TOOL  v' + $script:ICTVersion
    $right = '{0} {1} {2}  ' -f $ComputerName, $s.Dot, $Time.ToString('yyyy-MM-dd HH:mm')
    $gap = [math]::Max(1, $inner - $left.Length - $right.Length)

    $border = { param([string]$Text) Format-ICTColor -Text $Text -Color 'Cyan' -Theme $theme }
    $title = (Format-ICTColor -Text $left -Color 'Bold' -Theme $theme) + (' ' * $gap) + $right

    return [string[]]@(
        (& $border ($s.TL + ($s.H * $inner) + $s.TR))
        ((& $border $s.V) + $title + (& $border $s.V))
        (& $border ($s.BL + ($s.H * $inner) + $s.BR))
    )
}
