function Format-ICTProgressItem {
    <#
    .SYNOPSIS
        Returns one live progress item, e.g. a green check mark followed by "Device".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [bool]$Succeeded = $true,
        [switch]$NoColor,
        [switch]$Ascii
    )

    $theme = New-ICTTheme -NoColor:$NoColor -Ascii:$Ascii
    $status = $(if ($Succeeded) { 'Pass' } else { 'Warning' })
    $symbol = $theme.Symbols[$status].Trim()
    return (Format-ICTColor -Text $symbol -Color $theme.StatusColor[$status] -Theme $theme) + ' ' + $Name
}
