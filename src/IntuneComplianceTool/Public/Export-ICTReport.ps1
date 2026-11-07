function Export-ICTReport {
    <#
    .SYNOPSIS
        Saves a report (from New-ICTReport) as a JSON file and returns its full path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][psobject]$Report, [Parameter(Mandatory)][string]$OutputDirectory)

    Protect-ICTDirectory -Path $OutputDirectory
    $name = 'ICT_{0}_{1}.json' -f ("$($Report.ComputerName)" -replace '[^A-Za-z0-9_\-]', '_'), [datetime]::Now.ToString('yyyyMMdd-HHmmss', $script:ICTInvariant)
    $path = Join-Path $OutputDirectory $name
    $Report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
    Write-ICTLog "Report saved: $path"
    return (Resolve-Path -LiteralPath $path).ProviderPath
}
