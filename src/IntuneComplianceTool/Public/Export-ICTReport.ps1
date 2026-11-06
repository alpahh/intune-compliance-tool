function Export-ICTReport {
    <#
    .SYNOPSIS
        Saves a report (from New-ICTReport) as JSON and/or a self-contained HTML page.
    .OUTPUTS
        The full paths of the files written.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][psobject]$Report,
        [Parameter(Mandatory)][string]$OutputDirectory,
        [ValidateSet('Json', 'Html', 'Both')][string]$Format = 'Both'
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        $null = New-Item -Path $OutputDirectory -ItemType Directory -Force -ErrorAction Stop
    }

    $safeName = ("$($Report.ComputerName)" -replace '[^A-Za-z0-9_\-]', '_')
    if (-not $safeName) { $safeName = 'device' }
    $baseName = 'ICT_{0}_{1}' -f $safeName, (Get-Date).ToString('yyyyMMdd-HHmmss')
    $written = New-Object 'System.Collections.Generic.List[string]'

    if ($Format -eq 'Json' -or $Format -eq 'Both') {
        $jsonPath = Join-Path $OutputDirectory "$baseName.json"
        $Report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8 -ErrorAction Stop
        $written.Add((Resolve-Path -LiteralPath $jsonPath).ProviderPath)
    }

    if ($Format -eq 'Html' -or $Format -eq 'Both') {
        $htmlPath = Join-Path $OutputDirectory "$baseName.html"
        ConvertTo-ICTHtml -Report $Report | Set-Content -LiteralPath $htmlPath -Encoding UTF8 -ErrorAction Stop
        $written.Add((Resolve-Path -LiteralPath $htmlPath).ProviderPath)
    }

    Write-ICTLog ('Report saved: {0}' -f ($written -join ', '))
    return [string[]]$written.ToArray()
}
