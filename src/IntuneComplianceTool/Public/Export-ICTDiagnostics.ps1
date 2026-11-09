function Export-ICTDiagnostics {
    <#
    .SYNOPSIS
        Runs MdmDiagnosticsTool.exe (enrollment, provisioning and Autopilot areas) and
        returns the path of the ZIP file, e.g. to attach to a Microsoft support case.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-ICTIsWindows)) { throw 'Export-ICTDiagnostics must run on Windows.' }
    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) { $null = New-Item -Path $directory -ItemType Directory -Force }
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    Invoke-ICTMdmDiagnosticsTool -ZipPath $Path
    Write-ICTLog "MDM diagnostics saved: $Path"
    return $Path
}
