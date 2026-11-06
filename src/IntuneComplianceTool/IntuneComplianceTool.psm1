# Development loader. The single-file build (build/Build-IntuneComplianceTool.ps1)
# inlines the Private and Public files into IntuneComplianceTool.ps1 instead.

$privateFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -File | Sort-Object Name)
$publicFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File | Sort-Object Name)

foreach ($file in ($privateFiles + $publicFiles)) {
    . $file.FullName
}

Export-ModuleMember -Function ($publicFiles | ForEach-Object { $_.BaseName })
