<#
.SYNOPSIS
    Builds dist/IntuneComplianceTool.ps1: the entry script with the module code inlined,
    so a single file can be copied to a client and run there.
.DESCRIPTION
    Replaces the block between the ICT-MODULE-IMPORT markers in IntuneComplianceTool.ps1
    with the contents of src/IntuneComplianceTool/Private/*.ps1 and Public/*.ps1.
    Fails if any source file contains non-ASCII characters (Windows PowerShell 5.1
    misreads BOM-less UTF-8) or if the result does not parse.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Path $PSScriptRoot -Parent
$entryPath = Join-Path $root 'IntuneComplianceTool.ps1'
$moduleRoot = Join-Path (Join-Path $root 'src') 'IntuneComplianceTool'
if (-not $OutputPath) { $OutputPath = Join-Path (Join-Path $root 'dist') 'IntuneComplianceTool.ps1' }

$sources = @(
    Get-ChildItem -Path (Join-Path $moduleRoot 'Private') -Filter '*.ps1' -File | Sort-Object Name
    Get-ChildItem -Path (Join-Path $moduleRoot 'Public') -Filter '*.ps1' -File | Sort-Object Name
)

foreach ($file in @(Get-Item -LiteralPath $entryPath) + $sources) {
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    foreach ($byte in $bytes) {
        if ($byte -gt 127) { throw "Non-ASCII character in $($file.FullName). Use [char]0x.... instead." }
    }
}

$entry = [System.IO.File]::ReadAllText($entryPath)
$pattern = '(?s)# >>> ICT-MODULE-IMPORT.*?# <<< ICT-MODULE-IMPORT'
if ($entry -notmatch $pattern) { throw "Module import markers not found in $entryPath." }

$builder = New-Object System.Text.StringBuilder
$null = $builder.AppendLine('# >>> Module code inlined by build/Build-IntuneComplianceTool.ps1 - edit src/, not this file.')
foreach ($file in $sources) {
    $relative = $file.FullName.Substring($root.Length + 1) -replace '\\', '/'
    $null = $builder.AppendLine("#region $relative")
    $null = $builder.AppendLine(([System.IO.File]::ReadAllText($file.FullName)).TrimEnd())
    $null = $builder.AppendLine("#endregion $relative")
    $null = $builder.AppendLine()
}
$null = $builder.Append('# <<< Module code')

$bundle = [regex]::Replace($entry, $pattern, { param($match) $builder.ToString() })
$bundle = $bundle -replace "`r`n", "`n" -replace "`n", "`r`n"

$tokens = $null
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($bundle, [ref]$tokens, [ref]$errors)
if ($errors) { throw ("The bundled script does not parse: {0}" -f (($errors | ForEach-Object { $_.Message }) -join '; ')) }

$outputDirectory = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path -LiteralPath $outputDirectory)) { $null = New-Item -Path $outputDirectory -ItemType Directory -Force }
[System.IO.File]::WriteAllText($OutputPath, $bundle, (New-Object System.Text.UTF8Encoding($true)))

if (-not $Quiet) {
    Write-Host ('Built {0} ({1:N0} KB, {2} source files)' -f $OutputPath, ((Get-Item -LiteralPath $OutputPath).Length / 1KB), $sources.Count)
}
