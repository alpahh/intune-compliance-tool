<#
.SYNOPSIS
    Builds dist/IntuneComplianceTool.ps1: the entry script with the module code inlined
    (comments stripped), so a single file can be copied to a client and run there.
.DESCRIPTION
    Replaces the block between the ICT-MODULE-IMPORT markers in IntuneComplianceTool.ps1
    with src/IntuneComplianceTool/Private/*.ps1 and Public/*.ps1. Fails if a source file
    contains non-ASCII characters (Windows PowerShell 5.1 misreads BOM-less UTF-8) or
    if the result does not parse.
#>
[CmdletBinding()]
param([string]$OutputPath, [switch]$Quiet)

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
    if (@([System.IO.File]::ReadAllBytes($file.FullName) -gt 127).Count) { throw "Non-ASCII character in $($file.FullName). Use [char]0x.... instead." }
}

function Remove-Comments([string]$Text) {
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Parse error: $($errors[0].Message)" }
    $builder = New-Object System.Text.StringBuilder($Text)
    foreach ($token in @($tokens | Where-Object { $_.Kind -eq 'Comment' } | Sort-Object { $_.Extent.StartOffset } -Descending)) {
        $null = $builder.Remove($token.Extent.StartOffset, $token.Extent.EndOffset - $token.Extent.StartOffset)
    }
    $lines = $builder.ToString() -split "`r?`n" | ForEach-Object { $_.TrimEnd() }
    return (($lines -join "`n") -replace "`n{3,}", "`n`n").Trim()
}

$entry = [System.IO.File]::ReadAllText($entryPath)
$pattern = '(?s)# >>> ICT-MODULE-IMPORT.*?# <<< ICT-MODULE-IMPORT'
if ($entry -notmatch $pattern) { throw "Module import markers not found in $entryPath." }

$builder = New-Object System.Text.StringBuilder
$null = $builder.AppendLine('# >>> Module code inlined by build/Build-IntuneComplianceTool.ps1 - edit src/, not this file.')
foreach ($file in $sources) {
    $null = $builder.AppendLine((Remove-Comments ([System.IO.File]::ReadAllText($file.FullName))))
    $null = $builder.AppendLine()
}
$null = $builder.Append('# <<< Module code')

$bundle = [regex]::Replace($entry, $pattern, { param($match) $builder.ToString() })
$bundle = ($bundle -replace "`r`n", "`n") -replace "`n", "`r`n"

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
