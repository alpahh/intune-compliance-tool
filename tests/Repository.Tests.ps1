# Guards that keep the tool runnable on Windows PowerShell 5.1, which cannot be run
# on macOS/Linux: ASCII-only sources and no PowerShell 7-only syntax.

BeforeDiscovery {
    $root = Split-Path -Path $PSScriptRoot -Parent
    $script:sourceFiles = @(
        Get-Item -LiteralPath (Join-Path $root 'IntuneComplianceTool.ps1')
        Get-ChildItem -Path (Join-Path $root 'src') -Recurse -Include '*.ps1', '*.psm1', '*.psd1' -File
        Get-ChildItem -Path (Join-Path $root 'tests') -Recurse -Include '*.ps1' -File
    ) | ForEach-Object { @{ Path = $_.FullName; Name = $_.FullName.Substring($root.Length + 1) } }
}

BeforeAll {
    $script:root = Split-Path -Path $PSScriptRoot -Parent
}

Describe 'Source file <Name>' -ForEach $sourceFiles {
    It 'contains only ASCII characters' {
        $offending = @([System.IO.File]::ReadAllBytes($Path) | Where-Object { $_ -gt 127 })
        $offending.Count | Should -Be 0 -Because 'Windows PowerShell 5.1 reads BOM-less UTF-8 as ANSI'
    }

    It 'parses' {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }

    # These AST types only exist in PowerShell 7; on 5.1 the 'parses' test above is the real check.
    It 'uses no PowerShell 7-only syntax' -Skip:($PSVersionTable.PSVersion.Major -lt 7) {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)

        $ps7Only = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.TernaryExpressionAst] -or
                $node -is [System.Management.Automation.Language.PipelineChainAst] -or
                ($node -is [System.Management.Automation.Language.MemberExpressionAst] -and $node.NullConditional) -or
                ($node -is [System.Management.Automation.Language.IndexExpressionAst] -and $node.NullConditional) -or
                ($node -is [System.Management.Automation.Language.BinaryExpressionAst] -and $node.Operator -eq 'QuestionQuestion') -or
                ($node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Operator -eq 'QuestionQuestionEquals')
            }, $true)
        @($ps7Only | ForEach-Object { '{0} (line {1})' -f $_.Extent.Text, $_.Extent.StartLineNumber }) | Should -BeNullOrEmpty

        $text = [System.IO.File]::ReadAllText($Path)
        # Patterns are split so this file does not match itself.
        $text | Should -Not -Match ('-As' + 'Hashtable') -Because 'that ConvertFrom-Json switch does not exist in 5.1'
        $text | Should -Not -Match ('ForEach-Object\s+-Par' + 'allel')
        $text | Should -Not -Match ('`' + 'e\[') -Because 'the backtick-e escape does not exist in 5.1'
    }
}

Describe 'Repository hygiene' {
    It 'mentions no AI assistant anywhere in the tracked files' {
        $word = 'cla' + 'ude'
        $hits = @(git -C $root grep -n -i -I $word -- . 2>$null)
        $LASTEXITCODE | Should -Be 1 -Because 'git grep exits 1 when it searched and found nothing'
        $hits | Should -BeNullOrEmpty
    }
}

Describe 'ict.sh' -Skip:($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows) {
    It 'passes its offline tests' {
        $output = & /bin/bash (Join-Path $root 'tests/ict-sh.test.sh') 2>&1
        ($output -join "`n") | Should -Match ' 0 failed'
        $LASTEXITCODE | Should -Be 0
    }
}

Describe 'Module manifest' {
    It 'exports exactly the functions in Public/' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path $root 'src/IntuneComplianceTool/IntuneComplianceTool.psd1')
        $public = Get-ChildItem -Path (Join-Path $root 'src/IntuneComplianceTool/Public') -Filter '*.ps1' | ForEach-Object { $_.BaseName }
        ($manifest.FunctionsToExport | Sort-Object) | Should -Be ($public | Sort-Object)
    }
}

Describe 'Single-file build' {
    It 'produces a script that parses and defines every function' {
        $output = Join-Path $TestDrive 'IntuneComplianceTool.ps1'
        & (Join-Path $root 'build/Build-IntuneComplianceTool.ps1') -OutputPath $output -Quiet

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($output, [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty

        $defined = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
        $expected = Get-ChildItem -Path (Join-Path $root 'src/IntuneComplianceTool') -Recurse -Filter '*.ps1' | ForEach-Object {
            $fileAst = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null)
            $fileAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name }
        }
        foreach ($name in $expected) { $defined | Should -Contain $name }

        $text = [System.IO.File]::ReadAllText($output)
        $text | Should -Not -Match 'Import-Module -Name \(Join-Path'
        $text | Should -Match '\[CmdletBinding\(SupportsShouldProcess\)\]\s*param\('
    }

    It 'runs the bundled functions in a fresh session' -Skip:($PSVersionTable.PSVersion.Major -lt 6 -or $IsWindows) {
        $output = Join-Path $TestDrive 'bundle-run.ps1'
        & (Join-Path $root 'build/Build-IntuneComplianceTool.ps1') -OutputPath $output -Quiet
        $pwsh = (Get-Process -Id $PID).Path
        # On macOS/Linux the script stops at the Windows check with exit code 10.
        $result = & $pwsh -NoProfile -File $output -NoColor -Ascii 2>&1
        $LASTEXITCODE | Should -Be 10
        ($result -join "`n") | Should -Match 'INTUNE COMPLIANCE TOOL'
        ($result -join "`n") | Should -Match 'must run on Windows'
    }
}
