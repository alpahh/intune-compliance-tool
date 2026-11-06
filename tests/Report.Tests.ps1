BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'IntuneComplianceTool' 'IntuneComplianceTool.psd1') -Force
    . (Join-Path $PSScriptRoot 'TestData.ps1')

    $script:ansi = [regex]"$([char]27)\[[0-9;]*m"

    function New-TestReport {
        param([scriptblock]$Change, $Remediation, [switch]$AfterRepair)
        $data = New-TestDeviceData
        if ($Change) { & $Change $data }
        $evaluation = Test-ICTCompliance -DeviceData $data -Now $TestNow
        if ($AfterRepair) {
            $healthy = New-TestDeviceData
            $post = Test-ICTCompliance -DeviceData $healthy -Now $TestNow
            return New-ICTReport -DeviceData $data -Evaluation $evaluation -Remediation $Remediation -PostRemediationEvaluation $post -PostRemediationDeviceData $healthy
        }
        New-ICTReport -DeviceData $data -Evaluation $evaluation -Remediation $Remediation
    }

    function Get-PlainText {
        param([string[]]$Lines)
        ($Lines | ForEach-Object { $ansi.Replace($_, '') }) -join "`n"
    }

    $script:brokenCertificate = { param($d) $d.MdmCertificates[0].NotAfter = '2026-10-28T08:00:00Z' }
}

Describe 'Format-ICTReport' {
    It 'shows a compliant device' {
        $text = Get-PlainText (Format-ICTReport -Report (New-TestReport) -Now $TestNow -NoColor)
        $text | Should -Match 'COMPLIANT'
        $text | Should -Match 'Recommended: nothing'
        $text | Should -Match 'Signed in\s+CONTOSO\\anna\.berger'
        $text | Should -Match 'SSH user\s+PC-0421\\masteruser \(admin\)'
        $text | Should -Match 'Nothing to do\.'
    }

    It 'shows a broken enrollment with the repair commands' {
        $lines = Format-ICTReport -Report (New-TestReport -Change $brokenCertificate) -Now $TestNow -NoColor -CommandHint './ict.sh PC-0421'
        $text = Get-PlainText $lines
        $text | Should -Match 'ENROLLMENT BROKEN'
        $text | Should -Match 'Recommended: RE-ENROLL'
        $text | Should -Match 'Repair possible: yes'
        $text | Should -Match 'expired 2026-10-28 \(8 days ago\)'
        $text | Should -Match ([regex]::Escape('./ict.sh PC-0421 -Remediate -WhatIf'))
    }

    It 'lists the blockers when the repair is not possible' {
        $change = { param($d) $d.MdmCertificates = @(); $d.Network.Endpoints[0].Reachable = $false }
        $text = Get-PlainText (Format-ICTReport -Report (New-TestReport -Change $change) -Now $TestNow -NoColor)
        $text | Should -Match 'Repair possible: no'
        $text | Should -Match 'Automatic repair is blocked by:'
        $text | Should -Match 'login\.microsoftonline\.com:443: unreachable'
    }

    It 'adds reasons and fixes with -Detailed' {
        $report = New-TestReport -Change $brokenCertificate
        $plain = Get-PlainText (Format-ICTReport -Report $report -Now $TestNow -NoColor)
        $detailed = Get-PlainText (Format-ICTReport -Report $report -Now $TestNow -NoColor -Detailed)
        $plain | Should -Not -Match 'Fix: Re-enroll'
        $detailed | Should -Match 'Fix: Re-enroll'
    }

    It 'shows a repair preview' {
        $remediation = [pscustomobject]@{
            Status = 'WhatIf'; WhatIf = $true; ChangesMade = $false; Blockers = @(); Sync = $null; ReEnrollment = $null; LapsRetry = $null
            Steps = @([pscustomobject]@{ Name = 'Remove enrollment'; Status = 'Info'; Detail = 'would remove 7 registry keys' })
        }
        $text = Get-PlainText (Format-ICTReport -Report (New-TestReport -Change $brokenCertificate -Remediation $remediation) -Now $TestNow -NoColor)
        $text | Should -Match 'REPAIR PREVIEW'
        $text | Should -Match 'would remove 7 registry keys'
        $text | Should -Match 'This was a preview'
    }

    It 'shows the before and after status of a successful repair' {
        $remediation = [pscustomobject]@{
            Status = 'Succeeded'; WhatIf = $false; ChangesMade = $true; Blockers = @(); Sync = $null; LapsRetry = $null
            ReEnrollment = [pscustomobject]@{ Succeeded = $true; BackupPath = 'C:\ProgramData\IntuneComplianceTool\Backup\20261105-143300'; Message = $null }
            Steps = @([pscustomobject]@{ Name = 'New enrollment'; Status = 'Pass'; Detail = '9D1E52A1... after 40 s' })
        }
        $text = Get-PlainText (Format-ICTReport -Report (New-TestReport -Change $brokenCertificate -Remediation $remediation -AfterRepair) -Now $TestNow -NoColor)
        $text | Should -Match 'Result: ENROLLMENT BROKEN . COMPLIANT'
        $text | Should -Match 'The device is healthy again'
        $text | Should -Match 'Backup of the removed enrollment'
    }

    It 'lists sections that could not be read' {
        $change = { param($d) $d.CollectionErrors = @([pscustomobject]@{ Section = 'BitLocker'; Error = 'Access denied' }) }
        $text = Get-PlainText (Format-ICTReport -Report (New-TestReport -Change $change) -Now $TestNow -NoColor)
        $text | Should -Match 'COULD NOT READ'
        $text | Should -Match 'BitLocker: Access denied'
    }

    It 'uses colours only when asked to' {
        $report = New-TestReport -Change $brokenCertificate
        (Format-ICTReport -Report $report -Now $TestNow -NoColor) -join '' | Should -Not -Match ([regex]::Escape([string][char]27))
        (Format-ICTReport -Report $report -Now $TestNow) -join '' | Should -Match ([regex]::Escape([string][char]27))
    }

    It 'uses only ASCII characters with -Ascii' {
        $lines = @(Format-ICTHeader -ComputerName 'PC-0421' -NoColor -Ascii) + @(Format-ICTReport -Report (New-TestReport -Change $brokenCertificate) -Now $TestNow -NoColor -Ascii -Detailed)
        foreach ($line in $lines) { $line | Should -Match '^[\x20-\x7E]*$' }
    }

    It 'never writes lines wider than the requested width' -TestCases @(@{ Width = 78 }, @{ Width = 100 }) {
        $change = { param($d) $d.Network.Endpoints += [pscustomobject]@{ HostName = 'enterpriseenrollment-s.manage.microsoft.com'; Port = 443; Reachable = $false; Error = 'timed out' } }
        $report = New-TestReport -Change $change
        $lines = @(Format-ICTHeader -ComputerName 'PC-0421' -Width $Width) + @(Format-ICTReport -Report $report -Now $TestNow -Detailed -Width $Width)
        foreach ($line in $lines) { $ansi.Replace($line, '').Length | Should -BeLessOrEqual $Width }
    }
}

Describe 'Format-ICTProgressItem' {
    It 'marks failed sections' {
        Format-ICTProgressItem -Name 'Security' -Succeeded $false -NoColor -Ascii | Should -Be '[WARN] Security'
        Format-ICTProgressItem -Name 'Device' -NoColor -Ascii | Should -Be '[OK] Device'
    }
}

Describe 'Export-ICTReport' {
    It 'writes JSON that round-trips and HTML that escapes values' {
        $change = { param($d) $d.ConsoleUser = '<script>alert(1)</script>' }
        $report = New-TestReport -Change $change
        $files = Export-ICTReport -Report $report -OutputDirectory (Join-Path $TestDrive 'reports')

        $files.Count | Should -Be 2
        $json = Get-Content -LiteralPath ($files | Where-Object { $_ -like '*.json' }) -Raw | ConvertFrom-Json
        $json.ComputerName | Should -Be 'PC-0421'
        $json.OverallStatus | Should -Be 'Compliant'
        @($json.Evaluation.Results).Count | Should -BeGreaterThan 20

        $html = Get-Content -LiteralPath ($files | Where-Object { $_ -like '*.html' }) -Raw
        $html | Should -Match '&lt;script&gt;'
        $html | Should -Not -Match '<script>alert'
    }

    It 'writes only the requested format' {
        $files = @(Export-ICTReport -Report (New-TestReport) -OutputDirectory (Join-Path $TestDrive 'json-only') -Format Json)
        $files.Count | Should -Be 1
        $files[0] | Should -BeLike '*.json'
    }
}
