BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'IntuneComplianceTool' 'IntuneComplianceTool.psd1') -Force
}

Describe 'Date helpers' {
    It 'parses the OMA-DM format as UTC' {
        InModuleScope IntuneComplianceTool {
            $date = ConvertFrom-ICTDate '20261024T101500Z'
            $date.Kind | Should -Be 'Utc'
            $date.ToString('yyyy-MM-dd HH:mm:ss') | Should -Be '2026-10-24 10:15:00'
        }
    }

    It 'parses ISO 8601 strings and returns $null for garbage' {
        InModuleScope IntuneComplianceTool {
            (ConvertFrom-ICTDate '2026-11-05T14:32:00Z').Hour | Should -Be 14
            ConvertFrom-ICTDate 'not a date' | Should -BeNullOrEmpty
            ConvertFrom-ICTDate '' | Should -BeNullOrEmpty
            ConvertFrom-ICTDate $null | Should -BeNullOrEmpty
        }
    }

    It 'formats ISO dates and treats dates before 2000 as never' {
        InModuleScope IntuneComplianceTool {
            ConvertTo-ICTIsoDate ([datetime]::new(2026, 1, 2, 3, 4, 5, [System.DateTimeKind]::Utc)) | Should -Be '2026-01-02T03:04:05Z'
            ConvertTo-ICTIsoDate ([datetime]::new(1999, 11, 30, 0, 0, 0, [System.DateTimeKind]::Utc)) | Should -BeNullOrEmpty
        }
    }

    It 'formats relative times' -TestCases @(
        @{ Date = '2026-11-05T14:31:40Z'; Expected = 'just now' }
        @{ Date = '2026-11-05T14:07:00Z'; Expected = '25 min ago' }
        @{ Date = '2026-11-05T11:32:00Z'; Expected = '3 h ago' }
        @{ Date = '2026-10-24T14:32:00Z'; Expected = '12 days ago' }
        @{ Date = '2026-11-10T14:32:00Z'; Expected = 'in 5 days' }
        @{ Date = $null; Expected = 'never' }
    ) {
        InModuleScope IntuneComplianceTool -Parameters @{ Date = $Date; Expected = $Expected } {
            $now = [datetime]::new(2026, 11, 5, 14, 32, 0, [System.DateTimeKind]::Utc)
            Format-ICTRelativeTime $Date -Now $now | Should -Be $Expected
        }
    }
}

Describe 'Small helpers' {
    It 'extracts the host from a URL' {
        InModuleScope IntuneComplianceTool {
            Get-ICTUriHost 'https://Enrollment.Manage.Microsoft.com/enrollmentserver/discovery.svc' | Should -Be 'enrollment.manage.microsoft.com'
            Get-ICTUriHost 'not a url' | Should -BeNullOrEmpty
            Get-ICTUriHost '' | Should -BeNullOrEmpty
        }
    }

    It 'validates GUIDs' {
        InModuleScope IntuneComplianceTool {
            Test-ICTGuid '8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45' | Should -BeTrue
            Test-ICTGuid '{8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45}' | Should -BeTrue
            Test-ICTGuid 'Status' | Should -BeFalse
            Test-ICTGuid '..\..\SOFTWARE' | Should -BeFalse
        }
    }

    It 'returns the eight registry keys of an enrollment and refuses non-GUID IDs' {
        InModuleScope IntuneComplianceTool {
            $paths = Get-ICTEnrollmentRegistryPath -EnrollmentId '8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45'
            $paths.Count | Should -Be 8
            $paths | Should -Contain 'HKLM:\SOFTWARE\Microsoft\Enrollments\8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45'
            { Get-ICTEnrollmentRegistryPath -EnrollmentId '..\Microsoft' } | Should -Throw
        }
    }

    It 'shortens IDs' {
        InModuleScope IntuneComplianceTool {
            Get-ICTShortId '{8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45}' | Should -Be '8C2F41D0...'
            Get-ICTShortId '' | Should -Be ''
        }
    }
}

Describe 'WinHTTP proxy setting parser' {
    It 'returns direct access for an empty or short value' {
        InModuleScope IntuneComplianceTool {
            (ConvertFrom-ICTWinHttpProxySetting -Bytes $null).ProxyConfigured | Should -BeFalse
            (ConvertFrom-ICTWinHttpProxySetting -Bytes ([byte[]](0x28, 0, 0, 0))).ProxyConfigured | Should -BeFalse
        }
    }

    It 'reads proxy server and bypass list' {
        InModuleScope IntuneComplianceTool {
            $proxy = [System.Text.Encoding]::ASCII.GetBytes('proxy.contoso.com:8080')
            $bypass = [System.Text.Encoding]::ASCII.GetBytes('<local>')
            $bytes = New-Object System.Collections.Generic.List[byte]
            $bytes.AddRange([System.BitConverter]::GetBytes([int]0x28))
            $bytes.AddRange([System.BitConverter]::GetBytes([int]0))
            $bytes.AddRange([System.BitConverter]::GetBytes([int]3))
            $bytes.AddRange([System.BitConverter]::GetBytes([int]$proxy.Length))
            $bytes.AddRange($proxy)
            $bytes.AddRange([System.BitConverter]::GetBytes([int]$bypass.Length))
            $bytes.AddRange($bypass)

            $result = ConvertFrom-ICTWinHttpProxySetting -Bytes $bytes.ToArray()
            $result.ProxyConfigured | Should -BeTrue
            $result.ProxyServer | Should -Be 'proxy.contoso.com:8080'
            $result.BypassList | Should -Be '<local>'
        }
    }
}

Describe 'Text helpers' {
    It 'truncates with an ellipsis' {
        InModuleScope IntuneComplianceTool {
            $theme = New-ICTTheme -Ascii
            Limit-ICTText -Text 'abcdefghij' -Width 6 -Theme $theme | Should -Be 'abc...'
            Limit-ICTText -Text 'abc' -Width 6 -Theme $theme | Should -Be 'abc'
        }
    }

    It 'wraps text at word boundaries' {
        InModuleScope IntuneComplianceTool {
            $lines = Split-ICTText -Text 'one two three four five' -Width 9
            $lines | Should -Be @('one two', 'three', 'four five')
        }
    }
}

Describe 'Get-ICTConfig' {
    It 'returns the defaults' {
        $config = Get-ICTConfig
        $config.MaxDaysSinceLastSync | Should -Be 7
        $config.LapsExpectedAccount | Should -Be 'masteruser'
        @($config.Endpoints).Count | Should -BeGreaterThan 3
    }

    It 'overrides known keys and warns about unknown ones' {
        $path = Join-Path $TestDrive 'settings.json'
        '{ "MaxDaysSinceLastSync": 3, "_comment": "ignored", "Typo": 1 }' | Set-Content -LiteralPath $path
        $config = Get-ICTConfig -Path $path -WarningVariable warnings -WarningAction SilentlyContinue
        $config.MaxDaysSinceLastSync | Should -Be 3
        $warnings.Count | Should -Be 1
        "$($warnings[0])" | Should -Match 'Typo'
    }

    It 'rejects invalid JSON and invalid values' {
        $bad = Join-Path $TestDrive 'bad.json'
        '{ not json' | Set-Content -LiteralPath $bad
        { Get-ICTConfig -Path $bad } | Should -Throw '*not valid JSON*'

        $method = Join-Path $TestDrive 'method.json'
        '{ "EnrollmentMethod": "Magic" }' | Set-Content -LiteralPath $method
        { Get-ICTConfig -Path $method } | Should -Throw '*EnrollmentMethod*'

        { Get-ICTConfig -Path (Join-Path $TestDrive 'missing.json') } | Should -Throw '*not found*'
    }
}

Describe 'Event and proxy helpers' {
    It 'builds an XPath filter for levels, event ids and a time window' {
        InModuleScope IntuneComplianceTool {
            New-ICTEventXPath -Level 1, 2 -EventId 10004 -Days 7 | Should -Be '*[System[(Level=1 or Level=2 or EventID=10004) and TimeCreated[timediff(@SystemTime) <= 604800000]]]'
        }
    }

    It 'picks the HTTPS proxy from a WinHTTP setting' -TestCases @(
        @{ Server = 'proxy.contoso.com:8080'; Expected = 'proxy.contoso.com:8080' }
        @{ Server = 'http=p1:80;https=p2:443'; Expected = 'p2:443' }
        @{ Server = 'http=p1:80'; Expected = $null }
    ) {
        InModuleScope IntuneComplianceTool -Parameters @{ Server = $Server; Expected = $Expected } {
            Get-ICTHttpProxyAddress ([pscustomobject]@{ ProxyConfigured = $true; ProxyServer = $Server }) | Should -Be $Expected
        }
    }

    It 'returns no proxy for direct access' {
        InModuleScope IntuneComplianceTool {
            Get-ICTHttpProxyAddress ([pscustomobject]@{ ProxyConfigured = $false; ProxyServer = $null }) | Should -BeNullOrEmpty
            Get-ICTHttpProxyAddress $null | Should -BeNullOrEmpty
        }
    }
}

Describe 'Re-enrollment helpers' {
    It 'accepts Entra and domain users and rejects local, SSH and LAPS accounts' -TestCases @(
        @{ User = 'AzureAD\AnnaBerger'; Expected = $null }
        @{ User = 'CONTOSO\anna.berger'; Expected = $null }
        @{ User = $null; Expected = 'nobody is signed in at the console' }
        @{ User = 'PC-0421\localadmin'; Expected = 'PC-0421\localadmin is a local account' }
        @{ User = 'PC-0421\masteruser'; Expected = 'PC-0421\masteruser is the SSH / LAPS admin account' }
    ) {
        InModuleScope IntuneComplianceTool -Parameters @{ User = $User; Expected = $Expected } {
            Test-ICTEnrollmentUser -User $User -ComputerName 'PC-0421' -ExcludeAccount @('PC-0421\masteruser') | Should -Be $Expected
        }
    }

    It 'generates a repair script that parses, is ASCII and quotes its values' {
        InModuleScope IntuneComplianceTool {
            $text = New-ICTRepairScript -RegistryPath @("HKLM:\SOFTWARE\Microsoft\Enrollments\8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45") `
                -EnrollmentId @('8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45') -Thumbprint @('ABC') -EnrollerArgument '/c /AutoEnrollMDM' -StatePath "C:\Program Data\it's\state.jsonl"
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errors)
            $errors | Should -BeNullOrEmpty
            $text | Should -Match '^[\x09\x0A\x0D\x20-\x7E]*$'
            $text | Should -Match ([regex]::Escape("'C:\Program Data\it''s\state.jsonl'"))
            $text | Should -Match ([regex]::Escape("-ArgumentList '/c /AutoEnrollMDM'"))
            $text | Should -Match ([regex]::Escape("@('ABC')"))
        }
    }

    It 'generates an empty list when there is nothing to remove' {
        InModuleScope IntuneComplianceTool {
            $text = New-ICTRepairScript -EnrollerArgument '/c /AutoEnrollMDM' -StatePath 'C:\s.jsonl'
            $text | Should -Match ([regex]::Escape('$registryPaths = @()'))
        }
    }

    It 'quotes typographic apostrophes too' {
        InModuleScope IntuneComplianceTool {
            $value = 'O' + [char]0x2019 + 'Neil'
            ConvertTo-ICTPsLiteral $value | Should -Be ("'O" + [char]0x2019 + [char]0x2019 + "Neil'")
        }
    }

    It 'writes restore commands for keys, tasks and certificates' {
        InModuleScope IntuneComplianceTool {
            $lines = New-ICTRestoreText -BackupPath 'C:\B' -RegistryFile 'registry-01.reg' -Task @([pscustomobject]@{ File = 't.xml'; TaskName = 'PushLaunch'; TaskPath = '\Microsoft\Windows\EnterpriseMgmt\X\' }) `
                -Certificate @([pscustomobject]@{ File = 'c.cer'; Thumbprint = 'ABC' })
            ($lines -join "`n") | Should -Match ([regex]::Escape("reg.exe import 'C:\B\registry-01.reg'"))
            ($lines -join "`n") | Should -Match 'Register-ScheduledTask -Xml'
            ($lines -join "`n") | Should -Match 'certutil.exe -repairstore my ABC'
        }
    }
}
