BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/IntuneComplianceTool/IntuneComplianceTool.psd1') -Force
    $script:fixtures = Join-Path $PSScriptRoot 'fixtures'
}

Describe 'ConvertFrom-ICTDsregOutput' {
    It 'parses a hybrid-joined device' {
        $lines = Get-Content -LiteralPath (Join-Path $fixtures 'dsregcmd-hybrid.txt')
        InModuleScope IntuneComplianceTool -Parameters @{ Lines = $lines } {
            $join = ConvertFrom-ICTDsregOutput -Line $Lines
            $join.JoinType | Should -Be 'HybridJoined'
            $join.DeviceName | Should -Be 'PC-0421.contoso.com'
            $join.DeviceId | Should -Be 'b1d5e7a0-1c2d-4e3f-8a9b-0c1d2e3f4a5b'
            $join.DeviceAuthStatus | Should -Be 'SUCCESS'
            $join.DeviceCertificateNotAfter | Should -Be '2035-01-10T08:30:00Z'
            $join.KeySignTest | Should -Be 'PASSED'
            $join.TenantName | Should -Be 'Contoso'
            $join.MdmUrl | Should -Be 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc'
        }
    }

    It 'parses a device that is only domain joined' {
        $lines = Get-Content -LiteralPath (Join-Path $fixtures 'dsregcmd-notjoined.txt')
        InModuleScope IntuneComplianceTool -Parameters @{ Lines = $lines } {
            $join = ConvertFrom-ICTDsregOutput -Line $Lines
            $join.JoinType | Should -Be 'DomainJoinedOnly'
            $join.AzureAdJoined | Should -BeFalse
            $join.MdmUrl | Should -BeNullOrEmpty
            $join.DeviceCertificateNotAfter | Should -BeNullOrEmpty
        }
    }

    It 'treats empty values as missing and keeps the first non-empty one' {
        InModuleScope IntuneComplianceTool {
            $join = ConvertFrom-ICTDsregOutput -Line @('             AzureAdJoined : YES', '                    MdmUrl :', '   MdmUrl : https://x.example/y')
            $join.JoinType | Should -Be 'EntraJoined'
            $join.MdmUrl | Should -Be 'https://x.example/y'
        }
    }

    It 'returns NotJoined for empty output' {
        InModuleScope IntuneComplianceTool { (ConvertFrom-ICTDsregOutput -Line @()).JoinType | Should -Be 'NotJoined' }
    }
}

Describe 'ConvertFrom-ICTImeLog' {
    It 'keeps only error entries inside the window, newest first' {
        InModuleScope IntuneComplianceTool {
            $now = [datetime]::new(2026, 11, 5, 12, 0, 0, [System.DateTimeKind]::Local)
            $log = @(
                '<![LOG[Started fine]LOG]!><time="08:00:01.1234567" date="11-5-2026" component="IntuneManagementExtension" context="" type="1" thread="1" file="">'
                '<![LOG[Old failure]LOG]!><time="08:00:01.0" date="10-1-2026" component="AppWorkload" context="" type="3" thread="1" file="">'
                "<![LOG[Download failed`nwith a second line]LOG]!><time=`"09:30:00.5`" date=`"11-5-2026`" component=`"AppWorkload`" context=`"`" type=`"3`" thread=`"1`" file=`"`">"
                '<![LOG[A warning]LOG]!><time="10:00:00.0" date="11-5-2026" component="AgentExecutor" context="" type="2" thread="1" file="">'
                '<![LOG[Script failed]LOG]!><time="10:30:00.0" date="11-5-2026" component="AgentExecutor" context="" type="3" thread="1" file="">'
            ) -join "`n"
            $result = ConvertFrom-ICTImeLog -Text @($log) -Days 7 -Now $now
            $result.ErrorCount | Should -Be 2
            $result.Recent[0].Message | Should -Be 'Script failed'
            $result.Recent[0].Component | Should -Be 'AgentExecutor'
            $result.Recent[1].Message | Should -Be 'Download failed with a second line'
        }
    }

    It 'does not glue an informational entry onto a later error' {
        InModuleScope IntuneComplianceTool {
            $now = [datetime]::new(2026, 11, 5, 12, 0, 0, [System.DateTimeKind]::Local)
            $log = '<![LOG[info]LOG]!><time="08:00:00.0" date="11-5-2026" component="A" type="1"><![LOG[bad]LOG]!><time="09:00:00.0" date="11-5-2026" component="B" type="3">'
            $result = ConvertFrom-ICTImeLog -Text @($log) -Days 7 -Now $now
            $result.ErrorCount | Should -Be 1
            $result.Recent[0].Message | Should -Be 'bad'
        }
    }

    It 'keeps truncated entries from merging with the next one' -TestCases @(
        @{ Broken = '<![LOG[cut off in the header]LOG]!><time="12:00' }
        @{ Broken = '<![LOG[cut off in the message' }
    ) {
        InModuleScope IntuneComplianceTool -Parameters @{ Broken = $Broken } {
            $now = [datetime]::new(2026, 11, 5, 12, 0, 0, [System.DateTimeKind]::Local)
            $log = $Broken + "`n" + '<![LOG[real error]LOG]!><time="09:00:00.0" date="11-5-2026" component="B" type="3">'
            $result = ConvertFrom-ICTImeLog -Text @($log) -Days 7 -Now $now
            $result.ErrorCount | Should -Be 1
            $result.Recent[0].Message | Should -Be 'real error'
        }
    }

    It 'reports how far back the logs go' {
        InModuleScope IntuneComplianceTool {
            $now = [datetime]::new(2026, 11, 5, 12, 0, 0, [System.DateTimeKind]::Local)
            $log = '<![LOG[a]LOG]!><time="08:00:00.0" date="11-4-2026" component="A" type="1"><![LOG[b]LOG]!><time="09:00:00.0" date="11-5-2026" component="B" type="1">'
            $result = ConvertFrom-ICTImeLog -Text @($log) -Days 7 -Now $now
            $result.ErrorCount | Should -Be 0
            $result.OldestEntry | Should -Be (ConvertTo-ICTIsoDate ([datetime]::new(2026, 11, 4, 8, 0, 0, [System.DateTimeKind]::Local)))
        }
    }

    It 'handles no logs at all' {
        InModuleScope IntuneComplianceTool { (ConvertFrom-ICTImeLog -Text @() -Days 7).ErrorCount | Should -Be 0 }
    }
}

Describe 'LAPS helpers' {
    It 'resolves the managed account like Windows does' -TestCases @(
        @{ Policy = @{ AdministratorAccountName = 'masteruser' }; Name = 'masteruser'; Prefix = $null }
        @{ Policy = @{ AdministratorAccountName = 'masteruser'; AutomaticAccountManagement = $true; AutomaticAccountTarget = 0 }; Name = $null; Prefix = $null }
        @{ Policy = @{ AutomaticAccountManagement = $true; AutomaticAccountTarget = 1 }; Name = 'WLapsAdmin'; Prefix = $null }
        @{ Policy = @{ AutomaticAccountManagement = $true; AutomaticAccountTarget = 1; AutomaticAccountNameOrPrefix = 'AVeryLongAdminPrefix'; AutomaticAccountRandomize = $true }; Name = $null; Prefix = 'AVeryLongAdmin' }
    ) {
        InModuleScope IntuneComplianceTool -Parameters @{ Policy = $Policy; Name = $Name; Prefix = $Prefix } {
            $spec = Get-ICTLapsAccountSpec -Policy ([pscustomobject]$Policy)
            $spec.Name | Should -Be $Name
            $spec.NamePrefix | Should -Be $Prefix
        }
    }

    It 'reports an unconfigured device' {
        InModuleScope IntuneComplianceTool { (New-ICTLapsState -Policy $null).Configured | Should -BeFalse }
    }

    It 'treats a policy without BackupDirectory as disabled and applies the defaults' {
        InModuleScope IntuneComplianceTool {
            $state = New-ICTLapsState -Policy ([pscustomobject]@{ Source = 'Intune'; PasswordAgeDays = 14 })
            $state.BackupTarget | Should -Be 'Disabled'
            $state.PasswordAgeDays | Should -Be 14
            $state.PostAuthenticationActions | Should -Be 3
            $state.PostAuthenticationResetDelayHours | Should -Be 24
        }
    }

    It 'recognises legacy Microsoft LAPS' {
        InModuleScope IntuneComplianceTool { (New-ICTLapsState -Policy ([pscustomobject]@{ Source = 'Legacy' })).BackupTarget | Should -Be 'Legacy' }
    }

    It 'summarises errors and the latest success' {
        InModuleScope IntuneComplianceTool {
            $events = @(
                [pscustomobject]@{ TimeCreated = '2026-11-04T10:00:00Z'; Id = 10059; Level = 2; Message = 'Backup failed' }
                [pscustomobject]@{ TimeCreated = '2026-11-03T10:00:00Z'; Id = 10004; Level = 4; Message = 'Processing succeeded' }
                [pscustomobject]@{ TimeCreated = '2026-11-01T10:00:00Z'; Id = 10059; Level = 2; Message = 'Older failure' }
                [pscustomobject]@{ TimeCreated = '2026-11-01T09:00:00Z'; Id = 10000; Level = 0; Message = 'LogAlways is not an error' }
            )
            $state = New-ICTLapsState -Policy ([pscustomobject]@{ Source = 'Intune'; BackupDirectory = 1 }) -Events $events
            $state.Events.ErrorCount | Should -Be 2
            $state.Events.LastErrorMessage | Should -Be 'Backup failed'
            $state.Events.LastSuccessTime | Should -Be '2026-11-03T10:00:00Z'
            (New-ICTLapsState -Policy ([pscustomobject]@{ Source = 'Intune'; BackupDirectory = 1 }) -Events @()).Events.ErrorCount | Should -Be 0
            (New-ICTLapsState -Policy ([pscustomobject]@{ Source = 'Intune'; BackupDirectory = 1 }) -Events $null).Events | Should -BeNullOrEmpty
        }
    }

    It 'describes post-authentication actions' -TestCases @(
        @{ Actions = 1; Delay = 24; Expected = 'reset password after 24 h' }
        @{ Actions = 3; Delay = 8; Expected = 'reset password + sign out after 8 h' }
        @{ Actions = 5; Delay = 24; Expected = 'reset password + reboot after 24 h' }
        @{ Actions = 11; Delay = 24; Expected = 'reset password + sign out + end processes after 24 h' }
        @{ Actions = 3; Delay = 0; Expected = 'none (disabled)' }
        @{ Actions = 0; Delay = 24; Expected = 'none (disabled)' }
    ) {
        InModuleScope IntuneComplianceTool -Parameters @{ Actions = $Actions; Delay = $Delay; Expected = $Expected } {
            ConvertTo-ICTLapsPostActionText -Actions $Actions -DelayHours $Delay | Should -Be $Expected
        }
    }
}
