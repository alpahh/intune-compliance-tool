BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'IntuneComplianceTool' 'IntuneComplianceTool.psd1') -Force
    $script:fixtures = Join-Path $PSScriptRoot 'fixtures'
}

Describe 'ConvertFrom-ICTDsregOutput' {
    It 'parses a hybrid-joined device' {
        $lines = Get-Content -LiteralPath (Join-Path $fixtures 'dsregcmd-hybrid.txt')
        InModuleScope IntuneComplianceTool -Parameters @{ Lines = $lines } {
            $join = ConvertFrom-ICTDsregOutput -Line $Lines
            $join.JoinType | Should -Be 'HybridJoined'
            $join.AzureAdJoined | Should -BeTrue
            $join.DomainJoined | Should -BeTrue
            $join.DeviceName | Should -Be 'PC-0421.contoso.com'
            $join.DeviceId | Should -Be 'b1d5e7a0-1c2d-4e3f-8a9b-0c1d2e3f4a5b'
            $join.DeviceAuthStatus | Should -Be 'SUCCESS'
            $join.TenantName | Should -Be 'Contoso'
            $join.MdmUrl | Should -Be 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc'
            $join.TpmProtected | Should -BeTrue
            $join.AzureAdPrt | Should -BeFalse
            $join.DeviceCertificateValidity | Should -Match '^\[ 2025-01-10'
        }
    }

    It 'parses a device that is only domain joined' {
        $lines = Get-Content -LiteralPath (Join-Path $fixtures 'dsregcmd-notjoined.txt')
        InModuleScope IntuneComplianceTool -Parameters @{ Lines = $lines } {
            $join = ConvertFrom-ICTDsregOutput -Line $Lines
            $join.JoinType | Should -Be 'DomainJoinedOnly'
            $join.AzureAdJoined | Should -BeFalse
            $join.MdmUrl | Should -BeNullOrEmpty
            $join.DeviceAuthStatus | Should -BeNullOrEmpty
        }
    }

    It 'treats empty values as $null' {
        InModuleScope IntuneComplianceTool {
            $join = ConvertFrom-ICTDsregOutput -Line @('             AzureAdJoined : YES', '                    MdmUrl :')
            $join.JoinType | Should -Be 'EntraJoined'
            $join.MdmUrl | Should -BeNullOrEmpty
        }
    }

    It 'returns NotJoined for empty output' {
        InModuleScope IntuneComplianceTool {
            (ConvertFrom-ICTDsregOutput -Line @()).JoinType | Should -Be 'NotJoined'
        }
    }
}

Describe 'New-ICTLapsState' {
    It 'reports an unconfigured device' {
        InModuleScope IntuneComplianceTool {
            $state = New-ICTLapsState -Policy $null
            $state.Configured | Should -BeFalse
        }
    }

    It 'applies Windows LAPS defaults and summarises events' {
        InModuleScope IntuneComplianceTool {
            $policy = [pscustomobject]@{ Source = 'Intune'; BackupDirectory = 1; AdministratorAccountName = 'masteruser'; PasswordAgeDays = $null; PostAuthenticationActions = $null; PostAuthenticationResetDelay = $null }
            $events = @(
                [pscustomobject]@{ TimeCreated = '2026-11-04T10:00:00Z'; Id = 10059; Level = 2; Message = 'Backup failed' }
                [pscustomobject]@{ TimeCreated = '2026-11-03T10:00:00Z'; Id = 10004; Level = 4; Message = 'Processing succeeded' }
                [pscustomobject]@{ TimeCreated = '2026-11-01T10:00:00Z'; Id = 10059; Level = 2; Message = 'Older failure' }
            )
            $state = New-ICTLapsState -Policy $policy -Account $null -LastPasswordUpdate '' -Events $events -LookbackDays 7

            $state.Configured | Should -BeTrue
            $state.BackupTarget | Should -Be 'EntraId'
            $state.PasswordAgeDays | Should -Be 30
            $state.PostAuthenticationActions | Should -Be 3
            $state.PostAuthenticationResetDelayHours | Should -Be 24
            $state.LastPasswordUpdateTime | Should -BeNullOrEmpty
            $state.Events.ErrorCount | Should -Be 2
            $state.Events.LastErrorTime | Should -Be '2026-11-04T10:00:00Z'
            $state.Events.LastErrorMessage | Should -Be 'Backup failed'
            $state.Events.LastSuccessTime | Should -Be '2026-11-03T10:00:00Z'
        }
    }

    It 'keeps "no events" apart from "event log unreadable"' {
        InModuleScope IntuneComplianceTool {
            $policy = [pscustomobject]@{ Source = 'Intune'; BackupDirectory = 1 }
            (New-ICTLapsState -Policy $policy -Events @()).Events.ErrorCount | Should -Be 0
            (New-ICTLapsState -Policy $policy -Events $null).Events | Should -BeNullOrEmpty
        }
    }

    It 'describes post-authentication actions' -TestCases @(
        @{ Actions = 1; Expected = 'reset password after 24 h' }
        @{ Actions = 3; Expected = 'reset password + sign out after 24 h' }
        @{ Actions = 5; Expected = 'reset password + reboot after 24 h' }
        @{ Actions = 11; Expected = 'reset password + sign out + end processes after 24 h' }
        @{ Actions = 0; Expected = 'no action' }
    ) {
        InModuleScope IntuneComplianceTool -Parameters @{ Actions = $Actions; Expected = $Expected } {
            ConvertTo-ICTLapsPostActionText -Actions $Actions -DelayHours 24 | Should -Be $Expected
        }
    }
}
