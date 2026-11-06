BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'IntuneComplianceTool' 'IntuneComplianceTool.psd1') -Force
    . (Join-Path $PSScriptRoot 'TestData.ps1')

    function Get-Result {
        param($Evaluation, [string]$Id)
        $Evaluation.Results | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
    }
}

Describe 'Test-ICTCompliance' {
    BeforeEach {
        $data = New-TestDeviceData
        $config = Get-ICTConfig
    }

    Context 'healthy device' {
        It 'is compliant with nothing to do' {
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $evaluation.OverallStatus | Should -Be 'Compliant'
            @($evaluation.RecommendedActions).Count | Should -Be 0
            @($evaluation.Blockers).Count | Should -Be 0
            $evaluation.Summary.Fail | Should -Be 0
            $evaluation.Summary.Unknown | Should -Be 0
        }

        It 'covers every check group' {
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $categories = @($evaluation.Results | ForEach-Object { $_.Category } | Sort-Object -Unique)
            $categories | Should -Be @('Enrollment', 'Health', 'Join', 'LAPS', 'Network', 'Security')
        }
    }

    Context 'broken enrollment' {
        It 'recommends re-enrollment for an expired certificate' {
            $data.MdmCertificates[0].NotAfter = '2026-10-28T08:00:00Z'
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $evaluation.OverallStatus | Should -Be 'EnrollmentBroken'
            $evaluation.RecommendedActions | Should -Be @('ReEnroll')
            $evaluation.CanRepairEnrollment | Should -BeTrue
            (Get-Result $evaluation 'ENR-002').Actual | Should -Match '^expired 2026-10-28'
        }

        It 'recommends re-enrollment when the certificate has no private key' {
            $data.MdmCertificates[0].HasPrivateKey = $false
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'ENR-002').Action | Should -Be 'ReEnroll'
        }

        It 'only warns when the certificate expires soon' {
            $data.MdmCertificates[0].NotAfter = '2026-11-20T08:00:00Z'
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'ENR-002').Status | Should -Be 'Warning'
            $evaluation.OverallStatus | Should -Be 'Compliant'
        }

        It 'recommends re-enrollment when the sync tasks are missing' {
            $data.Sync[0].TaskCount = 0
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'ENR-003').Status | Should -Be 'Fail'
            $evaluation.RecommendedActions | Should -Be @('ReEnroll')
        }

        It 'recommends only a sync when the last check-in is old but everything else is fine' {
            $data.Sync[0].ServerLastSuccessTime = '2026-10-24T10:00:00Z'
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $evaluation.OverallStatus | Should -Be 'EnrollmentBroken'
            $evaluation.RecommendedActions | Should -Be @('Sync')
            (Get-Result $evaluation 'ENR-004').Actual | Should -Be '12 days ago (limit 7 days)'
        }

        It 'prefers re-enrollment over sync when both fail' {
            $data.Sync[0].ServerLastSuccessTime = '2026-10-24T10:00:00Z'
            $data.MdmCertificates = @()
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $evaluation.RecommendedActions | Should -Be @('ReEnroll')
        }

        It 'falls back to the last successful task run for the check-in time' {
            $data.Sync[0].ServerLastSuccessTime = $null
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'ENR-004').Actual | Should -Be '2 h ago (task run)'
        }

        It 'reports a missing enrollment without the follow-up enrollment checks' {
            $data.Enrollments = @()
            $data.Sync = @()
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'ENR-001').Status | Should -Be 'Fail'
            Get-Result $evaluation 'ENR-002' | Should -BeNullOrEmpty
            $evaluation.RecommendedActions | Should -Be @('ReEnroll')
        }

        It 'warns about duplicate enrollments' {
            $second = $data.Enrollments[0].PSObject.Copy()
            $second.EnrollmentId = '11111111-1111-1111-1111-111111111111'
            $data.Enrollments = @($data.Enrollments[0], $second)
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'ENR-001').Status | Should -Be 'Warning'
        }
    }

    Context 'blockers' {
        It 'blocks the repair when the device is not Entra joined' {
            $data.Join.JoinType = 'DomainJoinedOnly'
            $data.Join.AzureAdJoined = $false
            $data.Enrollments = @()
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $evaluation.OverallStatus | Should -Be 'EnrollmentBroken'
            $evaluation.CanRepairEnrollment | Should -BeFalse
            $evaluation.Blockers | Should -Contain 'Entra ID join: Domain joined only'
            Get-Result $evaluation 'JOIN-003' | Should -BeNullOrEmpty
        }

        It 'blocks the repair when an endpoint is unreachable' {
            $data.MdmCertificates = @()
            $data.Network.Endpoints[0].Reachable = $false
            $data.Network.Endpoints[0].Error = 'No such host is known'
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $evaluation.CanRepairEnrollment | Should -BeFalse
            $evaluation.Blockers | Should -Contain 'login.microsoftonline.com:443: unreachable'
        }

        It 'only warns about unreachable endpoints when a WinHTTP proxy is set' {
            $data.Network.WinHttpProxy = [pscustomobject]@{ ProxyConfigured = $true; ProxyServer = 'proxy:8080'; BypassList = $null }
            $data.Network.Endpoints[0].Reachable = $false
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'NET-login.microsoftonline.com').Status | Should -Be 'Warning'
            (Get-Result $evaluation 'NET-PROXY').Actual | Should -Be 'proxy:8080'
            @($evaluation.Blockers).Count | Should -Be 0
        }

        It 'blocks the repair when the MDM URL is missing' {
            $data.Join.MdmUrl = $null
            $data.MdmCertificates = @()
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $evaluation.Blockers | Should -Contain 'MDM auto-enrollment URL: not set'
        }

        It 'blocks the repair when the session is not elevated' {
            $data.IsElevated = $false
            $data.MdmCertificates = @()
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $evaluation.Blockers | Should -Contain 'Session: not running as administrator'
        }
    }

    Context 'security settings' {
        It 'is non-compliant without any repair action when BitLocker is off' {
            $data.Security.BitLocker.ProtectionOn = $false
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $evaluation.OverallStatus | Should -Be 'NonCompliant'
            @($evaluation.RecommendedActions).Count | Should -Be 0
        }

        It 'skips checks that are turned off in the config' {
            $data.Security.BitLocker.ProtectionOn = $false
            $config.RequireBitLocker = $false
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            Get-Result $evaluation 'SEC-002' | Should -BeNullOrEmpty
            $evaluation.OverallStatus | Should -Be 'Compliant'
        }

        It 'fails old builds, old signatures and disabled firewall profiles' {
            $data.Device.OSBuild = 19044
            $data.Security.Defender.AntivirusSignatureAgeDays = 4
            $data.Security.Firewall[2].Enabled = $false
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'SEC-001').Status | Should -Be 'Fail'
            (Get-Result $evaluation 'SEC-006').Actual | Should -Be '4 days old (limit 3)'
            (Get-Result $evaluation 'SEC-007').Actual | Should -Be 'Public off'
        }

        It 'warns instead of failing when Defender runs in passive mode' {
            $data.Security.Defender.AMRunningMode = 'Passive Mode'
            $data.Security.Defender.RealTimeProtectionEnabled = $false
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'SEC-005').Status | Should -Be 'Warning'
            Get-Result $evaluation 'SEC-006' | Should -BeNullOrEmpty
        }

        It 'is indeterminate when data is missing but nothing failed' {
            $data.Security.BitLocker = $null
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'SEC-002').Status | Should -Be 'Unknown'
            $evaluation.OverallStatus | Should -Be 'Indeterminate'
        }
    }

    Context 'services and events' {
        It 'fails a disabled required service and warns about a missing extension' {
            $data.Services[0].StartType = 'Disabled'
            $data.Services[1].Present = $false
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'SVC-dmwappushservice').Status | Should -Be 'Fail'
            (Get-Result $evaluation 'SVC-IntuneManagementExtension').Status | Should -Be 'Warning'
        }

        It 'warns about MDM error events' {
            $data.MdmEvents = [pscustomobject]@{ LookbackDays = 7; ErrorCount = 3; Recent = @([pscustomobject]@{ TimeCreated = '2026-11-05T12:32:00Z'; Id = 404; Message = 'x' }) }
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'EVT-001').Actual | Should -Be '3 in 7 days, latest 2 h ago'
        }
    }

    Context 'LAPS' {
        It 'fails when no LAPS policy is applied' {
            $data.Laps = [pscustomobject]@{ Configured = $false }
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'LAPS-001').Status | Should -Be 'Fail'
            Get-Result $evaluation 'LAPS-002' | Should -BeNullOrEmpty
            $evaluation.OverallStatus | Should -Be 'NonCompliant'
        }

        It 'warns when LAPS manages a different account than masteruser' {
            $data.Laps.Account.Name = 'Administrator'
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'LAPS-002').Status | Should -Be 'Warning'
            (Get-Result $evaluation 'LAPS-002').Actual | Should -Be 'Administrator (expected masteruser)'
        }

        It 'fails when the managed account is not an administrator' {
            $data.Laps.Account.IsAdministrator = $false
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'LAPS-002').Status | Should -Be 'Fail'
        }

        It 'recommends a LAPS retry when the rotation is overdue' {
            $data.Laps.LastPasswordUpdateTime = '2026-09-01T00:00:00Z'
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'LAPS-003').Status | Should -Be 'Fail'
            $evaluation.RecommendedActions | Should -Be @('LapsRetry')
            $evaluation.OverallStatus | Should -Be 'NonCompliant'
        }

        It 'recommends a LAPS retry when the last backup attempt failed' {
            $data.Laps.Events = [pscustomobject]@{ LookbackDays = 7; ErrorCount = 2; LastErrorTime = '2026-11-04T10:00:00Z'; LastErrorId = 10059; LastErrorMessage = 'Backup failed'; LastSuccessTime = '2026-11-02T09:00:00Z' }
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'LAPS-004').Status | Should -Be 'Fail'
            (Get-Result $evaluation 'LAPS-004').Actual | Should -Be 'last attempt failed 28 h ago (event 10059)'
        }

        It 'only warns about LAPS errors that were followed by a successful run' {
            $data.Laps.Events = [pscustomobject]@{ LookbackDays = 7; ErrorCount = 1; LastErrorTime = '2026-11-01T10:00:00Z'; LastErrorId = 10059; LastErrorMessage = 'Backup failed'; LastSuccessTime = '2026-11-02T09:00:00Z' }
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            (Get-Result $evaluation 'LAPS-004').Status | Should -Be 'Warning'
        }

        It 'shows the post-sign-in actions as information' {
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            $result = Get-Result $evaluation 'LAPS-005'
            $result.Status | Should -Be 'Info'
            $result.Actual | Should -Be 'reset password + sign out after 24 h'
        }

        It 'does not check LAPS when RequireLaps is off' {
            $config.RequireLaps = $false
            $evaluation = Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow
            @($evaluation.Results | Where-Object { $_.Category -eq 'LAPS' }).Count | Should -Be 0
        }
    }
}
