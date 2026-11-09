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
        $evaluate = { Test-ICTCompliance -DeviceData $data -Config $config -Now $TestNow }
    }

    Context 'healthy device' {
        It 'is compliant with nothing to do' {
            $evaluation = & $evaluate
            $evaluation.OverallStatus | Should -Be 'Compliant'
            @($evaluation.RecommendedActions).Count | Should -Be 0
            @($evaluation.Blockers).Count | Should -Be 0
            $evaluation.Summary.Fail | Should -Be 0
            $evaluation.Summary.Unknown | Should -Be 0
        }

        It 'covers every check group and derives the category from the id' {
            $evaluation = & $evaluate
            @($evaluation.Results | ForEach-Object { $_.Category } | Sort-Object -Unique) | Should -Be @('Enrollment', 'Health', 'Join', 'LAPS', 'Network', 'Security')
            (Get-Result $evaluation 'HLT-REBOOT').Category | Should -Be 'Health'
            (Get-Result $evaluation 'NET-TIME').Category | Should -Be 'Network'
        }
    }

    Context 'broken enrollment' {
        It 'recommends re-enrollment for an expired certificate' {
            $data.MdmCertificates[0].NotAfter = '2026-10-28T08:00:00Z'
            $evaluation = & $evaluate
            $evaluation.OverallStatus | Should -Be 'EnrollmentBroken'
            $evaluation.RecommendedActions | Should -Be @('ReEnroll')
            $evaluation.CanRepairEnrollment | Should -BeTrue
            (Get-Result $evaluation 'ENR-002').Actual | Should -Be 'expired 2026-10-28 (8 days ago)'
            (Get-Result $evaluation 'ENR-002').Remediation | Should -Match 'Re-enroll'
        }

        It 'recommends re-enrollment when the certificate has no private key' {
            $data.MdmCertificates[0].HasPrivateKey = $false
            (Get-Result (& $evaluate) 'ENR-002').Action | Should -Be 'ReEnroll'
        }

        It 'only warns when the certificate expires soon' {
            $data.MdmCertificates[0].NotAfter = '2026-11-20T08:00:00Z'
            $evaluation = & $evaluate
            (Get-Result $evaluation 'ENR-002').Status | Should -Be 'Warning'
            $evaluation.OverallStatus | Should -Be 'Compliant'
        }

        It 'recommends re-enrollment when the sync tasks are missing' {
            $data.Sync[0].TaskCount = 0
            $evaluation = & $evaluate
            (Get-Result $evaluation 'ENR-003').Status | Should -Be 'Fail'
            $evaluation.RecommendedActions | Should -Be @('ReEnroll')
        }

        It 'recommends only a sync when the last check-in is old' {
            $data.Sync[0].ServerLastSuccessTime = '2026-10-24T10:00:00Z'
            $evaluation = & $evaluate
            $evaluation.OverallStatus | Should -Be 'EnrollmentBroken'
            $evaluation.RecommendedActions | Should -Be @('Sync')
            (Get-Result $evaluation 'ENR-004').Actual | Should -Be '12 days ago (limit 7 days)'
        }

        It 'prefers re-enrollment over sync when both fail' {
            $data.Sync[0].ServerLastSuccessTime = '2026-10-24T10:00:00Z'
            $data.MdmCertificates = @()
            (& $evaluate).RecommendedActions | Should -Be @('ReEnroll')
        }

        It 'falls back to the last successful task run for the check-in time' {
            $data.Sync[0].ServerLastSuccessTime = $null
            (Get-Result (& $evaluate) 'ENR-004').Actual | Should -Be '2 h ago (task run)'
        }

        It 'explains a failed auto-enrollment of an unenrolled device and blocks a repair that would fail again' {
            $data.Enrollments = @()
            $data.Sync = @()
            $data.AutoEnroll.LastResult = 'Failed'
            $data.AutoEnroll.LastResultTime = '2026-11-05T12:32:00Z'
            $data.AutoEnroll.LastErrorCode = '0x80180018'
            $evaluation = & $evaluate
            (Get-Result $evaluation 'ENR-001').Status | Should -Be 'Fail'
            Get-Result $evaluation 'ENR-002' | Should -BeNullOrEmpty
            (Get-Result $evaluation 'ENR-005').Actual | Should -Be 'last attempt failed 2 h ago: 0x80180018 (user has no Intune license)'
            $evaluation.CanRepairEnrollment | Should -BeFalse
        }

        It 'does not block the repair for an unknown auto-enrollment error' {
            $data.Enrollments = @(); $data.Sync = @()
            $data.AutoEnroll.LastResult = 'Failed'; $data.AutoEnroll.LastErrorCode = '0x80070005'
            $evaluation = & $evaluate
            (Get-Result $evaluation 'ENR-005').Status | Should -Be 'Warning'
            $evaluation.CanRepairEnrollment | Should -BeTrue
        }

        It 'blocks re-enrollment when another MDM owns the device' {
            $data.AutoEnroll.ExternallyManaged = $true
            $data.MdmCertificates = @()
            $evaluation = & $evaluate
            (Get-Result $evaluation 'ENR-006').Status | Should -Be 'Warning'
            $evaluation.ReEnrollBlockers | Should -Contain 'Managed by another MDM: ExternallyManaged = 1'
        }

        It 'warns about duplicate enrollments' {
            $second = $data.Enrollments[0].PSObject.Copy()
            $second.EnrollmentId = '11111111-1111-1111-1111-111111111111'
            $data.Enrollments = @($data.Enrollments[0], $second)
            (Get-Result (& $evaluate) 'ENR-001').Status | Should -Be 'Warning'
        }
    }

    Context 'unreadable data is Unknown, never a reason to re-enroll' {
        It 'reports unreadable enrollments as Unknown' -TestCases @(
            @{ Property = 'Enrollments'; Id = 'ENR-001' }
            @{ Property = 'MdmCertificates'; Id = 'ENR-002' }
        ) {
            $data.$Property = $null
            $evaluation = & $evaluate
            (Get-Result $evaluation $Id).Status | Should -Be 'Unknown'
            $evaluation.RecommendedActions | Should -Not -Contain 'ReEnroll'
            $evaluation.OverallStatus | Should -Be 'Indeterminate'
        }

        It 'reports unreadable sync tasks as Unknown' {
            $data.Sync[0].TaskCount = $null
            $evaluation = & $evaluate
            (Get-Result $evaluation 'ENR-003').Status | Should -Be 'Unknown'
            @($evaluation.RecommendedActions).Count | Should -Be 0
        }

        It 'reports an unreadable LAPS policy as Unknown, not as "not configured"' {
            $data.Laps = $null
            $evaluation = & $evaluate
            (Get-Result $evaluation 'LAPS-001').Status | Should -Be 'Unknown'
            $evaluation.OverallStatus | Should -Be 'Indeterminate'
        }
    }

    Context 'blockers' {
        It 'blocks the repair when the device is not Entra joined' {
            $data.Join.JoinType = 'DomainJoinedOnly'
            $data.Join.AzureAdJoined = $false
            $data.Enrollments = @()
            $evaluation = & $evaluate
            $evaluation.OverallStatus | Should -Be 'EnrollmentBroken'
            $evaluation.CanRepairEnrollment | Should -BeFalse
            $evaluation.Blockers | Should -Contain 'Entra ID join: Domain joined only'
            Get-Result $evaluation 'JOIN-003' | Should -BeNullOrEmpty
        }

        It 'blocks every enrollment repair when an endpoint is unreachable' {
            $data.Sync[0].ServerLastSuccessTime = '2026-10-24T10:00:00Z'
            $data.Network.Endpoints[0].Reachable = $false
            $data.Network.Endpoints[0].Error = 'No such host is known'
            $evaluation = & $evaluate
            $evaluation.CanRepairEnrollment | Should -BeFalse
            $evaluation.SyncBlockers | Should -Contain 'login.microsoftonline.com:443: unreachable'
        }

        It 'does not let a missing MDM URL block a plain sync' {
            $data.Join.MdmUrl = $null
            $data.Sync[0].ServerLastSuccessTime = '2026-10-24T10:00:00Z'
            $evaluation = & $evaluate
            $evaluation.RecommendedActions | Should -Be @('Sync')
            $evaluation.CanRepairEnrollment | Should -BeTrue
            @($evaluation.SyncBlockers).Count | Should -Be 0
            $evaluation.ReEnrollBlockers | Should -Contain 'MDM auto-enrollment URL: not set'
        }

        It 'only warns about unreachable endpoints when a WinHTTP proxy is set' {
            $data.Network.WinHttpProxy = [pscustomobject]@{ ProxyConfigured = $true; ProxyServer = 'proxy:8080'; BypassList = $null }
            $data.Network.Endpoints[0].Reachable = $false
            $evaluation = & $evaluate
            (Get-Result $evaluation 'NET-login.microsoftonline.com').Status | Should -Be 'Warning'
            (Get-Result $evaluation 'NET-PROXY').Actual | Should -Be 'proxy:8080'
            @($evaluation.SyncBlockers).Count | Should -Be 0
        }

        It 'blocks repairs when the session is not elevated' {
            $data.IsElevated = $false
            $data.MdmCertificates = @()
            (& $evaluate).Blockers | Should -Contain 'Session: not running as administrator'
        }

        It 'blocks re-enrollment when the Entra device key is broken' {
            $data.Join.KeySignTest = 'FAILED. 0x80090016'
            $data.MdmCertificates = @()
            $evaluation = & $evaluate
            (Get-Result $evaluation 'JOIN-004').Status | Should -Be 'Fail'
            $evaluation.CanRepairEnrollment | Should -BeFalse
        }
    }

    Context 'clock, services and reboot' {
        It 'recommends a time sync for a large clock skew, before everything else' {
            $data.Network.ClockOffsetSeconds = 420
            $data.MdmCertificates = @()
            $evaluation = & $evaluate
            (Get-Result $evaluation 'NET-TIME').Actual | Should -Be '7 min ahead'
            $evaluation.RecommendedActions | Should -Be @('TimeSync', 'ReEnroll')
        }

        It 'recommends a time sync when the server certificate is rejected (clock far off)' {
            $data.Network.ClockOffsetSeconds = $null
            $data.Network.ClockError = 'TLS certificate rejected (clock wrong?), and the HTTP fallback failed: timeout'
            $evaluation = & $evaluate
            (Get-Result $evaluation 'NET-TIME').Status | Should -Be 'Fail'
            $evaluation.RecommendedActions | Should -Be @('TimeSync')
        }

        It 'only notes the clock when it could not be measured' {
            $data.Network.ClockOffsetSeconds = $null
            $data.Network.ClockError = 'timed out'
            $evaluation = & $evaluate
            (Get-Result $evaluation 'NET-TIME').Status | Should -Be 'Info'
            $evaluation.OverallStatus | Should -Be 'Compliant'
        }

        It 'repairs a disabled push service and a stopped extension' {
            $data.Services[0].StartType = 'Disabled'
            $data.Services[1].Status = 'Stopped'
            $evaluation = & $evaluate
            (Get-Result $evaluation 'SVC-dmwappushservice').Status | Should -Be 'Fail'
            (Get-Result $evaluation 'SVC-IntuneManagementExtension').Action | Should -Be 'ServiceFix'
            $evaluation.RecommendedActions | Should -Be @('ServiceFix')
            $evaluation.OverallStatus | Should -Be 'NonCompliant'
        }

        It 'warns about a missing extension without a repair' {
            $data.Services[1].Present = $false
            $result = Get-Result (& $evaluate) 'SVC-IntuneManagementExtension'
            $result.Status | Should -Be 'Warning'
            $result.Action | Should -BeNullOrEmpty
        }

        It 'warns about a pending reboot and a long uptime' {
            $data.PendingReboot = [pscustomobject]@{ Pending = $true; Reasons = @('Windows Update') }
            (Get-Result (& $evaluate) 'HLT-REBOOT').Actual | Should -Be 'yes, Windows Update (up 2 h)'

            $data.PendingReboot = [pscustomobject]@{ Pending = $false; Reasons = @() }
            $data.Device.LastBootTime = '2026-09-01T00:00:00Z'
            (Get-Result (& $evaluate) 'HLT-REBOOT').Status | Should -Be 'Warning'
        }

        It 'shows a capped MDM error count with a plus' {
            $data.MdmEvents = [pscustomobject]@{ LookbackDays = 7; ErrorCount = 100; Truncated = $true; Recent = @([pscustomobject]@{ TimeCreated = '2026-11-05T12:32:00Z'; Id = 404; Message = 'x' }) }
            (Get-Result (& $evaluate) 'EVT-001').Actual | Should -Be '100+ in 7 days, latest 2 h ago'
        }
    }

    Context 'security settings' {
        It 'is non-compliant without any repair when BitLocker is off' {
            $data.Security.BitLocker.ProtectionOn = $false
            $evaluation = & $evaluate
            $evaluation.OverallStatus | Should -Be 'NonCompliant'
            @($evaluation.RecommendedActions).Count | Should -Be 0
        }

        It 'skips checks that are turned off in the config' {
            $data.Security.BitLocker.ProtectionOn = $false
            $config.RequireBitLocker = $false
            $evaluation = & $evaluate
            Get-Result $evaluation 'SEC-002' | Should -BeNullOrEmpty
            $evaluation.OverallStatus | Should -Be 'Compliant'
        }

        It 'checks the patch level (UBR) when a minimum is configured' {
            $config.MinimumOSRevision = [pscustomobject]@{ '22631' = 4600 }
            $result = Get-Result (& $evaluate) 'SEC-001'
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be '22631.4460 (min 22631.4600)'

            $config.MinimumOSRevision = [pscustomobject]@{ '26100' = 9999 }
            (Get-Result (& $evaluate) 'SEC-001').Status | Should -Be 'Pass'

            $config.MinimumOSRevision = [pscustomobject]@{ '22631' = 4600 }
            $data.Device.OSUpdateBuildRevision = $null
            (Get-Result (& $evaluate) 'SEC-001').Status | Should -Be 'Unknown'
        }

        It 'fails old builds, old signatures and disabled firewall profiles' {
            $data.Device.OSBuild = 19044
            $data.Security.Defender.AntivirusSignatureAgeDays = 4
            $data.Security.Firewall[2].Enabled = $false
            $evaluation = & $evaluate
            (Get-Result $evaluation 'SEC-001').Status | Should -Be 'Fail'
            (Get-Result $evaluation 'SEC-006').Actual | Should -Be '4 days old (limit 3)'
            (Get-Result $evaluation 'SEC-007').Actual | Should -Be 'Public off'
        }

        It 'warns instead of failing when Defender runs in passive mode' {
            $data.Security.Defender.AMRunningMode = 'Passive Mode'
            $data.Security.Defender.RealTimeProtectionEnabled = $false
            $evaluation = & $evaluate
            (Get-Result $evaluation 'SEC-005').Status | Should -Be 'Warning'
            Get-Result $evaluation 'SEC-006' | Should -BeNullOrEmpty
        }

        It 'is indeterminate when data is missing but nothing failed' {
            $data.Security.BitLocker = $null
            $evaluation = & $evaluate
            (Get-Result $evaluation 'SEC-002').Status | Should -Be 'Unknown'
            $evaluation.OverallStatus | Should -Be 'Indeterminate'
        }
    }

    Context 'LAPS' {
        It 'fails when no LAPS policy is applied' {
            $data.Laps = [pscustomobject]@{ Configured = $false }
            $evaluation = & $evaluate
            (Get-Result $evaluation 'LAPS-001').Status | Should -Be 'Fail'
            Get-Result $evaluation 'LAPS-002' | Should -BeNullOrEmpty
            $evaluation.OverallStatus | Should -Be 'NonCompliant'
        }

        It 'warns about legacy Microsoft LAPS' {
            $data.Laps.BackupTarget = 'Legacy'
            (Get-Result (& $evaluate) 'LAPS-001').Actual | Should -Be 'legacy Microsoft LAPS (AdmPwd)'
        }

        It 'fails when the backup is disabled' {
            $data.Laps.BackupTarget = 'Disabled'
            (Get-Result (& $evaluate) 'LAPS-001').Status | Should -Be 'Fail'
        }

        It 'shows the policy source and automatic account management' {
            $data.Laps.AutomaticAccountManagement = $true
            $data.Laps.PolicySource = 'GroupPolicy'
            (Get-Result (& $evaluate) 'LAPS-001').Actual | Should -Be 'backup to Entra ID (GroupPolicy, automatic account)'
        }

        It 'warns when LAPS manages a different account than masteruser' {
            $data.Laps.Account.Name = 'Administrator'
            $result = Get-Result (& $evaluate) 'LAPS-002'
            $result.Status | Should -Be 'Warning'
            $result.Actual | Should -Be 'Administrator (expected masteruser)'
        }

        It 'accepts a randomized name built from the expected prefix' {
            $data.Laps.Account.Name = 'masteruser123456'
            (Get-Result (& $evaluate) 'LAPS-002').Status | Should -Be 'Pass'
        }

        It 'accepts an account that automatic account management keeps disabled' {
            $data.Laps.AutomaticAccountManagement = $true
            $data.Laps.AutomaticAccountEnabled = $false
            $data.Laps.Account.Enabled = $false
            (Get-Result (& $evaluate) 'LAPS-002').Actual | Should -Be 'masteruser (disabled by LAPS policy)'

            $data.Laps.AutomaticAccountEnabled = $true
            $result = Get-Result (& $evaluate) 'LAPS-002'
            $result.Status | Should -Be 'Fail'
            $result.Remediation | Should -Match 'LAPS policy'
        }

        It 'fails when the managed account is not an administrator' {
            $data.Laps.Account.IsAdministrator = $false
            (Get-Result (& $evaluate) 'LAPS-002').Status | Should -Be 'Fail'
        }

        It 'recommends a LAPS retry when the rotation is overdue' {
            $data.Laps.LastPasswordUpdateTime = '2026-09-01T00:00:00Z'
            $evaluation = & $evaluate
            (Get-Result $evaluation 'LAPS-003').Status | Should -Be 'Fail'
            $evaluation.RecommendedActions | Should -Be @('LapsRetry')
        }

        It 'recommends a LAPS retry when the last backup attempt failed' {
            $data.Laps.Events = [pscustomobject]@{ LookbackDays = 7; ErrorCount = 2; LastErrorTime = '2026-11-04T10:00:00Z'; LastErrorId = 10059; LastErrorMessage = 'Backup failed'; LastSuccessTime = '2026-11-02T09:00:00Z' }
            $result = Get-Result (& $evaluate) 'LAPS-004'
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be 'last attempt failed 28 h ago (event 10059)'
        }

        It 'only warns about LAPS errors that were followed by a successful run' {
            $data.Laps.Events = [pscustomobject]@{ LookbackDays = 7; ErrorCount = 1; LastErrorTime = '2026-11-01T10:00:00Z'; LastErrorId = 10059; LastErrorMessage = 'Backup failed'; LastSuccessTime = '2026-11-02T09:00:00Z' }
            (Get-Result (& $evaluate) 'LAPS-004').Status | Should -Be 'Warning'
        }

        It 'describes the post-sign-in actions, and calls them off when the delay is 0' {
            $result = Get-Result (& $evaluate) 'LAPS-005'
            $result.Status | Should -Be 'Info'
            $result.Actual | Should -Be 'reset password + sign out after 24 h'
            $result.Message | Should -Match 'SSH'

            $data.Laps.PostAuthenticationResetDelayHours = 0
            $result = Get-Result (& $evaluate) 'LAPS-005'
            $result.Actual | Should -Be 'none (disabled)'
            $result.Message | Should -BeNullOrEmpty
        }

        It 'does not check LAPS when RequireLaps is off' {
            $config.RequireLaps = $false
            @((& $evaluate).Results | Where-Object { $_.Category -eq 'LAPS' }).Count | Should -Be 0
        }
    }
}
