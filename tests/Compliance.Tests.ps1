BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/IntuneComplianceTool/IntuneComplianceTool.psd1') -Force
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
            @($evaluation.Results | ForEach-Object { $_.Category } | Sort-Object -Unique) | Should -Be @('Enrollment', 'Health', 'Join', 'LAPS', 'Network', 'Security', 'Updates')
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

        It 'shows the extension log errors as information' {
            $data.ImeLog = [pscustomobject]@{ LookbackDays = 7; OldestEntry = '2026-10-01T00:00:00Z'; ErrorCount = 4; Recent = @([pscustomobject]@{ TimeCreated = '2026-11-05T12:32:00Z'; Component = 'AppWorkload'; Message = 'x' }) }
            $evaluation = & $evaluate
            (Get-Result $evaluation 'HLT-IME').Status | Should -Be 'Info'
            (Get-Result $evaluation 'HLT-IME').Actual | Should -Be '4 errors in 7 days, latest 2 h ago'
            $evaluation.OverallStatus | Should -Be 'Compliant'
        }

        It 'names the period the rotated extension logs really cover' {
            $data.ImeLog = [pscustomobject]@{ LookbackDays = 7; OldestEntry = '2026-11-03T14:32:00Z'; ErrorCount = 0; Recent = @() }
            (Get-Result (& $evaluate) 'HLT-IME').Actual | Should -Be 'no errors since 2 days ago'
        }

        It 'does not check the extension log when the extension is not installed' {
            $data.Services[1].Present = $false
            Get-Result (& $evaluate) 'HLT-IME' | Should -BeNullOrEmpty
        }

        It 'shows nothing about ConfigMgr without a client' {
            Get-Result (& $evaluate) 'HLT-COMGMT' | Should -BeNullOrEmpty
        }

        It 'decodes the co-management workloads, also with the newer marker bits' -TestCases @(
            @{ Flags = 11; Text = 'co-managed, 2 workloads in Intune'; Listed = 'Compliance, Device config' }
            @{ Flags = 8203; Text = 'co-managed, 2 workloads in Intune'; Listed = 'Compliance, Device config' }
            @{ Flags = 4130; Text = 'co-managed, 2 workloads in Intune'; Listed = 'Compliance, Endpoint protection' }
        ) {
            $data.ConfigMgr = [pscustomobject]@{ ClientInstalled = $true; Workloads = $Flags; WorkloadsReadable = $true }
            $result = Get-Result (& $evaluate) 'HLT-COMGMT'
            $result.Status | Should -Be 'Info'
            $result.Actual | Should -Be $Text
            $result.Message | Should -Match $Listed
        }

        It 'warns when ConfigMgr keeps the compliance workload' {
            $data.ConfigMgr = [pscustomobject]@{ ClientInstalled = $true; Workloads = 9; WorkloadsReadable = $true }
            (Get-Result (& $evaluate) 'HLT-COMGMT').Status | Should -Be 'Warning'
        }

        It 'does not call a client co-managed when no workload moved' -TestCases @(@{ Flags = 1 }, @{ Flags = 8193 }, @{ Flags = 0 }, @{ Flags = $null }) {
            $data.ConfigMgr = [pscustomobject]@{ ClientInstalled = $true; Workloads = $Flags; WorkloadsReadable = $true }
            $data.MdmCertificates = @()
            $evaluation = & $evaluate
            (Get-Result $evaluation 'HLT-COMGMT').Actual | Should -Be 'client installed, no workloads in Intune'
            $evaluation.CanRepairEnrollment | Should -BeTrue
        }

        It 'blocks re-enrollment when the co-management state cannot be read' {
            $data.ConfigMgr = [pscustomobject]@{ ClientInstalled = $true; Workloads = $null; WorkloadsReadable = $false }
            $data.MdmCertificates = @()
            $evaluation = & $evaluate
            (Get-Result $evaluation 'HLT-COMGMT').Actual | Should -Be 'client installed, workloads unreadable'
            $evaluation.Blockers | Should -Contain 'ConfigMgr: the co-management state could not be read'
        }

        It 'blocks re-enrollment, also behind a sync, but not the sync itself, on co-managed devices' {
            $data.ConfigMgr = [pscustomobject]@{ ClientInstalled = $true; Workloads = 3; WorkloadsReadable = $true }
            $data.Sync[0].ServerLastSuccessTime = '2026-10-24T10:00:00Z'
            $evaluation = & $evaluate
            $evaluation.RecommendedActions | Should -Be @('Sync')
            $evaluation.CanRepairEnrollment | Should -BeTrue
            $evaluation.ReEnrollBlockers | Should -Contain 'Co-management: ConfigMgr controls the MDM enrollment of this device'

            $data.MdmCertificates = @()
            (& $evaluate).CanRepairEnrollment | Should -BeFalse
        }

        It 'shows a capped MDM error count with a plus' {
            $data.MdmEvents = [pscustomobject]@{ LookbackDays = 7; ErrorCount = 100; Truncated = $true; Recent = @([pscustomobject]@{ TimeCreated = '2026-11-05T12:32:00Z'; Id = 404; Message = 'x' }) }
            (Get-Result (& $evaluate) 'EVT-001').Actual | Should -Be '100+ in 7 days, latest 2 h ago'
        }
    }

    Context 'Windows Update' {
        BeforeEach { $data.Device.LastBootTime = '2026-11-01T00:00:00Z' }   # running for days, so an old scan is not just "was off"

        It 'is healthy with a recent scan and install' {
            $evaluation = & $evaluate
            (Get-Result $evaluation 'UPD-SCAN').Actual | Should -Be '6 h ago'
            (Get-Result $evaluation 'UPD-SOURCE').Actual | Should -Be 'Windows Update (Intune policy)'
            (Get-Result $evaluation 'UPD-DISK').Actual | Should -Be '120.5 GB free of 237.9 GB'
            @($evaluation.Results | Where-Object { $_.Category -eq 'Updates' -and $_.Status -in 'Fail', 'Warning' }).Count | Should -Be 0
        }

        It 'repairs Windows Update when the last successful scan is too old' {
            $data.Updates.Agent.LastSearchSuccess = '2026-10-01T00:00:00Z'
            $evaluation = & $evaluate
            (Get-Result $evaluation 'UPD-SCAN').Status | Should -Be 'Fail'
            $evaluation.RecommendedActions | Should -Be @('UpdateFix')
            $evaluation.OverallStatus | Should -Be 'NonCompliant'
        }

        It 'repairs Windows Update when it never scanned successfully' {
            $data.Updates.Agent.LastSearchSuccess = $null
            (Get-Result (& $evaluate) 'UPD-SCAN').Actual | Should -Be 'never succeeded'
        }

        It 'repairs disabled update services' {
            $data.Updates.Services[0].StartType = 'Disabled'
            $result = Get-Result (& $evaluate) 'UPD-SVC'
            $result.Actual | Should -Be 'wuauserv disabled'
            $result.Action | Should -Be 'UpdateFix'
        }

        It 'counts failed updates by update and repairs only for component errors' {
            $failure = { param($kb, $code) [pscustomobject]@{ Date = '2026-11-04T03:00:00Z'; Title = "2026-11 Cumulative Update ($kb)"; ResultCode = 4; HResult = $code } }
            $data.Updates.History = @((& $failure 'KB5067777' '0x800f0922'), (& $failure 'KB5067777' '0x800f0922'))
            $result = Get-Result (& $evaluate) 'UPD-FAILED'
            $result.Status | Should -Be 'Warning'
            $result.Actual | Should -Be 'KB5067777 0x800f0922, 1 failing in 30 days'
            $result.Action | Should -BeNullOrEmpty -Because '0x800f0922 is not a broken-component error'

            $data.Updates.History = @((& $failure 'KB5067777' '0x80073712'))
            (Get-Result (& $evaluate) 'UPD-FAILED').Action | Should -Be 'UpdateFix'
        }

        It 'ignores Defender definitions, KB5034441 and aborted installs' {
            $data.Updates.History = @(
                [pscustomobject]@{ Date = '2026-11-04T03:00:00Z'; Title = 'Security Intelligence Update for Microsoft Defender Antivirus - KB2267602'; ResultCode = 4; HResult = '0x80070002' }
                [pscustomobject]@{ Date = '2026-11-04T03:00:00Z'; Title = 'Windows Recovery Environment update (KB5034441)'; ResultCode = 4; HResult = '0x80070643' }
                [pscustomobject]@{ Date = '2026-11-04T03:00:00Z'; Title = 'Cumulative Update (KB5067777)'; ResultCode = 5; HResult = '0x80240022' }
            )
            (Get-Result (& $evaluate) 'UPD-FAILED').Status | Should -Be 'Pass'
        }

        It 'says when the history was cleared by a reset' {
            $data.Updates.History = @()
            $data.Updates.LastReset = '2026-11-04T14:32:00Z'
            (Get-Result (& $evaluate) 'UPD-FAILED').Actual | Should -Be 'none since the reset 24 h ago'
        }

        It 'does not judge the agent dates when ConfigMgr, WSUS or a policy drives updates' -TestCases @(
            @{ Change = { param($d) $d.ConfigMgr = [pscustomobject]@{ ClientInstalled = $true; Workloads = 3; WorkloadsReadable = $true } }; Via = 'ConfigMgr' }
            @{ Change = { param($d) $d.Updates.Policy.WsusServer = 'http://wsus:8530' }; Via = 'WSUS' }
            @{ Change = { param($d) $d.Updates.Policy.NoAutoUpdate = $true }; Via = 'policy' }
        ) {
            $data.Updates.Agent.LastSearchSuccess = '2026-10-01T00:00:00Z'
            & $Change $data
            $result = Get-Result (& $evaluate) 'UPD-SCAN'
            $result.Status | Should -Be 'Info'
            $result.Actual | Should -Match "updates via $Via"
            $result.Action | Should -BeNullOrEmpty
        }

        It 'judges the agent dates when ConfigMgr left the update workload to Intune' {
            $data.ConfigMgr = [pscustomobject]@{ ClientInstalled = $true; Workloads = 19; WorkloadsReadable = $true }
            $data.Updates.Agent.LastSearchSuccess = '2026-10-01T00:00:00Z'
            (Get-Result (& $evaluate) 'UPD-SCAN').Status | Should -Be 'Fail'
        }

        It 'only warns about an old scan on a device that just started' {
            $data.Updates.Agent.LastSearchSuccess = '2026-10-01T00:00:00Z'
            $data.Device.LastBootTime = '2026-11-05T13:00:00Z'
            $result = Get-Result (& $evaluate) 'UPD-SCAN'
            $result.Status | Should -Be 'Warning'
            $result.Action | Should -BeNullOrEmpty
        }

        It 'never repairs only because no update was installed for a while' {
            $data.Updates.Agent.LastInstallSuccess = '2026-08-01T00:00:00Z'
            $result = Get-Result (& $evaluate) 'UPD-INSTALL'
            $result.Status | Should -Be 'Warning'
            $result.Action | Should -BeNullOrEmpty
        }

        It 'reports an update agent that cannot be asked as Unknown' {
            $data.Updates.Agent = [pscustomobject]@{ Readable = $false; Error = 'The service cannot be started (0x80070422)'; LastSearchSuccess = $null; LastInstallSuccess = $null; InstallerBusy = $null }
            $data.Updates.Services[0].StartType = 'Disabled'
            $evaluation = & $evaluate
            (Get-Result $evaluation 'UPD-SCAN').Status | Should -Be 'Unknown'
            $evaluation.RecommendedActions | Should -Be @('UpdateFix') -Because 'the disabled service still asks for the repair'
        }

        It 'ignores a missing UsoSvc on builds without it' {
            $data.Updates.Services[3].Present = $false
            (Get-Result (& $evaluate) 'UPD-SVC').Status | Should -Be 'Pass'
        }

        It 'fails on an unreachable WSUS server without a repair' {
            $data.Updates.Policy.WsusServer = 'http://wsus.contoso.local:8530'
            $data.Updates.Wsus = [pscustomobject]@{ HostName = 'wsus.contoso.local'; Port = 8530; Reachable = $false; Error = 'timed out' }
            $result = Get-Result (& $evaluate) 'UPD-SOURCE'
            $result.Status | Should -Be 'Fail'
            $result.Actual | Should -Be 'WSUS wsus.contoso.local unreachable'
            $result.Action | Should -BeNullOrEmpty
        }

        It 'only warns about an unreachable WSUS when quality updates come from Windows Update' {
            $data.Updates.Policy.WsusServer = 'http://wsus.contoso.local:8530'
            $data.Updates.Policy.QualityFromWindowsUpdate = $true
            $data.Updates.Wsus = [pscustomobject]@{ HostName = 'wsus.contoso.local'; Port = 8530; Reachable = $false; Error = 'timed out' }
            (Get-Result (& $evaluate) 'UPD-SOURCE').Status | Should -Be 'Warning'
        }

        It 'blocks a reset that cannot help or that just happened' {
            $data.Updates.Services[0].StartType = 'Disabled'
            $data.Updates.Policy.WsusServer = 'http://wsus.contoso.local:8530'
            $data.Updates.Wsus = [pscustomobject]@{ HostName = 'wsus.contoso.local'; Port = 8530; Reachable = $false; Error = 'timed out' }
            $data.Updates.LastReset = '2026-11-05T10:32:00Z'
            $evaluation = & $evaluate
            $evaluation.UpdateBlockers | Should -Contain 'Update source: WSUS wsus.contoso.local unreachable'
            $evaluation.UpdateBlockers | Should -Contain 'Windows Update: reset 4 h ago, give it time to recover'
        }

        It 'warns about policies that switch updates off' {
            $data.Updates.Policy.DisableAccess = $true
            (Get-Result (& $evaluate) 'UPD-SOURCE').Status | Should -Be 'Warning'
        }

        It 'warns and fails on low disk space' {
            $data.Updates.Disk.FreeGB = 8
            (Get-Result (& $evaluate) 'UPD-DISK').Status | Should -Be 'Warning'
            $data.Updates.Disk.FreeGB = 3
            (Get-Result (& $evaluate) 'UPD-DISK').Status | Should -Be 'Fail'
        }

        It 'reports unreadable parts as Unknown and recommends nothing' {
            $data.Updates.Agent = $null
            $data.Updates.History = $null
            $evaluation = & $evaluate
            (Get-Result $evaluation 'UPD-SCAN').Status | Should -Be 'Unknown'
            (Get-Result $evaluation 'UPD-FAILED').Status | Should -Be 'Unknown'
            @($evaluation.RecommendedActions).Count | Should -Be 0
        }

        It 'blocks the update repair during a pending reboot or a running installation' {
            $data.Updates.Agent.LastSearchSuccess = '2026-10-01T00:00:00Z'
            $data.PendingReboot = [pscustomobject]@{ Pending = $true; Reasons = @('Windows Update') }
            $data.Updates.Agent.InstallerBusy = $true
            $evaluation = & $evaluate
            $evaluation.UpdateBlockers | Should -Be @('Pending reboot: restart the device first', 'Windows Update: installing right now')
        }

        It 'checks nothing about updates when it is turned off' {
            $config.CheckWindowsUpdate = $false
            @((& $evaluate).Results | Where-Object { $_.Category -eq 'Updates' }).Count | Should -Be 0
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
