BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'IntuneComplianceTool' 'IntuneComplianceTool.psd1') -Force
    . (Join-Path $PSScriptRoot 'TestData.ps1')
    $script:dsregLines = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'dsregcmd-hybrid.txt')
    $script:enrollmentId = '8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45'
}

Describe 'Get-ICTDeviceData' {
    BeforeEach {
        $m = 'IntuneComplianceTool'
        Mock -ModuleName $m Test-ICTIsWindows { $true }
        Mock -ModuleName $m Test-ICTIsElevated { $true }
        Mock -ModuleName $m Get-ICTCurrentIdentity { 'PC-0421\masteruser' }
        Mock -ModuleName $m Get-ICTSystemInfo { [pscustomobject]@{ Manufacturer = 'Dell Inc.'; Model = 'Latitude 5440'; OSBuild = 22631; ConsoleUser = 'CONTOSO\anna.berger' } }
        Mock -ModuleName $m Get-ICTPendingReboot { [pscustomobject]@{ Pending = $false; Reasons = @() } }
        Mock -ModuleName $m Get-ICTDsregOutput { $dsregLines }
        Mock -ModuleName $m Get-ICTEnrollmentRegistry {
            [pscustomobject]@{ EnrollmentId = $enrollmentId; IsIntune = $true; Upn = 'anna.berger@contoso.com'; DiscoveryServiceFullUrl = 'https://discovery.contoso.example/x' }
            [pscustomobject]@{ EnrollmentId = '22222222-2222-2222-2222-222222222222'; IsIntune = $false }
        }
        Mock -ModuleName $m Get-ICTAutoEnrollState { [pscustomobject]@{ PolicyAutoEnroll = 1; ExternallyManaged = $false; LastResult = 'Succeeded' } }
        Mock -ModuleName $m Get-ICTMdmCertificate { [pscustomobject]@{ Thumbprint = 'AB'; NotAfter = '2027-05-01T08:00:00Z'; HasPrivateKey = $true } }
        Mock -ModuleName $m Get-ICTEnterpriseMgmtTask {
            [pscustomobject]@{ EnrollmentId = $enrollmentId; TaskName = 'PushLaunch'; LastRunTime = '2026-11-05T10:00:00Z'; LastTaskResult = 0 }
            [pscustomobject]@{ EnrollmentId = $enrollmentId; TaskName = 'Schedule #3'; LastRunTime = '2026-11-05T12:00:00Z'; LastTaskResult = 1 }
        }
        Mock -ModuleName $m Get-ICTOmadmConnectionInfo { [pscustomobject]@{ ServerLastSuccessTime = '2026-11-05T12:15:00Z' } }
        Mock -ModuleName $m Get-ICTServiceState { foreach ($n in $Name) { [pscustomobject]@{ Name = $n; Present = $true; Status = 'Running'; StartType = 'Automatic' } } }
        Mock -ModuleName $m Get-ICTBitLockerState { [pscustomobject]@{ ProtectionOn = $true } }
        Mock -ModuleName $m Get-ICTTpmState { [pscustomobject]@{ Present = $true; Ready = $true } }
        Mock -ModuleName $m Get-ICTSecureBootState { [pscustomobject]@{ Supported = $true; Enabled = $true } }
        Mock -ModuleName $m Get-ICTDefenderState { [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $true } }
        Mock -ModuleName $m Get-ICTFirewallState { [pscustomobject]@{ Profile = 'Domain'; Enabled = $true } }
        Mock -ModuleName $m Get-ICTLapsPolicy { [pscustomobject]@{ Source = 'Intune'; BackupDirectory = 1; AdministratorAccountName = 'masteruser' } }
        Mock -ModuleName $m Get-ICTLocalAccount { [pscustomobject]@{ Name = $Name; Exists = $true; Enabled = $true; IsAdministrator = $true } }
        Mock -ModuleName $m Get-ICTLapsLastPasswordUpdate { '2026-11-02T09:00:00Z' }
        Mock -ModuleName $m Get-ICTWinEvent { }
        Mock -ModuleName $m Get-ICTWinHttpProxy { [pscustomobject]@{ ProxyConfigured = $false } }
        Mock -ModuleName $m Test-ICTTcpEndpoint { foreach ($h in $HostName) { [pscustomobject]@{ HostName = $h; Port = $Port; Reachable = $true; Error = $null } } }
        Mock -ModuleName $m Get-ICTClockOffset { 2 }
    }

    It 'refuses to run on anything but Windows' {
        Mock -ModuleName IntuneComplianceTool Test-ICTIsWindows { $false }
        { Get-ICTDeviceData } | Should -Throw '*must run on Windows*'
    }

    It 'collects every section' {
        $data = Get-ICTDeviceData
        $data.SchemaVersion | Should -Be 2
        $data.RunAs | Should -Be 'PC-0421\masteruser'
        $data.ConsoleUser | Should -Be 'CONTOSO\anna.berger'
        $data.Join.JoinType | Should -Be 'HybridJoined'
        @($data.Enrollments).Count | Should -Be 2
        $data.AutoEnroll.PolicyAutoEnroll | Should -Be 1
        $data.Security.Tpm.Ready | Should -BeTrue
        @($data.Security.Firewall).Count | Should -Be 1
        $data.Laps.Account.Name | Should -Be 'masteruser'
        $data.Network.ClockOffsetSeconds | Should -Be 2
        $data.MdmEvents.ErrorCount | Should -Be 0
        @($data.CollectionErrors).Count | Should -Be 0
    }

    It 'summarises the sync state per Intune enrollment' {
        $data = Get-ICTDeviceData
        @($data.Sync).Count | Should -Be 1
        $data.Sync[0].TaskCount | Should -Be 2
        $data.Sync[0].LastTaskRunTime | Should -Be '2026-11-05T12:00:00Z'
        $data.Sync[0].ServerLastSuccessTime | Should -Be '2026-11-05T12:15:00Z'
    }

    It 'tests all endpoints in one call, including the MDM and discovery hosts' {
        $data = Get-ICTDeviceData
        $hosts = @($data.Network.Endpoints | ForEach-Object { $_.HostName })
        $hosts | Should -Contain 'login.microsoftonline.com'
        $hosts | Should -Contain 'discovery.contoso.example'
        @($hosts | Where-Object { $_ -eq 'enrollment.manage.microsoft.com' }).Count | Should -Be 1
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Test-ICTTcpEndpoint -Times 1 -Exactly
    }

    It 'keeps "none found" apart from "could not read"' {
        Mock -ModuleName IntuneComplianceTool Get-ICTMdmCertificate { }
        Mock -ModuleName IntuneComplianceTool Get-ICTEnterpriseMgmtTask { throw 'Access denied' }
        $data = Get-ICTDeviceData
        $null -eq $data.MdmCertificates | Should -BeFalse -Because 'an empty array means "none found"'
        @($data.MdmCertificates).Count | Should -Be 0
        $data.Sync[0].TaskCount | Should -BeNullOrEmpty -Because 'unreadable tasks must not look like "no tasks"'
        $data.CollectionErrors[0].Group | Should -Be 'Enrollment'
        $data.CollectionErrors[0].Section | Should -Be 'SyncTasks'
    }

    It 'returns $null for an unreadable LAPS policy and does not read the rest' {
        Mock -ModuleName IntuneComplianceTool Get-ICTLapsPolicy { throw 'Access denied' }
        $data = Get-ICTDeviceData
        $data.Laps | Should -BeNullOrEmpty
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Get-ICTLocalAccount -Times 0 -Exactly
    }

    It 'reports an unconfigured LAPS policy' {
        Mock -ModuleName IntuneComplianceTool Get-ICTLapsPolicy { }
        (Get-ICTDeviceData).Laps.Configured | Should -BeFalse
    }

    It 'looks up the automatic LAPS account by prefix' {
        Mock -ModuleName IntuneComplianceTool Get-ICTLapsPolicy {
            [pscustomobject]@{ Source = 'Intune'; BackupDirectory = 1; AutomaticAccountManagement = $true; AutomaticAccountTarget = 1; AutomaticAccountNameOrPrefix = 'masteruser'; AutomaticAccountRandomize = $true }
        }
        $null = Get-ICTDeviceData
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Get-ICTLocalAccount -ParameterFilter { $NamePrefix -eq 'masteruser' -and -not $Name }
    }

    It 'records a clock that cannot be measured without a collection error' {
        Mock -ModuleName IntuneComplianceTool Get-ICTClockOffset { throw 'The operation has timed out.' }
        $data = Get-ICTDeviceData
        $data.Network.ClockOffsetSeconds | Should -BeNullOrEmpty
        $data.Network.ClockError | Should -Be 'The operation has timed out.'
        @($data.CollectionErrors).Count | Should -Be 0
    }

    It 'reports progress for every section' {
        $script:progress = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName IntuneComplianceTool Get-ICTTpmState { throw 'TPM error' }
        $null = Get-ICTDeviceData -OnProgress { param($Name, $Succeeded) $script:progress.Add("$Name=$Succeeded") }
        $progress | Should -Be @('Device=True', 'Join=True', 'Enrollment=True', 'Services=True', 'Security=False', 'LAPS=True', 'Network=True', 'Event log=True')
    }

    It 're-checks only the requested sections and keeps the rest' {
        $previous = New-TestDeviceData
        $previous.CollectionErrors = @([pscustomobject]@{ Group = 'Security'; Section = 'BitLocker'; Error = 'old' }, [pscustomobject]@{ Group = 'Enrollment'; Section = 'SyncTasks'; Error = 'old' })
        $data = Get-ICTDeviceData -Section Enrollment, LAPS -Previous $previous
        $data.Security.BitLocker.EncryptionMethod | Should -Be 'XtsAes256'
        $data.Device.Model | Should -Be 'Latitude 5440'
        @($data.Enrollments).Count | Should -Be 2
        @($data.CollectionErrors | ForEach-Object { $_.Section }) | Should -Be @('BitLocker')
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Get-ICTBitLockerState -Times 0 -Exactly
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Test-ICTTcpEndpoint -Times 0 -Exactly
    }
}
