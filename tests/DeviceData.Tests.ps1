BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'IntuneComplianceTool' 'IntuneComplianceTool.psd1') -Force
    $script:dsregLines = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'dsregcmd-hybrid.txt')
    $script:enrollmentId = '8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45'
    $script:orphanId = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
}

Describe 'Get-ICTDeviceData' {
    BeforeEach {
        $m = 'IntuneComplianceTool'
        Mock -ModuleName $m Test-ICTIsWindows { $true }
        Mock -ModuleName $m Test-ICTIsElevated { $true }
        Mock -ModuleName $m Get-ICTCurrentIdentity { 'PC-0421\masteruser' }
        Mock -ModuleName $m Get-ICTConsoleUser { 'CONTOSO\anna.berger' }
        Mock -ModuleName $m Get-ICTSystemInfo { [pscustomobject]@{ Manufacturer = 'Dell Inc.'; Model = 'Latitude 5440'; OSBuild = 22631 } }
        Mock -ModuleName $m Get-ICTDsregOutput { $dsregLines }
        Mock -ModuleName $m Get-ICTEnrollmentRegistry {
            [pscustomobject]@{ EnrollmentId = $enrollmentId; ProviderId = 'MS DM Server'; IsIntune = $true; Upn = 'anna.berger@contoso.com'; DiscoveryServiceFullUrl = 'https://discovery.contoso.example/x' }
            [pscustomobject]@{ EnrollmentId = '22222222-2222-2222-2222-222222222222'; ProviderId = $null; IsIntune = $false }
        }
        Mock -ModuleName $m Get-ICTMdmCertificate { [pscustomobject]@{ Thumbprint = 'AB'; NotAfter = '2027-05-01T08:00:00Z'; HasPrivateKey = $true } }
        Mock -ModuleName $m Get-ICTEnterpriseMgmtTask {
            [pscustomobject]@{ EnrollmentId = $enrollmentId; TaskName = 'PushLaunch'; LastRunTime = '2026-11-05T10:00:00Z'; LastTaskResult = 0 }
            [pscustomobject]@{ EnrollmentId = $enrollmentId; TaskName = 'Schedule #3'; LastRunTime = '2026-11-05T12:00:00Z'; LastTaskResult = 1 }
            [pscustomobject]@{ EnrollmentId = $orphanId; TaskName = 'PushLaunch'; LastRunTime = $null; LastTaskResult = $null }
        }
        Mock -ModuleName $m Get-ICTOmadmConnectionInfo { [pscustomobject]@{ ServerLastSuccessTime = '2026-11-05T12:15:00Z'; ServerLastAccessTime = '2026-11-05T12:15:00Z' } }
        Mock -ModuleName $m Get-ICTServiceState { foreach ($n in $Name) { [pscustomobject]@{ Name = $n; Present = $true; Status = 'Running'; StartType = 'Automatic' } } }
        Mock -ModuleName $m Get-ICTBitLockerState { [pscustomobject]@{ ProtectionOn = $true } }
        Mock -ModuleName $m Get-ICTTpmState { [pscustomobject]@{ Present = $true; Ready = $true } }
        Mock -ModuleName $m Get-ICTSecureBootState { [pscustomobject]@{ Supported = $true; Enabled = $true } }
        Mock -ModuleName $m Get-ICTDefenderState { [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $true } }
        Mock -ModuleName $m Get-ICTFirewallState { [pscustomobject]@{ Profile = 'Domain'; Enabled = $true } }
        Mock -ModuleName $m Get-ICTLapsPolicy { [pscustomobject]@{ Source = 'Intune'; BackupDirectory = 1; AdministratorAccountName = 'masteruser' } }
        Mock -ModuleName $m Get-ICTLocalAccount { [pscustomobject]@{ Name = $Name; Exists = $true; Enabled = $true; IsAdministrator = $true } }
        Mock -ModuleName $m Get-ICTLapsLastPasswordUpdate { '2026-11-02T09:00:00Z' }
        Mock -ModuleName $m Get-ICTLapsEvent { }
        Mock -ModuleName $m Get-ICTWinHttpProxy { [pscustomobject]@{ ProxyConfigured = $false } }
        Mock -ModuleName $m Test-ICTTcpEndpoint { [pscustomobject]@{ HostName = $HostName; Port = $Port; Reachable = $true; Error = $null } }
        Mock -ModuleName $m Get-ICTMdmEvent { }
    }

    It 'refuses to run on anything but Windows' {
        Mock -ModuleName IntuneComplianceTool Test-ICTIsWindows { $false }
        { Get-ICTDeviceData } | Should -Throw '*must run on Windows*'
    }

    It 'collects every section' {
        $data = Get-ICTDeviceData
        $data.SchemaVersion | Should -Be 1
        $data.RunAs | Should -Be 'PC-0421\masteruser'
        $data.ConsoleUser | Should -Be 'CONTOSO\anna.berger'
        $data.IsElevated | Should -BeTrue
        $data.Join.JoinType | Should -Be 'HybridJoined'
        @($data.Enrollments).Count | Should -Be 2
        @($data.MdmCertificates).Count | Should -Be 1
        $data.Security.Tpm.Ready | Should -BeTrue
        @($data.Security.Firewall).Count | Should -Be 1
        $data.Laps.Configured | Should -BeTrue
        $data.Laps.Account.Name | Should -Be 'masteruser'
        @($data.CollectionErrors).Count | Should -Be 0
    }

    It 'summarises sync state per Intune enrollment and finds orphaned task folders' {
        $data = Get-ICTDeviceData
        @($data.Sync).Count | Should -Be 1
        $data.Sync[0].TaskCount | Should -Be 2
        $data.Sync[0].LastTaskRunTime | Should -Be '2026-11-05T12:00:00Z'
        $data.Sync[0].ServerLastSuccessTime | Should -Be '2026-11-05T12:15:00Z'
        $data.OrphanTaskIds | Should -Be @($orphanId)
    }

    It 'tests configured endpoints plus the MDM and discovery hosts, without duplicates' {
        $data = Get-ICTDeviceData
        $hosts = @($data.Network.Endpoints | ForEach-Object { $_.HostName })
        $hosts | Should -Contain 'login.microsoftonline.com'
        $hosts | Should -Contain 'discovery.contoso.example'
        @($hosts | Where-Object { $_ -eq 'enrollment.manage.microsoft.com' }).Count | Should -Be 1
    }

    It 'keeps going when a section fails and records the error' {
        Mock -ModuleName IntuneComplianceTool Get-ICTBitLockerState { throw 'Access denied' }
        $data = Get-ICTDeviceData
        $data.Security.BitLocker | Should -BeNullOrEmpty
        $data.Security.Tpm | Should -Not -BeNullOrEmpty
        @($data.CollectionErrors).Count | Should -Be 1
        $data.CollectionErrors[0].Section | Should -Be 'BitLocker'
        $data.CollectionErrors[0].Error | Should -Be 'Access denied'
    }

    It 'tells "no LAPS events" apart from "LAPS event log unreadable"' {
        (Get-ICTDeviceData).Laps.Events.ErrorCount | Should -Be 0

        Mock -ModuleName IntuneComplianceTool Get-ICTLapsEvent { throw 'The log does not exist' }
        (Get-ICTDeviceData).Laps.Events | Should -BeNullOrEmpty
    }

    It 'does not read LAPS details when no LAPS policy exists' {
        Mock -ModuleName IntuneComplianceTool Get-ICTLapsPolicy { }
        $data = Get-ICTDeviceData
        $data.Laps.Configured | Should -BeFalse
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Get-ICTLocalAccount -Times 0 -Exactly
    }

    It 'reports progress for every section' {
        $script:progress = New-Object System.Collections.Generic.List[string]
        Mock -ModuleName IntuneComplianceTool Get-ICTTpmState { throw 'TPM error' }
        $null = Get-ICTDeviceData -OnProgress { param($Name, $Succeeded) $script:progress.Add("$Name=$Succeeded") }
        $progress | Should -Be @('Device=True', 'Join=True', 'Enrollment=True', 'Services=True', 'Security=False', 'LAPS=True', 'Network=True', 'Event log=True')
    }
}
