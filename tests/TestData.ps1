# Shared test data: a healthy, compliant device as returned by Get-ICTDeviceData.
# Tests take a fresh copy and break the part they want to test.

$script:TestNow = [datetime]::new(2026, 11, 5, 14, 32, 0, [System.DateTimeKind]::Utc)
$script:TestEnrollmentId = '8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45'
$script:TestIntuneDeviceId = '3f9c1a2e-7d4b-4c8e-a1f6-5e2b9d0c91b0'

function New-TestDeviceData {
    [CmdletBinding()]
    param()

    $enrollmentId = $script:TestEnrollmentId
    [pscustomobject]@{
        SchemaVersion    = 2
        ToolVersion      = '0.2.0'
        CollectedAt      = '2026-11-05T14:32:00Z'
        ComputerName     = 'PC-0421'
        IsElevated       = $true
        RunAs            = 'PC-0421\masteruser'
        ConsoleUser      = 'CONTOSO\anna.berger'
        Device           = [pscustomobject]@{
            Manufacturer = 'Dell Inc.'; Model = 'Latitude 5440'; SerialNumber = '7XK2Q93'
            OSCaption = 'Microsoft Windows 11 Enterprise'; OSBuild = 22631; OSUpdateBuildRevision = 4460; OSDisplayVersion = '23H2'
            LastBootTime = '2026-11-05T12:10:00Z'; ConsoleUser = 'CONTOSO\anna.berger'
        }
        PendingReboot    = [pscustomobject]@{ Pending = $false; Reasons = @() }
        Join             = [pscustomobject]@{
            JoinType = 'HybridJoined'; AzureAdJoined = $true; DomainJoined = $true; DeviceName = 'PC-0421'
            DeviceId = 'b1d5e7a0-1c2d-4e3f-8a9b-0c1d2e3f4a5b'; DeviceAuthStatus = 'SUCCESS'
            DeviceCertificateNotAfter = '2035-01-10T08:30:00Z'; KeySignTest = 'PASSED'
            TenantName = 'Contoso'; TenantId = '11111111-2222-3333-4444-555555555555'
            MdmUrl = 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc'
        }
        AutoEnroll       = [pscustomobject]@{
            PolicyAutoEnroll = 1; PolicyCredentialType = 1; ExternallyManaged = $false
            LastResult = 'Succeeded'; LastResultTime = '2026-05-01T08:00:00Z'; LastErrorCode = $null
        }
        Enrollments      = @(
            [pscustomobject]@{
                EnrollmentId = $enrollmentId; IsIntune = $true; Upn = 'anna.berger@contoso.com'; EnrollmentState = 1
                DiscoveryServiceFullUrl = 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc'
            }
        )
        MdmCertificates  = @(
            [pscustomobject]@{
                Thumbprint = 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678'; Subject = "CN=$($script:TestIntuneDeviceId)"
                IntuneDeviceId = $script:TestIntuneDeviceId; NotBefore = '2026-05-01T08:00:00Z'; NotAfter = '2027-05-01T08:00:00Z'; HasPrivateKey = $true
            }
        )
        Sync             = @(
            [pscustomobject]@{
                EnrollmentId = $enrollmentId; TaskCount = 8; LastTaskRunTime = '2026-11-05T12:15:00Z'; LastTaskResult = 0
                ServerLastSuccessTime = '2026-11-05T12:15:00Z'
            }
        )
        Services         = @(
            [pscustomobject]@{ Name = 'dmwappushservice'; Present = $true; Status = 'Stopped'; StartType = 'Manual' }
            [pscustomobject]@{ Name = 'IntuneManagementExtension'; Present = $true; Status = 'Running'; StartType = 'Automatic' }
        )
        Security         = [pscustomobject]@{
            BitLocker  = [pscustomobject]@{ MountPoint = 'C:'; ProtectionOn = $true; VolumeStatus = 'FullyEncrypted'; EncryptionMethod = 'XtsAes256' }
            Tpm        = [pscustomobject]@{ Present = $true; Ready = $true }
            SecureBoot = [pscustomobject]@{ Supported = $true; Enabled = $true }
            Defender   = [pscustomobject]@{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $true; AMRunningMode = 'Normal'; AntivirusSignatureAgeDays = 0 }
            Firewall   = @(
                [pscustomobject]@{ Profile = 'Domain'; Enabled = $true }
                [pscustomobject]@{ Profile = 'Private'; Enabled = $true }
                [pscustomobject]@{ Profile = 'Public'; Enabled = $true }
            )
        }
        Laps             = [pscustomobject]@{
            Configured = $true; PolicySource = 'Intune'; BackupTarget = 'EntraId'; AutomaticAccountManagement = $false; AutomaticAccountEnabled = $false
            AdministratorAccountName = 'masteruser'; PasswordAgeDays = 30; PostAuthenticationActions = 3; PostAuthenticationResetDelayHours = 24
            LastPasswordUpdateTime = '2026-11-02T09:00:00Z'
            Account = [pscustomobject]@{ Name = 'masteruser'; Exists = $true; Enabled = $true; IsAdministrator = $true }
            Events = [pscustomobject]@{ LookbackDays = 7; ErrorCount = 0; LastErrorTime = $null; LastErrorId = $null; LastErrorMessage = $null; LastSuccessTime = '2026-11-05T13:00:00Z' }
        }
        Network          = [pscustomobject]@{
            WinHttpProxy       = [pscustomobject]@{ ProxyConfigured = $false; ProxyServer = $null; BypassList = $null }
            Endpoints          = @(
                [pscustomobject]@{ HostName = 'login.microsoftonline.com'; Port = 443; Reachable = $true; Error = $null }
                [pscustomobject]@{ HostName = 'enterpriseregistration.windows.net'; Port = 443; Reachable = $true; Error = $null }
                [pscustomobject]@{ HostName = 'enrollment.manage.microsoft.com'; Port = 443; Reachable = $true; Error = $null }
            )
            ClockOffsetSeconds = 1
            ClockError         = $null
        }
        MdmEvents        = [pscustomobject]@{ LookbackDays = 7; ErrorCount = 0; Truncated = $false; Recent = @() }
        CollectionErrors = @()
    }
}
