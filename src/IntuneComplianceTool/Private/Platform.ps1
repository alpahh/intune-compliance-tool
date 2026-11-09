# Thin wrappers around Windows-only commands, registry paths and executables.
# Every call that touches the operating system goes through a function in this
# file, which keeps the rest of the module testable with Pester mocks.

#region Session and device

function Test-ICTIsElevated {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (-not (Test-ICTIsWindows)) { return $false }
    $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ICTCurrentIdentity {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Get-ICTConsoleUser {
    <# The user signed in at the physical console (not RDP, not the SSH account). $null when nobody is. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $userName = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
    if ([string]::IsNullOrWhiteSpace($userName)) { return $null }
    return $userName
}

function Get-ICTSystemInfo {
    [CmdletBinding()]
    param()
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue

    $consoleUser = $computerSystem.UserName
    if ([string]::IsNullOrWhiteSpace($consoleUser)) { $consoleUser = $null }

    return [pscustomobject]@{
        Manufacturer          = $computerSystem.Manufacturer
        Model                 = $computerSystem.Model
        SerialNumber          = $bios.SerialNumber
        OSCaption             = $os.Caption
        OSBuild               = [int]$os.BuildNumber
        OSUpdateBuildRevision = $currentVersion.UBR
        OSDisplayVersion      = $currentVersion.DisplayVersion
        LastBootTime          = ConvertTo-ICTIsoDate $os.LastBootUpTime
        ConsoleUser           = $consoleUser
    }
}

function Get-ICTPendingReboot {
    <# Reboot flags set by component servicing and Windows Update. #>
    [CmdletBinding()]
    param()
    $reasons = @()
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'servicing' }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'Windows Update' }
    return [pscustomobject]@{ Pending = ($reasons.Count -gt 0); Reasons = $reasons }
}

#endregion

#region Entra join and MDM enrollment

function Get-ICTDsregOutput {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $output = & (Join-Path $env:windir 'System32\dsregcmd.exe') /status 2>&1
    if ($LASTEXITCODE -ne 0) { throw "dsregcmd.exe /status exited with code $LASTEXITCODE." }
    return [string[]]@($output | ForEach-Object { "$_" })
}

function Get-ICTEnrollmentRegistry {
    <# Enrollments under HKLM:\SOFTWARE\Microsoft\Enrollments (GUID-named keys only). #>
    [CmdletBinding()]
    param()
    $root = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path -LiteralPath $root)) { return }
    foreach ($key in Get-ChildItem -LiteralPath $root -ErrorAction Stop) {
        if (-not (Test-ICTGuid $key.PSChildName)) { continue }
        $props = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
        if ($null -eq $props) { continue }
        [pscustomobject]@{
            EnrollmentId            = $key.PSChildName
            IsIntune                = ($props.ProviderID -eq $script:ICTIntuneProviderId)
            Upn                     = $props.UPN
            EnrollmentState         = $props.EnrollmentState
            DiscoveryServiceFullUrl = $props.DiscoveryServiceFullURL
        }
    }
}

function Get-ICTAutoEnrollState {
    <#
        Why a device does (not) auto-enroll: the MDM auto-enrollment policy (GPO), the
        ExternallyManaged flag (another MDM owns the device) and the latest auto-enroll
        result from the MDM event log (75 = succeeded, 76 = failed).
    #>
    [CmdletBinding()]
    param()
    $policy = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' -ErrorAction SilentlyContinue
    $enrollments = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue
    $last = @(Get-ICTWinEvent -LogName $script:ICTMdmLogName -XPath '*[System[(EventID=75 or EventID=76)]]' -MaxEvents 1) | Select-Object -First 1

    $hresult = $null
    if ($last -and $last.Message -match '0x[0-9A-Fa-f]{8}') { $hresult = $Matches[0].ToLowerInvariant() }

    return [pscustomobject]@{
        PolicyAutoEnroll     = $policy.AutoEnrollMDM
        PolicyCredentialType = $policy.UseAADCredentialType
        ExternallyManaged    = ($enrollments.ExternallyManaged -eq 1)
        LastResult           = $(if ($last) { $(if ($last.Id -eq 75) { 'Succeeded' } else { 'Failed' }) } else { $null })
        LastResultTime       = $last.TimeCreated
        LastErrorCode        = $hresult
    }
}

function Get-ICTOmadmConnectionInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EnrollmentId)
    if (-not (Test-ICTGuid $EnrollmentId)) { throw "'$EnrollmentId' is not a valid enrollment ID." }
    $path = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$EnrollmentId\Protected\ConnInfo"
    if (-not (Test-Path -LiteralPath $path)) { return }
    $props = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    return [pscustomobject]@{
        ServerLastSuccessTime = ConvertTo-ICTIsoDate $props.ServerLastSuccessTime
        ServerLastAccessTime  = ConvertTo-ICTIsoDate $props.ServerLastAccessTime
    }
}

function Get-ICTMdmCertificate {
    <# Intune MDM device certificates in the machine store. The subject CN is the Intune device ID. #>
    [CmdletBinding()]
    param()
    foreach ($cert in Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -ErrorAction Stop) {
        if ($cert.Issuer -notmatch 'Microsoft Intune MDM Device CA') { continue }
        $intuneDeviceId = $null
        if ($cert.Subject -match 'CN=(?<id>[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})') { $intuneDeviceId = $Matches['id'] }
        [pscustomobject]@{
            Thumbprint     = $cert.Thumbprint
            Subject        = $cert.Subject
            IntuneDeviceId = $intuneDeviceId
            NotBefore      = ConvertTo-ICTIsoDate $cert.NotBefore
            NotAfter       = ConvertTo-ICTIsoDate $cert.NotAfter
            HasPrivateKey  = [bool]$cert.HasPrivateKey
        }
    }
}

function Get-ICTEnterpriseMgmtTask {
    <#
        Tasks under \Microsoft\Windows\EnterpriseMgmt\<EnrollmentId>\, read through the
        Task Scheduler COM API (one call instead of one CIM query per task). Returns
        nothing when the folder does not exist; any other error is thrown.
    #>
    [CmdletBinding()]
    param()
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    try { $root = $scheduler.GetFolder('\Microsoft\Windows\EnterpriseMgmt') }
    catch {
        if ($_.Exception.GetBaseException().HResult -eq -2147024894) { return }   # 0x80070002: folder does not exist
        throw
    }
    $states = @{ 0 = 'Unknown'; 1 = 'Disabled'; 2 = 'Queued'; 3 = 'Ready'; 4 = 'Running' }
    foreach ($folder in @($root.GetFolders(0))) {
        foreach ($task in @($folder.GetTasks(1))) {
            [pscustomobject]@{
                EnrollmentId   = $folder.Name
                TaskName       = $task.Name
                TaskPath       = $folder.Path + '\'
                State          = $states[[int]$task.State]
                LastRunTime    = ConvertTo-ICTIsoDate $task.LastRunTime
                LastTaskResult = $task.LastTaskResult
            }
        }
    }
}

#endregion

#region Services, security and health

function Get-ICTServiceState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Name)
    foreach ($serviceName in $Name) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Name      = $serviceName
            Present   = ($null -ne $service)
            Status    = $(if ($service) { "$($service.Status)" } else { $null })
            StartType = $(if ($service) { "$($service.StartType)" } else { $null })
        }
    }
}

function Get-ICTBitLockerState {
    [CmdletBinding()]
    param()
    $drive = $env:SystemDrive
    if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        $volume = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
        return [pscustomobject]@{
            MountPoint       = $drive
            ProtectionOn     = ("$($volume.ProtectionStatus)" -eq 'On')
            VolumeStatus     = "$($volume.VolumeStatus)"
            EncryptionMethod = "$($volume.EncryptionMethod)"
        }
    }
    $volume = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$drive'" -ErrorAction Stop
    if ($null -eq $volume) { throw "No encryptable volume found for $drive." }
    return [pscustomobject]@{ MountPoint = $drive; ProtectionOn = ($volume.ProtectionStatus -eq 1); VolumeStatus = $null; EncryptionMethod = $null }
}

function Get-ICTTpmState {
    [CmdletBinding()]
    param()
    $tpm = Get-Tpm -ErrorAction Stop
    return [pscustomobject]@{ Present = [bool]$tpm.TpmPresent; Ready = [bool]$tpm.TpmReady }
}

function Get-ICTSecureBootState {
    [CmdletBinding()]
    param()
    try {
        return [pscustomobject]@{ Supported = $true; Enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    }
    catch [System.PlatformNotSupportedException] {
        return [pscustomobject]@{ Supported = $false; Enabled = $false }   # legacy BIOS
    }
}

function Get-ICTDefenderState {
    [CmdletBinding()]
    param()
    $status = Get-MpComputerStatus -ErrorAction Stop
    return [pscustomobject]@{
        AMServiceEnabled          = [bool]$status.AMServiceEnabled
        RealTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
        AMRunningMode             = "$($status.AMRunningMode)"
        AntivirusSignatureAgeDays = $status.AntivirusSignatureAge
    }
}

function Get-ICTFirewallState {
    <# Effective (ActiveStore) profile state, which includes Intune and GPO policy. #>
    [CmdletBinding()]
    param()
    foreach ($profile in Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop) {
        [pscustomobject]@{ Profile = $profile.Name; Enabled = ("$($profile.Enabled)" -eq 'True') }
    }
}

#endregion

#region Network

function Get-ICTWinHttpProxy {
    [CmdletBinding()]
    param()
    $props = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -ErrorAction SilentlyContinue
    return ConvertFrom-ICTWinHttpProxySetting -Bytes $props.WinHttpSettings
}

function Test-ICTTcpEndpoint {
    <#
        Direct TCP reachability of several hosts at once: all connects start together
        and share one timeout, so 6 unreachable hosts cost 5 s, not 30 s.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$HostName,
        [int]$Port = 443,
        [int]$TimeoutMs = 5000
    )
    $pending = foreach ($name in $HostName) {
        $client = New-Object System.Net.Sockets.TcpClient
        $item = [pscustomobject]@{ HostName = $name; Client = $client; Async = $null; Error = $null }
        try { $item.Async = $client.BeginConnect($name, $Port, $null, $null) }
        catch { $item.Error = $_.Exception.GetBaseException().Message }
        $item
    }

    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    foreach ($item in @($pending)) {
        $reachable = $false
        $errorText = $item.Error
        try {
            if ($item.Async) {
                $remaining = [int][math]::Max(0, ($deadline - [datetime]::UtcNow).TotalMilliseconds)
                if ($item.Async.AsyncWaitHandle.WaitOne($remaining)) {
                    try { $item.Client.EndConnect($item.Async); $reachable = $true }
                    catch { $errorText = $_.Exception.GetBaseException().Message }
                }
                else { $errorText = "Timed out after $TimeoutMs ms." }
            }
        }
        finally { $item.Client.Close() }
        [pscustomobject]@{ HostName = $item.HostName; Port = $Port; Reachable = $reachable; Error = $errorText }
    }
}

function Get-ICTClockOffset {
    <#
        Local clock minus the Date header of an HTTPS response, in seconds (precision
        about 1 s). A large skew breaks certificate and token validation.
    #>
    [CmdletBinding()]
    param([string]$Uri = 'https://login.microsoftonline.com/', [AllowNull()][string]$Proxy, [int]$TimeoutMs = 5000)

    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Method = 'HEAD'
    $request.Timeout = $TimeoutMs
    $request.AllowAutoRedirect = $false
    if ($Proxy) { $request.Proxy = New-Object System.Net.WebProxy($Proxy) } else { $request.Proxy = $null }

    $before = [datetime]::UtcNow
    try { $response = $request.GetResponse() }
    catch [System.Net.WebException] {
        $response = $_.Exception.Response   # 4xx/5xx responses still carry a Date header
        if ($null -eq $response) {
            # A clock far off makes the server certificate look invalid: retry over plain HTTP,
            # which still returns a Date header (the redirect to HTTPS), and say so if that fails too.
            if ($_.Exception.Status -ne [System.Net.WebExceptionStatus]::TrustFailure -or $Uri -notlike 'https://*') { throw }
            try { return (Get-ICTClockOffset -Uri ('http://' + $Uri.Substring(8)) -Proxy $Proxy -TimeoutMs $TimeoutMs) }
            catch { throw "TLS certificate rejected (clock wrong?), and the HTTP fallback failed: $($_.Exception.Message)" }
        }
    }
    $after = [datetime]::UtcNow
    try { $dateHeader = $response.Headers['Date'] } finally { $response.Close() }
    if (-not $dateHeader) { throw "No Date header in the response from $Uri." }

    $serverTime = [datetime]::SpecifyKind([datetime]::ParseExact($dateHeader, 'r', $script:ICTInvariant), [System.DateTimeKind]::Utc)
    $localMid = $before.AddTicks([int64](($after - $before).Ticks / 2))
    return [math]::Round(($localMid - $serverTime).TotalSeconds)
}

#endregion

#region Event logs

$script:ICTMdmLogName = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
$script:ICTLapsLogName = 'Microsoft-Windows-LAPS/Operational'

function Get-ICTWinEvent {
    <# Events filtered on the server side with XPath, newest first. Returns nothing when none match. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LogName, [Parameter(Mandatory)][string]$XPath, [int]$MaxEvents = 100)
    try {
        $events = @(Get-WinEvent -LogName $LogName -FilterXPath $XPath -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        throw
    }
    foreach ($event in $events) {
        $message = ("$($event.Message)".Trim() -split "`r?`n")[0]
        if (-not $message) { $message = "Event $($event.Id)" }   # missing message resources
        if ($message.Length -gt 300) { $message = $message.Substring(0, 300) }
        [pscustomobject]@{ TimeCreated = ConvertTo-ICTIsoDate $event.TimeCreated; Id = $event.Id; Level = [int]$event.Level; Message = $message }
    }
}

#endregion

#region LAPS

function Get-ICTLapsPolicy {
    <#
        The active Windows LAPS policy. Windows uses the first of these roots that holds
        any value (missing settings take their defaults, BackupDirectory 0 = disabled):
        CSP (Intune), Group Policy, local configuration. Legacy Microsoft LAPS (AdmPwd)
        is reported separately. Returns nothing when no root is configured.
    #>
    [CmdletBinding()]
    param()
    $roots = @(
        [pscustomobject]@{ Source = 'Intune'; Path = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' }
        [pscustomobject]@{ Source = 'GroupPolicy'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' }
        [pscustomobject]@{ Source = 'LocalConfig'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' }
        [pscustomobject]@{ Source = 'Legacy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' }
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root.Path)) { continue }
        if ((Get-Item -LiteralPath $root.Path -ErrorAction Stop).ValueCount -eq 0) { continue }
        $p = Get-ItemProperty -LiteralPath $root.Path -ErrorAction Stop
        # Automatic account management exists from Windows 11 24H2 (build 26100); older builds ignore it.
        $automatic = ($p.AutomaticAccountManagementEnabled -eq 1 -and [System.Environment]::OSVersion.Version.Build -ge 26100)
        return [pscustomobject]@{
            Source                       = $root.Source
            BackupDirectory              = $p.BackupDirectory
            AdministratorAccountName     = $p.AdministratorAccountName
            PasswordAgeDays              = $p.PasswordAgeDays
            PostAuthenticationActions    = $p.PostAuthenticationActions
            PostAuthenticationResetDelay = $p.PostAuthenticationResetDelay
            AutomaticAccountManagement   = $automatic
            AutomaticAccountEnabled      = ($p.AutomaticAccountManagementEnableAccount -eq 1)
            AutomaticAccountTarget       = $p.AutomaticAccountManagementTarget
            AutomaticAccountNameOrPrefix = $p.AutomaticAccountManagementNameOrPrefix
            AutomaticAccountRandomize    = ($p.AutomaticAccountManagementRandomizeName -eq 1)
        }
    }
}

function Get-ICTLapsLastPasswordUpdate {
    <# Time of the last password rotation (FILETIME in the LAPS state key), as an ISO string. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $raw = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State' -ErrorAction SilentlyContinue).LastPasswordUpdateTime
    if ($null -eq $raw -or [int64]$raw -le 0) { return $null }
    return ConvertTo-ICTIsoDate ([datetime]::FromFileTimeUtc([int64]$raw))
}

function Get-ICTLocalAccount {
    <#
        Local account details. -Name: exact name. -NamePrefix: a name made of the prefix
        and 6 digits (LAPS randomized names). Neither: the built-in Administrator (RID 500).
        Group membership is read through ADSI by SID, because Get-LocalGroupMember fails
        on Entra-joined devices (unresolvable S-1-12-1 members).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Name, [AllowEmptyString()][string]$NamePrefix)

    $users = @(Get-LocalUser -ErrorAction Stop)
    if ($Name) { $user = $users | Where-Object { $_.Name -eq $Name } | Select-Object -First 1 }
    elseif ($NamePrefix) {
        $pattern = '^' + [regex]::Escape($NamePrefix) + '\d{6}$'
        $user = $users | Where-Object { $_.Name -match $pattern } | Sort-Object Enabled -Descending | Select-Object -First 1
    }
    else { $user = $users | Where-Object { $_.SID.Value -match '^S-1-5-21-.+-500$' } | Select-Object -First 1 }

    $label = $(if ($Name) { $Name } elseif ($NamePrefix) { "$NamePrefix######" } else { 'built-in Administrator' })
    if ($null -eq $user) { return [pscustomobject]@{ Name = $label; Exists = $false; Enabled = $null; IsAdministrator = $null } }

    $isAdministrator = $null
    try {
        $groupName = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        $group = [ADSI]("WinNT://$env:COMPUTERNAME/$groupName,group")
        $isAdministrator = $false
        foreach ($member in @($group.Invoke('Members'))) {
            $bytes = $member.GetType().InvokeMember('objectSid', 'GetProperty', $null, $member, $null)
            if ((New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value -eq $user.SID.Value) { $isAdministrator = $true; break }
        }
    }
    catch {
        $isAdministrator = $null
        Write-ICTLog -Level Warning "Could not read local Administrators members: $($_.Exception.Message)"
    }

    return [pscustomobject]@{ Name = $user.Name; Exists = $true; Enabled = [bool]$user.Enabled; IsAdministrator = $isAdministrator }
}

#endregion

#region Files and folders

function New-ICTDirectorySecurity {
    <# Owner Administrators; full control for SYSTEM and Administrators only; no inherited entries. #>
    [CmdletBinding()]
    param()
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')), $admins) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')))
    }
    return $acl
}

function Assert-ICTTrustedItem {
    <# Throws when an existing file or folder is a reparse point or owned by anyone but SYSTEM, Administrators or the current admin. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.IO.FileSystemInfo]$Item)
    if ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "Refusing to use '$($Item.FullName)': it is a junction or symbolic link." }
    $owner = (Get-Acl -LiteralPath $Item.FullName).GetOwner([System.Security.Principal.SecurityIdentifier])
    $trusted = @('S-1-5-18', 'S-1-5-32-544', [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    if ($trusted -notcontains $owner.Value) { throw "Refusing to use '$($Item.FullName)': it is owned by $($owner.Value), not by Administrators or SYSTEM." }
}

function Protect-ICTDirectory {
    <#
        Makes sure only SYSTEM and Administrators can write to the folder and to
        everything in it. C:\ProgramData is writable for standard users, so a folder,
        subfolder or junction they created beforehand could be used to tamper with
        scripts that later run as SYSTEM. New folders get the restricted ACL at
        creation (no window in between); an existing folder is refused if it, or
        anything inside it, is a junction or owned by someone else.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-ICTIsWindows)) { if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -Path $Path -ItemType Directory -Force }; return }

    $security = New-ICTDirectorySecurity
    if (-not (Test-Path -LiteralPath $Path)) {
        $null = [System.IO.Directory]::CreateDirectory($Path, $security)
        return
    }
    $folder = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-ICTTrustedItem -Item $folder
    # Streamed, so a junction is rejected before Get-ChildItem could descend into it.
    Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop | ForEach-Object { Assert-ICTTrustedItem -Item $_ }
    Set-Acl -LiteralPath $Path -AclObject $security -ErrorAction Stop
}

function New-ICTPrivateDirectory {
    <# Creates a new, uniquely named folder with the restricted ACL from the start. Fails if it already exists. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Parent, [Parameter(Mandatory)][string]$Prefix)
    Protect-ICTDirectory -Path $Parent
    $path = Join-Path $Parent ('{0}-{1}' -f $Prefix, [guid]::NewGuid().ToString('N').Substring(0, 8))
    if (Test-Path -LiteralPath $path) { throw "'$path' already exists." }
    if (Test-ICTIsWindows) { $null = [System.IO.Directory]::CreateDirectory($path, (New-ICTDirectorySecurity)) }
    else { $null = New-Item -Path $path -ItemType Directory }
    return $path
}

#endregion

#region Repairs (used only by -Remediate)

function Export-ICTRegistryKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Destination)
    $regPath = $Path -replace '^HKLM:\\', 'HKLM\'
    $output = & (Join-Path $env:windir 'System32\reg.exe') export $regPath $Destination /y 2>&1
    if ($LASTEXITCODE -ne 0) { throw "reg.exe export '$regPath' failed (exit $LASTEXITCODE): $output" }
}

function Test-ICTRegistryKey {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)
    return (Test-Path -LiteralPath $Path)
}

function Export-ICTScheduledTask {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TaskName, [Parameter(Mandatory)][string]$TaskPath, [Parameter(Mandatory)][string]$Destination)
    $xml = Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    Set-Content -LiteralPath $Destination -Value $xml -Encoding Unicode -ErrorAction Stop
}

function Export-ICTCertificate {
    <# Public part only; the private key stays in the key store (Remove-Item does not delete it). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Thumbprint, [Parameter(Mandatory)][string]$Destination)
    $null = Export-Certificate -Cert (Get-Item -LiteralPath "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction Stop) -FilePath $Destination -Type CERT -ErrorAction Stop
}

function Start-ICTEnterpriseMgmtSyncTask {
    <# Starts the PushLaunch task, which makes the MDM client open a session with Intune. Returns $true if the task exists. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$EnrollmentId)
    if (-not (Test-ICTGuid $EnrollmentId)) { throw "'$EnrollmentId' is not a valid enrollment ID." }
    $task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$EnrollmentId\" -TaskName 'PushLaunch' -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $false }
    Start-ScheduledTask -InputObject $task -ErrorAction Stop
    return $true
}

$script:ICTSystemTaskPrefix = 'IntuneComplianceTool-Repair-'

function Start-ICTSystemScript {
    <#
        Runs a PowerShell script file as SYSTEM through a temporary scheduled task and
        returns the task name. The script keeps running when the SSH session ends.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$ScriptPath)
    $taskName = $script:ICTSystemTaskPrefix + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $powershell = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $ScriptPath)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest   # the name resolves on every display language
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    $null = Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop
    Start-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
    return $taskName
}

function Remove-ICTSystemTask {
    <# Removes finished temporary repair tasks (all of them, or one by name). Running tasks are left alone. #>
    [CmdletBinding()]
    param([string]$TaskName)
    $filter = $(if ($TaskName) { $TaskName } else { $script:ICTSystemTaskPrefix + '*' })
    foreach ($task in @(Get-ScheduledTask -TaskPath '\' -TaskName $filter -ErrorAction SilentlyContinue)) {
        if ($task -and "$($task.State)" -ne 'Running') { Unregister-ScheduledTask -InputObject $task -Confirm:$false -ErrorAction SilentlyContinue }
    }
}

function Get-ICTSystemTaskState {
    <# State and last result of a temporary repair task; $null when it does not exist. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TaskName)
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $null }
    $info = Get-ScheduledTaskInfo -InputObject $task -ErrorAction SilentlyContinue
    return [pscustomobject]@{ State = "$($task.State)"; LastTaskResult = $info.LastTaskResult }
}

function Test-ICTRepairRunning {
    <# $true while a repair task of this tool is queued or running. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $tasks = @(Get-ScheduledTask -TaskPath '\' -TaskName ($script:ICTSystemTaskPrefix + '*') -ErrorAction SilentlyContinue)
    return [bool](@($tasks | Where-Object { $_ -and ("$($_.State)" -eq 'Running' -or "$($_.State)" -eq 'Queued') }).Count)
}

function Get-ICTLastRepairTime {
    <# When the newest finished re-enrollment of this tool started (UTC), from its state file; $null if none. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RepairRoot)
    if (-not (Test-Path -LiteralPath $RepairRoot)) { return $null }
    $latest = Get-ChildItem -LiteralPath $RepairRoot -Directory -ErrorAction SilentlyContinue | Sort-Object CreationTimeUtc -Descending | Select-Object -First 1
    if ($null -eq $latest -or -not (Test-Path -LiteralPath (Join-Path $latest.FullName 'repair-state.jsonl'))) { return $null }
    return $latest.CreationTimeUtc
}

function Get-ICTOmadmCurrentEnrollmentId {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger' -ErrorAction SilentlyContinue).CurrentEnrollmentId
}

function Get-ICTSystemScriptState {
    <# Progress lines (JSON per line) that a SYSTEM repair script wrote to its state file. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        if (-not $line.Trim()) { continue }
        try { $line | ConvertFrom-Json -ErrorAction Stop } catch { Write-ICTLog "Skipped an incomplete state line: $line" }
    }
}

function Set-ICTCtrlCAsInput {
    <# Turns Ctrl+C handling off/on for the console. Returns the previous value, or $null without a console. #>
    [CmdletBinding()]
    param([bool]$Enabled)
    try {
        $previous = [Console]::TreatControlCAsInput
        [Console]::TreatControlCAsInput = $Enabled
        return $previous
    }
    catch { return $null }
}

function Invoke-ICTLapsPolicyProcessing {
    [CmdletBinding()]
    param()
    Invoke-LapsPolicyProcessing -ErrorAction Stop
}

function Invoke-ICTTimeResync {
    <# Makes sure the time service runs and resynchronises the clock. #>
    [CmdletBinding()]
    param()
    $service = Get-Service -Name W32Time -ErrorAction Stop
    if ("$($service.StartType)" -eq 'Disabled') { Set-Service -Name W32Time -StartupType Manual -ErrorAction Stop }
    if ("$($service.Status)" -ne 'Running') { Start-Service -Name W32Time -ErrorAction Stop }
    $output = & (Join-Path $env:windir 'System32\w32tm.exe') /resync /force 2>&1
    if ($LASTEXITCODE -ne 0) { throw "w32tm /resync failed (exit $LASTEXITCODE): $(($output | Out-String).Trim())" }
}

function Set-ICTServiceStartType {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][ValidateSet('Manual', 'Automatic')][string]$StartupType)
    Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
}

function Start-ICTService {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    Start-Service -Name $Name -ErrorAction Stop
}

function Invoke-ICTMdmDiagnosticsTool {
    <# Exports MDM diagnostics (enrollment, provisioning, Autopilot) to a ZIP file. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ZipPath)
    $exe = Join-Path $env:windir 'System32\MdmDiagnosticsTool.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw "MdmDiagnosticsTool.exe not found at $exe." }
    $output = & $exe -area 'DeviceEnrollment;DeviceProvisioning;Autopilot' -zip $ZipPath 2>&1
    if (-not (Test-Path -LiteralPath $ZipPath)) { throw "MdmDiagnosticsTool.exe did not create $ZipPath (exit $LASTEXITCODE): $(($output | Out-String).Trim())" }
}

#endregion
