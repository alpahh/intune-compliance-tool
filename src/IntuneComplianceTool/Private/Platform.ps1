# Thin wrappers around Windows-only commands, registry paths and executables.
# Every call that touches the operating system goes through a function in this
# file, which keeps the rest of the module testable with Pester mocks.

#region Read

function Test-ICTIsElevated {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if (-not (Test-ICTIsWindows)) { return $false }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ICTCurrentIdentity {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Get-ICTDsregOutput {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $exe = Join-Path $env:windir 'System32\dsregcmd.exe'
    $output = & $exe /status 2>&1
    if ($LASTEXITCODE -ne 0) { throw "dsregcmd.exe /status exited with code $LASTEXITCODE." }
    return [string[]]@($output | ForEach-Object { "$_" })
}

function Get-ICTSystemInfo {
    [CmdletBinding()]
    param()
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $currentVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue

    $ubr = $null
    $displayVersion = $null
    if ($currentVersion) {
        $ubr = $currentVersion.UBR
        $displayVersion = $currentVersion.DisplayVersion
    }

    return [pscustomobject]@{
        Manufacturer          = $computerSystem.Manufacturer
        Model                 = $computerSystem.Model
        SerialNumber          = $bios.SerialNumber
        OSCaption             = $os.Caption
        OSVersion             = $os.Version
        OSBuild               = [int]$os.BuildNumber
        OSUpdateBuildRevision = $ubr
        OSDisplayVersion      = $displayVersion
        LastBootTime          = ConvertTo-ICTIsoDate $os.LastBootUpTime
    }
}

function Get-ICTEnrollmentRegistry {
    <# Lists the enrollments under HKLM:\SOFTWARE\Microsoft\Enrollments (GUID-named keys only). #>
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
            ProviderId              = $props.ProviderID
            IsIntune                = ($props.ProviderID -eq $script:ICTIntuneProviderId)
            Upn                     = $props.UPN
            EnrollmentState         = $props.EnrollmentState
            EnrollmentType          = $props.EnrollmentType
            DiscoveryServiceFullUrl = $props.DiscoveryServiceFullURL
        }
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
    <# Intune MDM device certificates in the local machine store. The subject CN is the Intune device ID. #>
    [CmdletBinding()]
    param()
    foreach ($cert in Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop) {
        if ($cert.Issuer -notmatch 'Microsoft Intune MDM Device CA') { continue }
        $intuneDeviceId = $null
        if ($cert.Subject -match 'CN=(?<id>[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})') {
            $intuneDeviceId = $Matches['id']
        }
        [pscustomobject]@{
            Thumbprint     = $cert.Thumbprint
            Subject        = $cert.Subject
            Issuer         = $cert.Issuer
            IntuneDeviceId = $intuneDeviceId
            NotBefore      = ConvertTo-ICTIsoDate $cert.NotBefore
            NotAfter       = ConvertTo-ICTIsoDate $cert.NotAfter
            HasPrivateKey  = [bool]$cert.HasPrivateKey
        }
    }
}

function Get-ICTEnterpriseMgmtTask {
    <# Scheduled tasks the MDM client creates under \Microsoft\Windows\EnterpriseMgmt\<EnrollmentId>\. #>
    [CmdletBinding()]
    param()
    $tasks = @(Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction SilentlyContinue)
    foreach ($task in $tasks) {
        if ($null -eq $task) { continue }
        $enrollmentId = $null
        if ($task.TaskPath -match '\\EnterpriseMgmt\\(?<id>[^\\]+)\\') { $enrollmentId = $Matches['id'] }
        $info = Get-ScheduledTaskInfo -InputObject $task -ErrorAction SilentlyContinue
        $lastRun = $null
        $lastResult = $null
        if ($info) {
            $lastRun = ConvertTo-ICTIsoDate $info.LastRunTime
            $lastResult = $info.LastTaskResult
        }
        [pscustomobject]@{
            EnrollmentId   = $enrollmentId
            TaskName       = $task.TaskName
            TaskPath       = $task.TaskPath
            State          = "$($task.State)"
            LastRunTime    = $lastRun
            LastTaskResult = $lastResult
        }
    }
}

function Get-ICTServiceState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Name)
    foreach ($serviceName in $Name) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            [pscustomobject]@{ Name = $serviceName; Present = $false; Status = $null; StartType = $null }
            continue
        }
        [pscustomobject]@{ Name = $serviceName; Present = $true; Status = "$($service.Status)"; StartType = "$($service.StartType)" }
    }
}

function Get-ICTBitLockerState {
    [CmdletBinding()]
    param()
    $drive = $env:SystemDrive
    if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        $volume = Get-BitLockerVolume -MountPoint $drive -ErrorAction Stop
        return [pscustomobject]@{
            MountPoint           = $drive
            ProtectionOn         = ("$($volume.ProtectionStatus)" -eq 'On')
            VolumeStatus         = "$($volume.VolumeStatus)"
            EncryptionPercentage = $volume.EncryptionPercentage
            EncryptionMethod     = "$($volume.EncryptionMethod)"
        }
    }

    $volume = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$drive'" -ErrorAction Stop
    if ($null -eq $volume) { throw "No encryptable volume found for $drive." }
    return [pscustomobject]@{
        MountPoint           = $drive
        ProtectionOn         = ($volume.ProtectionStatus -eq 1)
        VolumeStatus         = $null
        EncryptionPercentage = $null
        EncryptionMethod     = $null
    }
}

function Get-ICTTpmState {
    [CmdletBinding()]
    param()
    $tpm = Get-Tpm -ErrorAction Stop
    return [pscustomobject]@{
        Present = [bool]$tpm.TpmPresent
        Ready   = [bool]$tpm.TpmReady
        Enabled = [bool]$tpm.TpmEnabled
    }
}

function Get-ICTSecureBootState {
    [CmdletBinding()]
    param()
    try {
        $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
        return [pscustomobject]@{ Supported = $true; Enabled = [bool]$enabled }
    }
    catch [System.PlatformNotSupportedException] {
        # Legacy BIOS firmware: Secure Boot is not available.
        return [pscustomobject]@{ Supported = $false; Enabled = $false }
    }
}

function Get-ICTDefenderState {
    [CmdletBinding()]
    param()
    $status = Get-MpComputerStatus -ErrorAction Stop
    return [pscustomobject]@{
        AMServiceEnabled              = [bool]$status.AMServiceEnabled
        AntivirusEnabled              = [bool]$status.AntivirusEnabled
        RealTimeProtectionEnabled     = [bool]$status.RealTimeProtectionEnabled
        AMRunningMode                 = "$($status.AMRunningMode)"
        AntivirusSignatureAgeDays     = $status.AntivirusSignatureAge
        AntivirusSignatureLastUpdated = ConvertTo-ICTIsoDate $status.AntivirusSignatureLastUpdated
    }
}

function Get-ICTFirewallState {
    [CmdletBinding()]
    param()
    foreach ($profile in Get-NetFirewallProfile -ErrorAction Stop) {
        [pscustomobject]@{ Profile = $profile.Name; Enabled = ("$($profile.Enabled)" -eq 'True') }
    }
}

function Get-ICTWinHttpProxy {
    [CmdletBinding()]
    param()
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
    $value = $null
    if (Test-Path -LiteralPath $path) {
        $props = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
        if ($props) { $value = $props.WinHttpSettings }
    }
    return ConvertFrom-ICTWinHttpProxySetting -Bytes $value
}

function Test-ICTTcpEndpoint {
    <# Direct TCP reachability check. Works on every PowerShell version without Test-NetConnection. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HostName,
        [int]$Port = 443,
        [int]$TimeoutMs = 5000
    )
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            return [pscustomobject]@{ HostName = $HostName; Port = $Port; Reachable = $false; Error = "Timed out after $TimeoutMs ms." }
        }
        $client.EndConnect($async)
        return [pscustomobject]@{ HostName = $HostName; Port = $Port; Reachable = $true; Error = $null }
    }
    catch {
        $message = $_.Exception.Message
        if ($_.Exception.InnerException) { $message = $_.Exception.InnerException.Message }
        return [pscustomobject]@{ HostName = $HostName; Port = $Port; Reachable = $false; Error = $message }
    }
    finally {
        $client.Close()
    }
}

function Get-ICTMdmEvent {
    [CmdletBinding()]
    param([int]$Days = 7, [int]$MaxEvents = 50)
    $filter = @{
        LogName   = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
        Level     = 1, 2
        StartTime = (Get-Date).AddDays(-$Days)
    }
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        throw
    }
    foreach ($event in $events) {
        $message = "$($event.Message)".Trim()
        $firstLine = ($message -split "`r?`n")[0]
        if ($firstLine.Length -gt 500) { $firstLine = $firstLine.Substring(0, 500) }
        [pscustomobject]@{
            TimeCreated = ConvertTo-ICTIsoDate $event.TimeCreated
            Id          = $event.Id
            Level       = $event.LevelDisplayName
            Message     = $firstLine
        }
    }
}

#endregion

#region Session

function Get-ICTConsoleUser {
    <# The user signed in at the device (not the SSH account). $null when nobody is signed in. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $userName = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
    if ([string]::IsNullOrWhiteSpace($userName)) { return $null }
    return $userName
}

#endregion

#region LAPS

function Get-ICTLapsPolicy {
    <#
        Windows LAPS policy. Intune (CSP) writes to HKLM:\SOFTWARE\Microsoft\Policies\LAPS,
        Group Policy to HKLM:\SOFTWARE\Policies\Microsoft Windows\LAPS. Returns nothing
        when no policy is applied.
    #>
    [CmdletBinding()]
    param()
    $sources = @(
        [pscustomobject]@{ Source = 'Intune'; Path = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' }
        [pscustomobject]@{ Source = 'GroupPolicy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft Windows\LAPS' }
    )
    foreach ($source in $sources) {
        if (-not (Test-Path -LiteralPath $source.Path)) { continue }
        $props = Get-ItemProperty -LiteralPath $source.Path -ErrorAction Stop
        if ($null -eq $props.BackupDirectory) { continue }
        return [pscustomobject]@{
            Source                       = $source.Source
            BackupDirectory              = [int]$props.BackupDirectory
            AdministratorAccountName     = $props.AdministratorAccountName
            PasswordAgeDays              = $props.PasswordAgeDays
            PostAuthenticationActions    = $props.PostAuthenticationActions
            PostAuthenticationResetDelay = $props.PostAuthenticationResetDelay
        }
    }
}

function Get-ICTLapsLastPasswordUpdate {
    <# Time of the last password rotation (FILETIME in the LAPS state key), as an ISO string. #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $raw = (Get-ItemProperty -LiteralPath $path -ErrorAction Stop).LastPasswordUpdateTime
    if ($null -eq $raw -or [int64]$raw -le 0) { return $null }
    return ConvertTo-ICTIsoDate ([datetime]::FromFileTimeUtc([int64]$raw))
}

function Get-ICTLocalAccount {
    <# Local account details. An empty name means the built-in Administrator (RID 500), which LAPS manages by default. #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Name)

    if ([string]::IsNullOrEmpty($Name)) {
        $user = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '^S-1-5-21-.+-500$' } | Select-Object -First 1
    }
    else {
        $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    }
    if ($null -eq $user) {
        return [pscustomobject]@{ Name = $Name; Exists = $false; Enabled = $null; IsAdministrator = $null }
    }

    $isAdministrator = $null
    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        $isAdministrator = [bool]($members | Where-Object { $_.SID.Value -eq $user.SID.Value })
    }
    catch {
        # Get-LocalGroupMember fails when the group contains orphaned SIDs; leave it unknown.
        Write-ICTLog -Level Warning "Could not read local Administrators members: $($_.Exception.Message)"
    }

    return [pscustomobject]@{ Name = $user.Name; Exists = $true; Enabled = [bool]$user.Enabled; IsAdministrator = $isAdministrator }
}

function Get-ICTLapsEvent {
    [CmdletBinding()]
    param([int]$Days = 7, [int]$MaxEvents = 200)
    $filter = @{ LogName = 'Microsoft-Windows-LAPS/Operational'; StartTime = (Get-Date).AddDays(-$Days) }
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return }
        throw
    }
    foreach ($event in $events) {
        $firstLine = ("$($event.Message)".Trim() -split "`r?`n")[0]
        if ($firstLine.Length -gt 300) { $firstLine = $firstLine.Substring(0, 300) }
        [pscustomobject]@{
            TimeCreated = ConvertTo-ICTIsoDate $event.TimeCreated
            Id          = $event.Id
            Level       = [int]$event.Level
            Message     = $firstLine
        }
    }
}

function Invoke-ICTLapsPolicyProcessing {
    [CmdletBinding()]
    param()
    Invoke-LapsPolicyProcessing -ErrorAction Stop
}

#endregion

#region Write (used only by remediation)

function Test-ICTRegistryKey {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Path)
    return (Test-Path -LiteralPath $Path)
}

function Export-ICTRegistryKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Destination)
    $regPath = $Path -replace '^HKLM:\\', 'HKLM\'
    $exe = Join-Path $env:windir 'System32\reg.exe'
    $output = & $exe export $regPath $Destination /y 2>&1
    if ($LASTEXITCODE -ne 0) { throw "reg.exe export '$regPath' failed (exit $LASTEXITCODE): $output" }
}

function Remove-ICTRegistryKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
}

function Export-ICTScheduledTask {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TaskName, [Parameter(Mandatory)][string]$TaskPath, [Parameter(Mandatory)][string]$Destination)
    $xml = Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    Set-Content -LiteralPath $Destination -Value $xml -Encoding Unicode -ErrorAction Stop
}

function Remove-ICTEnterpriseMgmtTask {
    <# Unregisters every task in the enrollment's EnterpriseMgmt folder, then deletes the folder. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$EnrollmentId)
    if (-not (Test-ICTGuid $EnrollmentId)) { throw "'$EnrollmentId' is not a valid enrollment ID." }
    $taskPath = "\Microsoft\Windows\EnterpriseMgmt\$EnrollmentId\"
    $tasks = @(Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue)
    foreach ($task in $tasks) {
        if ($null -ne $task) { Unregister-ScheduledTask -InputObject $task -Confirm:$false -ErrorAction Stop }
    }
    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    try {
        $parent = $scheduler.GetFolder('\Microsoft\Windows\EnterpriseMgmt')
        $parent.DeleteFolder($EnrollmentId, 0)
    }
    catch {
        # The folder is already gone or never existed.
        Write-ICTLog "Task folder $taskPath not removed: $($_.Exception.Message)"
    }
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

function Export-ICTCertificate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Thumbprint, [Parameter(Mandatory)][string]$Destination)
    $cert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction Stop
    $null = Export-Certificate -Cert $cert -FilePath $Destination -Type CERT -ErrorAction Stop
}

function Remove-ICTCertificate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Thumbprint)
    Remove-Item -LiteralPath "Cert:\LocalMachine\My\$Thumbprint" -Force -ErrorAction Stop
}

function Start-ICTDeviceEnrollerAsSystem {
    <#
        Runs deviceenroller.exe as SYSTEM through a temporary scheduled task. The SSH
        session runs as a local admin account, which is the wrong context for MDM
        enrollment. Returns the task result code, or $null if it is still running
        after the timeout. The task is always removed again.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Argument, [int]$TimeoutSeconds = 120)

    $exe = Join-Path $env:windir 'System32\deviceenroller.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw "deviceenroller.exe not found at $exe." }

    $taskName = 'IntuneComplianceTool-DeviceEnroller-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $action = New-ScheduledTaskAction -Execute $exe -Argument $Argument
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    $null = Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Principal $principal -Settings $settings -Force -ErrorAction Stop

    try {
        Start-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $state = 'Running'
        do {
            Start-Sleep -Seconds 2
            $state = "$((Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction Stop).State)"
        } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)

        if ($state -eq 'Running') { return $null }
        return (Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\' -ErrorAction Stop).LastTaskResult
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue
    }
}

#endregion
