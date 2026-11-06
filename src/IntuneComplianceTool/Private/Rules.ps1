function New-ICTRuleResult {
    <#
        One check result.
        Status: Pass | Fail | Warning | Unknown | Info
        Action: what fixes a Fail automatically (Sync | ReEnroll | LapsRetry) or $null.
        BlocksRemediation: this finding means an automatic enrollment repair would not work.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Warning', 'Unknown', 'Info')][string]$Status,
        [string]$Actual,
        [string]$Message,
        [string]$Remediation,
        [ValidateSet('Sync', 'ReEnroll', 'LapsRetry')][string]$Action,
        [switch]$BlocksRemediation
    )

    $resolvedAction = $null
    if ($Action -and $Status -eq 'Fail') { $resolvedAction = $Action }

    return [pscustomobject]@{
        Id                = $Id
        Category          = $Category
        Name              = $Name
        Status            = $Status
        Actual            = $Actual
        Message           = $Message
        Remediation       = $Remediation
        Action            = $resolvedAction
        BlocksRemediation = [bool]$BlocksRemediation
    }
}

function Get-ICTJoinRule {
    [CmdletBinding()]
    param([psobject]$DeviceData)

    $join = $DeviceData.Join
    if ($null -eq $join) {
        New-ICTRuleResult -Id 'JOIN-001' -Category 'Join' -Name 'Entra ID join' -Status Unknown -Actual 'dsregcmd data unavailable' `
            -Message 'dsregcmd /status could not be read, so the join state is unknown.'
        return
    }

    $joinText = @{ EntraJoined = 'Entra joined'; HybridJoined = 'Hybrid joined'; DomainJoinedOnly = 'Domain joined only'; WorkplaceJoined = 'Workplace registered only'; NotJoined = 'Not joined' }[$join.JoinType]
    $isJoined = ($join.JoinType -eq 'EntraJoined' -or $join.JoinType -eq 'HybridJoined')
    if ($isJoined) {
        $actual = $joinText
        if ($join.TenantName) { $actual = "$joinText - $($join.TenantName)" }
        New-ICTRuleResult -Id 'JOIN-001' -Category 'Join' -Name 'Entra ID join' -Status Pass -Actual $actual
    }
    else {
        $remediation = 'Join the device to Entra ID (or let hybrid join finish: Entra Connect sync + "dsregcmd /join" as SYSTEM). MDM auto-enrollment needs an Entra-joined device.'
        New-ICTRuleResult -Id 'JOIN-001' -Category 'Join' -Name 'Entra ID join' -Status Fail -Actual $joinText -BlocksRemediation `
            -Message 'The device is not Entra joined or hybrid joined, so it cannot auto-enroll into Intune.' -Remediation $remediation
        return
    }

    if ($join.DeviceAuthStatus) {
        if ($join.DeviceAuthStatus -eq 'SUCCESS') {
            New-ICTRuleResult -Id 'JOIN-002' -Category 'Join' -Name 'Device authentication' -Status Pass -Actual 'SUCCESS'
        }
        else {
            New-ICTRuleResult -Id 'JOIN-002' -Category 'Join' -Name 'Device authentication' -Status Fail -Actual $join.DeviceAuthStatus -BlocksRemediation `
                -Message 'The device cannot authenticate to Entra ID. The device object may be deleted or disabled.' `
                -Remediation 'Check the device in Entra ID. If it was deleted: run "dsregcmd /leave" as SYSTEM, then rejoin the device.'
        }
    }

    if ($join.MdmUrl) {
        New-ICTRuleResult -Id 'JOIN-003' -Category 'Join' -Name 'MDM auto-enrollment URL' -Status Pass -Actual (Get-ICTUriHost $join.MdmUrl)
    }
    else {
        New-ICTRuleResult -Id 'JOIN-003' -Category 'Join' -Name 'MDM auto-enrollment URL' -Status Warning -Actual 'not set' -BlocksRemediation `
            -Message 'dsregcmd shows no MDM URL, so automatic MDM enrollment is not configured for this device or tenant.' `
            -Remediation 'In Entra ID > Mobility (MDM and WIP) > Microsoft Intune, set the MDM user scope to include the device user.'
    }
}

function Get-ICTEnrollmentRule {
    [CmdletBinding()]
    param([psobject]$DeviceData, [psobject]$Config, [datetime]$Now)

    $intune = @($DeviceData.Enrollments | Where-Object { $_ -and $_.IsIntune })
    if ($intune.Count -eq 0) {
        New-ICTRuleResult -Id 'ENR-001' -Category 'Enrollment' -Name 'Intune enrollment' -Status Fail -Actual 'not enrolled' -Action ReEnroll `
            -Message 'No Intune MDM enrollment exists on this device.' `
            -Remediation 'Re-enroll the device (this tool: -Remediate).'
        return
    }
    if ($intune.Count -eq 1) {
        New-ICTRuleResult -Id 'ENR-001' -Category 'Enrollment' -Name 'Intune enrollment' -Status Pass -Actual ('1 enrollment ({0})' -f (Get-ICTShortId $intune[0].EnrollmentId))
    }
    else {
        New-ICTRuleResult -Id 'ENR-001' -Category 'Enrollment' -Name 'Intune enrollment' -Status Warning -Actual ('{0} enrollments' -f $intune.Count) `
            -Message 'More than one Intune enrollment exists. Stale duplicates can stop the device from syncing.' `
            -Remediation 'If the device does not sync, reset the enrollment (-Remediate removes all Intune enrollments before re-enrolling).'
    }

    # Certificate: the one with the latest expiry is the active one.
    $certificate = @($DeviceData.MdmCertificates | Where-Object { $_ } | Sort-Object NotAfter -Descending) | Select-Object -First 1
    if ($null -eq $certificate) {
        New-ICTRuleResult -Id 'ENR-002' -Category 'Enrollment' -Name 'MDM certificate' -Status Fail -Actual 'missing' -Action ReEnroll `
            -Message 'The Intune MDM device certificate is missing, so the device cannot authenticate to Intune.' `
            -Remediation 'Re-enroll the device (this tool: -Remediate).'
    }
    else {
        $notAfter = ConvertFrom-ICTDate $certificate.NotAfter
        $expiryDate = $(if ($notAfter) { $notAfter.ToString('yyyy-MM-dd') } else { 'unknown' })
        if (-not $certificate.HasPrivateKey) {
            New-ICTRuleResult -Id 'ENR-002' -Category 'Enrollment' -Name 'MDM certificate' -Status Fail -Actual 'private key missing' -Action ReEnroll `
                -Message 'The MDM certificate has no private key, so the device cannot authenticate to Intune.' `
                -Remediation 'Re-enroll the device (this tool: -Remediate).'
        }
        elseif ($null -eq $notAfter) {
            New-ICTRuleResult -Id 'ENR-002' -Category 'Enrollment' -Name 'MDM certificate' -Status Unknown -Actual 'expiry unknown'
        }
        elseif ($notAfter -le $Now) {
            New-ICTRuleResult -Id 'ENR-002' -Category 'Enrollment' -Name 'MDM certificate' -Status Fail -Action ReEnroll `
                -Actual ('expired {0} ({1})' -f $expiryDate, (Format-ICTRelativeTime $notAfter -Now $Now)) `
                -Message 'The Intune MDM device certificate has expired. The device can no longer check in, and the certificate cannot renew itself.' `
                -Remediation 'Re-enroll the device (this tool: -Remediate).'
        }
        else {
            $daysLeft = [int][math]::Floor(($notAfter - $Now).TotalDays)
            if ($daysLeft -lt $Config.MinCertificateDaysRemaining) {
                New-ICTRuleResult -Id 'ENR-002' -Category 'Enrollment' -Name 'MDM certificate' -Status Warning `
                    -Actual ('expires {0} (in {1} days)' -f $expiryDate, $daysLeft) `
                    -Message 'The MDM certificate expires soon. It renews automatically while the device checks in regularly.' `
                    -Remediation 'Make sure the device syncs before the expiry date.'
            }
            else {
                New-ICTRuleResult -Id 'ENR-002' -Category 'Enrollment' -Name 'MDM certificate' -Status Pass -Actual ('valid until {0}' -f $expiryDate)
            }
        }
    }

    $sync = @($DeviceData.Sync | Where-Object { $_ })
    $taskCount = 0
    foreach ($entry in $sync) { $taskCount += [int]$entry.TaskCount }
    if ($taskCount -eq 0) {
        New-ICTRuleResult -Id 'ENR-003' -Category 'Enrollment' -Name 'Sync tasks' -Status Fail -Actual 'none' -Action ReEnroll `
            -Message 'The scheduled tasks that make the device check in with Intune are missing.' `
            -Remediation 'Re-enroll the device (this tool: -Remediate).'
    }
    else {
        New-ICTRuleResult -Id 'ENR-003' -Category 'Enrollment' -Name 'Sync tasks' -Status Pass -Actual ('{0} tasks present' -f $taskCount)
    }

    # Last successful check-in: OMA-DM server success time, else the last successful task run.
    $lastSuccess = $null
    $source = 'server'
    foreach ($entry in $sync) {
        $date = ConvertFrom-ICTDate $entry.ServerLastSuccessTime
        if ($date -and ($null -eq $lastSuccess -or $date -gt $lastSuccess)) { $lastSuccess = $date }
    }
    if ($null -eq $lastSuccess) {
        $source = 'task'
        foreach ($entry in $sync) {
            if ($entry.LastTaskResult -ne 0) { continue }
            $date = ConvertFrom-ICTDate $entry.LastTaskRunTime
            if ($date -and ($null -eq $lastSuccess -or $date -gt $lastSuccess)) { $lastSuccess = $date }
        }
    }

    if ($null -eq $lastSuccess) {
        New-ICTRuleResult -Id 'ENR-004' -Category 'Enrollment' -Name 'Last check-in' -Status Unknown -Actual 'no successful check-in recorded' `
            -Message 'No successful Intune check-in could be found on the device.'
    }
    else {
        $ageDays = ($Now - $lastSuccess).TotalDays
        $actual = Format-ICTRelativeTime $lastSuccess -Now $Now
        if ($source -eq 'task') { $actual = "$actual (task run)" }
        if ($ageDays -gt $Config.MaxDaysSinceLastSync) {
            New-ICTRuleResult -Id 'ENR-004' -Category 'Enrollment' -Name 'Last check-in' -Status Fail -Action Sync `
                -Actual ('{0} (limit {1} days)' -f $actual, $Config.MaxDaysSinceLastSync) `
                -Message 'The device has not checked in with Intune recently.' `
                -Remediation 'Trigger a sync (this tool: -Remediate tries a sync first and re-enrolls only if the sync fails).'
        }
        else {
            New-ICTRuleResult -Id 'ENR-004' -Category 'Enrollment' -Name 'Last check-in' -Status Pass -Actual $actual
        }
    }
}

function Get-ICTHealthRule {
    [CmdletBinding()]
    param([psobject]$DeviceData, [psobject]$Config, [datetime]$Now)

    $friendly = @{ dmwappushservice = 'WAP push service'; IntuneManagementExtension = 'Intune Mgmt Extension' }
    $services = @($DeviceData.Services | Where-Object { $_ })
    $required = @($Config.RequiredServices)

    foreach ($name in @(@($Config.RequiredServices) + @($Config.RecommendedServices) | Where-Object { $_ })) {
        $isRequired = $required -contains $name
        $label = $(if ($friendly.ContainsKey($name)) { $friendly[$name] } else { $name })
        $id = 'SVC-' + $name
        $service = $services | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        $problem = $(if ($isRequired) { 'Fail' } else { 'Warning' })

        if ($null -eq $service) {
            New-ICTRuleResult -Id $id -Category 'Health' -Name $label -Status Unknown -Actual 'state unavailable'
        }
        elseif (-not $service.Present) {
            $message = "The service '$name' is not installed."
            if ($name -eq 'IntuneManagementExtension') { $message = 'The Intune Management Extension is not installed. That is normal when no Win32 apps, scripts or remediations are assigned.' }
            New-ICTRuleResult -Id $id -Category 'Health' -Name $label -Status $problem -Actual 'not installed' -Message $message
        }
        elseif ($service.StartType -eq 'Disabled') {
            New-ICTRuleResult -Id $id -Category 'Health' -Name $label -Status $problem -Actual 'disabled' `
                -Message "The service '$name' is disabled." -Remediation "Set-Service -Name $name -StartupType Manual (or Automatic for the Intune Management Extension)."
        }
        elseif ($service.StartType -eq 'Automatic' -and $service.Status -ne 'Running') {
            New-ICTRuleResult -Id $id -Category 'Health' -Name $label -Status Warning -Actual ('{0} (Automatic)' -f $service.Status) `
                -Message "The service '$name' should be running." -Remediation "Start-Service -Name $name"
        }
        else {
            $actual = '{0} ({1})' -f $service.Status, $service.StartType
            if ($service.StartType -eq 'Manual' -and $service.Status -ne 'Running') { $actual = 'Manual (starts on demand)' }
            New-ICTRuleResult -Id $id -Category 'Health' -Name $label -Status Pass -Actual $actual
        }
    }

    $events = $DeviceData.MdmEvents
    if ($null -eq $events) {
        New-ICTRuleResult -Id 'EVT-001' -Category 'Health' -Name 'MDM error events' -Status Unknown -Actual 'event log unavailable'
    }
    elseif ($events.ErrorCount -eq 0) {
        New-ICTRuleResult -Id 'EVT-001' -Category 'Health' -Name 'MDM error events' -Status Pass -Actual ('none in {0} days' -f $events.LookbackDays)
    }
    else {
        $latest = @($events.Recent) | Select-Object -First 1
        $when = $(if ($latest) { ', latest ' + (Format-ICTRelativeTime $latest.TimeCreated -Now $Now) } else { '' })
        New-ICTRuleResult -Id 'EVT-001' -Category 'Health' -Name 'MDM error events' -Status Warning `
            -Actual ('{0} in {1} days{2}' -f $events.ErrorCount, $events.LookbackDays, $when) `
            -Message 'The MDM client logged errors. Run with -Detailed to see them.' `
            -Remediation 'Event Viewer: Applications and Services Logs > Microsoft > Windows > DeviceManagement-Enterprise-Diagnostics-Provider > Admin.'
    }
}

function Get-ICTNetworkRule {
    [CmdletBinding()]
    param([psobject]$DeviceData)

    $network = $DeviceData.Network
    $proxy = $null
    if ($network) { $proxy = $network.WinHttpProxy }
    $proxyConfigured = ($proxy -and $proxy.ProxyConfigured)

    if ($null -eq $proxy) {
        New-ICTRuleResult -Id 'NET-PROXY' -Category 'Network' -Name 'WinHTTP proxy' -Status Unknown -Actual 'unavailable'
    }
    elseif ($proxyConfigured) {
        New-ICTRuleResult -Id 'NET-PROXY' -Category 'Network' -Name 'WinHTTP proxy' -Status Info -Actual $proxy.ProxyServer
    }
    else {
        New-ICTRuleResult -Id 'NET-PROXY' -Category 'Network' -Name 'WinHTTP proxy' -Status Info -Actual 'none (direct)'
    }

    foreach ($endpoint in @($network.Endpoints | Where-Object { $_ })) {
        $id = 'NET-' + $endpoint.HostName
        $name = '{0}:{1}' -f $endpoint.HostName, $endpoint.Port
        if ($endpoint.Reachable) {
            New-ICTRuleResult -Id $id -Category 'Network' -Name $name -Status Pass -Actual 'reachable'
        }
        elseif ($proxyConfigured) {
            New-ICTRuleResult -Id $id -Category 'Network' -Name $name -Status Warning -Actual 'no direct connection' `
                -Message "Direct connection failed ($($endpoint.Error)). The device uses the WinHTTP proxy $($proxy.ProxyServer), which this check does not use." `
                -Remediation 'Verify that the proxy allows this host.'
        }
        else {
            New-ICTRuleResult -Id $id -Category 'Network' -Name $name -Status Fail -Actual 'unreachable' -BlocksRemediation `
                -Message "The device cannot reach $($endpoint.HostName) on port $($endpoint.Port): $($endpoint.Error)" `
                -Remediation 'Fix DNS, firewall or proxy access to the Microsoft Intune and Entra ID endpoints first.'
        }
    }
}

function Get-ICTSecurityRule {
    [CmdletBinding()]
    param([psobject]$DeviceData, [psobject]$Config)

    $device = $DeviceData.Device
    $security = $DeviceData.Security

    if ($null -eq $device -or $null -eq $device.OSBuild) {
        New-ICTRuleResult -Id 'SEC-001' -Category 'Security' -Name 'OS build' -Status Unknown -Actual 'unavailable'
    }
    else {
        $build = [string]$device.OSBuild
        if ($null -ne $device.OSUpdateBuildRevision) { $build = '{0}.{1}' -f $device.OSBuild, $device.OSUpdateBuildRevision }
        $actual = '{0} (min {1})' -f $build, $Config.MinimumOSBuild
        if ([int]$device.OSBuild -lt [int]$Config.MinimumOSBuild) {
            New-ICTRuleResult -Id 'SEC-001' -Category 'Security' -Name 'OS build' -Status Fail -Actual $actual `
                -Message 'The Windows build is older than the minimum.' -Remediation 'Install the latest Windows feature update.'
        }
        else {
            New-ICTRuleResult -Id 'SEC-001' -Category 'Security' -Name 'OS build' -Status Pass -Actual $actual
        }
    }

    if ($Config.RequireBitLocker) {
        $bitLocker = $(if ($security) { $security.BitLocker } else { $null })
        if ($null -eq $bitLocker) {
            New-ICTRuleResult -Id 'SEC-002' -Category 'Security' -Name 'BitLocker' -Status Unknown -Actual 'unavailable (needs admin)'
        }
        elseif ($bitLocker.ProtectionOn) {
            $actual = 'On'
            if ($bitLocker.EncryptionMethod) { $actual = 'On ({0})' -f $bitLocker.EncryptionMethod }
            New-ICTRuleResult -Id 'SEC-002' -Category 'Security' -Name 'BitLocker' -Status Pass -Actual $actual
        }
        else {
            $actual = 'Off'
            if ($bitLocker.VolumeStatus) { $actual = 'Off ({0})' -f $bitLocker.VolumeStatus }
            New-ICTRuleResult -Id 'SEC-002' -Category 'Security' -Name 'BitLocker' -Status Fail -Actual $actual `
                -Message "BitLocker protection is off on $($bitLocker.MountPoint)." -Remediation 'Check the Intune disk encryption policy and the BitLocker event log.'
        }
    }

    if ($Config.RequireTpm) {
        $tpm = $(if ($security) { $security.Tpm } else { $null })
        if ($null -eq $tpm) {
            New-ICTRuleResult -Id 'SEC-003' -Category 'Security' -Name 'TPM' -Status Unknown -Actual 'unavailable (needs admin)'
        }
        elseif ($tpm.Present -and $tpm.Ready) {
            New-ICTRuleResult -Id 'SEC-003' -Category 'Security' -Name 'TPM' -Status Pass -Actual 'present, ready'
        }
        else {
            $actual = $(if (-not $tpm.Present) { 'not present' } else { 'present, not ready' })
            New-ICTRuleResult -Id 'SEC-003' -Category 'Security' -Name 'TPM' -Status Fail -Actual $actual `
                -Message 'The TPM is missing or not ready.' -Remediation 'Enable the TPM in the firmware settings and run tpm.msc to initialise it.'
        }
    }

    if ($Config.RequireSecureBoot) {
        $secureBoot = $(if ($security) { $security.SecureBoot } else { $null })
        if ($null -eq $secureBoot) {
            New-ICTRuleResult -Id 'SEC-004' -Category 'Security' -Name 'Secure Boot' -Status Unknown -Actual 'unavailable (needs admin)'
        }
        elseif ($secureBoot.Enabled) {
            New-ICTRuleResult -Id 'SEC-004' -Category 'Security' -Name 'Secure Boot' -Status Pass -Actual 'On'
        }
        else {
            $actual = $(if ($secureBoot.Supported) { 'Off' } else { 'not supported (legacy BIOS)' })
            New-ICTRuleResult -Id 'SEC-004' -Category 'Security' -Name 'Secure Boot' -Status Fail -Actual $actual `
                -Message 'Secure Boot is not enabled.' -Remediation 'Switch the firmware to UEFI and enable Secure Boot.'
        }
    }

    $defender = $(if ($security) { $security.Defender } else { $null })
    if ($Config.RequireDefenderRealTimeProtection) {
        if ($null -eq $defender) {
            New-ICTRuleResult -Id 'SEC-005' -Category 'Security' -Name 'Defender real-time' -Status Unknown -Actual 'unavailable'
        }
        elseif ($defender.AMRunningMode -match 'Passive') {
            New-ICTRuleResult -Id 'SEC-005' -Category 'Security' -Name 'Defender real-time' -Status Warning -Actual 'passive mode' `
                -Message 'Defender runs in passive mode, usually because another antivirus product is installed.' `
                -Remediation 'Check that the other antivirus product is reported to Windows Security Center.'
        }
        elseif ($defender.AMServiceEnabled -and $defender.RealTimeProtectionEnabled) {
            New-ICTRuleResult -Id 'SEC-005' -Category 'Security' -Name 'Defender real-time' -Status Pass -Actual 'On'
        }
        else {
            New-ICTRuleResult -Id 'SEC-005' -Category 'Security' -Name 'Defender real-time' -Status Fail -Actual 'Off' `
                -Message 'Microsoft Defender real-time protection is off.' -Remediation 'Check the Intune antivirus policy and tamper protection.'
        }
    }

    if ($null -ne $Config.MaxDefenderSignatureAgeDays -and $null -ne $defender -and $defender.AMRunningMode -notmatch 'Passive') {
        $age = $defender.AntivirusSignatureAgeDays
        if ($null -eq $age) {
            New-ICTRuleResult -Id 'SEC-006' -Category 'Security' -Name 'Defender signatures' -Status Unknown -Actual 'age unknown'
        }
        elseif ([int]$age -gt [int]$Config.MaxDefenderSignatureAgeDays) {
            New-ICTRuleResult -Id 'SEC-006' -Category 'Security' -Name 'Defender signatures' -Status Fail `
                -Actual ('{0} days old (limit {1})' -f $age, $Config.MaxDefenderSignatureAgeDays) `
                -Message 'Defender signatures are out of date.' -Remediation 'Run "Update-MpSignature" and check Windows Update / WSUS access.'
        }
        else {
            $actual = $(if ([int]$age -eq 0) { 'up to date' } else { '{0} days old' -f $age })
            New-ICTRuleResult -Id 'SEC-006' -Category 'Security' -Name 'Defender signatures' -Status Pass -Actual $actual
        }
    }

    if ($Config.RequireFirewallAllProfiles) {
        $firewall = @($(if ($security) { $security.Firewall } else { $null }) | Where-Object { $_ })
        if ($firewall.Count -eq 0) {
            New-ICTRuleResult -Id 'SEC-007' -Category 'Security' -Name 'Firewall' -Status Unknown -Actual 'unavailable'
        }
        else {
            $off = @($firewall | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Profile })
            if ($off.Count -eq 0) {
                New-ICTRuleResult -Id 'SEC-007' -Category 'Security' -Name 'Firewall' -Status Pass -Actual (((@($firewall | ForEach-Object { $_.Profile })) -join ', ') + ' on')
            }
            else {
                New-ICTRuleResult -Id 'SEC-007' -Category 'Security' -Name 'Firewall' -Status Fail -Actual (($off -join ', ') + ' off') `
                    -Message 'Windows Firewall is off for at least one profile.' -Remediation 'Check the Intune firewall policy.'
            }
        }
    }
}

function Get-ICTLapsRule {
    [CmdletBinding()]
    param([psobject]$DeviceData, [psobject]$Config, [datetime]$Now)

    if (-not $Config.RequireLaps) { return }
    $laps = $DeviceData.Laps
    $targetText = @{ EntraId = 'Entra ID'; ActiveDirectory = 'Active Directory'; Disabled = 'disabled'; Unknown = 'unknown target' }

    if ($null -eq $laps) {
        New-ICTRuleResult -Id 'LAPS-001' -Category 'LAPS' -Name 'LAPS policy' -Status Unknown -Actual 'unavailable'
        return
    }
    if (-not $laps.Configured) {
        New-ICTRuleResult -Id 'LAPS-001' -Category 'LAPS' -Name 'LAPS policy' -Status Fail -Actual 'not configured' `
            -Message 'No Windows LAPS policy is applied, so the local admin password is not rotated or backed up.' `
            -Remediation 'Assign the Intune LAPS policy (Endpoint security > Account protection) to this device.'
        return
    }

    $policyText = 'active - backup to {0} ({1})' -f $targetText[$laps.BackupTarget], $laps.PolicySource
    if ($laps.BackupTarget -eq 'Disabled') {
        New-ICTRuleResult -Id 'LAPS-001' -Category 'LAPS' -Name 'LAPS policy' -Status Fail -Actual 'backup disabled' `
            -Message 'A LAPS policy exists but its backup directory is set to disabled.' -Remediation 'Set the backup directory to Entra ID in the Intune LAPS policy.'
        return
    }
    elseif ($laps.BackupTarget -ne $Config.LapsExpectedBackupTarget) {
        New-ICTRuleResult -Id 'LAPS-001' -Category 'LAPS' -Name 'LAPS policy' -Status Warning -Actual $policyText `
            -Message ('LAPS backs up to {0}, expected {1}.' -f $targetText[$laps.BackupTarget], $targetText[$Config.LapsExpectedBackupTarget])
    }
    else {
        New-ICTRuleResult -Id 'LAPS-001' -Category 'LAPS' -Name 'LAPS policy' -Status Pass -Actual $policyText
    }

    # Managed account
    $account = $laps.Account
    $expected = $Config.LapsExpectedAccount
    if ($null -eq $account) {
        New-ICTRuleResult -Id 'LAPS-002' -Category 'LAPS' -Name 'Managed account' -Status Unknown -Actual 'unavailable'
    }
    elseif (-not $account.Exists) {
        $name = $(if ($laps.AdministratorAccountName) { $laps.AdministratorAccountName } else { 'built-in Administrator' })
        New-ICTRuleResult -Id 'LAPS-002' -Category 'LAPS' -Name 'Managed account' -Status Fail -Actual "$name does not exist" `
            -Message 'The account LAPS should manage does not exist on this device.' `
            -Remediation 'Create the account, or enable automatic account management in the LAPS policy.'
    }
    elseif ($account.Enabled -eq $false) {
        New-ICTRuleResult -Id 'LAPS-002' -Category 'LAPS' -Name 'Managed account' -Status Fail -Actual "$($account.Name) (disabled)" `
            -Message 'The LAPS-managed account is disabled.' -Remediation "Enable-LocalUser -Name $($account.Name)"
    }
    elseif ($account.IsAdministrator -eq $false) {
        New-ICTRuleResult -Id 'LAPS-002' -Category 'LAPS' -Name 'Managed account' -Status Fail -Actual "$($account.Name) (not an administrator)" `
            -Message 'The LAPS-managed account is not in the local Administrators group.' `
            -Remediation "Add-LocalGroupMember -SID S-1-5-32-544 -Member $($account.Name)"
    }
    elseif ($expected -and $account.Name -ne $expected) {
        New-ICTRuleResult -Id 'LAPS-002' -Category 'LAPS' -Name 'Managed account' -Status Warning -Actual "$($account.Name) (expected $expected)" `
            -Message "LAPS manages '$($account.Name)', not '$expected'. The password of '$expected' is then not rotated by LAPS."
    }
    else {
        $details = $(if ($null -eq $account.IsAdministrator) { 'enabled' } else { 'enabled, administrator' })
        New-ICTRuleResult -Id 'LAPS-002' -Category 'LAPS' -Name 'Managed account' -Status Pass -Actual "$($account.Name) ($details)"
    }

    # Last rotation
    $lastUpdate = ConvertFrom-ICTDate $laps.LastPasswordUpdateTime
    if ($null -eq $lastUpdate) {
        New-ICTRuleResult -Id 'LAPS-003' -Category 'LAPS' -Name 'Last rotation' -Status Unknown -Actual 'no rotation recorded'
    }
    else {
        $actual = '{0} (every {1} days)' -f (Format-ICTRelativeTime $lastUpdate -Now $Now), $laps.PasswordAgeDays
        if (($Now - $lastUpdate).TotalDays -gt ($laps.PasswordAgeDays + 1)) {
            New-ICTRuleResult -Id 'LAPS-003' -Category 'LAPS' -Name 'Last rotation' -Status Fail -Actual $actual -Action LapsRetry `
                -Message 'The LAPS password is older than the rotation interval.' `
                -Remediation 'Run Invoke-LapsPolicyProcessing and check the LAPS event log.'
        }
        else {
            New-ICTRuleResult -Id 'LAPS-003' -Category 'LAPS' -Name 'Last rotation' -Status Pass -Actual $actual
        }
    }

    # Backup errors
    $events = $laps.Events
    $backupName = 'Backup to {0}' -f $targetText[$laps.BackupTarget]
    if ($null -eq $events) {
        New-ICTRuleResult -Id 'LAPS-004' -Category 'LAPS' -Name $backupName -Status Unknown -Actual 'LAPS event log unavailable'
    }
    elseif ($events.ErrorCount -eq 0) {
        New-ICTRuleResult -Id 'LAPS-004' -Category 'LAPS' -Name $backupName -Status Pass -Actual ('no errors in {0} days' -f $events.LookbackDays)
    }
    else {
        $lastError = ConvertFrom-ICTDate $events.LastErrorTime
        $lastSuccess = ConvertFrom-ICTDate $events.LastSuccessTime
        if ($null -eq $lastSuccess -or ($lastError -and $lastError -gt $lastSuccess)) {
            New-ICTRuleResult -Id 'LAPS-004' -Category 'LAPS' -Name $backupName -Status Fail -Action LapsRetry `
                -Actual ('last attempt failed {0} (event {1})' -f (Format-ICTRelativeTime $lastError -Now $Now), $events.LastErrorId) `
                -Message ('LAPS logged an error: {0}' -f $events.LastErrorMessage) `
                -Remediation 'Run Invoke-LapsPolicyProcessing (this tool: -Remediate) and check the LAPS event log.'
        }
        else {
            New-ICTRuleResult -Id 'LAPS-004' -Category 'LAPS' -Name $backupName -Status Warning `
                -Actual ('{0} error(s) in {1} days, last run OK' -f $events.ErrorCount, $events.LookbackDays) `
                -Message ('Latest error: {0}' -f $events.LastErrorMessage)
        }
    }

    # Post-authentication actions
    $postText = ConvertTo-ICTLapsPostActionText -Actions $laps.PostAuthenticationActions -DelayHours $laps.PostAuthenticationResetDelayHours
    New-ICTRuleResult -Id 'LAPS-005' -Category 'LAPS' -Name 'After sign-in' -Status Info -Actual $postText `
        -Message 'What LAPS does after someone signs in with the managed account password. SSH logons with that password may count too; SSH keys avoid it.'
}
