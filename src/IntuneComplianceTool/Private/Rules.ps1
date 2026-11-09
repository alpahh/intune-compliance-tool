$script:ICTRuleCategory = @{ JOIN = 'Join'; ENR = 'Enrollment'; SVC = 'Health'; EVT = 'Health'; HLT = 'Health'; NET = 'Network'; SEC = 'Security'; LAPS = 'LAPS' }

# Auto-enrollment error codes (event 76) worth explaining. Blocks = re-enrolling would fail the same way.
$script:ICTEnrollErrors = @{
    '0x8018002b' = @{ Text = 'user not in MDM scope or UPN domain not verified'; Blocks = $true }
    '0x80180018' = @{ Text = 'user has no Intune license'; Blocks = $true }
    '0x80180014' = @{ Text = 'blocked by enrollment restrictions'; Blocks = $true }
    '0x8018000a' = @{ Text = 'device already enrolled'; Blocks = $false }
    '0x80192ee7' = @{ Text = 'server name could not be resolved'; Blocks = $false }
    '0x80192ee2' = @{ Text = 'connection timed out'; Blocks = $false }
}

function New-ICTRuleResult {
    <#
        One check result. The category comes from the Id prefix.
        Status: Pass | Fail | Warning | Unknown | Info
        Action: the repair -Remediate runs for a Fail or Warning (TimeSync, ServiceFix, Sync, ReEnroll, LapsRetry).
        Blocks: for a Fail or Warning, the repairs this finding makes pointless: ReEnroll, or All (sync too).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Id,
        [Parameter(Mandatory, Position = 1)][string]$Name,
        [Parameter(Mandatory, Position = 2)][ValidateSet('Pass', 'Fail', 'Warning', 'Unknown', 'Info')][string]$Status,
        [Parameter(Position = 3)][string]$Actual,
        [string]$Message,
        [string]$Remediation,
        [ValidateSet('TimeSync', 'ServiceFix', 'Sync', 'ReEnroll', 'LapsRetry')][string]$Action,
        [ValidateSet('ReEnroll', 'All')][string]$Blocks
    )

    $isProblem = ($Status -eq 'Fail' -or $Status -eq 'Warning')
    if ($Action -eq 'ReEnroll' -and -not $Remediation) { $Remediation = 'Re-enroll the device (this tool: -Remediate).' }
    return [pscustomobject]@{
        Id          = $Id
        Category    = $script:ICTRuleCategory[$Id.Split('-')[0]]
        Name        = $Name
        Status      = $Status
        Actual      = $Actual
        Message     = $Message
        Remediation = $Remediation
        Action      = $(if ($isProblem -and $Action) { $Action } else { $null })
        Blocks      = $(if ($isProblem -and $Blocks) { $Blocks } else { $null })
    }
}

function Format-ICTDate {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Date)
    $value = ConvertFrom-ICTDate $Date
    if ($null -eq $value) { return 'unknown' }
    return $value.ToString('yyyy-MM-dd', $script:ICTInvariant)
}

function Get-ICTJoinRule {
    [CmdletBinding()]
    param([psobject]$DeviceData, [datetime]$Now)

    $join = $DeviceData.Join
    if ($null -eq $join) { New-ICTRuleResult 'JOIN-001' 'Entra ID join' Unknown 'could not read dsregcmd'; return }

    $joinText = $script:ICTJoinText[$join.JoinType]
    if ($join.JoinType -ne 'EntraJoined' -and $join.JoinType -ne 'HybridJoined') {
        New-ICTRuleResult 'JOIN-001' 'Entra ID join' Fail $joinText -Blocks ReEnroll `
            -Message 'The device is not Entra joined or hybrid joined, so it cannot auto-enroll into Intune.' `
            -Remediation 'Join the device to Entra ID (or let hybrid join finish: Entra Connect sync + "dsregcmd /join" as SYSTEM).'
        return
    }
    New-ICTRuleResult 'JOIN-001' 'Entra ID join' Pass ($(if ($join.TenantName) { "$joinText - $($join.TenantName)" } else { $joinText }))

    if ($join.DeviceAuthStatus -and $join.DeviceAuthStatus -ne 'SUCCESS') {
        New-ICTRuleResult 'JOIN-002' 'Device authentication' Fail $join.DeviceAuthStatus -Blocks ReEnroll `
            -Message 'The device cannot authenticate to Entra ID. The device object may be deleted or disabled.' `
            -Remediation 'Check the device in Entra ID. If it was deleted: run "dsregcmd /leave" as SYSTEM, then rejoin the device.'
    }
    elseif ($join.DeviceAuthStatus) { New-ICTRuleResult 'JOIN-002' 'Device authentication' Pass 'SUCCESS' }

    if ($join.MdmUrl) { New-ICTRuleResult 'JOIN-003' 'MDM auto-enrollment URL' Pass (Get-ICTUriHost $join.MdmUrl) }
    else {
        New-ICTRuleResult 'JOIN-003' 'MDM auto-enrollment URL' Warning 'not set' -Blocks ReEnroll `
            -Message 'dsregcmd shows no MDM URL, so automatic MDM enrollment is not configured for this device or tenant.' `
            -Remediation 'In Entra ID > Mobility (MDM and WIP) > Microsoft Intune, set the MDM user scope to include the device user.'
    }

    $notAfter = ConvertFrom-ICTDate $join.DeviceCertificateNotAfter
    if ($join.KeySignTest -match 'FAIL') {
        New-ICTRuleResult 'JOIN-004' 'Entra device key' Fail $join.KeySignTest -Blocks ReEnroll `
            -Message 'The Entra device key failed its signing test (TPM or key problem), so the device cannot prove its identity.' `
            -Remediation 'Run "dsregcmd /leave" as SYSTEM, clear the TPM if needed, then rejoin the device.'
    }
    elseif ($notAfter -and $notAfter -le $Now) {
        New-ICTRuleResult 'JOIN-004' 'Entra device key' Fail ('certificate expired {0}' -f (Format-ICTDate $notAfter)) -Blocks ReEnroll `
            -Message 'The Entra device certificate has expired.' -Remediation 'Rejoin the device to Entra ID.'
    }
    elseif ($notAfter) {
        $keyText = $(if ($join.KeySignTest -match 'PASS') { ', key test passed' } else { '' })
        New-ICTRuleResult 'JOIN-004' 'Entra device key' Pass ('certificate valid until {0}{1}' -f (Format-ICTDate $notAfter), $keyText)
    }
}

function Get-ICTEnrollmentRule {
    [CmdletBinding()]
    param([psobject]$DeviceData, [psobject]$Config, [datetime]$Now)

    $auto = $DeviceData.AutoEnroll
    if ($auto -and $auto.ExternallyManaged) {
        New-ICTRuleResult 'ENR-006' 'Managed by another MDM' Warning 'ExternallyManaged = 1' -Blocks ReEnroll `
            -Message 'The device is flagged as managed by another MDM, so Windows refuses to auto-enroll into Intune.' `
            -Remediation 'Remove the other MDM, then clear HKLM\SOFTWARE\Microsoft\Enrollments\ExternallyManaged.'
    }

    if ($null -eq $DeviceData.Enrollments) { New-ICTRuleResult 'ENR-001' 'Intune enrollment' Unknown 'could not read the enrollments'; return }
    $intune = @($DeviceData.Enrollments | Where-Object { $_ -and $_.IsIntune })
    if ($intune.Count -eq 0) {
        New-ICTRuleResult 'ENR-001' 'Intune enrollment' Fail 'not enrolled' -Action ReEnroll -Message 'No Intune MDM enrollment exists on this device.'
        if ($auto) { Get-ICTAutoEnrollRule -AutoEnroll $auto -Now $Now }
        return
    }
    if ($intune.Count -eq 1) { New-ICTRuleResult 'ENR-001' 'Intune enrollment' Pass ('1 enrollment ({0})' -f (Get-ICTShortId $intune[0].EnrollmentId)) }
    else {
        New-ICTRuleResult 'ENR-001' 'Intune enrollment' Warning ('{0} enrollments' -f $intune.Count) `
            -Message 'More than one Intune enrollment exists. Stale duplicates can stop the device from syncing.' `
            -Remediation 'If the device does not sync, reset the enrollment (-Remediate removes all Intune enrollments before re-enrolling).'
    }

    # Certificate: the one with the latest expiry is the active one.
    if ($null -eq $DeviceData.MdmCertificates) { New-ICTRuleResult 'ENR-002' 'MDM certificate' Unknown 'could not read the certificate store' }
    else {
        $certificate = @($DeviceData.MdmCertificates | Where-Object { $_ } | Sort-Object NotAfter -Descending) | Select-Object -First 1
        $notAfter = ConvertFrom-ICTDate $certificate.NotAfter
        if ($null -eq $certificate) {
            New-ICTRuleResult 'ENR-002' 'MDM certificate' Fail 'missing' -Action ReEnroll -Message 'The Intune MDM device certificate is missing, so the device cannot authenticate to Intune.'
        }
        elseif (-not $certificate.HasPrivateKey) {
            New-ICTRuleResult 'ENR-002' 'MDM certificate' Fail 'private key missing' -Action ReEnroll -Message 'The MDM certificate has no private key, so the device cannot authenticate to Intune.'
        }
        elseif ($null -eq $notAfter) { New-ICTRuleResult 'ENR-002' 'MDM certificate' Unknown 'expiry unknown' }
        elseif ($notAfter -le $Now) {
            New-ICTRuleResult 'ENR-002' 'MDM certificate' Fail ('expired {0} ({1})' -f (Format-ICTDate $notAfter), (Format-ICTRelativeTime $notAfter -Now $Now)) -Action ReEnroll `
                -Message 'The Intune MDM device certificate has expired. The device can no longer check in, and the certificate cannot renew itself.'
        }
        elseif (($notAfter - $Now).TotalDays -lt $Config.MinCertificateDaysRemaining) {
            New-ICTRuleResult 'ENR-002' 'MDM certificate' Warning ('expires {0} (in {1} days)' -f (Format-ICTDate $notAfter), [int][math]::Floor(($notAfter - $Now).TotalDays)) `
                -Message 'The MDM certificate expires soon. It renews automatically while the device checks in regularly.' -Remediation 'Make sure the device syncs before the expiry date.'
        }
        else { New-ICTRuleResult 'ENR-002' 'MDM certificate' Pass ('valid until {0}' -f (Format-ICTDate $notAfter)) }
    }

    $sync = @($DeviceData.Sync | Where-Object { $_ })
    if (@($sync | Where-Object { $null -eq $_.TaskCount }).Count -gt 0) { New-ICTRuleResult 'ENR-003' 'Sync tasks' Unknown 'could not read the scheduled tasks' }
    else {
        $taskCount = ($sync | Measure-Object -Property TaskCount -Sum).Sum
        if (-not $taskCount) {
            New-ICTRuleResult 'ENR-003' 'Sync tasks' Fail 'none' -Action ReEnroll -Message 'The scheduled tasks that make the device check in with Intune are missing.'
        }
        else { New-ICTRuleResult 'ENR-003' 'Sync tasks' Pass ('{0} tasks present' -f $taskCount) }
    }

    # Last successful check-in: OMA-DM server success time, else the last successful task run.
    $lastSuccess = @($sync | ForEach-Object { ConvertFrom-ICTDate $_.ServerLastSuccessTime } | Where-Object { $_ } | Sort-Object -Descending) | Select-Object -First 1
    $suffix = ''
    if ($null -eq $lastSuccess) {
        $lastSuccess = @($sync | Where-Object { $_.LastTaskResult -eq 0 } | ForEach-Object { ConvertFrom-ICTDate $_.LastTaskRunTime } | Where-Object { $_ } | Sort-Object -Descending) | Select-Object -First 1
        $suffix = ' (task run)'
    }
    if ($null -eq $lastSuccess) {
        New-ICTRuleResult 'ENR-004' 'Last check-in' Unknown 'no successful check-in recorded' -Message 'No successful Intune check-in could be found on the device.'
    }
    elseif (($Now - $lastSuccess).TotalDays -gt $Config.MaxDaysSinceLastSync) {
        New-ICTRuleResult 'ENR-004' 'Last check-in' Fail ('{0}{1} (limit {2} days)' -f (Format-ICTRelativeTime $lastSuccess -Now $Now), $suffix, $Config.MaxDaysSinceLastSync) -Action Sync `
            -Message 'The device has not checked in with Intune recently.' `
            -Remediation 'Trigger a sync (this tool: -Remediate tries a sync first and re-enrolls only if the sync fails).'
    }
    else { New-ICTRuleResult 'ENR-004' 'Last check-in' Pass ((Format-ICTRelativeTime $lastSuccess -Now $Now) + $suffix) }
}

function Get-ICTAutoEnrollRule {
    <# Explains why an unenrolled device did not auto-enroll (shown only when it is not enrolled). #>
    [CmdletBinding()]
    param([psobject]$AutoEnroll, [datetime]$Now)

    $policy = $(if ($AutoEnroll.PolicyAutoEnroll -eq 1) { 'auto-enrollment GPO on' } else { 'no auto-enrollment GPO' })
    if ($AutoEnroll.LastResult -eq 'Failed') {
        $code = $AutoEnroll.LastErrorCode
        $known = $(if ($code) { $script:ICTEnrollErrors[$code] } else { $null })
        $actual = 'last attempt failed {0}: {1}' -f (Format-ICTRelativeTime $AutoEnroll.LastResultTime -Now $Now), $(if ($code) { $code } else { 'unknown error' })
        if ($known) { $actual += " ($($known.Text))" }
        $extra = @{}
        if ($known -and $known.Blocks) { $extra.Blocks = 'ReEnroll' }
        New-ICTRuleResult 'ENR-005' 'Auto-enrollment' Warning $actual @extra `
            -Message "Windows tried to enroll the device automatically and failed ($policy)." `
            -Remediation 'Fix the cause in Intune / Entra ID (license, MDM user scope, enrollment restrictions), then repair.'
    }
    elseif ($AutoEnroll.LastResult -eq 'Succeeded') {
        New-ICTRuleResult 'ENR-005' 'Auto-enrollment' Info ('last attempt succeeded {0}, enrollment removed since' -f (Format-ICTRelativeTime $AutoEnroll.LastResultTime -Now $Now))
    }
    else { New-ICTRuleResult 'ENR-005' 'Auto-enrollment' Info "no attempt logged, $policy" }
}

function Get-ICTHealthRule {
    [CmdletBinding()]
    param([psobject]$DeviceData, [psobject]$Config, [datetime]$Now)

    $friendly = @{ dmwappushservice = 'WAP push service'; IntuneManagementExtension = 'Intune Mgmt Extension' }
    $required = @($Config.RequiredServices)
    foreach ($name in @(@($Config.RequiredServices) + @($Config.RecommendedServices) | Where-Object { $_ })) {
        $label = $(if ($friendly.ContainsKey($name)) { $friendly[$name] } else { $name })
        $id = 'SVC-' + $name
        $problem = $(if ($required -contains $name) { 'Fail' } else { 'Warning' })
        $service = @($DeviceData.Services | Where-Object { $_ -and $_.Name -eq $name }) | Select-Object -First 1

        if ($null -eq $service) { New-ICTRuleResult $id $label Unknown 'state unavailable' }
        elseif (-not $service.Present) {
            $message = $(if ($name -eq 'IntuneManagementExtension') { 'Not installed. That is normal when no Win32 apps, scripts or remediations are assigned.' } else { "The service '$name' is not installed." })
            New-ICTRuleResult $id $label $problem 'not installed' -Message $message
        }
        elseif ($service.StartType -eq 'Disabled') {
            New-ICTRuleResult $id $label $problem 'disabled' -Action ServiceFix -Message "The service '$name' is disabled." -Remediation 'The tool sets it back to its normal start type (-Remediate).'
        }
        elseif ($service.StartType -eq 'Automatic' -and $service.Status -ne 'Running') {
            New-ICTRuleResult $id $label Warning ('{0} (Automatic)' -f $service.Status) -Action ServiceFix -Message "The service '$name' should be running." -Remediation 'The tool starts it (-Remediate).'
        }
        elseif ($service.StartType -eq 'Manual' -and $service.Status -ne 'Running') { New-ICTRuleResult $id $label Pass 'Manual (starts on demand)' }
        else { New-ICTRuleResult $id $label Pass ('{0} ({1})' -f $service.Status, $service.StartType) }
    }

    $events = $DeviceData.MdmEvents
    if ($null -eq $events) { New-ICTRuleResult 'EVT-001' 'MDM error events' Unknown 'event log unavailable' }
    elseif ($events.ErrorCount -eq 0) { New-ICTRuleResult 'EVT-001' 'MDM error events' Pass ('none in {0} days' -f $events.LookbackDays) }
    else {
        $latest = @($events.Recent) | Select-Object -First 1
        $count = $(if ($events.Truncated) { "$($events.ErrorCount)+" } else { "$($events.ErrorCount)" })
        New-ICTRuleResult 'EVT-001' 'MDM error events' Warning ('{0} in {1} days, latest {2}' -f $count, $events.LookbackDays, (Format-ICTRelativeTime $latest.TimeCreated -Now $Now)) `
            -Message 'The MDM client logged errors. Run with -Detailed to see them.' `
            -Remediation 'Event Viewer: Applications and Services Logs > Microsoft > Windows > DeviceManagement-Enterprise-Diagnostics-Provider > Admin.'
    }

    $reboot = $DeviceData.PendingReboot
    $boot = ConvertFrom-ICTDate $DeviceData.Device.LastBootTime
    $uptime = $(if ($boot) { 'up ' + ((Format-ICTRelativeTime $boot -Now $Now) -replace ' ago$', '') } else { 'uptime unknown' })
    if ($null -eq $reboot) { New-ICTRuleResult 'HLT-REBOOT' 'Pending reboot' Unknown 'could not read' }
    elseif ($reboot.Pending) {
        New-ICTRuleResult 'HLT-REBOOT' 'Pending reboot' Warning ('yes, {0} ({1})' -f (@($reboot.Reasons) -join ', '), $uptime) `
            -Message 'Updates wait for a reboot. Until then the OS version (and compliance) does not change.' -Remediation 'Ask the user to restart the device.'
    }
    elseif ($boot -and ($Now - $boot).TotalDays -gt $Config.MaxUptimeDays) {
        New-ICTRuleResult 'HLT-REBOOT' 'Pending reboot' Warning ('no, but {0}' -f $uptime) -Message 'The device has not restarted for a long time.' -Remediation 'Ask the user to restart the device.'
    }
    else { New-ICTRuleResult 'HLT-REBOOT' 'Pending reboot' Pass ('no ({0})' -f $uptime) }
}

function Get-ICTNetworkRule {
    [CmdletBinding()]
    param([psobject]$DeviceData, [psobject]$Config)

    $network = $DeviceData.Network
    if ($null -eq $network) { New-ICTRuleResult 'NET-ENDPOINTS' 'Network' Unknown 'not checked'; return }
    $proxy = $network.WinHttpProxy
    $proxyConfigured = ($proxy -and $proxy.ProxyConfigured)
    if ($null -eq $proxy) { New-ICTRuleResult 'NET-PROXY' 'WinHTTP proxy' Unknown 'unavailable' }
    else { New-ICTRuleResult 'NET-PROXY' 'WinHTTP proxy' Info $(if ($proxyConfigured) { $proxy.ProxyServer } else { 'none (direct)' }) }

    if ($null -eq $network.Endpoints) { New-ICTRuleResult 'NET-ENDPOINTS' 'Endpoints' Unknown 'could not test' }
    foreach ($endpoint in @($network.Endpoints | Where-Object { $_ })) {
        $id = 'NET-' + $endpoint.HostName
        $name = '{0}:{1}' -f $endpoint.HostName, $endpoint.Port
        if ($endpoint.Reachable) { New-ICTRuleResult $id $name Pass 'reachable' }
        elseif ($proxyConfigured) {
            New-ICTRuleResult $id $name Warning 'no direct connection' `
                -Message "Direct connection failed ($($endpoint.Error)). The device uses the WinHTTP proxy $($proxy.ProxyServer), which this check does not use." `
                -Remediation 'Verify that the proxy allows this host.'
        }
        else {
            New-ICTRuleResult $id $name Fail 'unreachable' -Blocks All `
                -Message "The device cannot reach $($endpoint.HostName) on port $($endpoint.Port): $($endpoint.Error)" `
                -Remediation 'Fix DNS, firewall or proxy access to the Microsoft Intune and Entra ID endpoints first.'
        }
    }

    $offset = $network.ClockOffsetSeconds
    if ($null -eq $offset -and $network.ClockError -like 'TLS certificate rejected*') {
        New-ICTRuleResult 'NET-TIME' 'Clock' Fail 'not measurable, server certificate rejected' -Action TimeSync -Message $network.ClockError `
            -Remediation 'Check the date and time; the tool resynchronises the time service (-Remediate).'
        return
    }
    if ($null -eq $offset) { New-ICTRuleResult 'NET-TIME' 'Clock' Info 'not measured (no HTTPS response)' -Message $network.ClockError; return }
    $direction = $(if ($offset -gt 0) { 'ahead' } else { 'behind' })
    $size = [math]::Abs($offset)
    $text = $(if ($size -ge 120) { '{0} min {1}' -f [int][math]::Round($size / 60), $direction } else { '{0} s {1}' -f $size, $direction })
    if ($size -gt $Config.MaxClockSkewSeconds) {
        New-ICTRuleResult 'NET-TIME' 'Clock' Fail $text -Action TimeSync `
            -Message 'The local clock is far off. Certificate and token checks against Intune and Entra ID fail with this skew.' `
            -Remediation 'The tool resynchronises the time service (-Remediate).'
    }
    elseif ($size -gt 60) {
        New-ICTRuleResult 'NET-TIME' 'Clock' Warning $text -Action TimeSync -Message 'The local clock drifts.' -Remediation 'The tool resynchronises the time service (-Remediate).'
    }
    else { New-ICTRuleResult 'NET-TIME' 'Clock' Pass ('in sync ({0} s)' -f $offset) }
}

function Get-ICTSecurityRule {
    [CmdletBinding()]
    param([psobject]$DeviceData, [psobject]$Config)

    $device = $DeviceData.Device
    $security = $DeviceData.Security

    if ($null -eq $device.OSBuild) { New-ICTRuleResult 'SEC-001' 'OS build' Unknown 'unavailable' }
    else {
        $build = [string]$device.OSBuild
        $minimumRevision = $null
        if ($Config.MinimumOSRevision) {
            $entry = $Config.MinimumOSRevision.PSObject.Properties[$build]
            if ($entry) { $minimumRevision = [int]$entry.Value }
        }
        $current = $(if ($null -ne $device.OSUpdateBuildRevision) { '{0}.{1}' -f $build, $device.OSUpdateBuildRevision } else { $build })
        $minimum = $(if ($null -ne $minimumRevision) { '{0}.{1}' -f $build, $minimumRevision } else { [string]$Config.MinimumOSBuild })
        $actual = '{0} (min {1})' -f $current, $minimum
        if ([int]$device.OSBuild -lt [int]$Config.MinimumOSBuild) {
            New-ICTRuleResult 'SEC-001' 'OS build' Fail $actual -Message 'The Windows build is older than the minimum.' -Remediation 'Install the latest Windows feature update.'
        }
        elseif ($null -ne $minimumRevision -and $null -eq $device.OSUpdateBuildRevision) { New-ICTRuleResult 'SEC-001' 'OS build' Unknown "$build (update revision unavailable)" }
        elseif ($null -ne $minimumRevision -and [int]$device.OSUpdateBuildRevision -lt $minimumRevision) {
            New-ICTRuleResult 'SEC-001' 'OS build' Fail $actual -Message 'The latest cumulative update is missing (Intune compares the full OS version).' `
                -Remediation 'Install the latest cumulative update and restart the device.'
        }
        else { New-ICTRuleResult 'SEC-001' 'OS build' Pass $actual }
    }

    if ($Config.RequireBitLocker) {
        $bitLocker = $security.BitLocker
        if ($null -eq $bitLocker) { New-ICTRuleResult 'SEC-002' 'BitLocker' Unknown 'unavailable (needs admin)' }
        elseif ($bitLocker.ProtectionOn) { New-ICTRuleResult 'SEC-002' 'BitLocker' Pass $(if ($bitLocker.EncryptionMethod) { 'On ({0})' -f $bitLocker.EncryptionMethod } else { 'On' }) }
        else {
            New-ICTRuleResult 'SEC-002' 'BitLocker' Fail $(if ($bitLocker.VolumeStatus) { 'Off ({0})' -f $bitLocker.VolumeStatus } else { 'Off' }) `
                -Message "BitLocker protection is off on $($bitLocker.MountPoint)." -Remediation 'Check the Intune disk encryption policy and the BitLocker event log.'
        }
    }

    if ($Config.RequireTpm) {
        $tpm = $security.Tpm
        if ($null -eq $tpm) { New-ICTRuleResult 'SEC-003' 'TPM' Unknown 'unavailable (needs admin)' }
        elseif ($tpm.Present -and $tpm.Ready) { New-ICTRuleResult 'SEC-003' 'TPM' Pass 'present, ready' }
        else {
            New-ICTRuleResult 'SEC-003' 'TPM' Fail $(if (-not $tpm.Present) { 'not present' } else { 'present, not ready' }) `
                -Message 'The TPM is missing or not ready.' -Remediation 'Enable the TPM in the firmware settings and run tpm.msc to initialise it.'
        }
    }

    if ($Config.RequireSecureBoot) {
        $secureBoot = $security.SecureBoot
        if ($null -eq $secureBoot) { New-ICTRuleResult 'SEC-004' 'Secure Boot' Unknown 'unavailable (needs admin)' }
        elseif ($secureBoot.Enabled) { New-ICTRuleResult 'SEC-004' 'Secure Boot' Pass 'On' }
        else {
            New-ICTRuleResult 'SEC-004' 'Secure Boot' Fail $(if ($secureBoot.Supported) { 'Off' } else { 'not supported (legacy BIOS)' }) `
                -Message 'Secure Boot is not enabled.' -Remediation 'Switch the firmware to UEFI and enable Secure Boot.'
        }
    }

    $defender = $security.Defender
    if ($Config.RequireDefenderRealTimeProtection) {
        if ($null -eq $defender) { New-ICTRuleResult 'SEC-005' 'Defender real-time' Unknown 'unavailable' }
        elseif ($defender.AMRunningMode -match 'Passive') {
            New-ICTRuleResult 'SEC-005' 'Defender real-time' Warning 'passive mode' -Message 'Defender runs in passive mode, usually because another antivirus product is installed.' `
                -Remediation 'Check that the other antivirus product is reported to Windows Security Center.'
        }
        elseif ($defender.AMServiceEnabled -and $defender.RealTimeProtectionEnabled) { New-ICTRuleResult 'SEC-005' 'Defender real-time' Pass 'On' }
        else {
            New-ICTRuleResult 'SEC-005' 'Defender real-time' Fail 'Off' -Message 'Microsoft Defender real-time protection is off.' -Remediation 'Check the Intune antivirus policy and tamper protection.'
        }
    }

    if ($null -ne $Config.MaxDefenderSignatureAgeDays -and $null -ne $defender -and $defender.AMRunningMode -notmatch 'Passive') {
        $age = $defender.AntivirusSignatureAgeDays
        if ($null -eq $age) { New-ICTRuleResult 'SEC-006' 'Defender signatures' Unknown 'age unknown' }
        elseif ([int]$age -gt [int]$Config.MaxDefenderSignatureAgeDays) {
            New-ICTRuleResult 'SEC-006' 'Defender signatures' Fail ('{0} days old (limit {1})' -f $age, $Config.MaxDefenderSignatureAgeDays) `
                -Message 'Defender signatures are out of date.' -Remediation 'Run "Update-MpSignature" and check Windows Update / WSUS access.'
        }
        else { New-ICTRuleResult 'SEC-006' 'Defender signatures' Pass $(if ([int]$age -eq 0) { 'up to date' } else { '{0} days old' -f $age }) }
    }

    if ($Config.RequireFirewallAllProfiles) {
        $firewall = @($security.Firewall | Where-Object { $_ })
        if ($firewall.Count -eq 0) { New-ICTRuleResult 'SEC-007' 'Firewall' Unknown 'unavailable' }
        else {
            $off = @($firewall | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Profile })
            if ($off.Count -eq 0) { New-ICTRuleResult 'SEC-007' 'Firewall' Pass ((@($firewall | ForEach-Object { $_.Profile }) -join ', ') + ' on') }
            else {
                New-ICTRuleResult 'SEC-007' 'Firewall' Fail (($off -join ', ') + ' off') -Message 'Windows Firewall is off for at least one profile (effective policy).' -Remediation 'Check the Intune firewall policy.'
            }
        }
    }
}

function Get-ICTLapsRule {
    [CmdletBinding()]
    param([psobject]$DeviceData, [psobject]$Config, [datetime]$Now)

    if (-not $Config.RequireLaps) { return }
    $laps = $DeviceData.Laps
    $targetText = @{ EntraId = 'Entra ID'; ActiveDirectory = 'Active Directory'; Disabled = 'disabled'; Legacy = 'legacy LAPS'; Unknown = 'unknown target' }

    if ($null -eq $laps) { New-ICTRuleResult 'LAPS-001' 'LAPS policy' Unknown 'could not read the LAPS policy'; return }
    if (-not $laps.Configured) {
        New-ICTRuleResult 'LAPS-001' 'LAPS policy' Fail 'not configured' `
            -Message 'No Windows LAPS policy is applied, so the local admin password is not rotated or backed up.' `
            -Remediation 'Assign the Intune LAPS policy (Endpoint security > Account protection) to this device.'
        return
    }
    if ($laps.BackupTarget -eq 'Legacy') {
        New-ICTRuleResult 'LAPS-001' 'LAPS policy' Warning 'legacy Microsoft LAPS (AdmPwd)' `
            -Message 'Only the legacy Microsoft LAPS policy is set; Windows LAPS is not configured.' -Remediation 'Move the device to the Windows LAPS policy in Intune.'
        return
    }
    if ($laps.BackupTarget -eq 'Disabled') {
        New-ICTRuleResult 'LAPS-001' 'LAPS policy' Fail 'backup disabled' -Message 'A LAPS policy exists, but its backup directory is not set (disabled).' `
            -Remediation 'Set the backup directory to Entra ID in the Intune LAPS policy.'
        return
    }
    $policyText = 'backup to {0} ({1}{2})' -f $targetText[$laps.BackupTarget], $laps.PolicySource, $(if ($laps.AutomaticAccountManagement) { ', automatic account' } else { '' })
    if ($laps.BackupTarget -ne $Config.LapsExpectedBackupTarget) {
        New-ICTRuleResult 'LAPS-001' 'LAPS policy' Warning $policyText -Message ('LAPS backs up to {0}, expected {1}.' -f $targetText[$laps.BackupTarget], $targetText[$Config.LapsExpectedBackupTarget])
    }
    else { New-ICTRuleResult 'LAPS-001' 'LAPS policy' Pass $policyText }

    $account = $laps.Account
    $expected = $Config.LapsExpectedAccount
    $automatic = [bool]$laps.AutomaticAccountManagement   # LAPS owns the account: fixes go through the policy
    $policyFix = 'Adjust the automatic account management settings of the Intune LAPS policy.'
    if ($null -eq $account) { New-ICTRuleResult 'LAPS-002' 'Managed account' Unknown 'could not read the account' }
    elseif (-not $account.Exists) {
        New-ICTRuleResult 'LAPS-002' 'Managed account' Fail "$($account.Name) does not exist" -Message 'The account LAPS should manage does not exist on this device.' `
            -Remediation $(if ($automatic) { 'Wait for the next LAPS cycle, which creates it, or check the LAPS event log.' } else { 'Create the account, or enable automatic account management in the LAPS policy.' })
    }
    elseif ($account.Enabled -eq $false -and $automatic -and -not $laps.AutomaticAccountEnabled) {
        New-ICTRuleResult 'LAPS-002' 'Managed account' Pass "$($account.Name) (disabled by LAPS policy)"
    }
    elseif ($account.Enabled -eq $false) {
        New-ICTRuleResult 'LAPS-002' 'Managed account' Fail "$($account.Name) (disabled)" -Message 'The LAPS-managed account is disabled.' `
            -Remediation $(if ($automatic) { $policyFix } else { "Enable-LocalUser -Name $($account.Name)" })
    }
    elseif ($account.IsAdministrator -eq $false) {
        New-ICTRuleResult 'LAPS-002' 'Managed account' Fail "$($account.Name) (not an administrator)" -Message 'The LAPS-managed account is not in the local Administrators group.' `
            -Remediation $(if ($automatic) { $policyFix } else { "Add-LocalGroupMember -SID S-1-5-32-544 -Member $($account.Name)" })
    }
    elseif ($expected -and $account.Name -ne $expected -and $account.Name -notmatch ('^' + [regex]::Escape($expected) + '\d{6}$')) {
        New-ICTRuleResult 'LAPS-002' 'Managed account' Warning "$($account.Name) (expected $expected)" `
            -Message "LAPS manages '$($account.Name)', not '$expected'. The password of '$expected' is then not rotated by LAPS."
    }
    else {
        New-ICTRuleResult 'LAPS-002' 'Managed account' Pass ('{0} ({1})' -f $account.Name, $(if ($null -eq $account.IsAdministrator) { 'enabled' } else { 'enabled, administrator' }))
    }

    $lastUpdate = ConvertFrom-ICTDate $laps.LastPasswordUpdateTime
    if ($null -eq $lastUpdate) { New-ICTRuleResult 'LAPS-003' 'Last rotation' Unknown 'no rotation recorded' }
    else {
        $actual = '{0} (every {1} days)' -f (Format-ICTRelativeTime $lastUpdate -Now $Now), $laps.PasswordAgeDays
        if (($Now - $lastUpdate).TotalDays -gt ($laps.PasswordAgeDays + 1)) {
            New-ICTRuleResult 'LAPS-003' 'Last rotation' Fail $actual -Action LapsRetry -Message 'The LAPS password is older than the rotation interval.' `
                -Remediation 'Run Invoke-LapsPolicyProcessing (this tool: -Remediate) and check the LAPS event log.'
        }
        else { New-ICTRuleResult 'LAPS-003' 'Last rotation' Pass $actual }
    }

    $events = $laps.Events
    $backupName = 'Backup to {0}' -f $targetText[$laps.BackupTarget]
    if ($null -eq $events) { New-ICTRuleResult 'LAPS-004' $backupName Unknown 'LAPS event log unavailable' }
    elseif ($events.ErrorCount -eq 0) { New-ICTRuleResult 'LAPS-004' $backupName Pass ('no errors in {0} days' -f $events.LookbackDays) }
    else {
        $lastError = ConvertFrom-ICTDate $events.LastErrorTime
        $lastSuccess = ConvertFrom-ICTDate $events.LastSuccessTime
        if ($null -eq $lastSuccess -or ($lastError -and $lastError -gt $lastSuccess)) {
            New-ICTRuleResult 'LAPS-004' $backupName Fail ('last attempt failed {0} (event {1})' -f (Format-ICTRelativeTime $lastError -Now $Now), $events.LastErrorId) -Action LapsRetry `
                -Message ('LAPS logged an error: {0}' -f $events.LastErrorMessage) -Remediation 'Run Invoke-LapsPolicyProcessing (this tool: -Remediate) and check the LAPS event log.'
        }
        else {
            New-ICTRuleResult 'LAPS-004' $backupName Warning ('{0} error(s) in {1} days, last run OK' -f $events.ErrorCount, $events.LookbackDays) -Message ('Latest error: {0}' -f $events.LastErrorMessage)
        }
    }

    $postText = ConvertTo-ICTLapsPostActionText -Actions $laps.PostAuthenticationActions -DelayHours $laps.PostAuthenticationResetDelayHours
    $postMessage = $null
    if ($postText -notlike 'none*') { $postMessage = 'What LAPS does after someone signs in with the managed account password. SSH logons with that password may count too; SSH keys avoid it.' }
    New-ICTRuleResult 'LAPS-005' 'After sign-in' Info $postText -Message $postMessage
}
