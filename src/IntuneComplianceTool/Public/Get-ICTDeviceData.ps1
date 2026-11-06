function Get-ICTDeviceData {
    <#
    .SYNOPSIS
        Collects MDM, Intune, security, LAPS and network data from the local Windows device.
    .DESCRIPTION
        Read-only. Every section is collected independently: if one fails, the error is
        recorded in CollectionErrors and the rest still runs.
    .PARAMETER OnProgress
        Optional script block called after each section as: & $OnProgress <SectionName> <Succeeded>.
        Used by the terminal output to show live progress over SSH.
    #>
    [CmdletBinding()]
    param(
        [psobject]$Config,
        [scriptblock]$OnProgress
    )

    if (-not (Test-ICTIsWindows)) {
        throw 'Get-ICTDeviceData reads the local Windows device and must run on Windows.'
    }
    if (-not $Config) { $Config = Get-ICTConfig }

    $errorList = New-Object 'System.Collections.Generic.List[object]'
    $sectionStart = 0
    $completeSection = {
        param([string]$Name)
        Write-ICTLog "Collected section '$Name'"
        if ($OnProgress) { & $OnProgress $Name ($errorList.Count -eq $sectionStart) }
    }

    $isElevated = Test-ICTIsElevated
    Write-ICTLog "Collection started (elevated: $isElevated)"

    # Device and session
    $sectionStart = $errorList.Count
    $device = Invoke-ICTCollector -Section 'Device' -ErrorList $errorList -ScriptBlock { Get-ICTSystemInfo }
    $runAs = Invoke-ICTCollector -Section 'RunAs' -ErrorList $errorList -ScriptBlock { Get-ICTCurrentIdentity }
    $consoleUser = Invoke-ICTCollector -Section 'ConsoleUser' -ErrorList $errorList -ScriptBlock { Get-ICTConsoleUser }
    & $completeSection 'Device'

    # Entra ID join
    $sectionStart = $errorList.Count
    $join = Invoke-ICTCollector -Section 'Join' -ErrorList $errorList -ScriptBlock { ConvertFrom-ICTDsregOutput -Line (Get-ICTDsregOutput) }
    & $completeSection 'Join'

    # MDM enrollment, certificate and sync state
    $sectionStart = $errorList.Count
    $enrollments = @(Invoke-ICTCollector -Section 'Enrollments' -ErrorList $errorList -ScriptBlock { Get-ICTEnrollmentRegistry })
    $intuneEnrollments = @($enrollments | Where-Object { $_.IsIntune })
    $certificates = @(Invoke-ICTCollector -Section 'MdmCertificate' -ErrorList $errorList -ScriptBlock { Get-ICTMdmCertificate })
    $tasks = @(Invoke-ICTCollector -Section 'SyncTasks' -ErrorList $errorList -ScriptBlock { Get-ICTEnterpriseMgmtTask })

    $sync = @(foreach ($enrollment in $intuneEnrollments) {
            $enrollmentId = $enrollment.EnrollmentId
            $connection = Invoke-ICTCollector -Section "SyncState:$enrollmentId" -ErrorList $errorList -ScriptBlock { Get-ICTOmadmConnectionInfo -EnrollmentId $enrollmentId }
            $enrollmentTasks = @($tasks | Where-Object { $_.EnrollmentId -eq $enrollmentId })
            $lastRun = $enrollmentTasks | Where-Object { $_.LastRunTime } | Sort-Object LastRunTime -Descending | Select-Object -First 1
            [pscustomobject]@{
                EnrollmentId          = $enrollmentId
                TaskCount             = $enrollmentTasks.Count
                LastTaskRunTime       = $(if ($lastRun) { $lastRun.LastRunTime } else { $null })
                LastTaskResult        = $(if ($lastRun) { $lastRun.LastTaskResult } else { $null })
                ServerLastSuccessTime = $(if ($connection) { $connection.ServerLastSuccessTime } else { $null })
                ServerLastAccessTime  = $(if ($connection) { $connection.ServerLastAccessTime } else { $null })
            }
        })
    $knownIds = @($enrollments | ForEach-Object { $_.EnrollmentId })
    $orphanTaskIds = @($tasks | Where-Object { $_.EnrollmentId -and ($knownIds -notcontains $_.EnrollmentId) } |
            ForEach-Object { $_.EnrollmentId } | Sort-Object -Unique)
    & $completeSection 'Enrollment'

    # Services
    $sectionStart = $errorList.Count
    $serviceNames = @(@($Config.RequiredServices) + @($Config.RecommendedServices) | Where-Object { $_ })
    $services = @(Invoke-ICTCollector -Section 'Services' -ErrorList $errorList -ScriptBlock { Get-ICTServiceState -Name $serviceNames })
    & $completeSection 'Services'

    # Security baseline
    $sectionStart = $errorList.Count
    $security = [pscustomobject]@{
        BitLocker  = Invoke-ICTCollector -Section 'BitLocker' -ErrorList $errorList -ScriptBlock { Get-ICTBitLockerState }
        Tpm        = Invoke-ICTCollector -Section 'Tpm' -ErrorList $errorList -ScriptBlock { Get-ICTTpmState }
        SecureBoot = Invoke-ICTCollector -Section 'SecureBoot' -ErrorList $errorList -ScriptBlock { Get-ICTSecureBootState }
        Defender   = Invoke-ICTCollector -Section 'Defender' -ErrorList $errorList -ScriptBlock { Get-ICTDefenderState }
        Firewall   = @(Invoke-ICTCollector -Section 'Firewall' -ErrorList $errorList -ScriptBlock { Get-ICTFirewallState })
    }
    & $completeSection 'Security'

    # LAPS
    $sectionStart = $errorList.Count
    $lapsPolicy = Invoke-ICTCollector -Section 'LapsPolicy' -ErrorList $errorList -ScriptBlock { Get-ICTLapsPolicy }
    $lapsAccount = $null
    $lapsLastUpdate = $null
    $lapsEvents = $null
    if ($lapsPolicy) {
        $lapsAccount = Invoke-ICTCollector -Section 'LapsAccount' -ErrorList $errorList -ScriptBlock { Get-ICTLocalAccount -Name $lapsPolicy.AdministratorAccountName }
        $lapsLastUpdate = Invoke-ICTCollector -Section 'LapsState' -ErrorList $errorList -ScriptBlock { Get-ICTLapsLastPasswordUpdate }
        # The leading comma keeps an empty result as an empty array; $null means "could not read".
        $lapsEvents = Invoke-ICTCollector -Section 'LapsEvents' -ErrorList $errorList -ScriptBlock { , @(Get-ICTLapsEvent -Days $Config.LapsEventLookbackDays) }
    }
    $laps = New-ICTLapsState -Policy $lapsPolicy -Account $lapsAccount -LastPasswordUpdate $lapsLastUpdate -Events $lapsEvents `
        -SuccessEventIds $Config.LapsSuccessEventIds -LookbackDays $Config.LapsEventLookbackDays
    & $completeSection 'LAPS'

    # Network
    $sectionStart = $errorList.Count
    $proxy = Invoke-ICTCollector -Section 'WinHttpProxy' -ErrorList $errorList -ScriptBlock { Get-ICTWinHttpProxy }
    $hosts = New-Object 'System.Collections.Generic.List[string]'
    $candidates = @($Config.Endpoints)
    if ($join -and $join.MdmUrl) { $candidates += Get-ICTUriHost $join.MdmUrl }
    foreach ($enrollment in $intuneEnrollments) { $candidates += Get-ICTUriHost $enrollment.DiscoveryServiceFullUrl }
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $hostName = $candidate.Trim().ToLowerInvariant()
        if (-not $hosts.Contains($hostName)) { $hosts.Add($hostName) }
    }
    $endpoints = @(foreach ($hostName in $hosts) {
            Invoke-ICTCollector -Section "Endpoint:$hostName" -ErrorList $errorList -ScriptBlock {
                Test-ICTTcpEndpoint -HostName $hostName -Port $Config.EndpointPort -TimeoutMs $Config.EndpointTimeoutMs
            }
        })
    & $completeSection 'Network'

    # MDM event log
    $sectionStart = $errorList.Count
    $mdmEvents = Invoke-ICTCollector -Section 'MdmEvents' -ErrorList $errorList -ScriptBlock {
        $list = @(Get-ICTMdmEvent -Days $Config.MdmEventLookbackDays)
        [pscustomobject]@{
            LookbackDays = $Config.MdmEventLookbackDays
            ErrorCount   = $list.Count
            Recent       = @($list | Sort-Object TimeCreated -Descending | Select-Object -First 10)
        }
    }
    & $completeSection 'Event log'

    Write-ICTLog "Collection finished with $($errorList.Count) error(s)"

    return [pscustomobject]@{
        SchemaVersion    = 1
        ToolVersion      = $script:ICTVersion
        CollectedAt      = ConvertTo-ICTIsoDate ([datetime]::UtcNow)
        ComputerName     = [System.Environment]::MachineName
        RunAs            = $runAs
        IsElevated       = $isElevated
        ConsoleUser      = $consoleUser
        Device           = $device
        Join             = $join
        Enrollments      = $enrollments
        OrphanTaskIds    = $orphanTaskIds
        MdmCertificates  = $certificates
        Sync             = $sync
        Services         = $services
        Security         = $security
        Laps             = $laps
        Network          = [pscustomobject]@{ WinHttpProxy = $proxy; Endpoints = $endpoints }
        MdmEvents        = $mdmEvents
        CollectionErrors = $errorList.ToArray()
    }
}
