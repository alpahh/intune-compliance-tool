function Get-ICTDeviceData {
    <#
    .SYNOPSIS
        Collects MDM, Intune, security, LAPS and network data from the local Windows device.
    .DESCRIPTION
        Read-only. Each part is collected independently: a failure is recorded in
        CollectionErrors and the rest still runs. A part that could not be read is
        $null, which the rules report as Unknown (never as "missing").
    .PARAMETER Section
        Collect only these sections; with -Previous, the other sections are copied from
        that earlier result (used for the quick re-check after a repair).
    .PARAMETER OnProgress
        Called after each section as: & $OnProgress <SectionName> <Succeeded>.
    #>
    [CmdletBinding()]
    param(
        [psobject]$Config,
        [scriptblock]$OnProgress,
        [ValidateSet('Device', 'Join', 'Enrollment', 'Services', 'Security', 'LAPS', 'Network', 'Event log')][string[]]$Section,
        [psobject]$Previous
    )

    if (-not (Test-ICTIsWindows)) { throw 'Get-ICTDeviceData reads the local Windows device and must run on Windows.' }
    if (-not $Config) { $Config = Get-ICTConfig }
    $allSections = @('Device', 'Join', 'Enrollment', 'Services', 'Security', 'LAPS', 'Network', 'Event log')
    if (-not $Section) { $Section = $allSections }
    $sectionProperties = @{
        'Device' = @('RunAs', 'ConsoleUser', 'Device', 'PendingReboot'); 'Join' = @('Join')
        'Enrollment' = @('AutoEnroll', 'Enrollments', 'MdmCertificates', 'Sync'); 'Services' = @('Services')
        'Security' = @('Security'); 'LAPS' = @('Laps'); 'Network' = @('Network'); 'Event log' = @('MdmEvents')
    }

    $data = [ordered]@{
        SchemaVersion = 2; ToolVersion = $script:ICTVersion; CollectedAt = ConvertTo-ICTIsoDate ([datetime]::UtcNow)
        ComputerName = [System.Environment]::MachineName; IsElevated = (Test-ICTIsElevated)
    }
    $errorList = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in $allSections) {
        foreach ($property in $sectionProperties[$name]) {
            $data[$property] = $(if ($Previous -and $Section -notcontains $name) { $Previous.$property } else { $null })
        }
    }
    if ($Previous) {
        foreach ($item in @($Previous.CollectionErrors)) { if ($item -and $Section -notcontains $item.Group) { $errorList.Add($item) } }
    }

    $group = $null
    $collect = {
        param([string]$Name, [scriptblock]$ScriptBlock)
        Invoke-ICTCollector -Group $group -Section $Name -ErrorList $errorList -ScriptBlock $ScriptBlock
    }

    foreach ($group in $allSections) {
        if ($Section -notcontains $group) { continue }
        $errorsBefore = $errorList.Count

        switch ($group) {
            'Device' {
                $data.Device = & $collect 'SystemInfo' { Get-ICTSystemInfo }
                $data.ConsoleUser = $data.Device.ConsoleUser
                $data.RunAs = & $collect 'RunAs' { Get-ICTCurrentIdentity }
                $data.PendingReboot = & $collect 'PendingReboot' { Get-ICTPendingReboot }
            }
            'Join' {
                $data.Join = & $collect 'Dsregcmd' { ConvertFrom-ICTDsregOutput -Line (Get-ICTDsregOutput) }
            }
            'Enrollment' {
                # ", @(...)" keeps "none found" (empty array) apart from "could not read" ($null).
                $data.Enrollments = & $collect 'Enrollments' { , @(Get-ICTEnrollmentRegistry) }
                $data.AutoEnroll = & $collect 'AutoEnroll' { Get-ICTAutoEnrollState }
                $data.MdmCertificates = & $collect 'MdmCertificate' { , @(Get-ICTMdmCertificate) }
                $tasks = & $collect 'SyncTasks' { , @(Get-ICTEnterpriseMgmtTask) }
                $data.Sync = @(foreach ($enrollment in @($data.Enrollments | Where-Object { $_ -and $_.IsIntune })) {
                        $id = $enrollment.EnrollmentId
                        $connection = & $collect "SyncState:$id" { Get-ICTOmadmConnectionInfo -EnrollmentId $id }
                        $own = @($tasks | Where-Object { $_ -and $_.EnrollmentId -eq $id })
                        # PushLaunch only starts a session (and the tool's own sync starts it), so it proves nothing.
                        $lastRun = $own | Where-Object { $_.LastRunTime -and $_.TaskName -ne 'PushLaunch' } | Sort-Object LastRunTime -Descending | Select-Object -First 1
                        [pscustomobject]@{
                            EnrollmentId          = $id
                            TaskCount             = $(if ($null -ne $tasks) { $own.Count } else { $null })
                            LastTaskRunTime       = $lastRun.LastRunTime
                            LastTaskResult        = $lastRun.LastTaskResult
                            ServerLastSuccessTime = $connection.ServerLastSuccessTime
                        }
                    })
            }
            'Services' {
                $names = @(@($Config.RequiredServices) + @($Config.RecommendedServices) | Where-Object { $_ })
                $data.Services = & $collect 'Services' { , @(Get-ICTServiceState -Name $names) }
            }
            'Security' {
                $data.Security = [pscustomobject]@{
                    BitLocker  = & $collect 'BitLocker' { Get-ICTBitLockerState }
                    Tpm        = & $collect 'Tpm' { Get-ICTTpmState }
                    SecureBoot = & $collect 'SecureBoot' { Get-ICTSecureBootState }
                    Defender   = & $collect 'Defender' { Get-ICTDefenderState }
                    Firewall   = & $collect 'Firewall' { , @(Get-ICTFirewallState) }
                }
            }
            'LAPS' {
                $policyErrors = $errorList.Count
                $policy = & $collect 'LapsPolicy' { Get-ICTLapsPolicy }
                if ($errorList.Count -gt $policyErrors) { $data.Laps = $null; break }   # unreadable, not "not configured"
                $account = $null; $lastUpdate = $null; $events = $null
                if ($policy -and $policy.Source -ne 'Legacy') {
                    $spec = Get-ICTLapsAccountSpec -Policy $policy
                    $account = & $collect 'LapsAccount' { Get-ICTLocalAccount -Name $spec.Name -NamePrefix $spec.NamePrefix }
                    $lastUpdate = & $collect 'LapsState' { Get-ICTLapsLastPasswordUpdate }
                    $xpath = New-ICTEventXPath -Level 1, 2 -EventId $Config.LapsSuccessEventIds -Days $Config.LapsEventLookbackDays
                    $events = & $collect 'LapsEvents' { , @(Get-ICTWinEvent -LogName $script:ICTLapsLogName -XPath $xpath -MaxEvents 1000) }
                }
                $data.Laps = New-ICTLapsState -Policy $policy -Account $account -LastPasswordUpdate $lastUpdate -Events $events `
                    -SuccessEventIds $Config.LapsSuccessEventIds -LookbackDays $Config.LapsEventLookbackDays
            }
            'Network' {
                $proxy = & $collect 'WinHttpProxy' { Get-ICTWinHttpProxy }
                $hosts = New-Object 'System.Collections.Generic.List[string]'
                $candidates = @($Config.Endpoints) + @(Get-ICTUriHost $data.Join.MdmUrl) +
                    @($data.Enrollments | Where-Object { $_ -and $_.IsIntune } | ForEach-Object { Get-ICTUriHost $_.DiscoveryServiceFullUrl })
                foreach ($candidate in $candidates) {
                    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
                    $hostName = $candidate.Trim().ToLowerInvariant()
                    if (-not $hosts.Contains($hostName)) { $hosts.Add($hostName) }
                }
                $endpoints = & $collect 'Endpoints' { , @(Test-ICTTcpEndpoint -HostName $hosts.ToArray() -Port $Config.EndpointPort -TimeoutMs $Config.EndpointTimeoutMs) }

                # Clock skew is a measurement, not a collection: offline devices simply have none.
                $offset = $null; $clockError = $null
                try { $offset = Get-ICTClockOffset -Uri $Config.ClockReferenceUri -Proxy (Get-ICTHttpProxyAddress $proxy) -TimeoutMs $Config.EndpointTimeoutMs }
                catch { $clockError = $_.Exception.GetBaseException().Message }
                $data.Network = [pscustomobject]@{ WinHttpProxy = $proxy; Endpoints = $endpoints; ClockOffsetSeconds = $offset; ClockError = $clockError }
            }
            'Event log' {
                $xpath = New-ICTEventXPath -Level 1, 2 -Days $Config.MdmEventLookbackDays
                $data.MdmEvents = & $collect 'MdmEvents' {
                    $list = @(Get-ICTWinEvent -LogName $script:ICTMdmLogName -XPath $xpath -MaxEvents 100)
                    [pscustomobject]@{ LookbackDays = $Config.MdmEventLookbackDays; ErrorCount = $list.Count; Truncated = ($list.Count -ge 100); Recent = @($list | Select-Object -First 10) }
                }
            }
        }

        Write-ICTLog "Collected section '$group'"
        if ($OnProgress) { & $OnProgress $group ($errorList.Count -eq $errorsBefore) }
    }

    $data.CollectionErrors = $errorList.ToArray()
    return [pscustomobject]$data
}
