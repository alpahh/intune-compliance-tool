function Test-ICTCompliance {
    <#
    .SYNOPSIS
        Evaluates collected device data against the compliance and enrollment-health rules.
    .DESCRIPTION
        Pure evaluation of the object from Get-ICTDeviceData.

        OverallStatus
          EnrollmentBroken  an enrollment check failed (the device does not reach Intune properly)
          NonCompliant      another check failed (e.g. BitLocker off); re-enrolling would not fix it
          Indeterminate     nothing failed, but some data could not be read
          Compliant         no failures and no unknowns (warnings and info are allowed)

        RecommendedActions, in the order -Remediate runs them:
          TimeSync, ServiceFix, Sync or ReEnroll, LapsRetry
        ReEnrollBlockers / SyncBlockers: findings that make that repair pointless.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][psobject]$DeviceData,
        [psobject]$Config,
        [datetime]$Now = [datetime]::UtcNow
    )

    process {
        if (-not $Config) { $Config = Get-ICTConfig }
        $utcNow = $Now.ToUniversalTime()

        $results = @(
            Get-ICTJoinRule -DeviceData $DeviceData -Now $utcNow
            Get-ICTEnrollmentRule -DeviceData $DeviceData -Config $Config -Now $utcNow
            Get-ICTHealthRule -DeviceData $DeviceData -Config $Config -Now $utcNow
            Get-ICTNetworkRule -DeviceData $DeviceData -Config $Config
            Get-ICTSecurityRule -DeviceData $DeviceData -Config $Config
            Get-ICTLapsRule -DeviceData $DeviceData -Config $Config -Now $utcNow
        )

        $wanted = @($results | Where-Object { $_.Action } | ForEach-Object { $_.Action } | Sort-Object -Unique)
        if ($wanted -contains 'ReEnroll') { $wanted = @($wanted | Where-Object { $_ -ne 'Sync' }) }
        $actions = @('TimeSync', 'ServiceFix', 'ReEnroll', 'Sync', 'LapsRetry' | Where-Object { $wanted -contains $_ })

        $describe = { '{0}: {1}' -f $_.Name, $_.Actual }
        $syncBlockers = @($results | Where-Object { $_.Blocks -eq 'All' } | ForEach-Object $describe)
        $reEnrollBlockers = @($results | Where-Object { $_.Blocks } | ForEach-Object $describe)
        if ($DeviceData.IsElevated -eq $false) {
            $syncBlockers += 'Session: not running as administrator'
            $reEnrollBlockers += 'Session: not running as administrator'
        }

        $enrollmentAction = @($actions | Where-Object { $_ -eq 'ReEnroll' -or $_ -eq 'Sync' }) | Select-Object -First 1
        $blockers = $(if ($enrollmentAction -eq 'Sync') { $syncBlockers } else { $reEnrollBlockers })

        $status = 'Compliant'
        if ($enrollmentAction) { $status = 'EnrollmentBroken' }
        elseif (@($results | Where-Object { $_.Status -eq 'Fail' }).Count -gt 0) { $status = 'NonCompliant' }
        elseif (@($results | Where-Object { $_.Status -eq 'Unknown' }).Count -gt 0) { $status = 'Indeterminate' }

        $summary = [ordered]@{}
        foreach ($name in 'Pass', 'Fail', 'Warning', 'Unknown', 'Info') { $summary[$name] = @($results | Where-Object { $_.Status -eq $name }).Count }

        [pscustomobject]@{
            EvaluatedAt         = ConvertTo-ICTIsoDate $utcNow
            OverallStatus       = $status
            RecommendedActions  = $actions
            CanRepairEnrollment = ([bool]$enrollmentAction -and @($blockers).Count -eq 0)
            Blockers            = @($(if ($enrollmentAction) { $blockers }))
            ReEnrollBlockers    = $reEnrollBlockers
            SyncBlockers        = $syncBlockers
            Summary             = [pscustomobject]$summary
            Results             = $results
        }
    }
}
