function Test-ICTCompliance {
    <#
    .SYNOPSIS
        Evaluates collected device data against the compliance and enrollment-health rules.
    .DESCRIPTION
        Pure evaluation: it reads the object from Get-ICTDeviceData and changes nothing.

        OverallStatus
          EnrollmentBroken  an enrollment check failed (the device does not reach Intune properly)
          NonCompliant      another check failed (e.g. BitLocker off); re-enrolling would not fix it
          Indeterminate     nothing failed, but some data could not be read
          Compliant         no failures and no unknowns (warnings and info are allowed)

        RecommendedActions: any of Sync, ReEnroll (exclusive with Sync), LapsRetry.
        Blockers: findings that make an automatic enrollment repair pointless.
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
            Get-ICTJoinRule -DeviceData $DeviceData
            Get-ICTEnrollmentRule -DeviceData $DeviceData -Config $Config -Now $utcNow
            Get-ICTHealthRule -DeviceData $DeviceData -Config $Config -Now $utcNow
            Get-ICTNetworkRule -DeviceData $DeviceData
            Get-ICTSecurityRule -DeviceData $DeviceData -Config $Config
            Get-ICTLapsRule -DeviceData $DeviceData -Config $Config -Now $utcNow
        ) | Where-Object { $_ }
        $results = @($results)

        $failed = @($results | Where-Object { $_.Status -eq 'Fail' })
        $actions = New-Object 'System.Collections.Generic.List[string]'
        if ($failed | Where-Object { $_.Action -eq 'ReEnroll' }) { $actions.Add('ReEnroll') }
        elseif ($failed | Where-Object { $_.Action -eq 'Sync' }) { $actions.Add('Sync') }
        if ($failed | Where-Object { $_.Action -eq 'LapsRetry' }) { $actions.Add('LapsRetry') }

        $enrollmentBroken = ($actions.Contains('ReEnroll') -or $actions.Contains('Sync'))
        $blockers = @($results | Where-Object { $_.BlocksRemediation -and ($_.Status -eq 'Fail' -or $_.Status -eq 'Warning') } |
                ForEach-Object { '{0}: {1}' -f $_.Name, $_.Actual })
        if ($DeviceData.IsElevated -eq $false) { $blockers += 'Session: not running as administrator' }

        $status = 'Compliant'
        if ($enrollmentBroken) { $status = 'EnrollmentBroken' }
        elseif ($failed.Count -gt 0) { $status = 'NonCompliant' }
        elseif ($results | Where-Object { $_.Status -eq 'Unknown' }) { $status = 'Indeterminate' }

        $summary = [ordered]@{}
        foreach ($name in 'Pass', 'Fail', 'Warning', 'Unknown', 'Info') {
            $summary[$name] = @($results | Where-Object { $_.Status -eq $name }).Count
        }

        [pscustomobject]@{
            EvaluatedAt              = ConvertTo-ICTIsoDate $utcNow
            OverallStatus            = $status
            RecommendedActions       = $actions.ToArray()
            CanRepairEnrollment      = ($enrollmentBroken -and $blockers.Count -eq 0)
            Blockers                 = $blockers
            Summary                  = [pscustomobject]$summary
            Results                  = $results
        }
    }
}
