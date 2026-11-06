function Format-ICTReport {
    <#
    .SYNOPSIS
        Renders a report (from New-ICTReport) as terminal lines: status badge, device
        summary, grouped checks, repair steps and next steps.
    .DESCRIPTION
        Returns strings; the caller writes them (Write-Host). Colours are ANSI escape
        codes, which work over SSH and in Windows 10/11 consoles. Use -NoColor and
        -Ascii for terminals that cannot show them.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][psobject]$Report,
        [switch]$NoColor,
        [switch]$Ascii,
        [switch]$Detailed,
        [ValidateRange(60, 200)][int]$Width = 78,
        [datetime]$Now = [datetime]::UtcNow,
        [string]$CommandHint = '.\IntuneComplianceTool.ps1',
        [string[]]$SavedFile = @()
    )

    $theme = New-ICTTheme -NoColor:$NoColor -Ascii:$Ascii
    $s = $theme.Symbols
    $utcNow = $Now.ToUniversalTime()
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $color = { param([string]$Text, [string]$Name) Format-ICTColor -Text $Text -Color $Name -Theme $theme }

    $data = $Report.DeviceData
    $evaluation = $Report.Evaluation
    if ($Report.PostRemediationEvaluation) {
        # After a repair, show the device as it is now.
        $data = $Report.PostRemediationDeviceData
        $evaluation = $Report.PostRemediationEvaluation
    }

    #region Status badge
    $statusInfo = @{
        Compliant        = @{ Text = 'COMPLIANT'; Color = 'GreenBold' }
        NonCompliant     = @{ Text = 'NOT COMPLIANT'; Color = 'RedBold' }
        EnrollmentBroken = @{ Text = 'ENROLLMENT BROKEN'; Color = 'RedBold' }
        Indeterminate    = @{ Text = 'INDETERMINATE'; Color = 'YellowBold' }
    }
    $badge = $statusInfo[$evaluation.OverallStatus]
    $badgeInner = 24
    $padLeft = [int][math]::Floor(($badgeInner - $badge.Text.Length) / 2)
    $badgeText = (' ' * $padLeft) + $badge.Text + (' ' * ($badgeInner - $badge.Text.Length - $padLeft))

    $actionNames = @{ ReEnroll = 'RE-ENROLL'; Sync = 'SYNC'; LapsRetry = 'LAPS RETRY' }
    $actions = @($evaluation.RecommendedActions | ForEach-Object { $actionNames[$_] })
    $sideWidth = $Width - $badgeInner - 7
    $recommended = 'Recommended: ' + $(if ($actions.Count -gt 0) { $actions -join ' + ' } else { 'nothing' })
    $repairText = ''
    if ($evaluation.OverallStatus -eq 'EnrollmentBroken') {
        $repairText = 'Repair possible: ' + $(if ($evaluation.CanRepairEnrollment) { 'yes' } else { 'no (see next steps)' })
    }

    $lines.Add('')
    $lines.Add('  ' + (& $color ($s.HTL + ($s.HH * $badgeInner) + $s.HTR) $badge.Color))
    $lines.Add('  ' + (& $color ($s.HV + $badgeText + $s.HV) $badge.Color) + '   ' + (Limit-ICTText -Text $recommended -Width $sideWidth -Theme $theme))
    $bottom = '  ' + (& $color ($s.HBL + ($s.HH * $badgeInner) + $s.HBR) $badge.Color)
    if ($repairText) { $bottom += '   ' + (& $color (Limit-ICTText -Text $repairText -Width $sideWidth -Theme $theme) 'Gray') }
    $lines.Add($bottom)
    #endregion

    #region Device summary
    $device = $data.Device
    $join = $data.Join
    $intune = @($data.Enrollments | Where-Object { $_ -and $_.IsIntune }) | Select-Object -First 1
    $certificate = @($data.MdmCertificates | Where-Object { $_ } | Sort-Object NotAfter -Descending) | Select-Object -First 1
    $checkIn = $evaluation.Results | Where-Object { $_.Id -eq 'ENR-004' } | Select-Object -First 1

    $model = ''
    $os = ''
    $lastBoot = ''
    $serial = ''
    if ($device) {
        $manufacturer = ("$($device.Manufacturer)" -replace '(?i)[\s,]*(Inc\.?|Corporation|Corp\.?|Ltd\.?|GmbH)$', '').Trim()
        $model = ('{0} {1}' -f $manufacturer, $device.Model).Trim()
        $os = ('{0} {1}' -f ("$($device.OSCaption)" -replace '^Microsoft\s+', ''), $device.OSDisplayVersion).Trim()
        $lastBoot = Format-ICTRelativeTime $device.LastBootTime -Now $utcNow
        $serial = $device.SerialNumber
    }
    $joinText = ''
    if ($join) {
        $joinText = @{ EntraJoined = 'Entra joined'; HybridJoined = 'Hybrid joined'; DomainJoinedOnly = 'Domain only'; WorkplaceJoined = 'Workplace only'; NotJoined = 'Not joined' }[$join.JoinType]
        if ($join.TenantName) { $joinText = '{0} {1} {2}' -f $joinText, $s.Dot, $join.TenantName }
    }
    $sshUser = "$($data.RunAs)"
    if ($data.IsElevated -eq $true) { $sshUser += ' (admin)' } elseif ($data.IsElevated -eq $false) { $sshUser += ' (NOT admin)' }

    $rows = @(
        , @('Model', $model, 'Serial', $serial)
        , @('OS', $os, 'Last boot', $lastBoot)
        , @('Join', $joinText, 'Intune ID', $(if ($certificate) { Get-ICTShortId $certificate.IntuneDeviceId } else { '-' }))
        , @('Signed in', $(if ($data.ConsoleUser) { $data.ConsoleUser } else { 'nobody' }), 'Last sync', $(if ($checkIn) { ($checkIn.Actual -replace '\s*\(.*$', '') } else { '-' }))
        , @('SSH user', $sshUser, 'Enrolled', $(if ($intune -and $intune.Upn) { $intune.Upn } else { '-' }))
    )

    $labelWidth = 11
    $valueWidth = [math]::Max(20, [int][math]::Floor(($Width - 4 - 2 * $labelWidth) * 0.55))
    $rightValueWidth = $Width - 4 - (2 * $labelWidth) - $valueWidth - 1
    $lines.Add('')
    $lines.Add('  ' + (& $color 'DEVICE' 'Bold'))
    foreach ($row in $rows) {
        $leftValue = Limit-ICTText -Text $row[1] -Width $valueWidth -Theme $theme
        $rightValue = Limit-ICTText -Text $row[3] -Width $rightValueWidth -Theme $theme
        $lines.Add('    ' + (& $color $row[0].PadRight($labelWidth) 'Gray') + $leftValue.PadRight($valueWidth) + ' ' +
            (& $color $row[2].PadRight($labelWidth) 'Gray') + $rightValue)
    }
    #endregion

    #region Checks
    $summary = $evaluation.Summary
    $counts = '{0} {1}   {2} {3}   {4} {5}   {6} {7}' -f $s.Pass.Trim(), $summary.Pass, $s.Fail.Trim(), $summary.Fail, $s.Warning.Trim(), $summary.Warning, $s.Unknown.Trim(), $summary.Unknown
    $countsColored = '{0} {1}   {2} {3}   {4} {5}   {6} {7}' -f (& $color $s.Pass.Trim() 'Green'), $summary.Pass, (& $color $s.Fail.Trim() 'Red'), $summary.Fail,
        (& $color $s.Warning.Trim() 'Yellow'), $summary.Warning, (& $color $s.Unknown.Trim() 'Gray'), $summary.Unknown
    $lines.Add('')
    $lines.Add('  ' + (& $color 'CHECKS' 'Bold') + (' ' * [math]::Max(2, $Width - 2 - 6 - $counts.Length)) + $countsColored)

    $symbolWidth = $s.Pass.Length
    $defaultNameWidth = 27
    $nameWidth = $defaultNameWidth
    $actualWidth = $Width - 4 - $symbolWidth - 2 - $nameWidth
    $detailIndent = 4 + $symbolWidth + 2

    foreach ($category in 'Join', 'Enrollment', 'Health', 'Network', 'Security', 'LAPS') {
        $categoryResults = @($evaluation.Results | Where-Object { $_.Category -eq $category })
        if ($categoryResults.Count -eq 0) { continue }
        $lines.Add((Format-ICTSectionRule -Title $category -Width $Width -Theme $theme))

        # Widen the name column for long names (endpoint host names), keeping room for the value.
        $longest = ($categoryResults | ForEach-Object { "$($_.Name)".Length } | Measure-Object -Maximum).Maximum
        $nameWidth = [math]::Min([math]::Max($defaultNameWidth, $longest + 2), $Width - 4 - $symbolWidth - 2 - 16)
        $actualWidth = $Width - 4 - $symbolWidth - 2 - $nameWidth

        foreach ($result in $categoryResults) {
            $statusColor = $theme.StatusColor[$result.Status]
            $symbol = & $color $s[$result.Status] $statusColor
            $name = Limit-ICTText -Text $result.Name -Width ($nameWidth - 1) -Theme $theme
            $actual = Limit-ICTText -Text $result.Actual -Width $actualWidth -Theme $theme
            if ($result.Status -eq 'Fail' -or $result.Status -eq 'Warning') { $actual = & $color $actual $statusColor }
            elseif ($result.Status -eq 'Unknown') { $actual = & $color $actual 'Gray' }
            $lines.Add('    ' + $symbol + '  ' + $name.PadRight($nameWidth) + $actual)

            if ($Detailed -and $result.Status -ne 'Pass') {
                foreach ($text in (Split-ICTText -Text $result.Message -Width ($Width - $detailIndent))) {
                    $lines.Add((' ' * $detailIndent) + (& $color $text 'Gray'))
                }
                $fixLines = @(Split-ICTText -Text $result.Remediation -Width ($Width - $detailIndent - 5))
                for ($i = 0; $i -lt $fixLines.Count; $i++) {
                    $prefix = $(if ($i -eq 0) { 'Fix: ' } else { '     ' })
                    $lines.Add((' ' * $detailIndent) + (& $color ($prefix + $fixLines[$i]) 'Gray'))
                }
            }
        }
    }
    #endregion

    #region Detailed event list
    if ($Detailed -and $data.MdmEvents -and @($data.MdmEvents.Recent).Count -gt 0) {
        $lines.Add('')
        $lines.Add('  ' + (& $color ('RECENT MDM ERRORS (last {0} days)' -f $data.MdmEvents.LookbackDays) 'Bold'))
        foreach ($event in @($data.MdmEvents.Recent)) {
            $when = (Format-ICTRelativeTime $event.TimeCreated -Now $utcNow).PadRight(12)
            $text = Limit-ICTText -Text ('{0}  {1}' -f $event.Id, $event.Message) -Width ($Width - 4 - 12) -Theme $theme
            $lines.Add('    ' + (& $color $when 'Gray') + $text)
        }
    }
    #endregion

    #region Collection errors
    $collectionErrors = @($data.CollectionErrors | Where-Object { $_ })
    if ($collectionErrors.Count -gt 0) {
        $lines.Add('')
        $lines.Add('  ' + (& $color 'COULD NOT READ' 'Bold'))
        foreach ($item in $collectionErrors) {
            $text = Limit-ICTText -Text ('{0}: {1}' -f $item.Section, $item.Error) -Width ($Width - 4 - $symbolWidth - 2) -Theme $theme
            $lines.Add('    ' + (& $color $s.Warning 'Yellow') + '  ' + $text)
        }
    }
    #endregion

    #region Repair
    $nameWidth = $defaultNameWidth
    $actualWidth = $Width - 4 - $symbolWidth - 2 - $nameWidth
    $remediation = $Report.Remediation
    if ($remediation -and @($remediation.Steps).Count -gt 0) {
        $title = $(if ($remediation.WhatIf) { 'REPAIR PREVIEW (-WhatIf, nothing was changed)' } else { 'REPAIR' })
        $lines.Add('')
        $lines.Add('  ' + (& $color $title 'Bold'))
        foreach ($step in @($remediation.Steps)) {
            $stepStatus = $(if ($theme.StatusColor.ContainsKey($step.Status)) { $step.Status } else { 'Info' })
            $symbol = & $color $s[$stepStatus] $theme.StatusColor[$stepStatus]
            $name = Limit-ICTText -Text $step.Name -Width ($nameWidth - 1) -Theme $theme
            $detail = Limit-ICTText -Text $step.Detail -Width $actualWidth -Theme $theme
            $lines.Add('    ' + $symbol + '  ' + $name.PadRight($nameWidth) + $detail)
        }
        if ($Report.PostRemediationEvaluation) {
            $before = $statusInfo[$Report.Evaluation.OverallStatus]
            $after = $statusInfo[$Report.PostRemediationEvaluation.OverallStatus]
            $lines.Add('    ' + 'Result: ' + (& $color $before.Text $before.Color) + ' ' + $s.Arrow + ' ' + (& $color $after.Text $after.Color))
        }
    }
    #endregion

    #region Next steps
    $next = New-Object 'System.Collections.Generic.List[string]'
    $failed = @($evaluation.Results | Where-Object { $_.Status -eq 'Fail' })
    $remediationStatus = $(if ($remediation) { $remediation.Status } else { $null })
    $backupPath = $(if ($remediation -and $remediation.ReEnrollment) { $remediation.ReEnrollment.BackupPath } else { $null })

    switch ($remediationStatus) {
        'WhatIf' {
            $next.Add("This was a preview. To apply it: $CommandHint -Remediate")
        }
        'Blocked' {
            $next.Add('The enrollment repair was not started because of:')
            foreach ($blocker in @($remediation.Blockers)) { $next.Add("  $($s.Dot) $blocker") }
            $next.Add("Fix these first, or force it with: $CommandHint -Remediate -Force")
        }
        'Failed' {
            $next.Add('The repair did not complete.')
            foreach ($part in @($remediation.Sync, $remediation.ReEnrollment, $remediation.LapsRetry)) {
                if ($part -and $part.Message -and -not $part.Succeeded) { $next.Add($part.Message) }
            }
            if ($backupPath) { $next.Add("Backup of the removed enrollment: $backupPath") }
        }
        'Succeeded' {
            if ($evaluation.OverallStatus -eq 'Compliant') { $next.Add('The device is healthy again.') }
            $next.Add('Policies and the compliance state in Intune can take a while to update. Run the tool again later to confirm.')
            if ($backupPath) { $next.Add("Backup of the removed enrollment: $backupPath") }
        }
    }

    if (-not $remediationStatus -or $remediationStatus -eq 'NothingToDo' -or ($remediationStatus -eq 'Succeeded' -and $evaluation.OverallStatus -ne 'Compliant')) {
        switch ($evaluation.OverallStatus) {
            'EnrollmentBroken' {
                $broken = @($failed | Where-Object { $_.Action -eq 'ReEnroll' -or $_.Action -eq 'Sync' } | ForEach-Object { $_.Name })
                $next.Add('The Intune connection is broken (' + ($broken -join ', ') + ').')
                if ($evaluation.CanRepairEnrollment) {
                    $next.Add("Preview the repair:  $CommandHint -Remediate -WhatIf")
                    $next.Add("Repair:              $CommandHint -Remediate")
                }
                else {
                    $next.Add('Automatic repair is blocked by:')
                    foreach ($blocker in @($evaluation.Blockers)) { $next.Add("  $($s.Dot) $blocker") }
                }
            }
            'NonCompliant' {
                $policyIssues = @($failed | Where-Object { -not $_.Action } | ForEach-Object { $_.Name })
                if ($policyIssues.Count -gt 0) { $next.Add('Fix through Intune policy or on the device: ' + ($policyIssues -join ', ') + '.') }
            }
            'Indeterminate' {
                $unknown = @($evaluation.Results | Where-Object { $_.Status -eq 'Unknown' } | ForEach-Object { $_.Name })
                $next.Add('Some data could not be read: ' + ($unknown -join ', ') + '.')
            }
            'Compliant' { $next.Add('Nothing to do.') }
        }
        if (@($evaluation.RecommendedActions) -contains 'LapsRetry') {
            $next.Add("LAPS has a problem: $CommandHint -Remediate also retries LAPS processing.")
        }
        if (-not $Detailed -and ($failed.Count -gt 0 -or $evaluation.Summary.Warning -gt 0)) {
            $next.Add("Reasons and fixes for each finding: $CommandHint -Detailed")
        }
    }
    foreach ($file in $SavedFile) { $next.Add("Report saved: $file") }

    $lines.Add('')
    $lines.Add('  ' + (& $color 'NEXT STEPS' 'Bold'))
    foreach ($item in $next) {
        if ($item.StartsWith('  ')) {
            $lines.Add('      ' + (Limit-ICTText -Text $item.Trim() -Width ($Width - 6) -Theme $theme))
            continue
        }
        $wrapped = @(Split-ICTText -Text $item -Width ($Width - 6))
        for ($i = 0; $i -lt $wrapped.Count; $i++) {
            $prefix = $(if ($i -eq 0) { (& $color $s.Arrow 'Cyan') + ' ' } else { (' ' * ($s.Arrow.Length + 1)) })
            $lines.Add('    ' + $prefix + $wrapped[$i])
        }
    }
    $lines.Add('')
    #endregion

    return [string[]]$lines.ToArray()
}
