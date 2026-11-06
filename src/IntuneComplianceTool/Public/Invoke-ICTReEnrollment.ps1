function Invoke-ICTReEnrollment {
    <#
    .SYNOPSIS
        Resets the Intune MDM enrollment of this device and enrolls it again.
    .DESCRIPTION
        1. Checks prerequisites (Entra join; a signed-in user for UserCredential).
        2. Backs up every registry key, scheduled task and MDM certificate it will
           remove. If the backup fails, it stops without changing anything.
        3. Removes the Intune enrollment(s), orphaned EnterpriseMgmt task folders and
           the Intune MDM device certificate.
        4. Runs deviceenroller.exe as SYSTEM (temporary scheduled task).
        5. Waits until a new Intune enrollment appears.

        Use -WhatIf to see the plan without changing anything. Only enrollments with
        the Intune provider ID ("MS DM Server") are touched.
    .PARAMETER Method
        UserCredential: enrolls with the signed-in user's Entra token (needs a user
        signed in at the device). DeviceCredential: enrolls with the device identity
        (no user needed; the tenant must allow device credential enrollment).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('UserCredential', 'DeviceCredential')][string]$Method = 'UserCredential',
        [string]$BackupDirectory,
        [ValidateRange(0, 3600)][int]$TimeoutSeconds = 300,
        [ValidateRange(1, 300)][int]$PollIntervalSeconds = 10,
        [switch]$KeepCertificate,
        [switch]$SkipPrerequisiteCheck
    )

    if (-not (Test-ICTIsWindows)) { throw 'Invoke-ICTReEnrollment must run on Windows.' }
    if (-not (Test-ICTIsElevated)) { throw 'Invoke-ICTReEnrollment must run as administrator.' }
    if (-not $BackupDirectory) { $BackupDirectory = Join-Path $env:ProgramData 'IntuneComplianceTool\Backup' }

    $steps = New-Object 'System.Collections.Generic.List[object]'
    $result = [pscustomobject]@{
        Action               = 'ReEnroll'
        Status               = 'NotStarted'
        Succeeded            = $false
        Method               = $Method
        Plan                 = @()
        RemovedEnrollmentIds = @()
        BackupPath           = $null
        EnrollerResult       = $null
        NewEnrollmentId      = $null
        Message              = $null
        Steps                = $null
    }
    $finish = {
        param([string]$Status, [string]$Message)
        $result.Status = $Status
        if ($Message) { $result.Message = $Message }
        $result.Steps = $steps.ToArray()
        return $result
    }

    #region Prerequisites
    if ($SkipPrerequisiteCheck) {
        $steps.Add((New-ICTStep -Name 'Prerequisites' -Status Skipped -Detail 'skipped (-Force)'))
    }
    else {
        try {
            $join = ConvertFrom-ICTDsregOutput -Line (Get-ICTDsregOutput)
            $consoleUser = $null
            if ($Method -eq 'UserCredential') { $consoleUser = Get-ICTConsoleUser }
        }
        catch {
            $steps.Add((New-ICTStep -Name 'Prerequisites' -Status Fail -Detail $_.Exception.Message))
            return (& $finish 'Failed' "Prerequisite check failed: $($_.Exception.Message)")
        }
        if (-not $join.AzureAdJoined) {
            $steps.Add((New-ICTStep -Name 'Prerequisites' -Status Fail -Detail 'device is not Entra joined'))
            return (& $finish 'Blocked' 'The device is not Entra joined or hybrid joined, so it cannot auto-enroll.')
        }
        if ($Method -eq 'UserCredential' -and -not $consoleUser) {
            $steps.Add((New-ICTStep -Name 'Prerequisites' -Status Fail -Detail 'nobody is signed in at the device'))
            return (& $finish 'Blocked' 'UserCredential enrollment needs a user signed in at the device. Wait for a user, or use -EnrollmentMethod DeviceCredential.')
        }
        $detail = 'Entra joined'
        if ($consoleUser) { $detail += ", signed in: $consoleUser" }
        $steps.Add((New-ICTStep -Name 'Prerequisites' -Status Pass -Detail $detail))
    }
    #endregion

    #region Plan
    $enrollments = @(Get-ICTEnrollmentRegistry)
    $knownIds = @($enrollments | ForEach-Object { $_.EnrollmentId })
    $intuneIds = @($enrollments | Where-Object { $_.IsIntune } | ForEach-Object { $_.EnrollmentId })
    $allTasks = @(Get-ICTEnterpriseMgmtTask)
    $orphanIds = @($allTasks | ForEach-Object { $_.EnrollmentId } | Where-Object { (Test-ICTGuid $_) -and ($knownIds -notcontains $_) } | Sort-Object -Unique)
    $targetIds = @(@($intuneIds) + @($orphanIds) | Where-Object { Test-ICTGuid $_ } | Sort-Object -Unique)

    $registryPaths = @(foreach ($id in $targetIds) {
            Get-ICTEnrollmentRegistryPath -EnrollmentId $id | Where-Object { Test-ICTRegistryKey -Path $_ }
        })
    $tasks = @($allTasks | Where-Object { $targetIds -contains $_.EnrollmentId })
    $certificates = @()
    if (-not $KeepCertificate) { $certificates = @(Get-ICTMdmCertificate) }

    $argument = '/c /AutoEnrollMDM'
    if ($Method -eq 'DeviceCredential') { $argument = '/c /AutoEnrollMDMUsingAADDeviceCredential' }

    $plan = New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in $registryPaths) { $plan.Add("Remove registry key $path") }
    foreach ($task in $tasks) { $plan.Add("Remove scheduled task $($task.TaskPath)$($task.TaskName)") }
    foreach ($certificate in $certificates) { $plan.Add("Remove certificate $($certificate.Thumbprint) ($($certificate.Subject))") }
    $plan.Add("Run deviceenroller.exe $argument as SYSTEM")
    $result.Plan = $plan.ToArray()

    $summary = '{0} registry keys, {1} tasks, {2} certificate(s)' -f $registryPaths.Count, $tasks.Count, $certificates.Count
    Write-ICTLog ("Re-enrollment plan ({0}):`n  {1}" -f $summary, ($plan -join "`n  "))
    #endregion

    if (-not $PSCmdlet.ShouldProcess([System.Environment]::MachineName, "Remove the Intune enrollment ($summary) and re-enroll using $Method")) {
        $steps.Add((New-ICTStep -Name 'Backup' -Status Info -Detail "would back up to $BackupDirectory"))
        $steps.Add((New-ICTStep -Name 'Remove enrollment' -Status Info -Detail "would remove $summary"))
        $steps.Add((New-ICTStep -Name 'Enroll (as SYSTEM)' -Status Info -Detail "would run deviceenroller.exe $argument"))
        return (& $finish 'WhatIf' $null)
    }

    #region Backup (nothing has been changed until this succeeds)
    try {
        $backupPath = Join-Path $BackupDirectory (Get-Date).ToString('yyyyMMdd-HHmmss')
        $null = New-Item -Path $backupPath -ItemType Directory -Force -ErrorAction Stop
        $result.BackupPath = $backupPath

        $index = 0
        foreach ($path in $registryPaths) {
            $index++
            Export-ICTRegistryKey -Path $path -Destination (Join-Path $backupPath ('registry-{0:D2}.reg' -f $index))
        }
        foreach ($task in $tasks) {
            $fileName = 'task-{0}-{1}.xml' -f $task.EnrollmentId, ($task.TaskName -replace '[^A-Za-z0-9_\-]', '_')
            Export-ICTScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Destination (Join-Path $backupPath $fileName)
        }
        foreach ($certificate in $certificates) {
            Export-ICTCertificate -Thumbprint $certificate.Thumbprint -Destination (Join-Path $backupPath "certificate-$($certificate.Thumbprint).cer")
        }
        Set-Content -LiteralPath (Join-Path $backupPath 'plan.txt') -Value $plan -Encoding UTF8 -ErrorAction Stop
        $steps.Add((New-ICTStep -Name 'Backup' -Status Pass -Detail $backupPath))
    }
    catch {
        $steps.Add((New-ICTStep -Name 'Backup' -Status Fail -Detail $_.Exception.Message))
        return (& $finish 'Failed' "Backup failed, so nothing was changed: $($_.Exception.Message)")
    }
    #endregion

    #region Remove
    try {
        foreach ($id in $targetIds) { Remove-ICTEnterpriseMgmtTask -EnrollmentId $id }
        foreach ($path in $registryPaths) { Remove-ICTRegistryKey -Path $path }
        foreach ($certificate in $certificates) { Remove-ICTCertificate -Thumbprint $certificate.Thumbprint }
        $result.RemovedEnrollmentIds = $targetIds
        $steps.Add((New-ICTStep -Name 'Remove enrollment' -Status Pass -Detail $summary))
    }
    catch {
        $steps.Add((New-ICTStep -Name 'Remove enrollment' -Status Fail -Detail $_.Exception.Message))
        return (& $finish 'Failed' ("Removal stopped part-way: {0}. Restore the keys with 'reg import' from {1}." -f $_.Exception.Message, $result.BackupPath))
    }
    #endregion

    #region Enroll
    try {
        $code = Start-ICTDeviceEnrollerAsSystem -Argument $argument -TimeoutSeconds 120
    }
    catch {
        $steps.Add((New-ICTStep -Name 'Enroll (as SYSTEM)' -Status Fail -Detail $_.Exception.Message))
        return (& $finish 'Failed' "deviceenroller.exe could not be started: $($_.Exception.Message)")
    }
    $result.EnrollerResult = $code
    if ($null -eq $code) {
        $steps.Add((New-ICTStep -Name 'Enroll (as SYSTEM)' -Status Warning -Detail 'deviceenroller.exe still running after 120 s'))
    }
    elseif ($code -eq 0) {
        $steps.Add((New-ICTStep -Name 'Enroll (as SYSTEM)' -Status Pass -Detail 'deviceenroller.exe finished (0)'))
    }
    else {
        $steps.Add((New-ICTStep -Name 'Enroll (as SYSTEM)' -Status Warning -Detail ('deviceenroller.exe returned 0x{0:X8}' -f [int64]$code)))
    }
    #endregion

    #region Wait for the new enrollment
    $attempts = [int][math]::Ceiling($TimeoutSeconds / $PollIntervalSeconds)
    $waited = 0
    for ($i = 0; $i -lt $attempts; $i++) {
        Start-Sleep -Seconds $PollIntervalSeconds
        $waited += $PollIntervalSeconds
        # Only an enrollment with a new ID counts: a leftover old key must not look like success.
        $newEnrollment = @(Get-ICTEnrollmentRegistry | Where-Object { $_.IsIntune -and ($targetIds -notcontains $_.EnrollmentId) }) | Select-Object -First 1
        if ($newEnrollment) {
            $result.NewEnrollmentId = $newEnrollment.EnrollmentId
            $result.Succeeded = $true
            $steps.Add((New-ICTStep -Name 'New enrollment' -Status Pass -Detail ('{0} after {1} s' -f (Get-ICTShortId $newEnrollment.EnrollmentId), $waited)))
            return (& $finish 'Succeeded' $null)
        }
    }

    $steps.Add((New-ICTStep -Name 'New enrollment' -Status Fail -Detail ('none after {0} s' -f $TimeoutSeconds)))
    return (& $finish 'Pending' ('deviceenroller.exe ran, but no Intune enrollment appeared within {0} s. It may still finish in the background; check the DeviceManagement-Enterprise-Diagnostics-Provider Admin log.' -f $TimeoutSeconds))
    #endregion
}
