function Invoke-ICTReEnrollment {
    <#
    .SYNOPSIS
        Resets the Intune MDM enrollment of this device and enrolls it again.
    .DESCRIPTION
        1. Checks prerequisites: Entra join; for UserCredential an Entra or domain user
           signed in at the console (not a local account, not the SSH/LAPS account);
           no other repair running or finished in the last 15 minutes.
        2. Backs up every registry key, scheduled task and certificate it will remove
           into a new folder only SYSTEM and Administrators can write to, and writes
           restore.ps1. If the backup fails, nothing is changed.
        3. Runs the removal and deviceenroller.exe as SYSTEM in a temporary scheduled
           task, so a dropped SSH session or Ctrl+C cannot stop it half-way.
        4. Waits for a complete new enrollment (new key and a new MDM certificate).

        -WhatIf shows the plan. Only Intune enrollments ("MS DM Server") and orphaned
        EnterpriseMgmt task folders are touched.
    .PARAMETER Method
        UserCredential: enrolls with the signed-in user's Entra token. DeviceCredential:
        enrolls with the device identity (no user needed; the tenant must allow it).
    .PARAMETER WorkDirectory
        Root of the repair folders. Default %ProgramData%\IntuneComplianceTool.
    .PARAMETER ExcludeAccount
        Accounts that cannot provide a user token (the SSH and LAPS admin accounts).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('UserCredential', 'DeviceCredential')][string]$Method = 'UserCredential',
        [string]$WorkDirectory,
        [ValidateRange(10, 3600)][int]$ScriptTimeoutSeconds = 240,
        [ValidateRange(0, 3600)][int]$TimeoutSeconds = 300,
        [ValidateRange(1, 60)][int]$PollIntervalSeconds = 3,
        [string[]]$ExcludeAccount = @(),
        [scriptblock]$OnProgress
    )

    if (-not (Test-ICTIsWindows)) { throw 'Invoke-ICTReEnrollment must run on Windows.' }
    if (-not (Test-ICTIsElevated)) { throw 'Invoke-ICTReEnrollment must run as administrator.' }
    if (-not $WorkDirectory) { $WorkDirectory = Join-Path $env:ProgramData 'IntuneComplianceTool' }
    $repairRoot = Join-Path $WorkDirectory 'Repair'

    $steps = New-Object 'System.Collections.Generic.List[object]'
    $result = [pscustomobject]@{
        Status = 'NotStarted'; Succeeded = $false; Method = $Method; Plan = @(); RemovedEnrollmentIds = @()
        BackupPath = $null; RestoreFile = $null; NewEnrollmentId = $null; Message = $null; Steps = $null
    }
    $finish = {
        param([string]$Status, [string]$Message)
        $result.Status = $Status
        if ($Message) { $result.Message = $Message }
        $result.Steps = $steps.ToArray()
        return $result
    }
    $blocked = { param([string]$Detail, [string]$Message) $steps.Add((New-ICTStep 'Prerequisites' Fail $Detail)); return (& $finish 'Blocked' $Message) }
    $progress = { param([string]$Text) if ($OnProgress) { & $OnProgress $Text } }

    #region Prerequisites (always checked, also with -Force)
    try {
        $join = ConvertFrom-ICTDsregOutput -Line (Get-ICTDsregOutput)
        $consoleUser = $(if ($Method -eq 'UserCredential') { Get-ICTConsoleUser } else { $null })
        $running = Test-ICTRepairRunning
        $lastRepair = Get-ICTLastRepairTime -RepairRoot $repairRoot
    }
    catch {
        $steps.Add((New-ICTStep 'Prerequisites' Fail $_.Exception.Message))
        return (& $finish 'Failed' "Prerequisite check failed: $($_.Exception.Message)")
    }
    if ($running) { return (& $blocked 'another repair is running' 'Another repair of this tool is still running as SYSTEM. Wait until it has finished.') }
    if ($lastRepair -and ([datetime]::UtcNow - $lastRepair).TotalMinutes -lt 15) {
        return (& $blocked 'a repair ran less than 15 min ago' 'A re-enrollment started less than 15 minutes ago; the new enrollment may still be setting up. Run the tool again later.')
    }
    if (-not $join.AzureAdJoined) { return (& $blocked 'device is not Entra joined' 'The device is not Entra joined or hybrid joined, so it cannot auto-enroll.') }
    if ($Method -eq 'UserCredential') {
        $computerNames = @([System.Environment]::MachineName, ("$($join.DeviceName)" -split '\.')[0])
        $problem = Test-ICTEnrollmentUser -User $consoleUser -ComputerName $computerNames -ExcludeAccount $ExcludeAccount
        if ($problem) {
            return (& $blocked $problem "UserCredential enrollment needs an Entra or domain user signed in at the console ($problem). Use -EnrollmentMethod DeviceCredential instead.")
        }
    }
    $steps.Add((New-ICTStep 'Prerequisites' Pass ('Entra joined' + $(if ($consoleUser) { ", signed in: $consoleUser" } else { '' }))))
    #endregion

    #region Plan
    $enrollments = @(Get-ICTEnrollmentRegistry)
    $knownIds = @($enrollments | ForEach-Object { $_.EnrollmentId })
    $allTasks = @(Get-ICTEnterpriseMgmtTask)
    $orphanIds = @($allTasks | ForEach-Object { $_.EnrollmentId } | Where-Object { (Test-ICTGuid $_) -and ($knownIds -notcontains $_) })
    $targetIds = @(@($enrollments | Where-Object { $_.IsIntune } | ForEach-Object { $_.EnrollmentId }) + $orphanIds | Where-Object { Test-ICTGuid $_ } | Sort-Object -Unique)
    $registryPaths = @(foreach ($id in $targetIds) { Get-ICTEnrollmentRegistryPath -EnrollmentId $id | Where-Object { Test-ICTRegistryKey -Path $_ } })
    $tasks = @($allTasks | Where-Object { $targetIds -contains $_.EnrollmentId })
    $certificates = @(Get-ICTMdmCertificate)
    $currentEnrollmentId = Get-ICTOmadmCurrentEnrollmentId
    $argument = $(if ($Method -eq 'DeviceCredential') { '/c /AutoEnrollMDMUsingAADDeviceCredential' } else { '/c /AutoEnrollMDM' })

    $plan = @($registryPaths | ForEach-Object { "Remove registry key $_" }) +
        @($tasks | ForEach-Object { "Remove scheduled task $($_.TaskPath)$($_.TaskName)" }) +
        @($certificates | ForEach-Object { "Remove certificate $($_.Thumbprint) ($($_.Subject))" }) +
        @("Run deviceenroller.exe $argument as SYSTEM")
    $result.Plan = $plan
    $summary = '{0} registry keys, {1} tasks, {2} certificate(s)' -f $registryPaths.Count, $tasks.Count, $certificates.Count
    Write-ICTLog ("Re-enrollment plan ({0}):`n  {1}" -f $summary, ($plan -join "`n  "))
    #endregion

    # Checking $WhatIfPreference first avoids the host's "What if:" line (keeps -Json output clean).
    if ($WhatIfPreference -or -not $PSCmdlet.ShouldProcess([System.Environment]::MachineName, "Remove the Intune enrollment ($summary) and re-enroll using $Method")) {
        $steps.Add((New-ICTStep 'Backup' Info "would back up to $repairRoot"))
        $steps.Add((New-ICTStep 'Remove enrollment' Info "would remove $summary (as SYSTEM)"))
        $steps.Add((New-ICTStep 'Enroll (as SYSTEM)' Info "would run deviceenroller.exe $argument"))
        return (& $finish 'WhatIf' $null)
    }

    #region Backup (nothing has been changed until this succeeds)
    $started = [datetime]::UtcNow
    try {
        Protect-ICTDirectory -Path $WorkDirectory
        $backupPath = New-ICTPrivateDirectory -Parent $repairRoot -Prefix ([datetime]::Now.ToString('yyyyMMdd-HHmmss', $script:ICTInvariant))
        $result.BackupPath = $backupPath

        $registryFiles = @(for ($i = 0; $i -lt $registryPaths.Count; $i++) {
                $file = 'registry-{0:D2}.reg' -f ($i + 1)
                Export-ICTRegistryKey -Path $registryPaths[$i] -Destination (Join-Path $backupPath $file)
                $file
            })
        $taskFiles = @(foreach ($task in $tasks) {
                $file = 'task-{0}-{1}.xml' -f $task.EnrollmentId, ($task.TaskName -replace '[^A-Za-z0-9_\-]', '_')
                Export-ICTScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Destination (Join-Path $backupPath $file)
                [pscustomobject]@{ File = $file; TaskName = $task.TaskName; TaskPath = $task.TaskPath }
            })
        $certificateFiles = @(foreach ($certificate in $certificates) {
                $file = "certificate-$($certificate.Thumbprint).cer"
                Export-ICTCertificate -Thumbprint $certificate.Thumbprint -Destination (Join-Path $backupPath $file)
                [pscustomobject]@{ File = $file; Thumbprint = $certificate.Thumbprint }
            })
        $result.RestoreFile = Join-Path $backupPath 'restore.ps1'
        $loggerId = $(if ($currentEnrollmentId -and $targetIds -contains $currentEnrollmentId) { $currentEnrollmentId } else { $null })
        Set-Content -LiteralPath $result.RestoreFile -Encoding UTF8 -ErrorAction Stop -Value (
            New-ICTRestoreText -BackupPath $backupPath -RegistryFile $registryFiles -Task $taskFiles -Certificate $certificateFiles -CurrentEnrollmentId $loggerId)
        Set-Content -LiteralPath (Join-Path $backupPath 'plan.txt') -Value $plan -Encoding UTF8 -ErrorAction Stop
        $steps.Add((New-ICTStep 'Backup' Pass $backupPath))
    }
    catch {
        $steps.Add((New-ICTStep 'Backup' Fail $_.Exception.Message))
        return (& $finish 'Failed' "Backup failed, so nothing was changed: $($_.Exception.Message)")
    }
    #endregion

    #region Removal and enrollment as SYSTEM
    $statePath = Join-Path $backupPath 'repair-state.jsonl'
    try {
        Remove-ICTSystemTask   # finished leftovers of earlier runs
        $scriptPath = Join-Path $backupPath 'repair.ps1'
        Set-Content -LiteralPath $scriptPath -Encoding UTF8 -ErrorAction Stop -Value (
            New-ICTRepairScript -RegistryPath $registryPaths -EnrollmentId $targetIds -Thumbprint @($certificates | ForEach-Object { $_.Thumbprint }) -EnrollerArgument $argument -StatePath $statePath)
        $taskName = Start-ICTSystemScript -ScriptPath $scriptPath
    }
    catch {
        $steps.Add((New-ICTStep 'Start repair as SYSTEM' Fail $_.Exception.Message))
        return (& $finish 'Failed' "The repair could not be started as SYSTEM, so nothing was changed: $($_.Exception.Message)")
    }
    $result.RemovedEnrollmentIds = $targetIds
    $undo = "To undo it, run $($result.RestoreFile) as SYSTEM (see its first lines)."
    $keepTask = $false

    # The SYSTEM task finishes on its own; Ctrl+C here would only abandon the monitoring.
    $previousCtrlC = Set-ICTCtrlCAsInput -Enabled $true
    try {
        $final = $null
        $lines = @()
        $stopped = $null
        $attempts = [int][math]::Ceiling($ScriptTimeoutSeconds / $PollIntervalSeconds)
        for ($i = 1; $i -le $attempts -and -not $final -and -not $stopped; $i++) {
            Start-Sleep -Seconds $PollIntervalSeconds
            $lines = @(Get-ICTSystemScriptState -Path $statePath)
            $final = $lines | Where-Object { $_.Stage -eq 'end' } | Select-Object -Last 1
            if (-not $final) {
                $task = Get-ICTSystemTaskState -TaskName $taskName
                if ($null -eq $task -or ($task.State -ne 'Running' -and $task.State -ne 'Queued')) {
                    $lines = @(Get-ICTSystemScriptState -Path $statePath)   # it may have finished just now
                    $final = $lines | Where-Object { $_.Stage -eq 'end' } | Select-Object -Last 1
                    if (-not $final) { $stopped = $(if ($task) { $task } else { [pscustomobject]@{ State = 'missing'; LastTaskResult = $null } }) }
                }
            }
            $last = $lines | Select-Object -Last 1
            & $progress ('repair as SYSTEM: {0} ({1} s)' -f $(if ($last) { $last.Stage } else { 'starting' }), ($i * $PollIntervalSeconds))
        }

        $stageNames = @{ tasks = 'Remove tasks'; registry = 'Remove registry keys'; certificates = 'Remove certificates'; enroll = 'Enroll (as SYSTEM)' }
        foreach ($line in @($lines | Where-Object { $stageNames.ContainsKey([string]$_.Stage) })) {
            $steps.Add((New-ICTStep $stageNames[[string]$line.Stage] Pass $line.Detail))
        }
        $reached = $(if ($lines.Count) { ($lines | Select-Object -Last 1).Stage } else { 'nothing' })
        if ($stopped) {
            $keepTask = $true
            $code = $(if ($null -ne $stopped.LastTaskResult) { '0x{0:X8}' -f [int64]$stopped.LastTaskResult } else { 'unknown' })
            $steps.Add((New-ICTStep 'Repair as SYSTEM' Fail "the task stopped without finishing (result $code, last stage: $reached)"))
            return (& $finish 'Failed' "The SYSTEM repair task stopped without finishing (result $code, last stage: $reached). Blocked by antivirus or AppLocker? $undo")
        }
        if (-not $final) {
            $keepTask = $true
            $steps.Add((New-ICTStep 'Repair as SYSTEM' Warning ('still running after {0} s' -f $ScriptTimeoutSeconds)))
            return (& $finish 'Pending' "The repair is still running as SYSTEM and finishes on its own. Run the tool again in a few minutes. Progress: $statePath")
        }
        if ($final.Status -ne 'Succeeded') {
            $keepTask = $true
            $steps.Add((New-ICTStep 'Repair as SYSTEM' Fail $final.Detail))
            return (& $finish 'Failed' "The repair stopped at $($final.Detail). The enrollment may be partly removed. $undo")
        }

        $enrollLine = $lines | Where-Object { $_.Stage -eq 'enroll' } | Select-Object -Last 1
        $waitSeconds = $TimeoutSeconds
        if ($enrollLine -and $enrollLine.Detail -match '^exit (?<code>-?\d+)$' -and [int64]$Matches['code'] -ne 0) {
            $waitSeconds = [math]::Min($TimeoutSeconds, 30)   # the enroller reported an error: short grace period only
        }

        $attempts = [int][math]::Ceiling($waitSeconds / $PollIntervalSeconds)
        $earliest = $started.AddMinutes(-10)
        for ($i = 0; $i -le $attempts; $i++) {
            if ($i -gt 0) { Start-Sleep -Seconds $PollIntervalSeconds; & $progress ('waiting for the new enrollment ({0} s)' -f ($i * $PollIntervalSeconds)) }
            $new = @(Get-ICTEnrollmentRegistry | Where-Object { $_.IsIntune -and ($targetIds -notcontains $_.EnrollmentId) -and ($null -eq $_.EnrollmentState -or $_.EnrollmentState -eq 1) }) | Select-Object -First 1
            $certificate = @(Get-ICTMdmCertificate | Where-Object { $_.HasPrivateKey -and (ConvertFrom-ICTDate $_.NotBefore) -ge $earliest }) | Select-Object -First 1
            if ($new -and $certificate) {
                $result.NewEnrollmentId = $new.EnrollmentId
                $result.Succeeded = $true
                $steps.Add((New-ICTStep 'New enrollment' Pass ('{0} after {1} s' -f (Get-ICTShortId $new.EnrollmentId), [int]([datetime]::UtcNow - $started).TotalSeconds)))
                return (& $finish 'Succeeded' $null)
            }
        }
        $steps.Add((New-ICTStep 'New enrollment' Fail ('none after {0} s' -f $waitSeconds)))
        return (& $finish 'Pending' "The device is currently NOT enrolled in Intune. deviceenroller.exe ran ($($enrollLine.Detail)), but no complete enrollment appeared yet. Check the DeviceManagement-Enterprise-Diagnostics-Provider Admin log, then run -Remediate again after 15 minutes.")
    }
    catch {
        $keepTask = $true
        $steps.Add((New-ICTStep 'Monitor repair' Fail $_.Exception.Message))
        return (& $finish 'Failed' "Monitoring the repair failed: $($_.Exception.Message). The repair may still be running as SYSTEM (progress: $statePath). $undo")
    }
    finally {
        if ($null -ne $previousCtrlC) { $null = Set-ICTCtrlCAsInput -Enabled $previousCtrlC }
        if (-not $keepTask) { Remove-ICTSystemTask -TaskName $taskName }
    }
    #endregion
}
