BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'src' 'IntuneComplianceTool' 'IntuneComplianceTool.psd1') -Force
    $script:dsregHybrid = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'dsregcmd-hybrid.txt')
    $script:dsregNotJoined = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'dsregcmd-notjoined.txt')
    $script:oldId = '8C2F41D0-5B7A-4E21-9C3D-2A6B8F1E7D45'
    $script:newId = '9D1E52A1-6C8B-4F32-AD4E-3B7C9A2F8E56'
    $script:orphanId = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
}

Describe 'Invoke-ICTReEnrollment' {
    BeforeEach {
        $m = 'IntuneComplianceTool'
        $script:calls = New-Object System.Collections.Generic.List[string]
        $script:enrolled = $false
        $script:work = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:stateLines = @(
            '{"Stage":"start","Status":"Running","Detail":""}'
            '{"Stage":"tasks","Status":"Done","Detail":"9 tasks removed"}'
            '{"Stage":"registry","Status":"Done","Detail":"7 registry keys removed"}'
            '{"Stage":"certificates","Status":"Done","Detail":"1 certificates removed"}'
            '{"Stage":"enroll","Status":"Done","Detail":"exit 0"}'
            '{"Stage":"end","Status":"Succeeded","Detail":""}'
        )

        Mock -ModuleName $m Test-ICTIsWindows { $true }
        Mock -ModuleName $m Test-ICTIsElevated { $true }
        Mock -ModuleName $m Protect-ICTDirectory { $null = New-Item -Path $Path -ItemType Directory -Force }
        Mock -ModuleName $m New-ICTPrivateDirectory { $p = Join-Path $Parent ($Prefix + '-test'); $null = New-Item -Path $p -ItemType Directory -Force; $p }
        Mock -ModuleName $m Test-ICTRepairRunning { $false }
        Mock -ModuleName $m Get-ICTLastRepairTime { $null }
        Mock -ModuleName $m Get-ICTOmadmCurrentEnrollmentId { $oldId }
        Mock -ModuleName $m Get-ICTSystemTaskState { [pscustomobject]@{ State = 'Running'; LastTaskResult = 267009 } }
        Mock -ModuleName $m Get-ICTDsregOutput { $dsregHybrid }
        Mock -ModuleName $m Get-ICTConsoleUser { 'CONTOSO\anna.berger' }
        Mock -ModuleName $m Get-ICTEnrollmentRegistry {
            if ($script:enrolled) { [pscustomobject]@{ EnrollmentId = $newId; IsIntune = $true; EnrollmentState = 1 } }
            else {
                [pscustomobject]@{ EnrollmentId = $oldId; IsIntune = $true; EnrollmentState = 1 }
                [pscustomobject]@{ EnrollmentId = '22222222-2222-2222-2222-222222222222'; IsIntune = $false }
            }
        }
        Mock -ModuleName $m Get-ICTEnterpriseMgmtTask {
            [pscustomobject]@{ EnrollmentId = $oldId; TaskName = 'PushLaunch'; TaskPath = "\Microsoft\Windows\EnterpriseMgmt\$oldId\" }
            [pscustomobject]@{ EnrollmentId = $orphanId; TaskName = 'Schedule #1 created by enrollment client'; TaskPath = "\Microsoft\Windows\EnterpriseMgmt\$orphanId\" }
            [pscustomobject]@{ EnrollmentId = '22222222-2222-2222-2222-222222222222'; TaskName = 'Other'; TaskPath = '\Microsoft\Windows\EnterpriseMgmt\22222222-2222-2222-2222-222222222222\' }
        }
        Mock -ModuleName $m Test-ICTRegistryKey { $Path -match [regex]::Escape($oldId) -and $Path -notmatch 'Logger' }
        Mock -ModuleName $m Get-ICTMdmCertificate {
            if ($script:enrolled) { [pscustomobject]@{ Thumbprint = 'NEW'; Subject = 'CN=y'; HasPrivateKey = $true; NotBefore = [datetime]::UtcNow.ToString('o') } }
            else { [pscustomobject]@{ Thumbprint = 'ABC123'; Subject = 'CN=x'; HasPrivateKey = $true; NotBefore = '2026-05-01T08:00:00Z' } }
        }
        Mock -ModuleName $m Export-ICTRegistryKey { $script:calls.Add("backup-reg:$Path") }
        Mock -ModuleName $m Export-ICTScheduledTask { $script:calls.Add("backup-task:$TaskName") }
        Mock -ModuleName $m Export-ICTCertificate { $script:calls.Add("backup-cert:$Thumbprint") }
        Mock -ModuleName $m Remove-ICTSystemTask { $script:calls.Add("cleanup:$TaskName") }
        Mock -ModuleName $m Start-ICTSystemScript { $script:calls.Add("system:$ScriptPath"); $script:enrolled = $true; 'IntuneComplianceTool-Repair-1234' }
        Mock -ModuleName $m Get-ICTSystemScriptState { $script:stateLines | ForEach-Object { $_ | ConvertFrom-Json } }
        Mock -ModuleName $m Set-ICTCtrlCAsInput { $false }
        Mock -ModuleName $m Start-Sleep { }
    }

    It 'changes nothing with -WhatIf but returns the full plan' {
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -WhatIf
        $result.Status | Should -Be 'WhatIf'
        $calls.Count | Should -Be 0
        $result.Plan | Should -Contain "Remove registry key HKLM:\SOFTWARE\Microsoft\Enrollments\$oldId"
        $result.Plan | Should -Contain "Remove scheduled task \Microsoft\Windows\EnterpriseMgmt\$orphanId\Schedule #1 created by enrollment client"
        $result.Plan | Should -Not -Contain 'Remove scheduled task \Microsoft\Windows\EnterpriseMgmt\22222222-2222-2222-2222-222222222222\Other'
        $result.Plan[-1] | Should -Be 'Run deviceenroller.exe /c /AutoEnrollMDM as SYSTEM'
        Test-Path $work | Should -BeFalse
    }

    It 'backs up everything, then runs the removal and enrollment as SYSTEM' {
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -Confirm:$false
        $result.Status | Should -Be 'Succeeded'
        $result.NewEnrollmentId | Should -Be $newId
        $start = $calls.FindIndex({ param($c) $c.StartsWith('system:') })
        $calls.FindLastIndex({ param($c) $c.StartsWith('backup-') }) | Should -BeLessThan $start
        @($calls | Where-Object { $_ -like 'backup-reg:*' }).Count | Should -Be 7
        $result.Steps.Name | Should -Contain 'Remove registry keys'
        $result.Steps.Name | Should -Contain 'Enroll (as SYSTEM)'
        $calls[-1] | Should -Be 'cleanup:IntuneComplianceTool-Repair-1234'
    }

    It 'writes a repair script for SYSTEM that targets only the Intune and orphaned enrollments' {
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -Confirm:$false
        $result.BackupPath | Should -BeLike (Join-Path (Join-Path $work 'Repair') '*')
        $script = Get-Content -LiteralPath (Join-Path $result.BackupPath 'repair.ps1') -Raw
        $script | Should -Match ([regex]::Escape("'$oldId'"))
        $script | Should -Match ([regex]::Escape("'$orphanId'"))
        $script | Should -Not -Match '22222222-2222-2222-2222-222222222222'
        $script | Should -Match ([regex]::Escape("@('ABC123')"))
        $restore = Get-Content -LiteralPath $result.RestoreFile -Raw
        $restore | Should -Match 'reg.exe import'
        $restore | Should -Match "CurrentEnrollmentId' -Value '$oldId'"
        $restore | Should -Match 'schtasks /create /tn ICT-Restore /ru SYSTEM'
    }

    It 'refuses to start while another repair runs or right after one' -TestCases @(
        @{ Running = $true; Last = $null; Expected = 'still running' }
        @{ Running = $false; Last = [datetime]::UtcNow.AddMinutes(-5); Expected = 'less than 15 minutes' }
    ) {
        Mock -ModuleName IntuneComplianceTool Test-ICTRepairRunning { $Running }
        Mock -ModuleName IntuneComplianceTool Get-ICTLastRepairTime { $Last }
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Message | Should -Match $Expected
        $calls.Count | Should -Be 0
    }

    It 'fails at once when the SYSTEM task stopped without finishing, and keeps the task' {
        $script:stateLines = @()
        Mock -ModuleName IntuneComplianceTool Get-ICTSystemTaskState { [pscustomobject]@{ State = 'Ready'; LastTaskResult = 1 } }
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -PollIntervalSeconds 3 -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.Message | Should -Match 'stopped without finishing \(result 0x00000001'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Start-Sleep -Times 1 -Exactly
        $calls | Should -Not -Contain 'cleanup:IntuneComplianceTool-Repair-1234'
    }

    It 'keeps the backup and restore information when monitoring throws' {
        Mock -ModuleName IntuneComplianceTool Get-ICTSystemScriptState { throw 'sharing violation' }
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.Message | Should -Match 'Monitoring the repair failed'
        $result.RestoreFile | Should -Not -BeNullOrEmpty
    }

    It 'stops without changes when the backup fails' {
        Mock -ModuleName IntuneComplianceTool Export-ICTRegistryKey { throw 'reg.exe failed' }
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.Message | Should -Match 'nothing was changed'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Start-ICTSystemScript -Times 0 -Exactly
    }

    It 'points to restore.txt when the SYSTEM script fails part-way' {
        $script:stateLines = @('{"Stage":"tasks","Status":"Done","Detail":"9 tasks removed"}', '{"Stage":"end","Status":"Failed","Detail":"registry: Access denied"}')
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.Message | Should -Match 'registry: Access denied'
        $result.Message | Should -Match ([regex]::Escape($result.RestoreFile))
    }

    It 'reports Pending when the SYSTEM script is still running' {
        $script:stateLines = @('{"Stage":"start","Status":"Running","Detail":""}')
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -ScriptTimeoutSeconds 30 -PollIntervalSeconds 10 -Confirm:$false
        $result.Status | Should -Be 'Pending'
        $result.Message | Should -Match 'finishes on its own'
    }

    It 'does not count a key without a new certificate as a new enrollment' {
        Mock -ModuleName IntuneComplianceTool Get-ICTMdmCertificate { [pscustomobject]@{ Thumbprint = 'ABC123'; Subject = 'CN=x'; HasPrivateKey = $true; NotBefore = '2026-05-01T08:00:00Z' } }
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -TimeoutSeconds 9 -PollIntervalSeconds 3 -Confirm:$false
        $result.Status | Should -Be 'Pending'
        $result.Message | Should -Match 'NOT enrolled'
    }

    It 'waits only briefly when deviceenroller reported an error' {
        $script:stateLines = $script:stateLines -replace 'exit 0', 'exit -2145910774'
        $script:enrolled = $false
        Mock -ModuleName IntuneComplianceTool Start-ICTSystemScript { 'IntuneComplianceTool-Repair-1234' }
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -TimeoutSeconds 300 -PollIntervalSeconds 3 -Confirm:$false
        $result.Status | Should -Be 'Pending'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Start-Sleep -Times 11 -Exactly   # 1 state poll + 10 x 3 s
    }

    It 'is blocked when the device is not Entra joined' {
        Mock -ModuleName IntuneComplianceTool Get-ICTDsregOutput { $dsregNotJoined }
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $calls.Count | Should -Be 0
    }

    It 'is blocked for UserCredential when the console user cannot provide a token' -TestCases @(
        @{ User = $null }
        @{ User = 'PC-0421\localadmin' }
        @{ User = 'CONTOSO\masteruser' }
    ) {
        Mock -ModuleName IntuneComplianceTool Get-ICTConsoleUser { $User }
        $result = Invoke-ICTReEnrollment -WorkDirectory $work -ExcludeAccount @('PC-0421\masteruser') -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Message | Should -Match 'DeviceCredential'
    }

    It 'enrolls with the device credential without a signed-in user' {
        Mock -ModuleName IntuneComplianceTool Get-ICTConsoleUser { $null }
        $result = Invoke-ICTReEnrollment -Method DeviceCredential -WorkDirectory $work -Confirm:$false
        $result.Status | Should -Be 'Succeeded'
        Get-Content -LiteralPath (Join-Path $result.BackupPath 'repair.ps1') -Raw | Should -Match 'AutoEnrollMDMUsingAADDeviceCredential'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Get-ICTConsoleUser -Times 0 -Exactly
    }

    It 'refuses to run without administrator rights' {
        Mock -ModuleName IntuneComplianceTool Test-ICTIsElevated { $false }
        { Invoke-ICTReEnrollment -WorkDirectory $work -Confirm:$false } | Should -Throw '*administrator*'
    }
}

Describe 'Invoke-ICTSync' {
    BeforeEach {
        $m = 'IntuneComplianceTool'
        $script:synced = $false
        Mock -ModuleName $m Test-ICTIsWindows { $true }
        Mock -ModuleName $m Get-ICTEnrollmentRegistry { [pscustomobject]@{ EnrollmentId = $oldId; IsIntune = $true } }
        Mock -ModuleName $m Get-ICTOmadmConnectionInfo {
            if ($script:synced) { [pscustomobject]@{ ServerLastSuccessTime = '2026-11-05T14:35:00Z' } }
            else { [pscustomobject]@{ ServerLastSuccessTime = '2026-10-24T10:00:00Z' } }
        }
        Mock -ModuleName $m Start-ICTEnterpriseMgmtSyncTask { $true }
        Mock -ModuleName $m Start-Sleep { $script:synced = $true }
    }

    It 'succeeds when the last successful check-in moves forward' {
        $result = Invoke-ICTSync -Confirm:$false
        $result.Status | Should -Be 'Succeeded'
        $result.LastSuccessBefore | Should -Be '2026-10-24T10:00:00Z'
        $result.LastSuccessAfter | Should -Be '2026-11-05T14:35:00Z'
    }

    It 'accepts a newer successful task run when the device records no server time' {
        Mock -ModuleName IntuneComplianceTool Get-ICTOmadmConnectionInfo { }
        Mock -ModuleName IntuneComplianceTool Get-ICTEnterpriseMgmtTask {
            [pscustomobject]@{ EnrollmentId = $oldId; TaskName = 'Schedule to run OMADMClient by client'; LastTaskResult = 0; LastRunTime = [datetime]::UtcNow.AddMinutes(1).ToString('o') }
        }
        (Invoke-ICTSync -Confirm:$false).Status | Should -Be 'Succeeded'
    }

    It 'times out when the check-in does not move' {
        Mock -ModuleName IntuneComplianceTool Start-Sleep { }
        $result = Invoke-ICTSync -TimeoutSeconds 30 -PollIntervalSeconds 5 -Confirm:$false
        $result.Status | Should -Be 'TimedOut'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Start-Sleep -Times 6 -Exactly
    }

    It 'fails when the PushLaunch task is missing' {
        Mock -ModuleName IntuneComplianceTool Start-ICTEnterpriseMgmtSyncTask { $false }
        (Invoke-ICTSync -Confirm:$false).Status | Should -Be 'Failed'
    }

    It 'does nothing with -WhatIf' {
        (Invoke-ICTSync -WhatIf).Status | Should -Be 'WhatIf'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Start-ICTEnterpriseMgmtSyncTask -Times 0 -Exactly
    }
}

Describe 'Invoke-ICTLapsRetry' {
    BeforeEach {
        Mock -ModuleName IntuneComplianceTool Test-ICTIsWindows { $true }
        Mock -ModuleName IntuneComplianceTool Invoke-ICTLapsPolicyProcessing { }
        Mock -ModuleName IntuneComplianceTool Start-Sleep { }
    }

    It 'reports success only when LAPS logged 10004' {
        Mock -ModuleName IntuneComplianceTool Get-ICTWinEvent { [pscustomobject]@{ Id = 10004; Message = 'LAPS policy processing succeeded.' } }
        (Invoke-ICTLapsRetry -Confirm:$false).Status | Should -Be 'Succeeded'
    }

    It 'reports a failure when LAPS logged 10005' {
        Mock -ModuleName IntuneComplianceTool Get-ICTWinEvent { [pscustomobject]@{ Id = 10005; Message = 'LAPS policy processing failed.' } }
        $result = Invoke-ICTLapsRetry -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.Succeeded | Should -BeFalse
    }

    It 'reports Pending when nothing was logged' {
        Mock -ModuleName IntuneComplianceTool Get-ICTWinEvent { }
        (Invoke-ICTLapsRetry -TimeoutSeconds 4 -Confirm:$false).Status | Should -Be 'Pending'
    }
}

Describe 'Invoke-ICTRemediation' {
    BeforeAll {
        function New-Evaluation {
            param([string[]]$Actions, [string[]]$ReEnrollBlockers = @(), [string[]]$SyncBlockers = @(), [object[]]$Results = @())
            [pscustomobject]@{ RecommendedActions = $Actions; ReEnrollBlockers = $ReEnrollBlockers; SyncBlockers = $SyncBlockers; Results = $Results }
        }
        function New-Outcome { param([string]$Status = 'Succeeded', [string]$Name = 'x') [pscustomobject]@{ Status = $Status; Succeeded = ($Status -eq 'Succeeded'); Message = "$Name $Status"; BackupPath = $null; Steps = @([pscustomobject]@{ Name = $Name; Status = 'Pass'; Detail = '' }) } }
    }

    BeforeEach {
        $m = 'IntuneComplianceTool'
        Mock -ModuleName $m Invoke-ICTSync { New-Outcome -Name 'Check-in' }
        Mock -ModuleName $m Invoke-ICTReEnrollment { New-Outcome -Name 'New enrollment' }
        Mock -ModuleName $m Invoke-ICTLapsRetry { New-Outcome -Name 'LAPS retry' }
        Mock -ModuleName $m Invoke-ICTTimeResync { }
        Mock -ModuleName $m Set-ICTServiceStartType { }
        Mock -ModuleName $m Start-ICTService { }
    }

    It 'does nothing when nothing is recommended' {
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @()) -Confirm:$false
        $result.Status | Should -Be 'NothingToDo'
        $result.ChangesMade | Should -BeFalse
    }

    It 'syncs and stops there when the sync works' {
        (Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('Sync')) -Confirm:$false).Status | Should -Be 'Succeeded'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 0 -Exactly
    }

    It 're-enrolls when the sync does not help' {
        Mock -ModuleName IntuneComplianceTool Invoke-ICTSync { New-Outcome -Status 'TimedOut' }
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('Sync')) -Confirm:$false
        $result.Status | Should -Be 'Succeeded'
        $result.Steps.Name | Should -Contain 'Escalate'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 1 -Exactly
    }

    It 'does not escalate when EscalateSyncToReEnroll is off' {
        Mock -ModuleName IntuneComplianceTool Invoke-ICTSync { New-Outcome -Status 'TimedOut' }
        $config = Get-ICTConfig
        $config.EscalateSyncToReEnroll = $false
        (Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('Sync')) -Config $config -Confirm:$false).Status | Should -Be 'Failed'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 0 -Exactly
    }

    It 'lets a sync run past re-enrollment-only blockers, but not escalate past them' {
        Mock -ModuleName IntuneComplianceTool Invoke-ICTSync { New-Outcome -Status 'TimedOut' }
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('Sync') -ReEnrollBlockers @('MDM auto-enrollment URL: not set')) -Confirm:$false
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTSync -Times 1 -Exactly
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 0 -Exactly
        $result.Status | Should -Be 'Blocked'
        $result.Blockers | Should -Be @('MDM auto-enrollment URL: not set')
    }

    It 'does not start the enrollment repair when blockers exist' {
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('ReEnroll') -ReEnrollBlockers @('Entra ID join: Not joined')) -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 0 -Exactly
    }

    It 'ignores evaluation blockers with -Force' {
        (Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('ReEnroll') -ReEnrollBlockers @('x')) -Force -Confirm:$false).Status | Should -Be 'Succeeded'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 1 -Exactly
    }

    It 'reports Failed, not Blocked, when a repair that ran failed' {
        Mock -ModuleName IntuneComplianceTool Invoke-ICTLapsRetry { New-Outcome -Status 'Failed' -Name 'LAPS retry' }
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('ReEnroll', 'LapsRetry') -ReEnrollBlockers @('x')) -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.Blockers | Should -Be @('x')
    }

    It 'resyncs the clock and repairs services before the enrollment' {
        $results = @(
            [pscustomobject]@{ Id = 'SVC-dmwappushservice'; Action = 'ServiceFix'; Actual = 'disabled' }
            [pscustomobject]@{ Id = 'SVC-IntuneManagementExtension'; Action = 'ServiceFix'; Actual = 'Stopped (Automatic)' }
        )
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('TimeSync', 'ServiceFix', 'ReEnroll') -Results $results) -Confirm:$false
        $result.Status | Should -Be 'Succeeded'
        $result.Steps.Name | Select-Object -First 3 | Should -Be @('Time sync', 'Service dmwappushservice', 'Service IntuneManagementExtension')
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Set-ICTServiceStartType -Times 1 -Exactly -ParameterFilter { $Name -eq 'dmwappushservice' -and $StartupType -eq 'Manual' }
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Start-ICTService -Times 1 -Exactly -ParameterFilter { $Name -eq 'IntuneManagementExtension' }
    }

    It 'skips the enrollment repair when the clock could not be fixed' {
        Mock -ModuleName IntuneComplianceTool Invoke-ICTTimeResync { throw 'w32tm failed' }
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('TimeSync', 'ReEnroll')) -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.Blockers | Should -Be @('Clock: could not be resynchronised')
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 0 -Exactly
    }

    It 'passes -WhatIf on and shows the possible escalation' {
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('TimeSync', 'Sync', 'LapsRetry')) -WhatIf
        $result.Status | Should -Be 'WhatIf'
        $result.ChangesMade | Should -BeFalse
        $result.Steps.Name | Should -Contain 'Escalate'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTTimeResync -Times 0 -Exactly
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTSync -Times 1 -Exactly -ParameterFilter { $WhatIf }
    }

    It 'reports Failed when the re-enrollment does not finish' {
        Mock -ModuleName IntuneComplianceTool Invoke-ICTReEnrollment { New-Outcome -Status 'Pending' }
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('ReEnroll')) -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.ChangesMade | Should -BeTrue
    }

    It 'uses the enrollment method from the config unless one is given' {
        $config = Get-ICTConfig
        $config.EnrollmentMethod = 'DeviceCredential'
        $null = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('ReEnroll')) -Config $config -Confirm:$false
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -ParameterFilter { $Method -eq 'DeviceCredential' }
    }
}
