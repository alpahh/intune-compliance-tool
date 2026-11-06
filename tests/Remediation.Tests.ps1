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
        $script:backupDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))

        Mock -ModuleName $m Test-ICTIsWindows { $true }
        Mock -ModuleName $m Test-ICTIsElevated { $true }
        Mock -ModuleName $m Get-ICTDsregOutput { $dsregHybrid }
        Mock -ModuleName $m Get-ICTConsoleUser { 'CONTOSO\anna.berger' }
        Mock -ModuleName $m Get-ICTEnrollmentRegistry {
            if ($script:enrolled) {
                [pscustomobject]@{ EnrollmentId = $newId; ProviderId = 'MS DM Server'; IsIntune = $true }
            }
            else {
                [pscustomobject]@{ EnrollmentId = $oldId; ProviderId = 'MS DM Server'; IsIntune = $true }
                [pscustomobject]@{ EnrollmentId = '22222222-2222-2222-2222-222222222222'; ProviderId = 'Other MDM'; IsIntune = $false }
            }
        }
        Mock -ModuleName $m Get-ICTEnterpriseMgmtTask {
            [pscustomobject]@{ EnrollmentId = $oldId; TaskName = 'PushLaunch'; TaskPath = "\Microsoft\Windows\EnterpriseMgmt\$oldId\" }
            [pscustomobject]@{ EnrollmentId = $orphanId; TaskName = 'Schedule #1 created by enrollment client'; TaskPath = "\Microsoft\Windows\EnterpriseMgmt\$orphanId\" }
            [pscustomobject]@{ EnrollmentId = '22222222-2222-2222-2222-222222222222'; TaskName = 'Other'; TaskPath = '\Microsoft\Windows\EnterpriseMgmt\22222222-2222-2222-2222-222222222222\' }
        }
        Mock -ModuleName $m Test-ICTRegistryKey { $Path -match [regex]::Escape($oldId) -and $Path -notmatch 'Logger' }
        Mock -ModuleName $m Get-ICTMdmCertificate { [pscustomobject]@{ Thumbprint = 'ABC123'; Subject = 'CN=x' } }
        Mock -ModuleName $m Export-ICTRegistryKey { $script:calls.Add("backup-reg:$Path") }
        Mock -ModuleName $m Export-ICTScheduledTask { $script:calls.Add("backup-task:$TaskName") }
        Mock -ModuleName $m Export-ICTCertificate { $script:calls.Add("backup-cert:$Thumbprint") }
        Mock -ModuleName $m Remove-ICTEnterpriseMgmtTask { $script:calls.Add("remove-tasks:$EnrollmentId") }
        Mock -ModuleName $m Remove-ICTRegistryKey { $script:calls.Add("remove-reg:$Path") }
        Mock -ModuleName $m Remove-ICTCertificate { $script:calls.Add("remove-cert:$Thumbprint") }
        Mock -ModuleName $m Start-ICTDeviceEnrollerAsSystem { $script:calls.Add("enroll:$Argument"); $script:enrolled = $true; 0 }
        Mock -ModuleName $m Start-Sleep { }
    }

    It 'changes nothing with -WhatIf but returns the full plan' {
        $result = Invoke-ICTReEnrollment -BackupDirectory $backupDir -WhatIf
        $result.Status | Should -Be 'WhatIf'
        $calls.Count | Should -Be 0
        $result.Plan | Should -Contain "Remove registry key HKLM:\SOFTWARE\Microsoft\Enrollments\$oldId"
        $result.Plan | Should -Contain "Remove scheduled task \Microsoft\Windows\EnterpriseMgmt\$orphanId\Schedule #1 created by enrollment client"
        $result.Plan | Should -Contain 'Remove certificate ABC123 (CN=x)'
        $result.Plan[-1] | Should -Be 'Run deviceenroller.exe /c /AutoEnrollMDM as SYSTEM'
        Test-Path $backupDir | Should -BeFalse
    }

    It 'backs up everything before removing anything, then enrolls as SYSTEM' {
        $result = Invoke-ICTReEnrollment -BackupDirectory $backupDir -Confirm:$false
        $result.Status | Should -Be 'Succeeded'
        $result.Succeeded | Should -BeTrue
        $result.NewEnrollmentId | Should -Be $newId

        $firstRemove = $calls.FindIndex({ param($c) $c.StartsWith('remove-') })
        $lastBackup = $calls.FindLastIndex({ param($c) $c.StartsWith('backup-') })
        $lastBackup | Should -BeLessThan $firstRemove
        $calls[-1] | Should -Be 'enroll:/c /AutoEnrollMDM'

        Test-Path (Join-Path $result.BackupPath 'plan.txt') | Should -BeTrue
    }

    It 'removes the Intune enrollment and orphaned task folders, but not other MDM enrollments' {
        $result = Invoke-ICTReEnrollment -BackupDirectory $backupDir -Confirm:$false
        $calls | Should -Contain "remove-tasks:$oldId"
        $calls | Should -Contain "remove-tasks:$orphanId"
        $calls | Should -Not -Contain 'remove-tasks:22222222-2222-2222-2222-222222222222'
        @($calls | Where-Object { $_ -like 'remove-reg:*' }).Count | Should -Be 7
        $calls | Should -Contain 'remove-cert:ABC123'
        $result.RemovedEnrollmentIds | Should -Contain $oldId
    }

    It 'keeps the certificate with -KeepCertificate' {
        $null = Invoke-ICTReEnrollment -BackupDirectory $backupDir -KeepCertificate -Confirm:$false
        @($calls | Where-Object { $_ -like '*cert*' }).Count | Should -Be 0
    }

    It 'stops without changes when the backup fails' {
        Mock -ModuleName IntuneComplianceTool Export-ICTRegistryKey { throw 'reg.exe failed' }
        $result = Invoke-ICTReEnrollment -BackupDirectory $backupDir -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.Message | Should -Match 'nothing was changed'
        @($calls | Where-Object { $_ -like 'remove-*' -or $_ -like 'enroll:*' }).Count | Should -Be 0
    }

    It 'points to the backup when removal stops part-way' {
        Mock -ModuleName IntuneComplianceTool Remove-ICTRegistryKey { throw 'Access denied' }
        $result = Invoke-ICTReEnrollment -BackupDirectory $backupDir -Confirm:$false
        $result.Status | Should -Be 'Failed'
        $result.Message | Should -Match ([regex]::Escape($result.BackupPath))
        @($calls | Where-Object { $_ -like 'enroll:*' }).Count | Should -Be 0
    }

    It 'is blocked when the device is not Entra joined' {
        Mock -ModuleName IntuneComplianceTool Get-ICTDsregOutput { $dsregNotJoined }
        $result = Invoke-ICTReEnrollment -BackupDirectory $backupDir -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $calls.Count | Should -Be 0
    }

    It 'is blocked for UserCredential when nobody is signed in' {
        Mock -ModuleName IntuneComplianceTool Get-ICTConsoleUser { $null }
        $result = Invoke-ICTReEnrollment -BackupDirectory $backupDir -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Message | Should -Match 'DeviceCredential'
    }

    It 'enrolls with the device credential without needing a signed-in user' {
        Mock -ModuleName IntuneComplianceTool Get-ICTConsoleUser { $null }
        $result = Invoke-ICTReEnrollment -Method DeviceCredential -BackupDirectory $backupDir -Confirm:$false
        $result.Status | Should -Be 'Succeeded'
        $calls[-1] | Should -Be 'enroll:/c /AutoEnrollMDMUsingAADDeviceCredential'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Get-ICTConsoleUser -Times 0 -Exactly
    }

    It 'reports Pending when no new enrollment appears in time' {
        Mock -ModuleName IntuneComplianceTool Start-ICTDeviceEnrollerAsSystem { 0 }
        $result = Invoke-ICTReEnrollment -BackupDirectory $backupDir -TimeoutSeconds 30 -PollIntervalSeconds 10 -Confirm:$false
        $result.Status | Should -Be 'Pending'
        $result.Succeeded | Should -BeFalse
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Start-Sleep -Times 3 -Exactly
    }

    It 'refuses to run without administrator rights' {
        Mock -ModuleName IntuneComplianceTool Test-ICTIsElevated { $false }
        { Invoke-ICTReEnrollment -BackupDirectory $backupDir -Confirm:$false } | Should -Throw '*administrator*'
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

    It 'times out when the check-in does not move' {
        Mock -ModuleName IntuneComplianceTool Start-Sleep { }
        $result = Invoke-ICTSync -TimeoutSeconds 30 -PollIntervalSeconds 15 -Confirm:$false
        $result.Status | Should -Be 'TimedOut'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Start-Sleep -Times 2 -Exactly
    }

    It 'fails when the PushLaunch task is missing' {
        Mock -ModuleName IntuneComplianceTool Start-ICTEnterpriseMgmtSyncTask { $false }
        (Invoke-ICTSync -Confirm:$false).Status | Should -Be 'Failed'
    }

    It 'does nothing with -WhatIf' {
        $result = Invoke-ICTSync -WhatIf
        $result.Status | Should -Be 'WhatIf'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Start-ICTEnterpriseMgmtSyncTask -Times 0 -Exactly
    }
}

Describe 'Invoke-ICTRemediation' {
    BeforeAll {
        function New-Evaluation {
            param([string[]]$Actions, [string[]]$Blockers = @())
            [pscustomobject]@{ RecommendedActions = $Actions; Blockers = $Blockers; CanRepairEnrollment = ($Blockers.Count -eq 0) }
        }
    }

    BeforeEach {
        $m = 'IntuneComplianceTool'
        Mock -ModuleName $m Invoke-ICTSync { [pscustomobject]@{ Status = 'Succeeded'; Succeeded = $true; Message = $null; Steps = @([pscustomobject]@{ Name = 'Check-in'; Status = 'Pass'; Detail = 'ok' }) } }
        Mock -ModuleName $m Invoke-ICTReEnrollment { [pscustomobject]@{ Status = 'Succeeded'; Succeeded = $true; BackupPath = 'C:\b'; Message = $null; Steps = @([pscustomobject]@{ Name = 'New enrollment'; Status = 'Pass'; Detail = 'ok' }) } }
        Mock -ModuleName $m Invoke-ICTLapsRetry { [pscustomobject]@{ Status = 'Succeeded'; Succeeded = $true; Message = $null; Steps = @([pscustomobject]@{ Name = 'LAPS retry'; Status = 'Pass'; Detail = 'ok' }) } }
    }

    It 'does nothing when nothing is recommended' {
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @()) -Confirm:$false
        $result.Status | Should -Be 'NothingToDo'
        $result.ChangesMade | Should -BeFalse
    }

    It 'syncs and stops there when the sync works' {
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('Sync')) -Confirm:$false
        $result.Status | Should -Be 'Succeeded'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 0 -Exactly
    }

    It 're-enrolls when the sync does not help' {
        Mock -ModuleName IntuneComplianceTool Invoke-ICTSync { [pscustomobject]@{ Status = 'TimedOut'; Succeeded = $false; Message = 'no check-in'; Steps = @() } }
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('Sync')) -Confirm:$false
        $result.Status | Should -Be 'Succeeded'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 1 -Exactly
        $result.Steps.Name | Should -Contain 'Escalate'
    }

    It 'does not start the enrollment repair when blockers exist' {
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('ReEnroll') -Blockers @('Entra ID join: Not joined')) -Confirm:$false
        $result.Status | Should -Be 'Blocked'
        $result.Blockers | Should -Be @('Entra ID join: Not joined')
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 0 -Exactly
    }

    It 'ignores blockers with -Force and skips the prerequisite check' {
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('ReEnroll') -Blockers @('x')) -Force -Confirm:$false
        $result.Status | Should -Be 'Succeeded'
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 1 -Exactly -ParameterFilter { $SkipPrerequisiteCheck }
    }

    It 'passes -WhatIf on and reports a preview' {
        $result = Invoke-ICTRemediation -Evaluation (New-Evaluation -Actions @('ReEnroll', 'LapsRetry')) -WhatIf
        $result.Status | Should -Be 'WhatIf'
        $result.ChangesMade | Should -BeFalse
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTReEnrollment -Times 1 -Exactly -ParameterFilter { $WhatIf }
        Should -Invoke -ModuleName IntuneComplianceTool -CommandName Invoke-ICTLapsRetry -Times 1 -Exactly -ParameterFilter { $WhatIf }
    }

    It 'reports Failed when the re-enrollment does not finish' {
        Mock -ModuleName IntuneComplianceTool Invoke-ICTReEnrollment { [pscustomobject]@{ Status = 'Pending'; Succeeded = $false; BackupPath = 'C:\b'; Message = 'pending'; Steps = @() } }
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
