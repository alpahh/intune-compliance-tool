# Runs the real Windows calls instead of mocks. Needs Windows and an elevated session
# (GitHub Actions Windows runners are elevated). Skipped everywhere else.
# The 'Running as SYSTEM' tests create scheduled tasks, keys and certificates, so they
# only run in CI, or when ICT_RUN_SYSTEM_TESTS=1 is set, never on a managed device by accident.

BeforeDiscovery {
    $script:runHere = $false
    if ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
        $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
        $script:runHere = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    $script:runSystem = ($runHere -and ($env:GITHUB_ACTIONS -eq 'true' -or $env:ICT_RUN_SYSTEM_TESTS -eq '1'))
}

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/IntuneComplianceTool/IntuneComplianceTool.psd1') -Force
}

Describe 'Windows data collection' -Tag 'Windows' -Skip:(-not $runHere) {
    It 'reads the device' {
        InModuleScope IntuneComplianceTool {
            $info = Get-ICTSystemInfo
            $info.OSBuild | Should -BeGreaterThan 10000
            $info.LastBootTime | Should -Not -BeNullOrEmpty
        }
    }

    It 'parses the real dsregcmd output' {
        InModuleScope IntuneComplianceTool {
            (ConvertFrom-ICTDsregOutput -Line (Get-ICTDsregOutput)).JoinType | Should -BeIn @('EntraJoined', 'HybridJoined', 'DomainJoinedOnly', 'WorkplaceJoined', 'NotJoined')
        }
    }

    It 'reads enrollment state without errors on an unenrolled device' {
        InModuleScope IntuneComplianceTool {
            { $null = @(Get-ICTEnrollmentRegistry) } | Should -Not -Throw
            { $null = @(Get-ICTMdmCertificate) } | Should -Not -Throw
            { $null = @(Get-ICTEnterpriseMgmtTask) } | Should -Not -Throw
            { $null = Get-ICTAutoEnrollState } | Should -Not -Throw
            { $null = Get-ICTLapsPolicy } | Should -Not -Throw
            { $null = Get-ICTConfigMgrState } | Should -Not -Throw
        }
    }

    It 'reads the extension logs from the folder, within the time window' {
        $original = $env:ProgramData
        $temporary = Join-Path $env:TEMP ('ICT-CI-' + [guid]::NewGuid().ToString('N'))
        $logs = Join-Path $temporary 'Microsoft\IntuneManagementExtension\Logs'
        $null = New-Item -Path $logs -ItemType Directory -Force
        Set-Content -LiteralPath (Join-Path $logs 'new.log') -Value 'recent'
        Set-Content -LiteralPath (Join-Path $logs 'old.log') -Value 'stale'
        (Get-Item -LiteralPath (Join-Path $logs 'old.log')).LastWriteTime = (Get-Date).AddDays(-30)
        try {
            $env:ProgramData = $temporary
            InModuleScope IntuneComplianceTool { @(Get-ICTImeLogText -Days 7) | Should -Be @('recent') }
            $env:ProgramData = Join-Path $temporary 'missing'
            InModuleScope IntuneComplianceTool { { Get-ICTImeLogText -Days 7 } | Should -Throw '*does not exist*' }
        }
        finally {
            $env:ProgramData = $original
            Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports no ConfigMgr client on a CI runner' -Skip:($env:GITHUB_ACTIONS -ne 'true') {
        InModuleScope IntuneComplianceTool { (Get-ICTConfigMgrState).ClientInstalled | Should -BeFalse }
    }

    It 'reads the effective firewall profiles' {
        InModuleScope IntuneComplianceTool { @(Get-ICTFirewallState).Count | Should -Be 3 }
    }

    It 'reads services, reboot flags and the proxy' {
        InModuleScope IntuneComplianceTool {
            (Get-ICTServiceState -Name 'W32Time', 'NoSuchServiceHere')[0].Present | Should -BeTrue
            (Get-ICTServiceState -Name 'NoSuchServiceHere').Present | Should -BeFalse
            (Get-ICTPendingReboot).Pending | Should -BeOfType [bool]
            (Get-ICTWinHttpProxy).ProxyConfigured | Should -BeOfType [bool]
        }
    }

    It 'tests several endpoints at once' {
        InModuleScope IntuneComplianceTool {
            $results = @(Test-ICTTcpEndpoint -HostName 'github.com', 'no-such-host.invalid' -Port 443 -TimeoutMs 8000)
            $results.Count | Should -Be 2
            ($results | Where-Object { $_.HostName -eq 'github.com' }).Reachable | Should -BeTrue
            ($results | Where-Object { $_.HostName -eq 'no-such-host.invalid' }).Reachable | Should -BeFalse
        }
    }

    It 'measures the clock offset' {
        InModuleScope IntuneComplianceTool { [math]::Abs((Get-ICTClockOffset)) | Should -BeLessThan 300 }
    }

    It 'filters event logs and returns nothing when no event matches' {
        InModuleScope IntuneComplianceTool {
            $event = @(Get-ICTWinEvent -LogName 'System' -XPath '*[System[Level=4]]' -MaxEvents 1)[0]
            $event.TimeCreated | Should -Not -BeNullOrEmpty
            @(Get-ICTWinEvent -LogName 'System' -XPath '*[System[EventID=65000]]' -MaxEvents 1).Count | Should -Be 0
        }
    }

    It 'finds the current admin in the local Administrators group' {
        InModuleScope IntuneComplianceTool {
            $name = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
            $account = Get-ICTLocalAccount -Name $name
            $account.Exists | Should -BeTrue
            $account.IsAdministrator | Should -BeTrue
            (Get-ICTLocalAccount).Exists | Should -BeTrue -Because 'the built-in Administrator always exists'
            (Get-ICTLocalAccount -Name 'NoSuchUserHere').Exists | Should -BeFalse
        }
    }
}

Describe 'Protected folders' -Tag 'Windows' -Skip:(-not $runHere) {
    BeforeEach {
        $script:folder = Join-Path $env:ProgramData ('ICT-CI-' + [guid]::NewGuid().ToString('N'))
    }
    AfterEach {
        if (Test-Path -LiteralPath $folder) { cmd /c rmdir /s /q "$folder" }
    }

    It 'creates a folder only SYSTEM and Administrators can access' {
        InModuleScope IntuneComplianceTool -Parameters @{ Folder = $folder } { Protect-ICTDirectory -Path $Folder }
        $acl = Get-Acl -LiteralPath $folder
        $acl.AreAccessRulesProtected | Should -BeTrue
        @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique) | Should -Be @('S-1-5-18', 'S-1-5-32-544')
        $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value | Should -Be 'S-1-5-32-544'
    }

    It 'refuses a folder that contains a junction' {
        $null = New-Item -Path $folder -ItemType Directory
        $null = New-Item -Path (Join-Path $folder 'Backup') -ItemType Junction -Value $env:TEMP
        InModuleScope IntuneComplianceTool -Parameters @{ Folder = $folder } {
            { Protect-ICTDirectory -Path $Folder } | Should -Throw '*junction*'
        }
    }

    It 'refuses a folder with a child owned by a standard group' {
        $null = New-Item -Path (Join-Path $folder 'Backup') -ItemType Directory -Force
        & icacls.exe (Join-Path $folder 'Backup') /setowner '*S-1-5-32-545' | Out-Null
        $LASTEXITCODE | Should -Be 0
        InModuleScope IntuneComplianceTool -Parameters @{ Folder = $folder } {
            { Protect-ICTDirectory -Path $Folder } | Should -Throw '*owned by S-1-5-32-545*'
        }
    }

    It 'creates unique private subfolders' {
        InModuleScope IntuneComplianceTool -Parameters @{ Folder = $folder } {
            $first = New-ICTPrivateDirectory -Parent $Folder -Prefix 'run'
            $second = New-ICTPrivateDirectory -Parent $Folder -Prefix 'run'
            $first | Should -Not -Be $second
            (Get-Acl -LiteralPath $first).AreAccessRulesProtected | Should -BeTrue
        }
    }
}

Describe 'Running as SYSTEM' -Tag 'Windows' -Skip:(-not $runSystem) {
    BeforeEach {
        $script:folder = Join-Path $env:ProgramData ('ICT-CI-' + [guid]::NewGuid().ToString('N'))
        InModuleScope IntuneComplianceTool -Parameters @{ Folder = $folder } { Protect-ICTDirectory -Path $Folder }
    }
    AfterEach {
        if (Test-Path -LiteralPath $folder) { cmd /c rmdir /s /q "$folder" }
    }

    It 'runs a script as SYSTEM and removes the task afterwards' {
        $script = Join-Path $folder 'who.ps1'
        $output = Join-Path $folder 'who.txt'
        Set-Content -LiteralPath $script -Value "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value | Set-Content -LiteralPath '$output'"
        InModuleScope IntuneComplianceTool -Parameters @{ ScriptFile = $script; Output = $output } {
            $task = Start-ICTSystemScript -ScriptPath $ScriptFile
            $value = $null
            for ($i = 0; $i -lt 60 -and -not $value; $i++) { Start-Sleep -Seconds 1; $value = Get-Content -LiteralPath $Output -ErrorAction SilentlyContinue }
            $value | Should -Be 'S-1-5-18'
            for ($i = 0; $i -lt 30 -and (Test-ICTRepairRunning); $i++) { Start-Sleep -Seconds 1 }
            (Get-ICTSystemTaskState -TaskName $task).State | Should -Be 'Ready'
            Remove-ICTSystemTask -TaskName $task
            Get-ICTSystemTaskState -TaskName $task | Should -BeNullOrEmpty
        }
    }

    It 'removes registry keys, certificates and task folders with the generated script' {
        $id = [guid]::NewGuid().ToString().ToUpperInvariant()
        $key = "HKLM:\SOFTWARE\ICT-CI-$id"
        $null = New-Item -Path $key -Force
        $certificate = New-SelfSignedCertificate -Subject "CN=ict-ci-$id" -CertStoreLocation 'Cert:\LocalMachine\My'
        $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit 0'
        $taskPath = "\Microsoft\Windows\EnterpriseMgmt\$id\"
        $null = Register-ScheduledTask -TaskName 'PushLaunch' -TaskPath $taskPath -Action $action -User 'SYSTEM' -Force
        $state = Join-Path $folder 'state.jsonl'
        $script = Join-Path $folder 'repair.ps1'

        try {
            # cmd.exe instead of deviceenroller.exe: this test must never enroll the machine.
            InModuleScope IntuneComplianceTool -Parameters @{ Key = $key; Id = $id; Thumbprint = $certificate.Thumbprint; State = $state; ScriptFile = $script } {
                $text = New-ICTRepairScript -RegistryPath @($Key) -EnrollmentId @($Id) -Thumbprint @($Thumbprint) -EnrollerPath (Join-Path $env:windir 'System32\cmd.exe') -EnrollerArgument '/c exit 0' -StatePath $State
                Set-Content -LiteralPath $ScriptFile -Value $text -Encoding UTF8
                $task = Start-ICTSystemScript -ScriptPath $ScriptFile
                try {
                    $end = $null
                    for ($i = 0; $i -lt 120 -and -not $end; $i++) {
                        Start-Sleep -Seconds 1
                        $lines = @(Get-ICTSystemScriptState -Path $State)
                        $end = $lines | Where-Object { $_.Stage -eq 'end' } | Select-Object -Last 1
                    }
                    $end | Should -Not -BeNullOrEmpty -Because 'the script must report its end'
                    $end.Status | Should -Be 'Succeeded' -Because $end.Detail
                    ($lines | Where-Object { $_.Stage -eq 'tasks' }).Detail | Should -Be '1 tasks removed'
                    ($lines | Where-Object { $_.Stage -eq 'registry' }).Detail | Should -Be '1 registry keys removed'
                    ($lines | Where-Object { $_.Stage -eq 'certificates' }).Detail | Should -Be '1 certificates removed'
                    ($lines | Where-Object { $_.Stage -eq 'enroll' }).Detail | Should -Be 'exit 0'
                }
                finally {
                    Stop-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction SilentlyContinue
                    Remove-ICTSystemTask -TaskName $task
                }
            }

            Test-Path -LiteralPath $key | Should -BeFalse
            Test-Path -LiteralPath "Cert:\LocalMachine\My\$($certificate.Thumbprint)" | Should -BeFalse
            Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
        finally {
            Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName 'PushLaunch' -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
            try {
                $scheduler = New-Object -ComObject 'Schedule.Service'
                $scheduler.Connect()
                $scheduler.GetFolder('\Microsoft\Windows\EnterpriseMgmt').DeleteFolder($id, 0)
            }
            catch { Write-Verbose 'The test task folder is already gone.' }
            try { [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate).Key.Delete() } catch { Write-Verbose 'The test key is already gone.' }
        }
    }

    It 'exports keys, tasks and certificates for the backup' {
        $id = [guid]::NewGuid().ToString('N')
        $key = "HKLM:\SOFTWARE\ICT-CI-$id"
        $null = New-Item -Path $key -Force
        $certificate = New-SelfSignedCertificate -Subject "CN=ict-ci-$id" -CertStoreLocation 'Cert:\LocalMachine\My'
        $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit 0'
        $null = Register-ScheduledTask -TaskName "ICT-CI-$id" -TaskPath '\' -Action $action -Force
        try {
            InModuleScope IntuneComplianceTool -Parameters @{ Key = $key; Id = $id; Thumbprint = $certificate.Thumbprint; Folder = $folder } {
                Export-ICTRegistryKey -Path $Key -Destination (Join-Path $Folder 'k.reg')
                Export-ICTCertificate -Thumbprint $Thumbprint -Destination (Join-Path $Folder 'c.cer')
                Export-ICTScheduledTask -TaskName "ICT-CI-$Id" -TaskPath '\' -Destination (Join-Path $Folder 't.xml')
            }
            foreach ($file in 'k.reg', 'c.cer', 't.xml') { (Get-Item -LiteralPath (Join-Path $folder $file)).Length | Should -BeGreaterThan 0 }
        }
        finally {
            Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
            try { [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate).Key.Delete() } catch { Write-Verbose 'The test key is already gone.' }
            Unregister-ScheduledTask -TaskName "ICT-CI-$id" -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}
