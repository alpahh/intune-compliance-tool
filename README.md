# Intune Compliance Tool

Checks a Windows client's Intune MDM enrollment, compliance settings and Windows LAPS state, shows the result in the terminal, and can repair a broken enrollment. It is built to be run over SSH as the local admin account (`masteruser`).

```text
╭────────────────────────────────────────────────────────────────────────────╮
│  INTUNE COMPLIANCE TOOL  v0.1.0                PC-0421 · 2026-11-05 15:32  │
╰────────────────────────────────────────────────────────────────────────────╯

  Collecting  ✔ Device  ✔ Join  ✔ Enrollment  ✔ Services  ✔ Security
              ✔ LAPS  ✔ Network  ✔ Event log  (3.8 s)

  ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃   ENROLLMENT BROKEN    ┃   Recommended: RE-ENROLL · Repair possible: yes
  ┗━━━━━━━━━━━━━━━━━━━━━━━━┛

  CHECKS                                                ✔ 21   ✘ 3   ! 0   ? 0
  ── Enrollment ──────────────────────────────────────────────────────────────
    ✔  Intune enrollment          1 enrollment (8C2F41D0...)
    ✘  MDM certificate            expired 2026-10-28 (8 days ago)
    ✘  Last check-in              12 days ago (limit 7 days)
  ...
```

## Requirements

- **Client:** Windows 10/11 with Windows PowerShell 5.1 (or PowerShell 7), the built-in OpenSSH server, and an account in the local Administrators group.
- **Your Mac:** `ssh`/`scp` and PowerShell 7 (`pwsh`) to build the single-file script.

## Usage from the Mac

```bash
./ict.sh PC-0421                        # check and show the result
./ict.sh PC-0421 -Detailed              # with the reason and fix for every finding
./ict.sh PC-0421 -Remediate -WhatIf     # show what a repair would do
./ict.sh PC-0421 -Remediate             # repair
./ict.sh PC-0421 -Json | jq .OverallStatus
```

`ict.sh` connects as `masteruser@<host>` (override with `user@host` or `ICT_SSH_USER`), builds `dist/IntuneComplianceTool.ps1`, copies it to `C:\ProgramData\IntuneComplianceTool` on the client, runs it, removes it again and returns the tool's exit code. One SSH connection is reused, so a password is asked for only once.

**Use an SSH key.** `masteruser`'s password is rotated by Windows LAPS, and LAPS can reset the password and sign the account out after it has been used. For an administrator account, Windows OpenSSH reads keys from `C:\ProgramData\ssh\administrators_authorized_keys` (not from the user profile).

## Usage on the client

```powershell
.\IntuneComplianceTool.ps1 [-Remediate [-WhatIf] [-Force] [-EnrollmentMethod UserCredential|DeviceCredential]]
                           [-Detailed] [-Json] [-SaveReport [-ReportFormat Json|Html|Both]]
                           [-OutputDirectory <path>] [-ConfigPath <file.json>] [-NoColor] [-Ascii]
```

| Option | Effect |
|---|---|
| `-Remediate` | Repair what can be repaired. There is no prompt: the switch is the consent. |
| `-WhatIf` | With `-Remediate`: only show the plan, change nothing. |
| `-Force` | Repair even when blockers were found. |
| `-EnrollmentMethod` | `UserCredential` (default; needs a user signed in at the device) or `DeviceCredential`. |
| `-Detailed` | Reason and fix for every finding, plus the latest MDM error events. |
| `-Json` | Print only the full report as JSON. |
| `-SaveReport` | Also save JSON/HTML reports in `<OutputDirectory>\Reports`. |
| `-NoColor`, `-Ascii` | Plain output for terminals without colours or Unicode (`NO_COLOR` is honoured). |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Compliant |
| 1 | Not compliant or indeterminate (some data could not be read) |
| 2 | Enrollment broken and not repaired |
| 3 | Repair attempted but failed |
| 10 | Error |

## What is checked

| Group | Checks |
|---|---|
| Join | Entra / hybrid join, device authentication, MDM auto-enrollment URL (`dsregcmd /status`) |
| Enrollment | Intune enrollment (provider `MS DM Server`), MDM device certificate, sync tasks, last successful check-in |
| Health | `dmwappushservice`, Intune Management Extension, MDM error events |
| Network | WinHTTP proxy, TCP 443 to the Intune and Entra endpoints and to the tenant's MDM URL |
| Security | OS build, BitLocker, TPM, Secure Boot, Defender real-time protection and signature age, firewall profiles |
| LAPS | Policy and backup target, managed account (`masteruser`, enabled, administrator), last rotation, backup errors, post-sign-in actions |

The result is one of: **Compliant**, **Not compliant** (a setting is wrong; re-enrolling would not help), **Enrollment broken** (the device does not reach Intune properly) or **Indeterminate** (nothing failed, but some data could not be read).

The signed-in user is shown separately from the SSH account. User-specific data from `dsregcmd` (such as the Entra sign-in token) belongs to the SSH account and is not used for any check.

## How the repair works

`-Remediate` escalates step by step:

1. **Sync:** if only the last check-in is too old, the tool starts the `PushLaunch` task and waits for a successful check-in.
2. **Re-enroll:** if the sync does not help, or the enrollment, certificate or sync tasks are missing or broken:
   1. Check the prerequisites: Entra-joined, and someone signed in at the device for `UserCredential`.
   2. Back up every registry key, scheduled task and certificate that will be removed to `C:\ProgramData\IntuneComplianceTool\Backup\<timestamp>`. **If the backup fails, nothing is changed.**
   3. Remove the Intune enrollment, its scheduled tasks and registry keys, any orphaned EnterpriseMgmt task folders, and the Intune MDM device certificate.
   4. Run `deviceenroller.exe` **as SYSTEM** through a temporary scheduled task. The SSH session itself is the wrong context for enrollment.
   5. Wait for the new enrollment, then check the whole device again.
3. **LAPS retry:** if the LAPS backup failed or the rotation is overdue, run `Invoke-LapsPolicyProcessing` again.

The enrollment repair is not started when a blocker is found: the device isn't Entra-joined, device authentication fails, there's no MDM URL, an endpoint can't be reached, or the session isn't elevated. `-Force` overrides this. Problems like BitLocker, firewall or Defender are reported, but never "fixed" by re-enrolling.

Everything is logged to `C:\ProgramData\IntuneComplianceTool\ict.log`.

## Settings

Defaults live in [`src/IntuneComplianceTool/Private/DefaultConfig.ps1`](src/IntuneComplianceTool/Private/DefaultConfig.ps1). Override any of them with a JSON file passed as `-ConfigPath`:

```json
{
  "MinimumOSBuild": 22631,
  "MaxDaysSinceLastSync": 3,
  "LapsExpectedAccount": "masteruser",
  "EnrollmentMethod": "DeviceCredential"
}
```

## Development

```text
IntuneComplianceTool.ps1          entry script (imports the module from src/ when run from the repo)
src/IntuneComplianceTool/
  Public/                         Get-ICTDeviceData, Test-ICTCompliance, Format-ICTReport,
                                  Invoke-ICTRemediation, Invoke-ICTSync, Invoke-ICTReEnrollment, ...
  Private/Platform.ps1            every call that touches Windows (registry, cmdlets, exe files)
  Private/Rules.ps1               the checks
build/Build-IntuneComplianceTool.ps1   builds dist/IntuneComplianceTool.ps1 (single file)
ict.sh                            run on a client over SSH
tests/                            Pester 5 tests
```

All Windows access goes through `Private/Platform.ps1`, so everything else is tested with Pester mocks on any OS:

```bash
pwsh -NoProfile -Command "Invoke-Pester -Path tests -Output Detailed"
```

Source files must stay ASCII: Windows PowerShell 5.1 reads UTF-8 files without a BOM as ANSI. Build symbols from code points (`[char]0x2714`). A test enforces this, together with PowerShell 5.1-compatible syntax.

### To verify on a real client

These details come from documentation and community practice. They haven't been confirmed on a device yet:

- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State` → `LastPasswordUpdateTime`, and the LAPS success event IDs (`LapsSuccessEventIds`, default 10004 and 10029).
- `deviceenroller.exe /c /AutoEnrollMDM` started as SYSTEM, while a user is signed in, actually enrolls with that user's token.
- `Win32_ComputerSystem.UserName` shows the console user for both Entra and hybrid users.
