# Intune Compliance Tool

Checks a Windows client's Intune MDM enrollment, compliance settings and Windows LAPS state, shows the result in the terminal, and can repair a broken enrollment. It is built to be run over SSH as the local admin account (`masteruser`).

```text
╭────────────────────────────────────────────────────────────────────────────╮
│  INTUNE COMPLIANCE TOOL  v0.2.0                PC-0421 · 2026-11-05 15:32  │
╰────────────────────────────────────────────────────────────────────────────╯

  Collecting  ✔ Device  ✔ Join  ✔ Enrollment  ✔ Services  ✔ Security  ✔ LAPS
              ✔ Network  ✔ Event log  (3.1 s)

  ┏━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃   ENROLLMENT BROKEN    ┃   Recommended: RE-ENROLL
  ┗━━━━━━━━━━━━━━━━━━━━━━━━┛   Repair possible: yes

  CHECKS                                                ✔ 26   ✘ 2   ! 0   ? 0
  ── Enrollment ──────────────────────────────────────────────────────────────
    ✔  Intune enrollment          1 enrollment (8C2F41D0...)
    ✘  MDM certificate            expired 2026-10-28 (8 days ago)
    ✔  Sync tasks                 8 tasks present
    ✘  Last check-in              12 days ago (limit 7 days)
  ...
```

## Requirements

- **Client:** Windows 10/11 with Windows PowerShell 5.1, the built-in OpenSSH server (default shell cmd.exe or PowerShell), and an account in the local Administrators group.
- **Your Mac:** `ssh`, `scp` and PowerShell 7 (`pwsh`, only to build the single-file script).

## Usage from the Mac

```bash
./ict.sh PC-0421                          # check and show the result
./ict.sh PC-0421 -Detailed                # with the reason and fix for every finding
./ict.sh PC-0421 -Remediate -WhatIf       # show what a repair would do
./ict.sh PC-0421 -Remediate               # repair
./ict.sh PC-0421 -CollectDiagnostics      # also copy the MDM diagnostics ZIP to ./diagnostics
./ict.sh PC-0421,PC-0422,PC-0423          # several devices: one summary table
./ict.sh -f hosts.txt                     # hosts from a file
./ict.sh PC-0421 -Json | jq .OverallStatus
```

`ict.sh` connects as `masteruser@<host>` (override with `user@host` or `ICT_SSH_USER`). It builds `dist/IntuneComplianceTool.ps1` when the sources changed, copies it into the account's profile folder on the client, runs it, deletes it again and returns the tool's exit code. One SSH connection per host is reused. Several hosts run in parallel (`ICT_PARALLEL`, default 4) and need key-based login.

**Use an SSH key.** `masteruser`'s password is rotated by Windows LAPS, and LAPS can reset the password and sign the account out after it has been used. For an administrator account, Windows OpenSSH reads keys from `C:\ProgramData\ssh\administrators_authorized_keys` (not from the user profile).

## Options

```powershell
.\IntuneComplianceTool.ps1 [-Remediate [-WhatIf] [-Force] [-EnrollmentMethod UserCredential|DeviceCredential]]
                           [-Detailed | -Json | -Summary] [-SaveReport] [-CollectDiagnostics]
                           [-OutputDirectory <path>] [-ConfigPath <file.json>] [-NoColor] [-Ascii]
```

| Option | Effect |
|---|---|
| `-Remediate` | Repair what can be repaired. There is no prompt: the switch is the consent. |
| `-WhatIf` | With `-Remediate`: only show the plan, change nothing. |
| `-Force` | Start the enrollment repair even when blockers were found. The re-enrollment's own safety checks (Entra join, a usable signed-in user) still apply. |
| `-EnrollmentMethod` | `UserCredential` (default; needs an Entra or domain user signed in at the console) or `DeviceCredential`. |
| `-Detailed` | Reason and fix for every finding, plus the latest MDM error events. |
| `-Json` / `-Summary` | Print only the full report as JSON, or one tab-separated summary line. |
| `-SaveReport` | Also save the JSON report in `<OutputDirectory>\Reports`. |
| `-CollectDiagnostics` | Also export MDM diagnostics (`MdmDiagnosticsTool.exe`) to `ict-diagnostics.zip` in the profile folder; `ict.sh` copies it to the Mac. |
| `-NoColor`, `-Ascii` | Plain output for terminals without colours or Unicode (`NO_COLOR` is honoured). |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Compliant |
| 1 | Not compliant, or indeterminate (some data could not be read) |
| 2 | Enrollment broken and not repaired |
| 3 | Repair attempted but failed |
| 10 | Error (including a mistyped option) |
| 12 | `ict.sh` could not copy the script to the client |
| 255 | `ssh` could not connect |

With several hosts, `ict.sh` returns the highest code.

## What is checked

| Group | Checks |
|---|---|
| Join | Entra / hybrid join, device authentication, MDM auto-enrollment URL, Entra device certificate and key (`dsregcmd /status`) |
| Enrollment | Intune enrollment, MDM device certificate, sync tasks, last successful check-in; for an unenrolled device the last auto-enrollment error (decoded) and the "managed by another MDM" flag |
| Health | `dmwappushservice`, Intune Management Extension, MDM error events, pending reboot and uptime |
| Network | WinHTTP proxy, TCP 443 to the Intune and Entra endpoints (all at once), clock skew against Microsoft's servers |
| Security | OS build and, optionally, patch level (UBR), BitLocker, TPM, Secure Boot, Defender real-time protection and signature age, firewall (effective policy) |
| LAPS | Policy (Intune, Group Policy, local or legacy) and backup target, managed account (also with automatic account management), last rotation, backup errors, post-sign-in actions |

The result is one of: **Compliant**, **Not compliant** (a setting is wrong; re-enrolling would not help), **Enrollment broken** (the device does not reach Intune properly) or **Indeterminate** (nothing failed, but some data could not be read). Data that cannot be read is always reported as unknown, never as missing, so it never triggers a repair.

The person signed in at the device is shown separately from the SSH account. User-specific data from `dsregcmd` belongs to the SSH account and is not used.

## How the repair works

`-Remediate` runs what the evaluation recommends, in this order:

1. **Time sync:** if the clock is off by more than a minute, the tool resynchronises it (`w32tm /resync`). Certificate checks fail when the skew is large.
2. **Services:** a disabled `dmwappushservice` is set back to Manual; a stopped or disabled Intune Management Extension is started.
3. **Enrollment:**
   - If only the last check-in is too old, the tool starts a sync (`PushLaunch` task) and waits for a successful check-in.
   - If the sync does not help, or the enrollment, certificate or sync tasks are missing or broken, it **re-enrolls**:
     1. Check the prerequisites: the device is Entra-joined; for `UserCredential` an Entra or domain user is signed in at the console (not a local account, not `masteruser`).
     2. Back up every registry key, scheduled task and certificate that will be removed, and write `restore.txt` with the commands to put them back. **If the backup fails, nothing is changed.**
     3. Run the removal and `deviceenroller.exe` **as SYSTEM** in a temporary scheduled task. A dropped SSH session or Ctrl+C cannot stop it half-way.
     4. Wait until a complete new enrollment exists (a new enrollment key and a new MDM certificate), then check the device again.
4. **LAPS:** if the backup failed or the rotation is overdue, run `Invoke-LapsPolicyProcessing` and read the real outcome from the LAPS event log.

The enrollment repair does not start when a blocker is found: for example the device isn't Entra-joined, an endpoint can't be reached, auto-enrollment failed for a reason a new attempt would hit again (no license, user not in MDM scope), or the session isn't elevated. A plain sync is only blocked by problems that would stop it too. `-Force` overrides the blockers, but not the re-enrollment's own safety checks. Problems like BitLocker, firewall or Defender are reported but never "fixed" by re-enrolling.

Everything is logged to `C:\ProgramData\IntuneComplianceTool\ict.log`. That folder, the reports and the backups are restricted to SYSTEM and Administrators. A folder created by anyone else is refused, because the repair runs a script from it as SYSTEM.

## Settings

Defaults live in [`src/IntuneComplianceTool/Private/DefaultConfig.ps1`](src/IntuneComplianceTool/Private/DefaultConfig.ps1). Override any of them with a JSON file passed as `-ConfigPath`:

```json
{
  "MinimumOSBuild": 22631,
  "MinimumOSRevision": { "22631": 4460, "26100": 2314 },
  "MaxDaysSinceLastSync": 3,
  "LapsExpectedAccount": "masteruser",
  "EnrollmentMethod": "DeviceCredential",
  "EscalateSyncToReEnroll": false
}
```

## Development

```text
IntuneComplianceTool.ps1          entry script (imports the module from src/ when run from the repo)
src/IntuneComplianceTool/
  Public/                         Get-ICTDeviceData, Test-ICTCompliance, Format-ICTReport,
                                  Invoke-ICTRemediation, Invoke-ICTReEnrollment, Invoke-ICTSync, ...
  Private/Platform.ps1            every call that touches Windows (registry, cmdlets, COM, exe files)
  Private/Rules.ps1               the checks
  Private/RepairScript.ps1        the script the re-enrollment runs as SYSTEM
build/Build-IntuneComplianceTool.ps1   builds dist/IntuneComplianceTool.ps1 (single file, comments stripped)
ict.sh                            run on clients over SSH
tests/                            Pester 5 tests
```

All Windows access goes through `Private/Platform.ps1`, so everything else is tested with Pester mocks on any OS:

```bash
pwsh -NoProfile -Command "Invoke-Pester -Path tests -Output Detailed"
```

Source files must stay ASCII: Windows PowerShell 5.1 reads UTF-8 files without a BOM as ANSI. Build symbols from code points (`[char]0x2714`). Tests enforce this, together with PowerShell 5.1-compatible syntax.

### To verify on a real client

These details come from documentation and community practice. They haven't been confirmed on a device yet:

- `deviceenroller.exe /c /AutoEnrollMDM` started as SYSTEM, while an Entra user is signed in at the console, enrolls with that user's token.
- `LastPasswordUpdateTime` in `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State`, and the LAPS event IDs (10004/10029 success, 10005 failure).
- The auto-enrollment events 75/76 and the HRESULT in their message.
- `MdmDiagnosticsTool.exe -area ... -zip ...` with the areas used here.
