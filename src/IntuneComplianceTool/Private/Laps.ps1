function New-ICTLapsState {
    <#
        Combines the separately collected LAPS pieces into one object. Pure function:
        it only interprets values, so it is fully unit tested.
        $Events: $null = event log could not be read, empty array = no events.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Policy,
        [AllowNull()][object]$Account,
        [AllowNull()][string]$LastPasswordUpdate,
        [AllowNull()][object[]]$Events,
        [int[]]$SuccessEventIds = @(10004, 10029),
        [int]$LookbackDays = 7
    )

    if ($null -eq $Policy) {
        return [pscustomobject]@{
            Configured                        = $false
            PolicySource                      = $null
            BackupTarget                      = $null
            AdministratorAccountName          = $null
            PasswordAgeDays                   = $null
            PostAuthenticationActions         = $null
            PostAuthenticationResetDelayHours = $null
            LastPasswordUpdateTime            = $null
            Account                           = $null
            Events                            = $null
        }
    }

    $backupTarget = switch ([int]$Policy.BackupDirectory) {
        0 { 'Disabled' }
        1 { 'EntraId' }
        2 { 'ActiveDirectory' }
        default { 'Unknown' }
    }

    # Windows LAPS defaults when the policy leaves a value unset.
    $passwordAgeDays = 30
    if ($null -ne $Policy.PasswordAgeDays) { $passwordAgeDays = [int]$Policy.PasswordAgeDays }
    $postActions = 3
    if ($null -ne $Policy.PostAuthenticationActions) { $postActions = [int]$Policy.PostAuthenticationActions }
    $resetDelay = 24
    if ($null -ne $Policy.PostAuthenticationResetDelay) { $resetDelay = [int]$Policy.PostAuthenticationResetDelay }

    $eventSummary = $null
    if ($null -ne $Events) {
        $all = @($Events | Where-Object { $null -ne $_ })
        $errors = @($all | Where-Object { $_.Level -le 2 } | Sort-Object TimeCreated -Descending)
        $successes = @($all | Where-Object { $SuccessEventIds -contains [int]$_.Id } | Sort-Object TimeCreated -Descending)
        $lastError = $null
        if ($errors.Count -gt 0) { $lastError = $errors[0] }
        $lastSuccess = $null
        if ($successes.Count -gt 0) { $lastSuccess = $successes[0] }

        $eventSummary = [pscustomobject]@{
            LookbackDays     = $LookbackDays
            ErrorCount       = $errors.Count
            LastErrorTime    = $(if ($lastError) { $lastError.TimeCreated } else { $null })
            LastErrorId      = $(if ($lastError) { $lastError.Id } else { $null })
            LastErrorMessage = $(if ($lastError) { $lastError.Message } else { $null })
            LastSuccessTime  = $(if ($lastSuccess) { $lastSuccess.TimeCreated } else { $null })
        }
    }

    return [pscustomobject]@{
        Configured                        = $true
        PolicySource                      = $Policy.Source
        BackupTarget                      = $backupTarget
        AdministratorAccountName          = $Policy.AdministratorAccountName
        PasswordAgeDays                   = $passwordAgeDays
        PostAuthenticationActions         = $postActions
        PostAuthenticationResetDelayHours = $resetDelay
        LastPasswordUpdateTime            = $(if ($LastPasswordUpdate) { $LastPasswordUpdate } else { $null })
        Account                           = $Account
        Events                            = $eventSummary
    }
}

function ConvertTo-ICTLapsPostActionText {
    <# PostAuthenticationActions bit field: 1 reset password, 2 sign out, 4 reboot, 8 terminate processes. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([int]$Actions, [int]$DelayHours)

    if ($Actions -le 0) { return 'no action' }
    $parts = New-Object 'System.Collections.Generic.List[string]'
    if ($Actions -band 1) { $parts.Add('reset password') }
    if ($Actions -band 2) { $parts.Add('sign out') }
    if ($Actions -band 8) { $parts.Add('end processes') }
    if ($Actions -band 4) { $parts.Add('reboot') }
    return ('{0} after {1} h' -f ($parts -join ' + '), $DelayHours)
}
