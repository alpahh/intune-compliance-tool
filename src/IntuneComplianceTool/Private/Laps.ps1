function Get-ICTLapsAccountSpec {
    <#
        Which local account the LAPS policy manages, following Windows' rules: with
        automatic account management (Windows 11 24H2+) AdministratorAccountName is
        ignored; Target 0 = built-in Administrator, Target 1 (default) = the account
        named NameOrPrefix (default WLapsAdmin), with 6 random digits when RandomizeName
        is on (the prefix is cut to 14 characters). Returns Name and NamePrefix for
        Get-ICTLocalAccount (both empty = built-in Administrator).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject]$Policy)

    if (-not $Policy.AutomaticAccountManagement) {
        return [pscustomobject]@{ Name = $Policy.AdministratorAccountName; NamePrefix = $null }
    }
    if ($Policy.AutomaticAccountTarget -eq 0) { return [pscustomobject]@{ Name = $null; NamePrefix = $null } }

    $name = $(if ($Policy.AutomaticAccountNameOrPrefix) { [string]$Policy.AutomaticAccountNameOrPrefix } else { 'WLapsAdmin' })
    if ($Policy.AutomaticAccountRandomize) {
        return [pscustomobject]@{ Name = $null; NamePrefix = $name.Substring(0, [math]::Min(14, $name.Length)) }
    }
    return [pscustomobject]@{ Name = $name; NamePrefix = $null }
}

function New-ICTLapsState {
    <#
        Combines the separately collected LAPS pieces into one object (pure function).
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

    if ($null -eq $Policy) { return [pscustomobject]@{ Configured = $false } }

    $backupTarget = 'Unknown'
    if ($Policy.Source -eq 'Legacy') { $backupTarget = 'Legacy' }
    else {
        switch ([int]$Policy.BackupDirectory) {   # missing value = 0 = disabled
            0 { $backupTarget = 'Disabled' }
            1 { $backupTarget = 'EntraId' }
            2 { $backupTarget = 'ActiveDirectory' }
        }
    }

    $defaults = @{ PasswordAgeDays = 30; PostAuthenticationActions = 3; PostAuthenticationResetDelay = 24 }
    foreach ($name in @($defaults.Keys)) {
        if ($null -ne $Policy.$name) { $defaults[$name] = [int]$Policy.$name }
    }

    $eventSummary = $null
    if ($null -ne $Events) {
        $all = @($Events | Where-Object { $null -ne $_ })
        $errors = @($all | Where-Object { $_.Level -in 1, 2 } | Sort-Object TimeCreated -Descending)
        $lastSuccess = @($all | Where-Object { $SuccessEventIds -contains [int]$_.Id } | Sort-Object TimeCreated -Descending) | Select-Object -First 1
        $lastError = $errors | Select-Object -First 1
        $eventSummary = [pscustomobject]@{
            LookbackDays     = $LookbackDays
            ErrorCount       = $errors.Count
            LastErrorTime    = $lastError.TimeCreated
            LastErrorId      = $lastError.Id
            LastErrorMessage = $lastError.Message
            LastSuccessTime  = $lastSuccess.TimeCreated
        }
    }

    return [pscustomobject]@{
        Configured                        = $true
        PolicySource                      = $Policy.Source
        BackupTarget                      = $backupTarget
        AutomaticAccountManagement        = [bool]$Policy.AutomaticAccountManagement
        AutomaticAccountEnabled           = [bool]$Policy.AutomaticAccountEnabled
        AdministratorAccountName          = $Policy.AdministratorAccountName
        PasswordAgeDays                   = $defaults.PasswordAgeDays
        PostAuthenticationActions         = $defaults.PostAuthenticationActions
        PostAuthenticationResetDelayHours = $defaults.PostAuthenticationResetDelay
        LastPasswordUpdateTime            = $(if ($LastPasswordUpdate) { $LastPasswordUpdate } else { $null })
        Account                           = $Account
        Events                            = $eventSummary
    }
}

function ConvertTo-ICTLapsPostActionText {
    <#
        PostAuthenticationActions bit field: 1 reset password, 2 sign out, 4 reboot,
        8 terminate processes. A reset delay of 0 hours disables all of them.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([int]$Actions, [int]$DelayHours)

    if ($Actions -le 0 -or $DelayHours -le 0) { return 'none (disabled)' }
    $parts = @()
    if ($Actions -band 1) { $parts += 'reset password' }
    if ($Actions -band 2) { $parts += 'sign out' }
    if ($Actions -band 8) { $parts += 'end processes' }
    if ($Actions -band 4) { $parts += 'reboot' }
    return ('{0} after {1} h' -f ($parts -join ' + '), $DelayHours)
}
