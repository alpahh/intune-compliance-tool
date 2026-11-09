function ConvertFrom-ICTDsregOutput {
    <#
        Parses "dsregcmd /status" output. Field names are not localised, so this works
        on any display language. When a field appears in several sections, the first
        occurrence wins. User-specific fields (SSO state, PRT) are ignored on purpose:
        over SSH they describe the SSH account, not the person at the device.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Line)

    $values = @{}
    foreach ($text in $Line) {
        if ($text -match '^\s*(?<key>[A-Za-z][A-Za-z0-9 \-\.]*?)\s+:\s*(?<value>.*?)\s*$') {
            $key = $Matches['key'] -replace '\s', ''
            if (-not $values.ContainsKey($key) -and $Matches['value'] -ne '') { $values[$key] = $Matches['value'] }
        }
    }

    $azureAdJoined = ConvertFrom-ICTYesNo $values['AzureAdJoined']
    $domainJoined = ConvertFrom-ICTYesNo $values['DomainJoined']
    $joinType = 'NotJoined'
    if ($azureAdJoined -and $domainJoined) { $joinType = 'HybridJoined' }
    elseif ($azureAdJoined) { $joinType = 'EntraJoined' }
    elseif ($domainJoined) { $joinType = 'DomainJoinedOnly' }
    elseif (ConvertFrom-ICTYesNo $values['WorkplaceJoined']) { $joinType = 'WorkplaceJoined' }

    # "[ 2025-01-10 08:00:00.000 UTC -- 2035-01-10 08:30:00.000 UTC ]"
    $certificateNotAfter = $null
    if ($values['DeviceCertificateValidity'] -match '--\s*(?<to>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
        $certificateNotAfter = ConvertTo-ICTIsoDate $Matches['to']
    }

    return [pscustomobject]@{
        JoinType                  = $joinType
        AzureAdJoined             = $azureAdJoined
        DomainJoined              = $domainJoined
        DeviceName                = $values['DeviceName']
        DeviceId                  = $values['DeviceId']
        DeviceAuthStatus          = $values['DeviceAuthStatus']
        DeviceCertificateNotAfter = $certificateNotAfter
        KeySignTest               = $values['KeySignTest']
        TenantName                = $values['TenantName']
        TenantId                  = $values['TenantId']
        MdmUrl                    = $values['MdmUrl']
    }
}
