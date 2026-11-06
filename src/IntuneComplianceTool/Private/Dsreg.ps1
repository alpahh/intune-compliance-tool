function ConvertFrom-ICTDsregOutput {
    <#
        Parses the text output of "dsregcmd /status" into an object. dsregcmd field
        names are not localised, so this works on any Windows display language.
        When a field appears in more than one section, the first occurrence wins.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Line
    )

    $values = @{}
    foreach ($text in $Line) {
        if ($text -match '^\s*(?<key>[A-Za-z][A-Za-z0-9 \-\.]*?)\s+:\s*(?<value>.*?)\s*$') {
            $key = $Matches['key'] -replace '\s', ''
            if (-not $values.ContainsKey($key)) {
                $value = $Matches['value']
                if ($value -eq '') { $value = $null }
                $values[$key] = $value
            }
        }
    }

    $azureAdJoined = ConvertFrom-ICTYesNo $values['AzureAdJoined']
    $domainJoined = ConvertFrom-ICTYesNo $values['DomainJoined']
    $workplaceJoined = ConvertFrom-ICTYesNo $values['WorkplaceJoined']

    $joinType = 'NotJoined'
    if ($azureAdJoined -and $domainJoined) { $joinType = 'HybridJoined' }
    elseif ($azureAdJoined) { $joinType = 'EntraJoined' }
    elseif ($domainJoined) { $joinType = 'DomainJoinedOnly' }
    elseif ($workplaceJoined) { $joinType = 'WorkplaceJoined' }

    return [pscustomobject]@{
        JoinType                  = $joinType
        AzureAdJoined             = $azureAdJoined
        DomainJoined              = $domainJoined
        WorkplaceJoined           = $workplaceJoined
        EnterpriseJoined          = ConvertFrom-ICTYesNo $values['EnterpriseJoined']
        DeviceName                = $values['DeviceName']
        DeviceId                  = $values['DeviceId']
        DeviceAuthStatus          = $values['DeviceAuthStatus']
        DeviceCertificateValidity = $values['DeviceCertificateValidity']
        TpmProtected              = ConvertFrom-ICTYesNo $values['TpmProtected']
        TenantName                = $values['TenantName']
        TenantId                  = $values['TenantId']
        DomainName                = $values['DomainName']
        MdmUrl                    = $values['MdmUrl']
        MdmComplianceUrl          = $values['MdmComplianceUrl']
        AzureAdPrt                = ConvertFrom-ICTYesNo $values['AzureAdPrt']
    }
}
