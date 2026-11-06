function Get-ICTConfig {
    <#
    .SYNOPSIS
        Returns the effective settings: the built-in defaults, overridden by any keys
        in the JSON file given with -Path.
    .EXAMPLE
        Get-ICTConfig | ConvertTo-Json      # show the defaults
    .EXAMPLE
        Get-ICTConfig -Path .\my-settings.json
    #>
    [CmdletBinding()]
    param([string]$Path)

    $config = $script:ICTDefaultConfigJson | ConvertFrom-Json

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Config file not found: $Path" }
        try {
            $override = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "Config file '$Path' is not valid JSON: $($_.Exception.Message)"
        }

        foreach ($property in $override.PSObject.Properties) {
            if ($property.Name -like '_*') { continue }   # "_comment" keys are allowed
            if ($null -eq $config.PSObject.Properties[$property.Name]) {
                Write-Warning "Unknown setting '$($property.Name)' in '$Path' was ignored."
                continue
            }
            $config.($property.Name) = $property.Value
        }
    }

    if (@('UserCredential', 'DeviceCredential') -notcontains $config.EnrollmentMethod) {
        throw "EnrollmentMethod must be 'UserCredential' or 'DeviceCredential', not '$($config.EnrollmentMethod)'."
    }
    if (@('EntraId', 'ActiveDirectory') -notcontains $config.LapsExpectedBackupTarget) {
        throw "LapsExpectedBackupTarget must be 'EntraId' or 'ActiveDirectory', not '$($config.LapsExpectedBackupTarget)'."
    }

    return $config
}
