@{
    RootModule           = 'IntuneComplianceTool.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '62abaffe-db9d-4f72-8a65-594a41c12e50'
    Author               = 'alpahh'
    Description          = 'Collects local MDM, Intune and LAPS data from a Windows device, evaluates it against compliance and enrollment-health rules, renders the result for the terminal and can repair a broken Intune MDM enrollment.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Get-ICTConfig'
        'Get-ICTDeviceData'
        'Test-ICTCompliance'
        'Format-ICTHeader'
        'Format-ICTProgressItem'
        'Format-ICTReport'
        'New-ICTReport'
        'Export-ICTReport'
        'Invoke-ICTSync'
        'Invoke-ICTReEnrollment'
        'Invoke-ICTLapsRetry'
        'Invoke-ICTRemediation'
        'Initialize-ICTLogging'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags = @('Intune', 'MDM', 'Compliance', 'Enrollment', 'LAPS', 'Windows')
        }
    }
}
