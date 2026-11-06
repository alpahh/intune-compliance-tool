# Default settings. Kept as an embedded JSON string (not a separate file) so the
# single-file build stays one file. Override any key with -ConfigPath <file.json>.

$script:ICTDefaultConfigJson = @'
{
  "MinimumOSBuild": 19045,
  "RequireBitLocker": true,
  "RequireTpm": true,
  "RequireSecureBoot": true,
  "RequireDefenderRealTimeProtection": true,
  "MaxDefenderSignatureAgeDays": 3,
  "RequireFirewallAllProfiles": true,

  "MaxDaysSinceLastSync": 7,
  "MinCertificateDaysRemaining": 30,
  "RequiredServices": ["dmwappushservice"],
  "RecommendedServices": ["IntuneManagementExtension"],
  "MdmEventLookbackDays": 7,

  "Endpoints": [
    "login.microsoftonline.com",
    "enterpriseregistration.windows.net",
    "enrollment.manage.microsoft.com",
    "enterpriseenrollment-s.manage.microsoft.com",
    "portal.manage.microsoft.com"
  ],
  "EndpointPort": 443,
  "EndpointTimeoutMs": 5000,

  "RequireLaps": true,
  "LapsExpectedAccount": "masteruser",
  "LapsExpectedBackupTarget": "EntraId",
  "LapsEventLookbackDays": 7,
  "LapsSuccessEventIds": [10004, 10029],

  "EnrollmentMethod": "UserCredential",
  "EnrollmentTimeoutSeconds": 300,
  "SyncTimeoutSeconds": 180
}
'@
