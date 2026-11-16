# Default settings, embedded so the single-file build stays one file.
# Override any key with -ConfigPath <file.json>.

$script:ICTDefaultConfigJson = @'
{
  "MinimumOSBuild": 19045,
  "MinimumOSRevision": {},
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
  "MaxUptimeDays": 30,
  "ImeLogLookbackDays": 7,

  "CheckWindowsUpdate": true,
  "MaxUpdateScanAgeDays": 7,
  "MaxUpdateInstallAgeDays": 45,
  "UpdateHistoryDays": 30,
  "MinFreeDiskGB": 10,
  "UpdateRepairTimeoutSeconds": 900,
  "UpdateDeepRepairTimeoutSeconds": 5400,
  "UpdateScanTimeoutSeconds": 300,
  "UpdateRepairErrorCodes": ["0x80070002", "0x80070003", "0x80073712", "0x800f081f", "0x800f0831", "0x80070490", "0x80248007"],
  "UpdateResetCooldownHours": 24,

  "Endpoints": [
    "login.microsoftonline.com",
    "enterpriseregistration.windows.net",
    "enrollment.manage.microsoft.com",
    "enterpriseenrollment-s.manage.microsoft.com",
    "portal.manage.microsoft.com"
  ],
  "EndpointPort": 443,
  "EndpointTimeoutMs": 5000,
  "ClockReferenceUri": "https://login.microsoftonline.com/",
  "MaxClockSkewSeconds": 300,

  "RequireLaps": true,
  "LapsExpectedAccount": "masteruser",
  "LapsExpectedBackupTarget": "EntraId",
  "LapsEventLookbackDays": 7,
  "LapsSuccessEventIds": [10004, 10029],

  "EnrollmentMethod": "UserCredential",
  "EscalateSyncToReEnroll": true,
  "SyncTimeoutSeconds": 180,
  "RepairScriptTimeoutSeconds": 240,
  "EnrollmentTimeoutSeconds": 300
}
'@
