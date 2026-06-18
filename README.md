# Sirocco

**Sirocco** is a PowerShell password-spraying tool for Microsoft Online
(Azure / Entra ID / Office 365) that routes every authentication attempt through
a **FireProx** API Gateway endpoint so each request appears to come from a
rotating source IP address.

It is built for **authorized** red-team engagements and security assessments. The
core authentication request/response handling is based on
[MSOLSpray](https://github.com/dafthack/MSOLSpray) by Beau Bullock (@dafthack),
which is kept in `MSOLSpray/MSOLSpray.ps1` as the reference implementation.


---

## Features

- **Automatic FireProx provisioning** — creates a fresh API Gateway endpoint at
  startup (or reuses one you pass with `-Url`).
- **Forbidden recovery with resume** — if API Gateway / WAF returns
  `403 Forbidden`, Sirocco provisions a **new** FireProx endpoint and **resumes
  from the exact user that failed**. The spray never restarts from the
  beginning.
- **Full file-based logging** — every attempt is recorded with timestamp, user,
  password, and result, ready to hand to a client.
- **User refinery** — accounts that don't exist in Azure/Entra are detected and
  pruned from the user list so future passwords (and future runs) never waste
  attempts on them. This shrinks lockout risk and noise.
- **Automatic MFA sweep** — when `-MFASweepPath` is supplied, every *successful*
  credential is immediately run through [MFASweep](https://github.com/dafthack/MFASweep)
  to identify which Microsoft services allow single-factor (no-MFA) access. The
  sweep runs non-interactively and its results are logged per credential.
- **Lockout-aware result parsing** — distinguishes valid creds, MFA, conditional
  access, expired passwords, locked, disabled, invalid user, and invalid tenant
  via AADSTS error codes.
- **Clean progress display** — spray progress is shown on a single in-place
  progress bar (`Write-Progress`) instead of scrolling the console.

---

## Requirements

- **PowerShell** 5.1+ (Windows) or PowerShell 7+.
- **FireProx** (https://github.com/ustayready/fireprox) installed and reachable.
  Point Sirocco at your `fire.py` with `-FireProxPath` (required). By default it
  is launched through **WSL**; use `-Launcher` to change that if you run it
  natively.
- **AWS credentials** with permission to create/manage API Gateway endpoints
  (used by FireProx).
- *(Optional)* **MFASweep** (https://github.com/dafthack/MFASweep) — supply its
  `MFASweep.ps1` path via `-MFASweepPath` to enable the per-success MFA sweep.

---

## Files produced (in `.\logs\` by default)

| File | Contents |
|------|----------|
| `spray_attempts_<stamp>.csv` | One row per attempt: `Timestamp, Username, Password, Result, Detail, Endpoint` — the client deliverable. |
| `valid_creds_<stamp>.txt`    | Successful logins only (incl. MFA / conditional-access / expired notes). |
| `spray_run_<stamp>.log`      | Timestamped run transcript. |
| `fireprox_endpoints_<stamp>.txt` | Every FireProx endpoint created (`time, api_id, url`) — for cleanup. |
| `mfa_results_<stamp>.csv` | MFA sweep results: `Timestamp, Username, Password, Service, SingleFactorAccess` (one row per service per successful cred). |
| `mfa_raw_<stamp>.log` | Full raw MFASweep console output, captured per credential. |
| `refinery_removed_<stamp>.txt` | Users pruned by the refinery and why. |
| `userlist_backup_<stamp>.txt`  | One-time backup of your original user list (refinery rewrites it in place). |

---

## Usage

### Basic — create the endpoint automatically

```powershell
.\Sirocco.ps1 `
    -UserListPath .\users.txt `
    -PasswordListPath .\passwords.txt `
    -FireProxPath /path/to/fireprox/fire.py `
    -AwsProfile myprofile `
    -AccessKey "AKIA..." `
    -SecretAccessKey "xxxxx" `
    -Region us-east-1
```

### Reuse an existing FireProx URL

```powershell
.\Sirocco.ps1 -UserListPath .\users.txt -PasswordListPath .\passwords.txt `
    -FireProxPath /path/to/fireprox/fire.py `
    -Url https://abc123.execute-api.us-east-1.amazonaws.com/fireprox `
    -AccessKey "AKIA..." -SecretAccessKey "xxxxx" -Region us-east-1
```

### Single password, short delay, no list refining

```powershell
.\Sirocco.ps1 -UserListPath .\users.txt -PasswordListPath .\one_password.txt `
    -FireProxPath /path/to/fireprox/fire.py `
    -AwsProfile myprofile -AccessKey "AKIA..." -SecretAccessKey "xxxxx" `
    -SleepSeconds 0 -NoRefine
```

### With an MFA sweep on every valid credential

```powershell
.\Sirocco.ps1 -UserListPath .\users.txt -PasswordListPath .\passwords.txt `
    -FireProxPath /path/to/fireprox/fire.py `
    -AwsProfile myprofile -AccessKey "AKIA..." -SecretAccessKey "xxxxx" `
    -MFASweepPath /path/to/MFASweep/MFASweep.ps1 -IncludeADFS
```

---

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-UserListPath` *(required)* | — | File of usernames, one per line (`user@domain.com`). |
| `-PasswordListPath` *(required)* | — | File of passwords, one per line (sprayed one at a time). |
| `-Url` | *(auto)* | Existing FireProx base URL. If omitted, one is created. |
| `-AwsProfile` | `""` | AWS named profile for FireProx. |
| `-AccessKey` / `-SecretAccessKey` | `""` | AWS keys (required to create/rotate endpoints). |
| `-Region` | `us-east-1` | AWS region for FireProx. |
| `-FireProxPath` *(required)* | — | Path to `fire.py` (as seen by the launcher). |
| `-TargetUrl` | `https://login.microsoft.com/` | Upstream URL FireProx proxies to. |
| `-Launcher` | `wsl` | How `fire.py` is launched (`wsl`, `python3`, ...). |
| `-SleepSeconds` | `7200` (2h) | Pause between passwords (spray throttling). |
| `-MaxRotations` | `10` | Max new endpoints per password round before aborting. |
| `-LogDirectory` | `.\logs` | Where logs are written. |
| `-NoRefine` | *(off)* | Disable user-list refining. |
| `-RefineTenants` | *(off)* | Also prune users whose **tenant** doesn't exist. |
| `-MFASweepPath` | `""` | Path to `MFASweep.ps1`. When set, runs an MFA sweep after each successful spray. |
| `-IncludeADFS` | *(off)* | Include the on-prem ADFS login attempt in the MFA sweep. |

---

## How the user refinery works

When a spray response indicates a user does not exist in Azure/Entra
(`AADSTS50034` → *invalid user*; with `-RefineTenants`, also `AADSTS50128` /
`AADSTS50059` → *tenant doesn't exist*), Sirocco:

1. Adds the user to an in-memory "does-not-exist" set.
2. Logs the removal to `refinery_removed_<stamp>.txt`.
3. **Rewrites the user list file in place** (after backing it up once) with those
   users removed.

As a result:

- **Within the current run**, every subsequent password round sprays only the
  users that still exist — non-existent accounts are skipped immediately.
- **Future runs** against the same list file start from the already-refined set,
  so the list keeps getting cleaner with each engagement.

Your original list is never lost — it's copied to
`logs\userlist_backup_<stamp>.txt` before the first rewrite. Use `-NoRefine` to
leave the list untouched.

---

## How the MFA sweep works

When `-MFASweepPath` points at a copy of `MFASweep.ps1`, Sirocco dot-sources it
to load its per-service authentication functions, then **drives them
non-interactively** — MFASweep's own confirmation/recon prompts are bypassed, so
nothing blocks the spray.

For each credential confirmed valid during the spray, Sirocco runs the sweep
against the standard Microsoft endpoints (Graph API, Azure Service Management,
the M365 web portal under Windows/Linux/macOS/Android/iPhone/Windows-Phone user
agents, Exchange Web Services and ActiveSync basic auth; plus ADFS with
`-IncludeADFS`). It then records, per service, whether **single-factor access**
was possible:

- `mfa_results_<stamp>.csv` — one row per service per credential
  (`Timestamp, Username, Password, Service, SingleFactorAccess`).
- `mfa_raw_<stamp>.log` — the full raw MFASweep output, captured so the noise
  stays out of the console.
- The run log gets a one-line summary, e.g.
  `MFA sweep user@corp.com : SINGLE-FACTOR access on -> M365 w/ Android UA, Active Sync (BASIC)`.

> **Lockout warning:** the MFA sweep authenticates ~10–11 times per credential.
> It only runs against credentials already proven valid, so lockout risk is low,
> but keep it in mind for accounts with aggressive lockout policies.

---

## Cleaning up FireProx endpoints

Every endpoint Sirocco creates is recorded in
`logs\fireprox_endpoints_<stamp>.txt`. Delete them when finished:

```bash
python3 fire.py --access_key "AKIA..." --secret_access_key "xxxxx" \
    --region us-east-1 --command delete --api_id <api_id>
```

(List all of them with `--command list`.)

---

## Operational notes & safety

- **Authorized testing only.** Use Sirocco solely against environments you have
  written permission to assess.
- **Lockout risk.** Microsoft Entra Smart Lockout can trigger on repeated
  failures. Keep `-SleepSeconds` high between passwords and watch the run log for
  `LOCKED` results.
- **Credential exposure.** Passing AWS keys on the command line makes them
  visible in the process list. Prefer `-AwsProfile` with credentials stored in
  `~/.aws/credentials`, or environment variables, where possible.

---

## Credits

- Spray technique & AADSTS handling: [MSOLSpray](https://github.com/dafthack/MSOLSpray) — Beau Bullock (@dafthack), BSD-3-Clause.
- MFA sweep logic: [MFASweep](https://github.com/dafthack/MFASweep) — Beau Bullock (@dafthack), MIT.
- IP rotation: [FireProx](https://github.com/ustayready/fireprox) — Mike Felch (@ustayready).
