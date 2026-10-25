# KazeVault

KazeVault is a lightweight, self-hosted personal database for notes, journal entries, knowledge, records, attachments, search, and local backups. It uses FastAPI, SQLite, SQLAlchemy, and Argon2id. It is designed for a trusted home network and is not a security audit or a promise of complete security.

## Install on Windows

Open PowerShell and run:

```powershell
cd F:\KazeVault
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Start locally with `run.bat`, or:

```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

Open http://127.0.0.1:8765 and create the administrator account on first launch. There is no default password. Stop with Ctrl+C or `stop.bat`.

## LAN access

LAN mode is opt-in. Run `run-lan.bat`, then find the laptop's private address with:

```powershell
ipconfig
```

Use the IPv4 address from the Wi-Fi adapter, for example `http://192.168.1.25:8765`. Allow inbound TCP 8765 only on the Private profile, ideally restricted to your local subnet. In an Administrator PowerShell window:

```powershell
New-NetFirewallRule -DisplayName "KazeVault LAN" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8765 -Profile Private -RemoteAddress LocalSubnet
```

Do not disable Windows Firewall or configure router port forwarding. Plain HTTP does not encrypt traffic; use LAN mode only on a trusted network. For stronger protection, place KazeVault behind HTTPS with a properly managed certificate and review the threat model first.

## Data and backups

Persistent data is under `data\`, attachments under `data\attachments\`, and ZIP backups under `backups\`. Use the Backups page to create a consistent database-plus-attachments archive. A same-SSD backup does not protect against SSD failure; copy backup ZIPs to a separate physical drive and periodically test that they open.

KazeVault hashes passwords with Argon2id, but password hashing does not encrypt the SQLite database. Protect the drive and backup copies with BitLocker or another full-disk encryption solution. Do not expose the app to the public internet.

## Phase 2 security hardening

- Passwords use Argon2id; successful login clears the prior session state before establishing the authenticated session.
- Sessions are signed, unpredictable cookies with an eight-hour expiration. `KAZEVAULT_HTTPS=1` enables the Secure cookie flag when running behind HTTPS; leave it unset for ordinary localhost/LAN HTTP.
- All state-changing forms include a server-validated CSRF token. Missing or invalid tokens are rejected with HTTP 403.
- Failed logins are throttled per client address after five attempts in five minutes. This is intentionally temporary rather than a permanent account lockout.
- Uploads use generated storage names, reject path-like/control-character filenames, enforce a 25 MB limit and allowlist, and downloads send `nosniff` and restrictive content-security headers.
- Protected pages and attachment routes enforce authentication server-side. Queries use SQLAlchemy parameters.

## Phase 3 backup and recovery

Backups are versioned ZIP archives stored in `backups\`. Each contains a SQLite backup, `manifest.json`, and an attachment inventory with sizes and SHA-256 hashes. The Backups page verifies archive paths, the manifest, SQLite integrity, attachment presence, and attachment hashes. Temporary files are atomically renamed into place, so an interrupted backup does not replace an older backup.

The page supports creating, verifying, downloading, and deleting backups. The only verified backup cannot be deleted. Restore requires authentication, a valid archive, and typing `RESTORE`. Before replacement, KazeVault creates a verified `pre-restore-...zip` backup. The database and attachments are staged and validated before the old paths are moved aside. If replacement fails, the old database and attachments are restored where possible. Restart KazeVault after a successful restore so all application connections are reopened against the restored database.

Older unversioned ZIPs from the first prototype are not treated as restorable because they have no manifest or attachment hashes; keep them as legacy archives and verify them manually before relying on them. Local backups do not protect against SSD failure, theft, or ransomware. Copy verified ZIPs to a separate physical drive and periodically test them.

For drive protection on supported Windows editions, open **Settings → Privacy & security → Device encryption** or search for **Manage BitLocker**, then enable encryption for the data drive containing KazeVault. Save the recovery key separately. BitLocker protects the drive at rest; it does not protect data while the server is running.

## Optional startup

Automatic startup is intentionally not configured. If you later choose it, create a Windows Task Scheduler task that runs `run.bat` at logon, with the task set to run only when you choose. To disable it, remove that task. Do not use LAN mode for startup unless you explicitly want LAN exposure.

## Troubleshooting

- Port occupied: change `8765` consistently in the batch file and URL, or find the process with `netstat -ano | findstr :8765`.
- Cannot open database: check that the account has write access to `F:\KazeVault\data` and that no backup tool is locking it.
- Upload rejected: only the documented extensions and 25 MB maximum are accepted; uploaded HTML and executable files are not accepted.
- Updating: stop the server, back up `data` and `backups`, replace application source files, reinstall requirements, and start again. Never delete the `data` directory during an update.

