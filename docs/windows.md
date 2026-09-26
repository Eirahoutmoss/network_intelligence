# Windows installation

Nexus ships as a single installer, `Nexus-<version>-Setup-x64.exe`, for
Windows 10 1809 or newer, Windows 11 and Windows Server 2019 or newer (x64).

It installs Nexus as a native Windows service with its own PostgreSQL
database. **Nothing else is needed**: no Docker, WSL, Hyper-V, PostgreSQL,
Python or Node.js, no `.env` files, no key generation and no internet access.
The installer works the same when the technician is connected through
AnyDesk, TeamViewer or Remote Desktop.

```
Nexus-1.0.0-Setup-x64.exe
   │  Windows administrator prompt (UAC)
   ▼
Checking this computer...                Installing Nexus...
 √ Windows 11 Pro 23H2 (build 22631)      √ Engine: Nexus 1.0.0, PostgreSQL 16.15
 √ Architecture: x64                      √ Security: new encryption key generated
 √ Administrator rights: granted          √ Configuration: port 8080 (this computer only)
 √ Program disk / Data disk               √ Permissions, Service, Firewall
 √ Port: 8080 available                   √ Database: initialized
 √ Network: connected (10.2.33.20)        √ Health check: web interface and API answer
   ▼
Nexus is ready.  [Open Nexus]  →  browser: create the administrator account
```

## Why a native service (and not Docker)

The directive for Windows was a boring, reliable installer on institutional
PCs. Docker Desktop needs WSL2 or Hyper-V, hardware virtualization, often a
reboot, and a paid subscription for larger organizations; it is frequently
blocked by policy. Nexus consists of one Go binary and PostgreSQL, both of which
run natively on Windows, so the installer keeps the exact same architecture
(same code, same database, same migrations) and simply runs it as a service:

| Piece | Docker/Linux deployment | Windows deployment |
|---|---|---|
| Application | `nexus serve` in a container | `nexus.exe` as the Windows service **Nexus** |
| Database | `postgres:16` container | bundled PostgreSQL 16 started by the service on `127.0.0.1` |
| Configuration | environment variables | `C:\ProgramData\Nexus\config\nexus.env` (same variables) |
| Secrets | env / `*_FILE` | generated files in `ProgramData\Nexus\secrets` (`*_FILE`) |

The Windows-specific code lives in `backend/internal/deploy` (installation),
`backend/internal/platform` (OS facts), `backend/internal/pgembed` (embedded
database) and `cmd/nexus/platform_windows.go`; discovery and inventory code is
unchanged and has no Windows dependencies.

## Interactive installation

1. Copy the installer to the PC and run it; accept the administrator prompt.
2. **Welcome** → **Install location** (fresh installs only) → **Options**:
   * *Web interface port* — default 8080. When it is in use, setup names the
     program holding it and picks a free one (8480, 8888, 18080, …).
   * *Allow access from other computers* — off by default: Nexus answers only
     on `http://localhost`. When on, a Windows Firewall rule allows the port on
     **domain and private** networks only (never public); the firewall itself is
     never disabled or reconfigured.
   * *Desktop shortcut*, *Demo network* (the simulated campus for evaluation).
3. Setup shows every check and step. If something fails it names the
   component, offers **Retry**, and leaves nothing half-configured: running
   setup again continues where it stopped.
4. **Finish** → *Open Nexus* opens the default browser (as the signed-in user,
   not as administrator). On a new installation you create the administrator
   there. For security this is only possible on the Nexus computer itself.

Start menu → **Nexus** opens the web interface; **Nexus Diagnostics** writes a
redacted diagnostic bundle to the desktop.

The **notification area icon** (starts with Windows for every user; `/NOTRAY`
turns this off) shows the state in its tooltip and offers:

```
Nexus
  Open Nexus
  ● Running
  Start / Stop / Restart        (administrator prompt)
  Diagnostics…                  (bundle on the desktop)
  View logs                     (administrator prompt)
  Settings
  Exit
```

## Silent / unattended installation

```
Nexus-1.0.0-Setup-x64.exe /S [/D=C:\Program Files\Nexus] [/PORT=8080] [/LAN=1] [/DEMO=1]
                             [/NOSTART] [/NODESKTOP] [/NOBROWSER] [/NOTRAY] [/LOG=C:\Temp\nexus-install.log]
                             [/DATADIR=D:\NexusData]
```

| Exit code | Meaning |
|---|---|
| 0 | installed and healthy (or installed without start with `/NOSTART`) |
| 1 | cancelled |
| 2 | installation failed — see `/LOG` file and `ProgramData\Nexus\logs\install.log` |
| 3 | upgrade failed; the previous version was restored and is running |

No secret is ever passed on the command line: keys and passwords are generated
on the machine, and the administrator account is created in the browser.

## What gets installed where

| What | Location | Access |
|---|---|---|
| Program (per version) | `C:\Program Files\Nexus\app\<version>\` — `nexus.exe`, `nexus-tray.exe`, `web\`, `pgsql\`, licenses | read-only for everyone |
| Configuration | `C:\ProgramData\Nexus\config\nexus.env` | Administrators, SYSTEM; service: read |
| Master key, database password | `C:\ProgramData\Nexus\secrets\` | Administrators, SYSTEM; service: read |
| Database | `C:\ProgramData\Nexus\data\db\` | Administrators, SYSTEM; service: modify |
| Logs | `C:\ProgramData\Nexus\logs\` (`install.log`, `nexus.log`, `postgres-*.log`) | Administrators, SYSTEM; service: modify |
| Backups | `C:\ProgramData\Nexus\backups\` | Administrators, SYSTEM; service: modify |
| Service | **Nexus** ("Nexus Network Intelligence"), account `NT SERVICE\Nexus` | automatic start |
| Registry | `HKLM\Software\Nexus`, uninstall entry | |

The data folders have protected ACLs: ordinary users (and even
"Authenticated Users") have no access at all.

## The service

* Runs as the **virtual account `NT SERVICE\Nexus`** — not LocalSystem and not
  an administrator. It has no password and cannot log on interactively; it can
  only read its configuration and secrets and write its data, logs and backups.
* **Starts automatically** with Windows, before anyone logs on; nobody has to
  open anything after a reboot.
* **Restarts automatically** after a crash or failure (5 s, 15 s, then every
  60 s; counter reset daily).
* Starts PostgreSQL itself on `127.0.0.1` with a random port preference of
  54329 (another free port is used if taken), SCRAM authentication and a
  generated password; stops it cleanly on service stop. If PostgreSQL dies, the
  service stops too so that Windows restarts both.
* Writes events to the Windows event log (source *Nexus*) and a rotating JSON
  log to `logs\nexus.log`.

Manage it like any service (`services.msc`) or from an elevated prompt:

```
"C:\Program Files\Nexus\app\1.0.0\nexus.exe" service status|start|stop|restart
```

## Upgrade and rollback

Running a newer installer upgrades in place:

1. the running version is backed up (`backups\nexus-before-upgrade-to-<v>-<time>.nxbackup`);
2. the service is stopped; the new version is installed side by side in
   `app\<new version>`; configuration settings you added are kept;
3. the service is switched to the new version and started; database migrations
   run (each in a transaction) after another automatic backup;
4. the installer waits until the API, database and web interface answer.

If the new version does not become healthy, setup **stops it, restores the
previous configuration and service, starts the previous version, verifies
it** and reports the failure (exit code 3). Devices, topology, locations,
users, credentials, settings and audit history are never touched by setup.
Older program versions are removed only after a successful upgrade.
Downgrades are refused.

## Uninstall

Settings → Apps → *Nexus Network Intelligence* → Uninstall. The service,
firewall rule, program files, shortcuts and registry entries are removed. The
**data is kept** unless you tick *Also delete all Nexus data* and confirm a
second warning. Installing Nexus again continues with the kept data.

Silent: `"C:\Program Files\Nexus\Uninstall Nexus.exe" /S` (keeps data) or
`/S /PURGEDATA=YES` (deletes it). Add `_?=C:\Program Files\Nexus` as the last
argument when a script must wait for the uninstaller to finish.

## Backup and restore

* A backup is written **every day** and **before every upgrade** into
  `ProgramData\Nexus\backups` (the last 7 daily and 5 pre-upgrade backups are kept).
* **Settings → Diagnostics & backup → Download backup** exports one on demand.
  Tick *Include the encryption key* and enter a passphrase to be able to use
  the stored device credentials on another computer.
* Command line (elevated): `nexus.exe --config "%ProgramData%\Nexus\config\nexus.env" backup [--include-key]`.

Backups contain the complete inventory; stored SNMP/SSH credentials remain
AES-256-GCM encrypted, sessions are not included. **The master key**
(`secrets\master.key`) is what decrypts stored credentials: either keep a copy
of it somewhere safe or export backups with the passphrase-protected key.

Restore (replaces all current data, after writing a safety backup):

```
net stop Nexus
"C:\Program Files\Nexus\app\<version>\nexus.exe" --config "%ProgramData%\Nexus\config\nexus.env" restore [--ask-passphrase] FILE.nxbackup
net start Nexus
```

A backup from another installation restores with its credentials usable when
it includes the key and you give the passphrase (credentials are re-encrypted
with this installation's key); otherwise they are reported as needing to be
re-entered.

## Diagnostics

* **Settings → Diagnostics & backup → Run health check**: service, database,
  schema, web interface, network exposure, disk space, backups, credential
  encryption, recent discovery runs — each with a hint when something is wrong.
* **Export diagnostic bundle** (web) or Start menu → **Nexus Diagnostics**
  (works even when the web interface is down): a zip with versions, Windows
  version, service state, health checks, migration status, table sizes, recent
  discovery runs, configuration and the last 2 MB of each log.
* Passwords, SNMP communities, private keys, tokens, cookies, the master key
  and the database password are removed automatically; the configuration file
  lists only paths to the secret files.

## Security summary

* UAC elevation once, by the installer's manifest; nothing bypasses UAC and
  Windows security settings are not weakened.
* The master key (32 bytes) and database password come from the OS
  cryptographic random generator on the target machine; they never appear in
  logs, command lines, installer output or diagnostic bundles.
* No default passwords: the first administrator is created in the browser, only
  from the Nexus computer, and only while no account exists.
* The web interface listens on localhost unless network access is chosen.
  For network access, put Nexus behind HTTPS (reverse proxy) and set
  `NEXUS_COOKIE_SECURE=true` in `nexus.env`.
* Credential encryption (AES-256-GCM), authentication and roles are the same as
  in every other deployment.

## Offline and restricted networks

The installer contains everything (≈ 22 MB): Nexus, the web interface,
PostgreSQL and the Microsoft Visual C++ runtime DLLs it needs. It downloads
nothing, needs no proxy configuration and works on isolated networks.
Application whitelisting must allow `C:\Program Files\Nexus\app\*\nexus.exe`
and `…\pgsql\bin\*.exe`; setup detects a blocked engine early and says so.

## Building the installer

```
deployments/windows/build.sh          # Linux, macOS or Git Bash
```

Requirements: Go, Node.js, NSIS 3 (`makensis`), curl, unzip, xz;
optionally `x86_64-w64-mingw32-windres` (icon and version info) and
`osslsigncode`/`signtool` for signing. Third-party binaries are downloaded from
pinned URLs and verified against SHA-256 checksums in
`deployments/windows/deps.env`. Output:

```
dist/Nexus-1.0.0-Setup-x64.exe
dist/Nexus-1.0.0-Setup-x64.exe.sha256
dist/RELEASE-NOTES.md
```

The version comes from the `VERSION` file (also used for `nexus.exe`'s version
resource and the Windows uninstall entry).

### Code signing

No certificate is part of the repository. Without one the build produces
**unsigned** artifacts (stated in `RELEASE-NOTES.md`; SmartScreen may ask for
confirmation). With a certificate:

```
SIGN_PFX=cert.pfx SIGN_PFX_PASSWORD_FILE=pfx.pass SIGN_TIMESTAMP_URL=http://timestamp.digicert.com \
  deployments/windows/build.sh
```

signs `nexus.exe` before packaging and the installer afterwards.

### CI

`.github/workflows/windows.yml` builds the installer on Linux and then, on a
real `windows-latest` machine, runs `deployments/windows/tests/installer-test.ps1`:
occupied port → silent install → service account, recovery and SID type →
health and localhost-only binding → ACLs → no firewall rule → no secrets in
logs/command lines/config → first run in a real browser (create administrator,
Add Device on the simulator, health check, diagnostic bundle, backup) → crash
recovery → restart → diagnostics and backup CLI → upgrade keeping data →
forced failed upgrade with automatic rollback → LAN firewall rule (domain and
private only) and its removal → uninstall keeping data → reinstall with data →
uninstall with purge. It also runs the Windows-specific Go tests, including the
embedded PostgreSQL lifecycle with the bundled binaries.

## Troubleshooting

| Symptom | What to do |
|---|---|
| "Port 8080 is in use by …" | Nothing: setup picked another port and shows the URL. |
| Setup stops at *Engine* | An application whitelisting or antivirus product blocks the bundled programs; allow the Nexus program folder. |
| Setup stops at *Database* / *Health check* | See `ProgramData\Nexus\logs\nexus.log` and `postgres-*.log`; run Setup again to retry; Start menu → Nexus Diagnostics for support. |
| Browser shows "Setup is not finished" | Create the administrator on the Nexus computer itself (`http://localhost:<port>`). |
| Forgotten admin password | Another administrator resets it under Settings → Users. |
| Moved to a new PC | Install, stop the service, `nexus.exe restore` a backup made with *Include the encryption key*, start the service. |

## Future work

ARM64: the code already builds for `windows/arm64`; a native ARM64 package
needs ARM64 PostgreSQL binaries (the x64 installer runs under emulation and
setup says so).
