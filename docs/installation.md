# Installation & operations

For **Windows** use the installer — see [windows.md](windows.md). The rest of this page
covers Docker and Linux.

## Requirements

- Linux host (x86-64 or arm64) with Docker + Docker Compose, **or** Go 1.26+, Node 22+ and
  PostgreSQL 14+ for a bare-metal install.
- UDP/161 (SNMP) from the Nexus host to your network devices; TCP/22 for the CLI.
- Optional for active endpoint identification: TCP to endpoints (22, 80, 135, 139, 443,
  445, 515, 554, 631, 3389, 5060, 8080, 9100) and UDP/137.

## Docker Compose (recommended)

```bash
cp .env.example .env
openssl rand -base64 32          # paste into NEXUS_MASTER_KEY
$EDITOR .env                     # POSTGRES_PASSWORD, NEXUS_ADMIN_PASSWORD
docker compose up -d
docker compose logs -f nexus
```

The UI listens on port 8080 (`NEXUS_PORT` changes the published port). If
`NEXUS_ADMIN_PASSWORD` is empty on first start, a random admin password is printed once
in the logs.

### Evaluation without devices

Set `NEXUS_SIMULATOR=1` and restart. A simulated campus network answers SNMP (v2c
community `public`, v3 `prometheus` / `nexus-demo-pass`) and SSH (`netadmin` /
`nexus-demo-pass`) for 10.20.x.x addresses inside the container. Start with **Add Device
→ 10.20.99.1**. Real networks remain reachable in this mode.

## Bare-metal install

```bash
# database
sudo -u postgres createuser nexus -P
sudo -u postgres createdb -O nexus nexus

# build
cd frontend && npm ci && npm run build && cd ..
cd backend && CGO_ENABLED=0 go build -o /usr/local/bin/nexus ./cmd/nexus && cd ..
sudo mkdir -p /usr/share/nexus && sudo cp -r frontend/dist /usr/share/nexus/web

# configure (e.g. /etc/nexus/nexus.env, mode 0600)
NEXUS_DATABASE_URL=postgres://nexus:PASSWORD@127.0.0.1:5432/nexus?sslmode=disable
NEXUS_MASTER_KEY_FILE=/etc/nexus/master.key      # openssl rand -base64 32 > master.key; chmod 600
NEXUS_ADMIN_PASSWORD=...
NEXUS_WEB_DIR=/usr/share/nexus/web
NEXUS_LISTEN=127.0.0.1:8080
```

Example systemd unit:

```ini
[Unit]
Description=Nexus Network Intelligence
After=network-online.target postgresql.service

[Service]
EnvironmentFile=/etc/nexus/nexus.env
ExecStart=/usr/local/bin/nexus serve
User=nexus
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

## Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `NEXUS_DATABASE_URL` / `_FILE` | — (required) | PostgreSQL URL |
| `NEXUS_MASTER_KEY` / `_FILE` | — (required) | 32-byte key (base64 or hex) encrypting stored credentials |
| `NEXUS_LISTEN` | `:8080` | HTTP listen address |
| `NEXUS_WEB_DIR` | — | Built UI directory (served with SPA fallback) |
| `NEXUS_ADMIN_USER` / `NEXUS_ADMIN_PASSWORD` / `_FILE` | `admin` / generated | First admin account (only when no user exists) |
| `NEXUS_SESSION_TTL` | `12h` | Session lifetime (sliding) |
| `NEXUS_COOKIE_SECURE` | `false` | Set `true` behind HTTPS |
| `NEXUS_POLL_INTERVAL` | `5m` | SNMP polling of managed devices |
| `NEXUS_REDISCOVER_INTERVAL` | `6h` | Full re-collection of known devices (0 disables) |
| `NEXUS_METRICS_RETENTION` | `168h` | Interface rate history and poll logs |
| `NEXUS_SNMP_TIMEOUT` / `NEXUS_SNMP_RETRIES` | `3s` / `1` | SNMP transport |
| `NEXUS_DISCOVERY_WORKERS` | `4` | Parallel polls |
| `NEXUS_CLI_IDLE_TIMEOUT` / `NEXUS_CLI_MAX_DURATION` | `15m` / `4h` | CLI session limits |
| `NEXUS_SIMULATOR` | — | Any value starts the simulated campus network |
| `NEXUS_OUI_FILE` | — | Path to a newer IEEE `oui.csv` |
| `ANTHROPIC_API_KEY` / `NEXUS_LLM_MODEL` | — / `claude-opus-5` | Optional LLM question interpreter |
| `NEXUS_LOG_LEVEL` / `NEXUS_LOG_FORMAT` | `info` / `json` | Structured logs |

Discovery defaults (hops, allowed networks, device budget, active identification) and the
Telnet policy are edited in **Settings → Discovery & security**.

## TLS / reverse proxy

Nexus speaks plain HTTP; put it behind a reverse proxy that terminates TLS and forwards
WebSockets and Server-Sent Events. Set `NEXUS_COOKIE_SECURE=true`.

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;       # CLI WebSocket
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_buffering off;                          # discovery progress (SSE)
    proxy_read_timeout 1h;
}
```

## First test against a real Huawei switch (SNMPv3 authNoPriv SHA)

On the switch (VRP example):

```
snmp-agent
snmp-agent sys-info version v3
snmp-agent mib-view included iso-view iso
snmp-agent group v3 nexus-ro authentication read-view iso-view
snmp-agent usm-user v3 prometheus
snmp-agent usm-user v3 prometheus group nexus-ro
snmp-agent usm-user v3 prometheus authentication-mode sha
# (enter the authentication password when prompted)
snmp-agent acl 2000                      # restrict to the Nexus host
lldp enable
```

In Nexus: **Add Device** → IP of the switch, username `prometheus`, the password. Watch
the progress: reachability, "SNMP authenticated (SNMPv3 authNoPriv)", "Huawei detected",
model, interfaces, LLDP neighbors, MAC/ARP tables, topology. The SNMPv3 protocol does
not need to be chosen: with only username and password Nexus detects authNoPriv SHA (or
another protocol) and remembers it. Set it explicitly under *Advanced options* to skip
detection.

If authentication fails the progress shows *SNMP authentication failed* (wrong
user/password/protocol); if nothing answers it shows *no SNMP response* (IP, ACL,
firewall, SNMP disabled). Credentials for tests belong in the UI or in environment
variables — never in the repository.

## Backup & restore

Nexus writes portable backups itself (no `pg_dump` needed): a zip of the whole database
with a manifest (application and schema version, master-key fingerprint). Stored device
credentials stay encrypted; sessions are not exported.

```bash
# web: Settings → Diagnostics & backup → Download backup (optionally with the key, passphrase-protected)
docker compose exec nexus nexus backup --out /tmp/nexus.nxbackup      # or: nexus backup --include-key
docker compose cp nexus:/tmp/nexus.nxbackup .
# restore (replaces all data after writing a safety backup): stop the server, restore in a one-off container
docker compose stop nexus
docker compose run --rm -v "$PWD:/backup" nexus restore --yes /backup/nexus.nxbackup
docker compose start nexus
```

Set `NEXUS_BACKUP_DIR` to get a daily backup and one before every schema upgrade
(Windows installations do this by default). `pg_dump` works as well.

Back up the **master key** separately (or use `--include-key` with a passphrase):
without it stored credentials cannot be decrypted (re-enter them if lost; discovered
data is unaffected). A backup restored on an installation with a different key re-encrypts
the credentials when it contains the wrapped key and the passphrase is given.

## Upgrades

Pull the new version and `docker compose up -d --build`. Migrations run automatically at
start-up (serialized with an advisory lock) and are forward-only.

## Health & monitoring

- **Settings → Diagnostics & backup → Run health check** and **Export diagnostic bundle**
  (secrets are removed automatically); `nexus diagnostics --out FILE` on the command line.

- `GET /api/health` — database reachability and latency (503 when degraded).
- `GET /metrics` — Prometheus text format: discovery/poll durations, SNMP and poll errors
  by kind, HTTP responses, login failures, device/endpoint/edge counts, open alerts,
  discovery queue depth, DB latency.
- Logs are JSON (one line per event) with request method, path, status and duration.
