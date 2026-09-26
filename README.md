# Nexus — Network Intelligence Platform

> "Sen ağa erişimi ver. Gerisini sistem anlamaya çalışsın."
> *Give it access to the network. It works out the rest.*

Nexus is a self-hosted **network discovery + asset intelligence + topology + location
context + natural-language exploration** platform. It is not another monitoring
dashboard: an IT person with little networking background enters **one IP address and
an SNMP username/password**, and Nexus discovers the switches, routers, firewalls,
access points, phones, printers and computers behind it, works out what each device is,
where it is plugged in, and lets you ask the network questions in Turkish or English.

```
DISCOVER  →  UNDERSTAND  →  ASK
```

| | |
|---|---|
| **Discover** | SNMP v2c/v3 (incl. authNoPriv/SHA), LLDP/CDP recursion with scope, depth, rate and loop control; interfaces, optics, VLANs, MAC tables, ARP, routes, CPU/memory/sensors |
| **Understand** | Identity resolution (one device, many sources), device type / OS / vendor classification with **confidence and evidence**, port attachment with move history, automatic topology |
| **Ask** | "Kaç switch var?", "HP yazıcıları göster", "Laboratuvarda Windows XP kullanan cihazları göster", "SW-CORE-01'e bağlı cihazlar", "Room 214 jack 07'ye ne bağlı?" — answered only from discovered data |

## Türkçe özet

- **Windows kurulumu:** `Nexus-1.0.0-Setup-x64.exe` dosyasını çalıştırın, yönetici onayını verin. Kurulum bilgisayarı kontrol eder, Nexus'u kendi veritabanıyla birlikte Windows hizmeti olarak kurar, çalıştığını doğrular ve tarayıcıyı açar; ilk yönetici hesabını tarayıcıda oluşturursunuz. Docker, WSL, PostgreSQL veya internet bağlantısı gerekmez. Ayrıntılar: [docs/windows.md](docs/windows.md).
- **Docker kurulumu:** `cp .env.example .env` → `NEXUS_MASTER_KEY` (`openssl rand -base64 32`) ve parolaları doldurun → `docker compose up -d` → <http://localhost:8080>.
- **Deneme ağı:** `.env` içinde `NEXUS_SIMULATOR=1` ayarlayın. Gerçek cihaz olmadan simüle bir kampüs ağı (Huawei core, Cisco dağıtım, HPE lab switch'i, FortiGate, ~35 uç cihaz) kullanılır. *Add Device* ekranında `10.20.99.1` / `prometheus` / `nexus-demo-pass` girin.
- **Gerçek ağ:** *Add Device* ekranında switch'in IP'si, SNMPv3 kullanıcı adı ve parolası yeterlidir (varsayılan: SNMPv3 authNoPriv, SHA). Keşif yalnızca izin verilen ağlarda (varsayılan: başlangıç IP'sinin /16'sı) ve belirlenen komşu derinliğinde yapılır.
- **Explorer:** Soruları Türkçe veya İngilizce sorun. Soru yapılandırılmış bir filtreye çevrilir, cevap yalnızca veritabanındaki keşif verisinden gelir; nasıl anlaşıldığı ve kaynağı ekranda gösterilir.
- **CLI:** Cihaz sayfasında *Open CLI* sağdan bir terminal açar. Tarayıcı cihaza doğrudan bağlanmaz; bağlantı backend üzerinden SSH ile kurulur, parolalar tarayıcıya gönderilmez, oturumlar denetim için kaydedilir. Telnet varsayılan olarak kapalıdır.

## Quick start (Windows)

Run **`Nexus-<version>-Setup-x64.exe`** (built by `deployments/windows/build.sh`,
published by the *Windows installer* workflow) and accept the administrator prompt.
Setup checks the computer, installs Nexus as a Windows service with its own bundled
PostgreSQL, generates the encryption key, verifies the installation and opens the
browser, where you create the administrator. No Docker, WSL, PostgreSQL, `.env` file or
internet access is needed; silent installs, upgrades with automatic rollback, backups
and diagnostics are built in. See **[docs/windows.md](docs/windows.md)**.

## Quick start (Docker)

```bash
git clone https://github.com/Eirahoutmoss/network_intelligence.git nexus && cd nexus
cp .env.example .env
# edit .env: set NEXUS_MASTER_KEY (openssl rand -base64 32), POSTGRES_PASSWORD, NEXUS_ADMIN_PASSWORD
# optional: NEXUS_SIMULATOR=1 to try the built-in simulated network
docker compose up -d
```

Open <http://localhost:8080>, sign in as `admin`, click **Add Device**.

With the simulator enabled use IP `10.20.99.1`, username `prometheus`, password
`nexus-demo-pass` (the dialog offers a *Fill in* shortcut).

See [docs/installation.md](docs/installation.md) for bare-metal installs, TLS/reverse
proxy, backups, upgrades and the first test against a real Huawei switch.

## What you get

- **Add Device wizard** — IP + SNMP username + password. Advanced options (version,
  security level, auth/privacy protocols, context, port, scope, depth, active
  identification, SSH login for the CLI) are folded away.
- **Live discovery progress** — ✓ Reachable ✓ SNMP authenticated ✓ Huawei detected ✓ Model
  detected ✓ 30 interfaces ✓ LLDP neighbors ✓ MAC/ARP tables ✓ Topology updated … Device ready.
- **Dashboard, Devices, Printers, Computers** — searchable inventory with type/OS
  confidence badges, switch port and inferred location for every endpoint.
- **Device page** — "Why Nexus thinks this is…" evidence for type/OS/vendor, interfaces
  (speed, duplex, fiber/copper, SFP vendor/serial, Rx/Tx dBm), LLDP/CDP neighbors,
  connected devices, port history, your own context (name, location, tags, notes),
  advanced raw tables (MAC, ARP, routes, VLANs, ENTITY inventory).
- **Topology** — automatic tree (core → distribution → access → endpoints), physical and
  L3 layers, location filter and grouping, search, drag-and-drop positions that persist,
  manually added links for what discovery cannot see.
- **Explore Network** — natural-language questions plus structured filters.
- **Locations** — buildings → floors → rooms → racks → patch panels → wall jacks mapped to
  switch ports; one-click import from switches' SNMP `sysLocation`.
- **CLI drawer** — SSH (Telnet only when explicitly enabled) through the backend with
  TOFU host-key pinning, idle/max timeouts and recorded transcripts.
- **Monitoring** — periodic polling, device up/down, interface and uplink alerts, CPU and
  temperature alerts, events, reports (legacy OS, port capacity, software versions).
- **Security** — encrypted credentials (AES-256-GCM, key from environment), bcrypt
  users, roles (viewer/operator/admin), audit log, CSRF protection, strict CSP.
- **Observability** — structured JSON logs, Prometheus metrics at `/metrics`,
  `/api/health`.

## Repository layout

```
backend/        Go service (cmd/nexus, internal/*, migrations)
frontend/       React + TypeScript + Vite + Tailwind web UI
deployments/    Dockerfile; windows/ installer (NSIS script, build, tests)
docs/           Architecture, installation, security, API, vendors, licenses
scripts/        License audit
tests/e2e/      Playwright end-to-end tests
```

## Documentation

- [Architecture](docs/architecture.md) — data model, collectors, identity, classification, topology, explorer
- [Windows installation](docs/windows.md) — installer, service, upgrade/rollback, backup, diagnostics
- [Installation & operations](docs/installation.md)
- [Security](docs/security.md)
- [HTTP API](docs/api.md)
- [Development & testing](docs/development.md)
- [Vendor support & OIDs](docs/vendors.md)
- [Third-party licenses](docs/THIRD_PARTY_LICENSES.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). All dependencies are
permissively licensed; `scripts/license-audit.py` enforces this.
