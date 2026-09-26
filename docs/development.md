# Development & testing

## Running locally

```bash
# PostgreSQL (any 14+)
createdb nexus

# backend (demo network on, UI served by Vite below)
cd backend
export NEXUS_DATABASE_URL=postgres://nexus:nexus@127.0.0.1:5432/nexus?sslmode=disable
export NEXUS_MASTER_KEY=$(openssl rand -base64 32) NEXUS_ADMIN_PASSWORD=admin-pass-123
export NEXUS_SIMULATOR=1 NEXUS_LOG_FORMAT=text
go run ./cmd/nexus

# frontend with hot reload (proxies /api to :8080)
cd frontend && npm ci && npm run dev    # http://localhost:5173
```

## The simulated lab

`backend/internal/lab` renders a consistent campus network into SNMP MIBs:

```
SW-CORE-01  Huawei S6730 (L3 core, VRP 8)         10.20.99.1
├── SW-DIST-01  Cisco C9300 (IOS-XE 17.9)           10.20.99.2
│   ├── SW-ACC-F1-01  Huawei S5735 (Floor 1)         10.20.99.11  PCs, HP/Canon printers, camera
│   └── SW-ACC-F2-01  Huawei S5735 (Floor 2)         10.20.99.12  Room 214 PCs, Yealink phones, AP
├── SW-DIST-02  Huawei S5731                        10.20.99.3
│   └── SW-LAB-01  HPE 2530-24G (Laboratory)         10.20.99.21  Windows XP/7 PCs, server, printers
└── FW-01  FortiGate-100F (LLDP only, not SNMP)     10.20.255.254
```

LLDP is symmetric, MAC tables follow the physical tree (including Cisco per-VLAN
contexts), ARP and routes live on the core, uplinks carry SFPs with DOM values. The
in-process `snmp.Agent` serves v1/v2c and **SNMPv3 noAuthNoPriv/authNoPriv** (USM reports
for unknown engine, unknown user and wrong digest are implemented), and `lab.StartSSH`
provides read-only VRP/IOS/ProCurve-like consoles. Endpoint fingerprints (DNS names,
NetBIOS, SMB, HTTP, ports) are simulated by `lab.Prober()`.

`nexus lab-export DIR` writes the lab as `.snmprec` fixtures (snmpsim format), which the
`snmp.ParseSnmprec`/`snmp.MIBClient` fixture client can replay.

## Tests

```bash
cd backend
go test ./...                                   # unit tests (DB tests skip without a database)

# integration tests (PostgreSQL, the lab over real UDP/SNMPv3, SSH, WebSocket, HTTP API)
export NEXUS_TEST_DATABASE_URL=postgres://nexus:nexus@127.0.0.1:5432/nexus_test?sslmode=disable
go test -p 1 ./...

# optional: real net-snmp agent (v3 authNoPriv SHA + authPriv AES users) and Samba
export NEXUS_TEST_SNMPD=127.0.0.1:16161         # see snmp/v3_integration_test.go for users
export NEXUS_TEST_SMB=127.0.0.1:445
```

| Area | Tests |
|---|---|
| Credential encryption | seal/open, AAD binding, wrong key, nonce uniqueness, SNMP defaults |
| SNMP | snmprec parsing, bulk walks over UDP, SNMPv3 against the simulator and net-snmp, error classification |
| Collectors + vendors | Huawei core, Cisco distribution (CDP suppression, per-VLAN FDB), HPE access: system, OS/model parsing, interfaces, medium, optics dBm, LLDP port mapping, VLANs, FDB, ARP, routes |
| Identity resolution | unified device across sources, merges, IP reassignment, sysName rules |
| Classification | Windows XP 90%+, "Windows NT family" fallback, HP printer vs HP computer, network devices, cameras, phones, Samba vs Windows, build-based Windows versions |
| Topology | edge dedup, parallel links, hierarchy root, downstream, layout |
| Explorer | 20 Turkish/English example questions → structured queries; MVP scenario against the discovered lab |
| Discovery engine | full lab discovery (6 switches via recursion, 0 duplicate MACs, every endpoint on the right port, printers/phones/AP/camera/XP counts, confirmed links, uplinks) and move history |
| CLI | Telnet option negotiation; browser → WebSocket → SSH with audit transcript, host-key pinning and Telnet refusal |
| API | login, CSRF, Add Device with SSE progress, lists, explore, topology, CSV, metrics, CLI over the API, cross-origin WebSocket rejection, RBAC |
| Fingerprinting | NetBIOS parsing, SPNEGO encoding, SMB1/SMB2 against Samba |

### End-to-end (browser)

```bash
# start a fresh demo server first (NEXUS_SIMULATOR=1, empty database)
cd tests/e2e && npm ci
NEXUS_URL=http://localhost:8080 npx playwright test
# PW_CHROMIUM=/path/to/chrome to use a preinstalled browser, SHOTS_DIR=... for screenshots
```

The MVP spec signs in, adds `10.20.99.1` with username/password, waits for "Device ready",
asks the product-brief questions, imports locations, checks the lab Windows XP answer,
renders the topology, opens the device page and runs `display version` in the CLI drawer,
and checks a printer's classification evidence.

## License audit

```bash
python3 scripts/license-audit.py --write   # updates docs/THIRD_PARTY_LICENSES.md, fails on copyleft/unknown
```

## Adding a vendor

1. Create `backend/internal/vendors/<vendor>/` with an `Adapter` (`Match`, `Enrich`,
   `Collectors`). Keep vendor OIDs inside the package.
2. Register it in `vendors/all`.
3. Add the vendor's devices to the lab (or an `.snmprec` fixture) and a collection test.
