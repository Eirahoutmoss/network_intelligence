# Architecture

Nexus is a single Go service backed by PostgreSQL, serving a React single-page
application. Everything runs on one machine; no message broker or time-series
database is required for the first version.

```
Browser ──HTTPS──> nexus (Go)
  │                 ├─ api/            REST + SSE + WebSocket (CLI)
  │                 ├─ discovery/      run orchestration, recursion, progress hub
  │                 ├─ collectors/     standard MIB collectors → domain model
  │                 ├─ vendors/*       Huawei, Cisco, HPE, Juniper, Arista, MikroTik adapters
  │                 ├─ snmp/           client abstraction (gosnmp, fixtures, simulator agent)
  │                 ├─ inventory/      ingest, identity resolution, attachments, topology build
  │                 ├─ identity/       pure identity-resolution rules
  │                 ├─ classify/       device type / OS / vendor with evidence
  │                 ├─ fingerprint/    DNS, NetBIOS, SMB, HTTP, port and SNMP probes
  │                 ├─ topology/       graph algorithms and layout
  │                 ├─ explorer/       question parser, optional LLM interpreter, executor
  │                 ├─ locations/      buildings/floors/rooms/racks/jacks, device context
  │                 ├─ cli/            WebSocket ↔ SSH/Telnet bridge with audit
  │                 ├─ scheduler/      polling, rediscovery, retention
  │                 └─ credentials/    AES-256-GCM sealed secrets
  └───────────────> PostgreSQL
```

## Flow of a discovery

1. **Add Device** creates an encrypted SNMP credential and queues a discovery run.
2. The run **collects the seed**: reachability → SNMP authentication → system identity →
   vendor detection (sysObjectID enterprise number, then sysDescr) → standard collectors →
   vendor collectors → derived facts (port medium, transceivers).
3. The snapshot is **ingested**: the device record is found or created through identity
   resolution; interfaces, inventory, sensors, optics, VLANs, neighbors, MAC table, ARP
   table, routes and subnets are stored.
4. **Recursion**: LLDP/CDP neighbors that look like network devices, have a management
   address inside the scope, have not been visited and fit the device budget are queued
   (bounded concurrency, configurable depth). Other SNMP credentials are tried when the
   seed's credential fails on a neighbor.
5. **Network-wide derivation** (serialized):
   - neighbors are resolved to device records (unmanaged ones are created, e.g. a
     firewall seen only via LLDP),
   - uplinks are marked (ports facing network devices),
   - endpoints are created from ARP and MAC tables,
   - each endpoint is **attached** to the access port where its MAC is seen with the
     fewest other MACs (LLDP-MED phones/APs are authoritative); moves close the previous
     attachment and raise an event,
   - manufacturer (OUI) and randomized-MAC flags are set.
6. **Fingerprinting** of endpoints inside the scope: passive reverse DNS always; active
   probes (NetBIOS, TCP service check, HTTP banner, SMB negotiate + NTLM challenge, SNMP
   `public`) only when enabled.
7. **Classification** of every device (type, OS, vendor) with evidence rows.
8. **Topology** edges are rebuilt from neighbors, attachments and shared L3 subnets.

Progress is streamed to the UI with Server-Sent Events and persisted on the run.

## Data model: three layers

The schema (`backend/migrations/0001_init.sql`) deliberately separates:

| Layer | Examples | Written by |
|---|---|---|
| Machine-discovered facts | `devices.sys_*`, `interfaces`, `neighbors`, `fdb_entries`, `arp_entries`, `routes`, `optics`, `sensors`, `device_addresses/macs/hostnames` | collectors, ingest |
| User-defined context | `device_context` (display name, description, department, type override, location, rack), `device_tags`, `locations`, `racks`, `patch_panels`, `network_jacks`, `manual_links`, `topology_layout` | the UI only |
| Derived intelligence | `devices.device_type/os_name/*_confidence`, `evidence`, `attachments`, `topology_edges`, `subnets` | inventory derivation |

User context never overwrites discovered facts; the `device_view` view combines them
(display name falls back to discovered names, a type override wins over classification,
and location is inferred from the wall jack or from the switch an endpoint is plugged
into when the user has not placed it).

## Collectors

A collector answers a domain question and fills the vendor-neutral
`model.Snapshot`; it never maps OIDs to rows. Failures are recorded on the snapshot and
never abort discovery. Standard collectors cover SNMPv2-MIB, IF-MIB (+ifXTable,
EtherLike duplex), IP-MIB, ENTITY-MIB (+alias mapping), LLDP-MIB, Q-BRIDGE/BRIDGE-MIB,
ARP (ipNetToMedia/ipNetToPhysical), IP-FORWARD-MIB (inetCidr/ipCidr/ipRoute),
HOST-RESOURCES-MIB and ENTITY-SENSOR-MIB. Vendor adapters (`backend/internal/vendors/*`)
add only what standards cannot: Huawei CPU/memory/temperature/optical power and dynamic
MAC table, Cisco CDP, VTP VLANs, per-VLAN MAC tables through SNMP contexts and
environment monitoring; and they parse model/OS strings.

## Identity resolution

Every observation carries identifying keys. MAC addresses, LLDP chassis IDs and serial
numbers are strong; a network device's sysName is medium; an IP address is weak.

- Strong keys win; several devices sharing strong keys are **merged** (child rows move,
  user context of the older record wins, an `identity` evidence row explains the merge).
- A sysName only matches when no strong key disagrees.
- An IP only matches when the candidate has no conflicting MAC; otherwise the IP has moved
  (DHCP) and is released from the old owner.
- First-hop redundancy MACs (VRRP/HSRP) are never used as identity.

## Classification with confidence

Each rule contributes weighted evidence to a candidate value. Weights combine with a
noisy-OR (`1 − Π(1 − w)`), a competing candidate discounts the winner, and results below
a threshold stay `unknown`. Operating systems roll up into families: with strong evidence
(SMB native OS "Windows 5.1", DHCP option-55 signature, NetBIOS, TTL) Nexus reports
"Windows XP 95%"; with only weak signals it reports "Windows NT family 61%". Samba servers
are recognized so they are not mistaken for Windows 7. Every result keeps its evidence
and the UI shows it.

## Topology

Edges from both ends of an LLDP/CDP adjacency (and CDP duplicates) are merged; seeing a
link from both sides raises confidence to 99%. The hierarchy root is the graph center of
the network-device subgraph (not merely the busiest switch). The layout is a tidy tree in
which endpoints are packed under their switch; user-dragged positions are persisted.

## Explorer

`Natural language → structured Query → SQL on device_view / topology → answer`.
The rule-based parser handles Turkish and English (inflected forms such as
"Laboratuvarda", "HP'ler", "Kat 2'de", "SW-CORE-01'e bağlı"). When an Anthropic API key
is configured and the rules recognize nothing, Claude is asked to produce the same
structured query (JSON schema-constrained output); its output is validated against known
device names and types. The LLM never sees query results and cannot invent numbers.
Every answer lists how the question was understood and the data source.

## Scaling notes

- Tables are indexed for per-device and per-MAC access; derivation loads identity keys in
  memory (fine for tens of thousands of devices).
- Interface counters are stored as rates in `interface_metrics` with retention; a
  dedicated TSDB (VictoriaMetrics/TimescaleDB) can replace this table later without
  touching collectors.
- Discovery runs are processed one at a time; devices within a run are collected in
  parallel (default 4) and network-wide derivation is serialized.
