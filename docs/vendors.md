# Vendor support & OIDs

Standard MIBs are always tried first. Vendor adapters add data the standards do not
provide and parse vendor strings. The table shows how each item was verified.

**Verification legend:** ✅ tested against a real implementation (net-snmp agent over
SNMPv3 authNoPriv/SHA and authPriv/AES; Samba for SMB) ·
🧪 tested against the simulated lab only (OID layout from vendor documentation; confirm on
real hardware) · 📄 implemented, not yet exercised.

## Standard (all vendors)

| Data | MIB / OID | Status |
|---|---|---|
| System, uptime, services | SNMPv2-MIB `1.3.6.1.2.1.1` | ✅ |
| Interfaces, 64-bit counters, names, aliases | IF-MIB `ifTable`, `ifXTable` | ✅ |
| Duplex | EtherLike-MIB `dot3StatsDuplexStatus` | 🧪 |
| IP addresses | IP-MIB `ipAddrTable` | ✅ |
| Hardware inventory, serials, transceivers | ENTITY-MIB `entPhysicalTable`, `entAliasMappingTable` | 🧪 |
| Sensors | ENTITY-SENSOR-MIB `entPhySensorTable` | 🧪 |
| CPU / RAM | HOST-RESOURCES-MIB `hrProcessorLoad`, `hrStorageTable` | ✅ |
| LLDP | LLDP-MIB `lldpRemTable`, `lldpLocPortTable`, `lldpRemManAddrTable` | 🧪 |
| VLANs, PVID, membership | Q-BRIDGE-MIB `dot1qVlanStaticTable`, `dot1qPvid` | 🧪 |
| MAC table | Q-BRIDGE `dot1qTpFdbTable` → BRIDGE-MIB `dot1dTpFdbTable` | 🧪 |
| ARP | IP-MIB `ipNetToMediaTable` → `ipNetToPhysicalTable` | ✅ |
| Routes | IP-FORWARD-MIB `inetCidrRouteTable` → `ipCidrRouteTable` → `ipRouteTable` (capped at 5000) | ✅ |
| Printer detection | HOST-RESOURCES `hrDeviceType`, Printer-MIB `prtGeneralPrinterName` | 📄 |

## Huawei (VRP / CloudEngine)

Enterprise `2011`. Model and VRP version from sysDescr (`Version 5.170 (S5735
V200R019C00SPC500)`) and ENTITY-MIB.

| Data | OID | Status |
|---|---|---|
| CPU % per board | `hwEntityCpuUsage 1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5` | 🧪 |
| Memory % | `hwEntityMemUsage …1.1.1.1.7` | 🧪 |
| Temperature | `hwEntityTemperature …1.1.1.1.11` | 🧪 |
| Optical Rx/Tx power (µW → dBm) | `hwEntityOpticalRxPower/TxPower 1.3.6.1.4.1.2011.5.25.31.1.1.3.1.8/.9` | 🧪 (values outside 0–100 000 µW are discarded) |
| Dynamic MAC table (fallback) | `hwDynFdbPort 1.3.6.1.4.1.2011.5.25.42.2.1.3.1.4` | 🧪 |

The first real-device milestone is a Huawei switch with SNMPv3 authNoPriv/SHA: the
SNMPv3 path itself is verified against net-snmp; please report any mismatch in Huawei
private OIDs with an `snmpwalk -On` excerpt.

## Cisco (IOS, IOS-XE, NX-OS, ASA, AireOS)

Enterprise `9` (and `14179` Airespace). OS/version parsed for IOS, IOS-XE, IOS-XR, NX-OS,
ASA and AireOS.

| Data | OID | Status |
|---|---|---|
| CDP neighbors | `cdpCacheTable 1.3.6.1.4.1.9.9.23.1.2.1.1` (duplicates of LLDP adjacencies suppressed) | 🧪 |
| VLAN names | `vtpVlanName 1.3.6.1.4.1.9.9.46.1.3.1.1.4` | 🧪 |
| Access VLAN | `vmVlan 1.3.6.1.4.1.9.9.68.1.2.2.1.2` | 🧪 |
| Per-VLAN MAC table | BRIDGE-MIB via community `public@<vlan>` / v3 context `vlan-<vlan>` | 🧪 |
| CPU 5 min | `cpmCPUTotal5minRev 1.3.6.1.4.1.9.9.109.1.1.1.1.8` | 🧪 |
| Memory | `ciscoMemoryPoolUsed/Free 1.3.6.1.4.1.9.9.48.1.1.1.5/.6` | 🧪 |
| Temperature, fans, PSUs | CISCO-ENVMON-MIB `1.3.6.1.4.1.9.9.13.1.{3,4,5}` | 🧪 |

## HPE / Aruba / H3C

Enterprises `11`, `47196`, `14823`, `25506`. Parses ProCurve/ArubaOS-Switch
(`HP J9776A 2530-24G Switch, revision YA.16.11.0015`), AOS-CX and Comware strings. Data
comes from standard MIBs (🧪 with the HPE lab switch).

## Juniper, Arista, MikroTik

Identity parsing only (model, Junos/EOS/RouterOS versions); data from standard MIBs. 📄

## Vendor detection

`sysObjectID` enterprise number (≈90 vendors), then sysDescr keywords. Endpoint
manufacturers come from the embedded IEEE OUI registry (≈40 000 prefixes) normalized to
short names (e.g. "Hewlett Packard" → HP, "Hewlett Packard Enterprise" → HPE).
