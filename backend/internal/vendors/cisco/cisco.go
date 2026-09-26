// Package cisco adds Cisco IOS / IOS-XE / NX-OS / ASA specific discovery:
// CDP neighbors, VTP VLANs, per-VLAN MAC tables, CPU, memory and environment.
package cisco

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/collectors"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors"
)

const (
	OIDCdpCacheEntry   = "1.3.6.1.4.1.9.9.23.1.2.1.1" // 3 addrType, 4 address, 5 version, 6 deviceId, 7 devicePort, 8 platform, 9 capabilities
	OIDVtpVlanState    = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
	OIDVtpVlanName     = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"
	OIDVmVlan          = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"
	OIDTrunkStatus     = "1.3.6.1.4.1.9.9.46.1.6.1.1.14"
	OIDCPU5min         = "1.3.6.1.4.1.9.9.109.1.1.1.1.8"
	OIDMemPoolUsed     = "1.3.6.1.4.1.9.9.48.1.1.1.5"
	OIDMemPoolFree     = "1.3.6.1.4.1.9.9.48.1.1.1.6"
	OIDEnvTempEntry    = "1.3.6.1.4.1.9.9.13.1.3.1" // 2 descr, 3 value, 6 state
	OIDEnvFanEntry     = "1.3.6.1.4.1.9.9.13.1.4.1" // 2 descr, 3 state
	OIDEnvSupplyEntry  = "1.3.6.1.4.1.9.9.13.1.5.1" // 2 descr, 3 state
	oidDot1dBasePortIf = "1.3.6.1.2.1.17.1.4.1.2"
	oidDot1dTpFdbPort  = "1.3.6.1.2.1.17.4.3.1.2"
)

type Adapter struct{}

func (Adapter) Name() string { return "cisco" }

func (Adapter) Match(sys model.System) bool {
	e := vendors.EnterpriseOf(sys.ObjectID)
	return e == 9 || e == 14179 || strings.Contains(strings.ToLower(sys.Descr), "cisco")
}

var osPatterns = []struct {
	re   *regexp.Regexp
	name string
}{
	{regexp.MustCompile(`(?i)Cisco IOS[ -]XR Software.*?Version ([\w.()\-]+)`), "IOS-XR"},
	{regexp.MustCompile(`(?i)Cisco NX-OS.*?Version ([\w.()\-]+)`), "NX-OS"},
	{regexp.MustCompile(`(?i)Cisco Adaptive Security Appliance Version ([\w.()\-]+)`), "ASA"},
	{regexp.MustCompile(`(?i)Cisco IOS Software \[\w+\].*?Version ([\w.()\-]+)`), "IOS-XE"},
	{regexp.MustCompile(`(?i)IOS-XE Software.*?Version ([\w.()\-]+)`), "IOS-XE"},
	{regexp.MustCompile(`(?i)Cisco IOS Software.*?Version ([\w.()\-]+)`), "IOS"},
	{regexp.MustCompile(`(?i)Cisco Internetwork Operating System.*?Version ([\w.()\-]+)`), "IOS"},
	{regexp.MustCompile(`(?i)Cisco Controller.*?Version ([\w.()\-]+)`), "AireOS"},
}

var reImage = regexp.MustCompile(`\(([A-Z0-9_]+)-[A-Z0-9_]+-[A-Z]\)`)

func (Adapter) Enrich(sys *model.System) {
	sys.Vendor = "Cisco"
	for _, p := range osPatterns {
		if m := p.re.FindStringSubmatch(sys.Descr); m != nil {
			sys.OSName = p.name
			sys.OSVersion = strings.TrimRight(m[1], ",")
			break
		}
	}
	if sys.Model == "" {
		if m := reImage.FindStringSubmatch(sys.Descr); m != nil {
			sys.Model = m[1] // platform family, refined by ENTITY-MIB when available
		}
	}
}

func (Adapter) Collectors() []collectors.Collector {
	return []collectors.Collector{
		collectors.Func{N: "cdp", F: CollectCDP},
		collectors.Func{N: "cisco_vlans", F: collectVLANs},
		collectors.Func{N: "cisco_fdb", F: collectFDB},
		collectors.Func{N: "cisco_health", F: collectHealth},
	}
}

// CDP capability bits.
var cdpCaps = []struct {
	bit  uint32
	name string
}{{0x01, "router"}, {0x02, "bridge"}, {0x04, "bridge"}, {0x08, "bridge"}, {0x10, "station"}, {0x40, "repeater"}, {0x80, "phone"}}

func CollectCDP(ctx context.Context, s *collectors.Session, snap *model.Snapshot) error {
	rows, order, err := snmp.Table(ctx, s.Client, OIDCdpCacheEntry, 3, 4, 5, 6, 7, 8, 9)
	if err != nil {
		return err
	}
	for _, idx := range order {
		parts := snmp.IndexInts(idx)
		if len(parts) != 2 {
			continue
		}
		r := rows[idx]
		n := model.Neighbor{
			Protocol:  "cdp",
			SysName:   stripDomainSerial(r[6].String()),
			ChassisID: r[6].String(),
			PortID:    r[7].String(),
			SysDescr:  r[5].String(),
			Platform:  r[8].String(),
		}
		if r[3].Int() == 1 {
			if b := r[4].Bytes(); len(b) == 4 {
				n.MgmtIP = snmp.PDU{Value: b}.IP()
			}
		}
		if b := r[9].Bytes(); len(b) == 4 {
			v := binary.BigEndian.Uint32(b)
			seen := map[string]bool{}
			for _, c := range cdpCaps {
				if v&c.bit != 0 && !seen[c.name] {
					n.Capabilities = append(n.Capabilities, c.name)
					seen[c.name] = true
				}
			}
		}
		if it := snap.InterfaceByIndex(parts[0]); it != nil {
			n.LocalIfIndex = it.IfIndex
			n.LocalPort = it.Name
		}
		// Skip if LLDP already reported the same adjacency.
		dup := false
		for _, e := range snap.Neighbors {
			if e.LocalIfIndex == n.LocalIfIndex && e.LocalIfIndex != 0 && strings.EqualFold(e.SysName, n.SysName) {
				dup = true
				break
			}
		}
		if !dup {
			snap.Neighbors = append(snap.Neighbors, n)
		}
	}
	return nil
}

// stripDomainSerial turns "SW1.example.com" / "SEP001122334455" into a name.
func stripDomainSerial(s string) string {
	if i := strings.Index(s, "("); i > 0 { // NX-OS "switch(SERIAL)"
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func collectVLANs(ctx context.Context, s *collectors.Session, snap *model.Snapshot) error {
	names, err := s.Client.Walk(ctx, OIDVtpVlanName)
	if err != nil {
		return err
	}
	have := map[int]bool{}
	for _, v := range snap.VLANs {
		have[v.ID] = true
	}
	for _, p := range names {
		idx, _ := snmp.Suffix(p.OID, OIDVtpVlanName)
		parts := snmp.IndexInts(idx)
		if len(parts) != 2 || have[parts[1]] || parts[1] >= 1002 && parts[1] <= 1005 {
			continue
		}
		snap.VLANs = append(snap.VLANs, model.VLAN{ID: parts[1], Name: p.String()})
		have[parts[1]] = true
	}
	if snap.PortVLANs == nil {
		snap.PortVLANs = map[int][]model.PortVLAN{}
	}
	if acc, err := s.Client.Walk(ctx, OIDVmVlan); err == nil {
		for _, p := range acc {
			idx, _ := snmp.Suffix(p.OID, OIDVmVlan)
			n, _ := strconv.Atoi(idx)
			if it := snap.InterfaceByIndex(n); it != nil {
				it.PVID = int(p.Int())
				if len(snap.PortVLANs[n]) == 0 {
					snap.PortVLANs[n] = []model.PortVLAN{{VLAN: int(p.Int())}}
				}
			}
		}
	}
	return nil
}

// collectFDB walks BRIDGE-MIB in each VLAN context (community@vlan / context vlan-N),
// which is how Cisco exposes per-VLAN MAC tables.
func collectFDB(ctx context.Context, s *collectors.Session, snap *model.Snapshot) error {
	if len(snap.FDB) > 0 || s.ContextClient == nil {
		return nil
	}
	for _, v := range snap.VLANs {
		if v.ID >= 1002 && v.ID <= 1005 {
			continue
		}
		c, err := s.ContextClient(ctx, fmt.Sprintf("vlan-%d", v.ID))
		if err != nil {
			continue
		}
		portIf := map[int]int{}
		if bp, err := c.Walk(ctx, oidDot1dBasePortIf); err == nil {
			for _, p := range bp {
				idx, _ := snmp.Suffix(p.OID, oidDot1dBasePortIf)
				n, _ := strconv.Atoi(idx)
				portIf[n] = int(p.Int())
			}
		}
		fdb, err := c.Walk(ctx, oidDot1dTpFdbPort)
		c.Close()
		if err != nil {
			continue
		}
		for _, p := range fdb {
			idx, _ := snmp.Suffix(p.OID, oidDot1dTpFdbPort)
			parts := snmp.IndexInts(idx)
			if len(parts) != 6 {
				continue
			}
			ifIndex := portIf[int(p.Int())]
			if ifIndex == 0 {
				continue
			}
			b := make([]byte, 6)
			for i, x := range parts {
				b[i] = byte(x)
			}
			mac := snmp.PDU{Value: b}.MAC()
			if mac == "" {
				continue
			}
			snap.FDB = append(snap.FDB, model.FDBEntry{MAC: mac, VLAN: v.ID, IfIndex: ifIndex, Status: "learned"})
		}
	}
	return nil
}

var envState = map[int64]string{1: "ok", 2: "warning", 3: "critical", 4: "critical", 5: "unknown", 6: "critical"}

func collectHealth(ctx context.Context, s *collectors.Session, snap *model.Snapshot) error {
	if cpu, err := s.Client.Walk(ctx, OIDCPU5min); err == nil && len(cpu) > 0 {
		v := float64(cpu[0].Int())
		snap.System.CPUPercent = &v
	}
	used, err1 := s.Client.Walk(ctx, OIDMemPoolUsed)
	free, err2 := s.Client.Walk(ctx, OIDMemPoolFree)
	if err1 == nil && err2 == nil && len(used) > 0 && len(free) > 0 {
		u, f := float64(used[0].Uint()), float64(free[0].Uint())
		if u+f > 0 {
			v := math.Round(u/(u+f)*1000) / 10
			snap.System.MemoryPercent = &v
		}
	}
	if rows, order, err := snmp.Table(ctx, s.Client, OIDEnvTempEntry, 2, 3, 6); err == nil {
		for _, idx := range order {
			r := rows[idx]
			v := float64(r[3].Int())
			snap.Sensors = append(snap.Sensors, model.Sensor{Kind: "temperature", Name: r[2].String(), Value: &v, Unit: "°C", Status: envState[r[6].Int()]})
		}
	}
	for _, t := range []struct{ oid, kind string }{{OIDEnvFanEntry, "fan"}, {OIDEnvSupplyEntry, "power"}} {
		rows, order, err := snmp.Table(ctx, s.Client, t.oid, 2, 3)
		if err != nil {
			continue
		}
		for _, idx := range order {
			r := rows[idx]
			if r[3].Int() == 5 { // notPresent
				continue
			}
			snap.Sensors = append(snap.Sensors, model.Sensor{Kind: t.kind, Name: r[2].String(), Status: envState[r[3].Int()]})
		}
	}
	return nil
}
