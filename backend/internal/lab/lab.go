// Package lab builds a simulated campus network: SNMP MIBs for every managed
// device (served by snmp.Agent) plus simulated endpoint fingerprints.
//
// The lab is used by integration/E2E tests and by demo mode
// (NEXUS_SIMULATOR). All data is synthetic but internally consistent: LLDP is
// symmetric, MAC tables follow the physical tree, ARP lives on the L3 core.
package lab

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/fingerprint"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

// Port is a physical interface.
type Port struct {
	IfIndex    int
	BridgePort int
	LLDPNum    int
	Name       string // full ifName
	Short      string // what the device announces in LLDP (Cisco short names, HPE numbers)
	Alias      string
	Speed      uint64
	Up         bool
	PVID       int
	Trunk      []int
	Optic      *Optic
	InOctets   uint64
	OutOctets  uint64
	InErrors   uint64
}

type Optic struct {
	Descr, Vendor, Part, Serial string
	RxUW, TxUW                  int64
}

type SVI struct {
	IfIndex int
	VLAN    int
	IP      string
	Prefix  int
}

type Route struct {
	Dest, Mask, NextHop string
	IfIndex             int
	Proto               int
	Metric              int
}

// Device is a network device in the lab.
type Device struct {
	Name, MgmtIP, ChassisMAC string
	Family                   string // huawei|cisco|hpe|fortinet
	Descr, ObjectID, Model   string
	Serial, Location         string
	Router                   bool
	Managed                  bool // has an SNMP agent
	Parent                   string
	Ports                    []*Port
	SVIs                     []SVI
	VLANs                    map[int]string
	Routes                   []Route
	CPU, Mem, Temp           int
	ExtraCaps                []string
}

func (d *Device) port(name string) *Port {
	for _, p := range d.Ports {
		if p.Name == name {
			return p
		}
	}
	panic(fmt.Sprintf("lab: %s has no port %s", d.Name, name))
}

// Endpoint is a host attached to an access port.
type Endpoint struct {
	Name, IP, MAC string
	Switch, Port  string
	VLAN          int
	Obs           fingerprint.Observation
	LLDPCaps      []string // phones / APs announce LLDP
	LLDPDescr     string
}

type Link struct{ A, APort, B, BPort string }

// Lab is the whole simulated network.
type Lab struct {
	Devices   []*Device
	Endpoints []*Endpoint
	Links     []Link
	// V3 credentials accepted by every simulated agent (in addition to v2c Community).
	Community string
	V3User    string
	V3Pass    string
}

func (l *Lab) Device(name string) *Device {
	for _, d := range l.Devices {
		if d.Name == name {
			return d
		}
	}
	return nil
}

// Prober returns simulated fingerprints (DNS names, NetBIOS, SMB, HTTP, ports).
func (l *Lab) Prober() fingerprint.StaticProber {
	m := map[string]fingerprint.Observation{}
	for _, e := range l.Endpoints {
		o := e.Obs
		o.IP = e.IP
		m[e.IP] = o
	}
	return fingerprint.StaticProber{Obs: m}
}

// AgentMIBs holds the MIBs for one simulated agent.
type AgentMIBs struct {
	Main     *snmp.MIB
	Contexts map[string]*snmp.MIB
}

// Build renders MIBs for every managed device keyed by management IP.
func (l *Lab) Build() map[string]AgentMIBs {
	out := map[string]AgentMIBs{}
	for _, d := range l.Devices {
		if !d.Managed {
			continue
		}
		out[d.MgmtIP] = l.buildDevice(d)
	}
	return out
}

func macBytes(mac string) []byte {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	return hw
}

func portMAC(chassis string, ifIndex int) []byte {
	b := macBytes(chassis)
	b[5] = byte(int(b[5]) + ifIndex)
	b[4] = byte(int(b[4]) + ifIndex/256)
	return b
}

func ipIdx(ip string) string { return ip }

func macIdx(mac string) string {
	b := macBytes(mac)
	parts := make([]string, 6)
	for i, x := range b {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, ".")
}

func maskOf(prefix int) string { return net.IP(net.CIDRMask(prefix, 32)).String() }

// portList encodes 1-based bridge ports as an 802.1Q PortList.
func portList(ports []int, size int) []byte {
	b := make([]byte, (size+7)/8)
	for _, p := range ports {
		if p <= 0 || p > size {
			continue
		}
		b[(p-1)/8] |= 0x80 >> ((p - 1) % 8)
	}
	return b
}

// peer returns the device/port on the other side of a link from (dev, port).
func (l *Lab) peer(dev, port string) (*Device, *Port) {
	for _, k := range l.Links {
		if k.A == dev && k.APort == port {
			d := l.Device(k.B)
			return d, d.port(k.BPort)
		}
		if k.B == dev && k.BPort == port {
			d := l.Device(k.A)
			return d, d.port(k.APort)
		}
	}
	return nil, nil
}

// uplinkTo returns the port on parent that faces child.
func (l *Lab) uplinkTo(parent, child string) *Port {
	for _, k := range l.Links {
		if k.A == parent && k.B == child {
			return l.Device(parent).port(k.APort)
		}
		if k.B == parent && k.A == child {
			return l.Device(parent).port(k.BPort)
		}
	}
	return nil
}

type fdbRow struct {
	mac  string
	vlan int
	port *Port
}

// fdbFor computes the MAC table of device d by walking every endpoint (and
// every switch management MAC) up the tree.
func (l *Lab) fdbFor(d *Device) []fdbRow {
	var rows []fdbRow
	add := func(sw string, attach *Port, mac string, vlan int) {
		cur := l.Device(sw)
		if cur.Name == d.Name {
			rows = append(rows, fdbRow{mac, vlan, attach})
			return
		}
		for cur.Parent != "" {
			parent := l.Device(cur.Parent)
			if parent.Name == d.Name {
				rows = append(rows, fdbRow{mac, vlan, l.uplinkTo(parent.Name, cur.Name)})
				return
			}
			cur = parent
		}
	}
	for _, e := range l.Endpoints {
		sw := l.Device(e.Switch)
		add(e.Switch, sw.port(e.Port), e.MAC, e.VLAN)
	}
	// Management MACs of downstream switches and the firewall are learned too.
	for _, other := range l.Devices {
		if other.Name == d.Name || other.Parent == "" {
			continue
		}
		parent := l.Device(other.Parent)
		up := l.uplinkTo(parent.Name, other.Name)
		add(parent.Name, up, other.ChassisMAC, 99)
	}
	return rows
}

func (l *Lab) buildDevice(d *Device) AgentMIBs {
	m := snmp.NewMIB()
	ctxs := map[string]*snmp.MIB{}
	chassis := macBytes(d.ChassisMAC)

	// system group
	m.Str("1.3.6.1.2.1.1.1.0", d.Descr)
	m.OIDv("1.3.6.1.2.1.1.2.0", d.ObjectID)
	m.Ticks("1.3.6.1.2.1.1.3.0", 861234500)
	m.Str("1.3.6.1.2.1.1.4.0", "noc@example.local")
	m.Str("1.3.6.1.2.1.1.5.0", d.Name)
	m.Str("1.3.6.1.2.1.1.6.0", d.Location)
	svc := int64(2)
	fwd := int64(2)
	if d.Router {
		svc, fwd = 6, 1
	}
	m.Int("1.3.6.1.2.1.1.7.0", svc)
	m.Int("1.3.6.1.2.1.4.1.0", fwd)
	m.Octets("1.3.6.1.2.1.17.1.1.0", chassis)
	m.Int("1.3.6.1.2.1.17.1.2.0", int64(len(d.Ports)))
	m.Int("1.0.8802.1.1.2.1.3.1.0", 4)
	m.Octets("1.0.8802.1.1.2.1.3.2.0", chassis)
	m.Str("1.0.8802.1.1.2.1.3.3.0", d.Name)

	// interfaces
	type iface struct {
		idx                int
		name, descr, alias string
		typ                int64
		speed              uint64
		up                 bool
		in, out, inErr     uint64
	}
	var ifs []iface
	for _, p := range d.Ports {
		descr := p.Name
		if d.Family == "huawei" {
			descr = p.Name // Huawei ifDescr == ifName
		}
		ifs = append(ifs, iface{p.IfIndex, p.Name, descr, p.Alias, 6, p.Speed, p.Up, p.InOctets, p.OutOctets, p.InErrors})
	}
	for _, s := range d.SVIs {
		name := fmt.Sprintf("Vlanif%d", s.VLAN)
		if d.Family == "cisco" {
			name = fmt.Sprintf("Vlan%d", s.VLAN)
		}
		ifs = append(ifs, iface{s.IfIndex, name, name, "", 136, 1_000_000_000, true, 0, 0, 0})
	}
	for _, it := range ifs {
		i := fmt.Sprint(it.idx)
		m.Int("1.3.6.1.2.1.2.2.1.1."+i, int64(it.idx))
		m.Str("1.3.6.1.2.1.2.2.1.2."+i, it.descr)
		m.Int("1.3.6.1.2.1.2.2.1.3."+i, it.typ)
		m.Int("1.3.6.1.2.1.2.2.1.4."+i, 1500)
		m.Gauge("1.3.6.1.2.1.2.2.1.5."+i, min(it.speed, 4294967295))
		m.Octets("1.3.6.1.2.1.2.2.1.6."+i, portMAC(d.ChassisMAC, it.idx))
		m.Int("1.3.6.1.2.1.2.2.1.7."+i, 1)
		oper := int64(2)
		if it.up {
			oper = 1
		}
		m.Int("1.3.6.1.2.1.2.2.1.8."+i, oper)
		m.Ticks("1.3.6.1.2.1.2.2.1.9."+i, 1200)
		m.Counter("1.3.6.1.2.1.2.2.1.10."+i, it.in%4294967296)
		m.Counter("1.3.6.1.2.1.2.2.1.14."+i, it.inErr)
		m.Counter("1.3.6.1.2.1.2.2.1.16."+i, it.out%4294967296)
		m.Counter("1.3.6.1.2.1.2.2.1.20."+i, 0)
		m.Str("1.3.6.1.2.1.31.1.1.1.1."+i, it.name)
		m.Counter64("1.3.6.1.2.1.31.1.1.1.6."+i, it.in)
		m.Counter64("1.3.6.1.2.1.31.1.1.1.10."+i, it.out)
		m.Gauge("1.3.6.1.2.1.31.1.1.1.15."+i, it.speed/1_000_000)
		m.Str("1.3.6.1.2.1.31.1.1.1.18."+i, it.alias)
		if it.typ == 6 && it.up {
			m.Int("1.3.6.1.2.1.10.7.2.1.19."+i, 3)
		}
	}
	// bridge port mapping (Cisco exposes it per VLAN context only)
	if d.Family != "cisco" {
		for _, p := range d.Ports {
			m.Int(fmt.Sprintf("1.3.6.1.2.1.17.1.4.1.2.%d", p.BridgePort), int64(p.IfIndex))
		}
	}

	// IP addresses
	addIP := func(ip string, prefix, ifIndex int) {
		m.IPv("1.3.6.1.2.1.4.20.1.1."+ipIdx(ip), ip)
		m.Int("1.3.6.1.2.1.4.20.1.2."+ipIdx(ip), int64(ifIndex))
		m.IPv("1.3.6.1.2.1.4.20.1.3."+ipIdx(ip), maskOf(prefix))
	}
	mgmtIf := 0
	for _, s := range d.SVIs {
		addIP(s.IP, s.Prefix, s.IfIndex)
		if s.VLAN == 99 {
			mgmtIf = s.IfIndex
		}
	}
	if mgmtIf == 0 && len(d.SVIs) > 0 {
		mgmtIf = d.SVIs[0].IfIndex
	}
	hasMgmt := false
	for _, sv := range d.SVIs {
		hasMgmt = hasMgmt || sv.IP == d.MgmtIP
	}
	if !hasMgmt {
		addIP(d.MgmtIP, 32, mgmtIf)
	}

	l.buildEntity(m, d)
	l.buildLLDP(m, d)
	if d.Family == "cisco" {
		l.buildCisco(m, ctxs, d)
	} else {
		l.buildQBridge(m, d)
	}
	if d.Router {
		l.buildL3(m, d)
	}
	l.buildHealth(m, d)
	return AgentMIBs{Main: m, Contexts: ctxs}
}

func (l *Lab) buildEntity(m *snmp.MIB, d *Device) {
	mfg := map[string]string{"huawei": "Huawei Technologies Co., Ltd.", "cisco": "Cisco Systems, Inc.", "hpe": "Hewlett Packard Enterprise"}[d.Family]
	ent := func(idx int, descr string, parent int, class int64, name, model, serial, sw string) {
		i := fmt.Sprint(idx)
		m.Str("1.3.6.1.2.1.47.1.1.1.1.2."+i, descr)
		m.Int("1.3.6.1.2.1.47.1.1.1.1.4."+i, int64(parent))
		m.Int("1.3.6.1.2.1.47.1.1.1.1.5."+i, class)
		m.Str("1.3.6.1.2.1.47.1.1.1.1.7."+i, name)
		m.Str("1.3.6.1.2.1.47.1.1.1.1.8."+i, "")
		m.Str("1.3.6.1.2.1.47.1.1.1.1.10."+i, sw)
		m.Str("1.3.6.1.2.1.47.1.1.1.1.11."+i, serial)
		m.Str("1.3.6.1.2.1.47.1.1.1.1.12."+i, mfg)
		m.Str("1.3.6.1.2.1.47.1.1.1.1.13."+i, model)
	}
	ent(1, d.Model+" Chassis", 0, 3, d.Name, d.Model, d.Serial, "")
	ent(9, "Main Processing Unit", 1, 9, "MPU 0", "", d.Serial+"-MPU", "")
	ent(11, "Power Supply 1", 1, 6, "PWR1", "", "", "")
	ent(12, "Fan Tray 1", 1, 7, "FAN1", "", "", "")
	for _, p := range d.Ports {
		pe := 1000 + p.IfIndex
		ent(pe, p.Name, 9, 10, p.Name, "", "", "")
		m.OIDv(fmt.Sprintf("1.3.6.1.2.1.47.1.3.2.1.2.%d.0", pe), fmt.Sprintf("1.3.6.1.2.1.2.2.1.1.%d", p.IfIndex))
		if p.Optic != nil {
			oe := 2000 + p.IfIndex
			i := fmt.Sprint(oe)
			m.Str("1.3.6.1.2.1.47.1.1.1.1.2."+i, p.Optic.Descr)
			m.Int("1.3.6.1.2.1.47.1.1.1.1.4."+i, int64(pe))
			m.Int("1.3.6.1.2.1.47.1.1.1.1.5."+i, 9)
			m.Str("1.3.6.1.2.1.47.1.1.1.1.7."+i, p.Name+" transceiver")
			m.Str("1.3.6.1.2.1.47.1.1.1.1.11."+i, p.Optic.Serial)
			m.Str("1.3.6.1.2.1.47.1.1.1.1.12."+i, p.Optic.Vendor)
			m.Str("1.3.6.1.2.1.47.1.1.1.1.13."+i, p.Optic.Part)
		}
	}
}

var capBits = map[string]byte{"other": 0x80, "repeater": 0x40, "bridge": 0x20, "wlan-ap": 0x10, "router": 0x08, "phone": 0x04, "docsis": 0x02, "station": 0x01}

func caps(names ...string) []byte {
	var b byte
	for _, n := range names {
		b |= capBits[n]
	}
	return []byte{b, 0}
}

func (d *Device) caps() []string {
	c := []string{"bridge"}
	if d.Router {
		c = append(c, "router")
	}
	return append(c, d.ExtraCaps...)
}

func (l *Lab) buildLLDP(m *snmp.MIB, d *Device) {
	const loc = "1.0.8802.1.1.2.1.3.7.1"
	for _, p := range d.Ports {
		i := fmt.Sprint(p.LLDPNum)
		if d.Family == "hpe" {
			m.Int(loc+".2."+i, 7)
		} else {
			m.Int(loc+".2."+i, 5)
		}
		m.Str(loc+".3."+i, p.Short)
		m.Str(loc+".4."+i, p.Name)
	}
	const rem = "1.0.8802.1.1.2.1.4.1.1"
	const man = "1.0.8802.1.1.2.1.4.2.1"
	remIdx := 0
	addRem := func(localNum int, chassisMAC string, portSub int64, portID, portDesc, sysName, sysDescr string, capsList []string, mgmt string) {
		remIdx++
		i := fmt.Sprintf("0.%d.%d", localNum, remIdx)
		m.Int(rem+".4."+i, 4)
		m.Octets(rem+".5."+i, macBytes(chassisMAC))
		m.Int(rem+".6."+i, portSub)
		if portSub == 3 {
			m.Octets(rem+".7."+i, macBytes(portID))
		} else {
			m.Str(rem+".7."+i, portID)
		}
		m.Str(rem+".8."+i, portDesc)
		m.Str(rem+".9."+i, sysName)
		m.Str(rem+".10."+i, sysDescr)
		m.Octets(rem+".11."+i, caps(capsList...))
		m.Octets(rem+".12."+i, caps(capsList...))
		if mgmt != "" {
			m.Int(man+".3."+i+".1.4."+mgmt, 2)
		}
	}
	for _, p := range d.Ports {
		if pd, pp := l.peer(d.Name, p.Name); pd != nil {
			sub := int64(5)
			if pd.Family == "hpe" {
				sub = 7
			}
			descr := pp.Alias
			if descr == "" {
				descr = pp.Name
			}
			addRem(p.LLDPNum, pd.ChassisMAC, sub, pp.Short, descr, pd.Name, pd.Descr, pd.caps(), pd.MgmtIP)
		}
	}
	for _, e := range l.Endpoints {
		if e.Switch != d.Name || len(e.LLDPCaps) == 0 {
			continue
		}
		p := d.port(e.Port)
		addRem(p.LLDPNum, e.MAC, 3, e.MAC, "eth0", e.Name, e.LLDPDescr, e.LLDPCaps, e.IP)
	}
}

func (l *Lab) buildQBridge(m *snmp.MIB, d *Device) {
	ids := sortedKeys(d.VLANs)
	nports := 0
	for _, p := range d.Ports {
		nports = max(nports, p.BridgePort)
	}
	for _, v := range ids {
		var egress, untagged []int
		for _, p := range d.Ports {
			if p.PVID == v && len(p.Trunk) == 0 {
				egress = append(egress, p.BridgePort)
				untagged = append(untagged, p.BridgePort)
			}
			for _, t := range p.Trunk {
				if t == v {
					egress = append(egress, p.BridgePort)
				}
			}
		}
		i := fmt.Sprint(v)
		m.Str("1.3.6.1.2.1.17.7.1.4.3.1.1."+i, d.VLANs[v])
		m.Octets("1.3.6.1.2.1.17.7.1.4.3.1.2."+i, portList(egress, nports))
		m.Octets("1.3.6.1.2.1.17.7.1.4.3.1.4."+i, portList(untagged, nports))
	}
	for _, p := range d.Ports {
		pv := p.PVID
		if pv == 0 {
			pv = 1
		}
		m.Gauge(fmt.Sprintf("1.3.6.1.2.1.17.7.1.4.5.1.1.%d", p.BridgePort), uint64(pv))
	}
	for _, r := range l.fdbFor(d) {
		i := fmt.Sprintf("%d.%s", r.vlan, macIdx(r.mac))
		m.Int("1.3.6.1.2.1.17.7.1.2.2.1.2."+i, int64(r.port.BridgePort))
		m.Int("1.3.6.1.2.1.17.7.1.2.2.1.3."+i, 3)
	}
}

func (l *Lab) buildCisco(m *snmp.MIB, ctxs map[string]*snmp.MIB, d *Device) {
	for _, v := range sortedKeys(d.VLANs) {
		m.Int(fmt.Sprintf("1.3.6.1.4.1.9.9.46.1.3.1.1.2.1.%d", v), 1)
		m.Str(fmt.Sprintf("1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.%d", v), d.VLANs[v])
	}
	for _, p := range d.Ports {
		if len(p.Trunk) == 0 && p.PVID > 0 {
			m.Int(fmt.Sprintf("1.3.6.1.4.1.9.9.68.1.2.2.1.2.%d", p.IfIndex), int64(p.PVID))
		}
		if len(p.Trunk) > 0 {
			m.Int(fmt.Sprintf("1.3.6.1.4.1.9.9.46.1.6.1.1.14.%d", p.IfIndex), 1)
		}
	}
	// per-VLAN BRIDGE-MIB instances
	rows := l.fdbFor(d)
	for _, v := range sortedKeys(d.VLANs) {
		c := snmp.NewMIB()
		for _, p := range d.Ports {
			member := p.PVID == v
			for _, t := range p.Trunk {
				member = member || t == v
			}
			if member {
				c.Int(fmt.Sprintf("1.3.6.1.2.1.17.1.4.1.2.%d", p.BridgePort), int64(p.IfIndex))
			}
		}
		for _, r := range rows {
			if r.vlan == v {
				c.Int("1.3.6.1.2.1.17.4.3.1.2."+macIdx(r.mac), int64(r.port.BridgePort))
				c.Int("1.3.6.1.2.1.17.4.3.1.3."+macIdx(r.mac), 3)
			}
		}
		ctxs[fmt.Sprintf("vlan-%d", v)] = c
	}
	// CDP cache for switch-to-switch links
	for _, p := range d.Ports {
		pd, pp := l.peer(d.Name, p.Name)
		if pd == nil {
			continue
		}
		i := fmt.Sprintf("%d.1", p.IfIndex)
		const cdp = "1.3.6.1.4.1.9.9.23.1.2.1.1"
		m.Int(cdp+".3."+i, 1)
		m.Octets(cdp+".4."+i, net.ParseIP(pd.MgmtIP).To4())
		m.Str(cdp+".5."+i, pd.Descr)
		m.Str(cdp+".6."+i, pd.Name)
		m.Str(cdp+".7."+i, pp.Name)
		m.Str(cdp+".8."+i, strings.ToUpper(pd.Family)+" "+pd.Model)
		capv := byte(0x08)
		if pd.Router {
			capv |= 0x01
		}
		m.Octets(cdp+".9."+i, []byte{0, 0, 0, capv})
	}
}

func (l *Lab) buildL3(m *snmp.MIB, d *Device) {
	sviFor := map[int]SVI{}
	for _, s := range d.SVIs {
		sviFor[s.VLAN] = s
	}
	for _, e := range l.Endpoints {
		s, ok := sviFor[e.VLAN]
		if !ok {
			continue
		}
		i := fmt.Sprintf("%d.%s", s.IfIndex, e.IP)
		m.Octets("1.3.6.1.2.1.4.22.1.2."+i, macBytes(e.MAC))
		m.Int("1.3.6.1.2.1.4.22.1.4."+i, 3)
	}
	for _, o := range l.Devices {
		if o.Name == d.Name {
			continue
		}
		s, ok := sviFor[99]
		if o.Family == "fortinet" {
			s, ok = sviFor[100]
		}
		if !ok {
			continue
		}
		ip := o.MgmtIP
		i := fmt.Sprintf("%d.%s", s.IfIndex, ip)
		m.Octets("1.3.6.1.2.1.4.22.1.2."+i, macBytes(o.ChassisMAC))
		m.Int("1.3.6.1.2.1.4.22.1.4."+i, 3)
	}
	for _, r := range d.Routes {
		i := fmt.Sprintf("%s.%s.0.%s", r.Dest, r.Mask, r.NextHop)
		const rt = "1.3.6.1.2.1.4.24.4.1"
		m.Int(rt+".5."+i, int64(r.IfIndex))
		m.Int(rt+".7."+i, int64(r.Proto))
		m.Int(rt+".11."+i, int64(r.Metric))
	}
}

func (l *Lab) buildHealth(m *snmp.MIB, d *Device) {
	switch d.Family {
	case "huawei":
		m.Int("1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.9", int64(d.CPU))
		m.Int("1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7.9", int64(d.Mem))
		m.Int("1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11.9", int64(d.Temp))
		for _, p := range d.Ports {
			if p.Optic != nil {
				oe := fmt.Sprint(2000 + p.IfIndex)
				m.Int("1.3.6.1.4.1.2011.5.25.31.1.1.3.1.8."+oe, p.Optic.RxUW)
				m.Int("1.3.6.1.4.1.2011.5.25.31.1.1.3.1.9."+oe, p.Optic.TxUW)
			}
		}
	case "cisco":
		m.Gauge("1.3.6.1.4.1.9.9.109.1.1.1.1.8.1", uint64(d.CPU))
		m.Gauge("1.3.6.1.4.1.9.9.48.1.1.1.5.1", uint64(d.Mem)*10_000_000)
		m.Gauge("1.3.6.1.4.1.9.9.48.1.1.1.6.1", uint64(100-d.Mem)*10_000_000)
		m.Str("1.3.6.1.4.1.9.9.13.1.3.1.2.1", "Switch 1 - Inlet Temp Sensor")
		m.Gauge("1.3.6.1.4.1.9.9.13.1.3.1.3.1", uint64(d.Temp))
		m.Int("1.3.6.1.4.1.9.9.13.1.3.1.6.1", 1)
		m.Str("1.3.6.1.4.1.9.9.13.1.4.1.2.1", "Switch 1 - FAN 1")
		m.Int("1.3.6.1.4.1.9.9.13.1.4.1.3.1", 1)
		m.Str("1.3.6.1.4.1.9.9.13.1.5.1.2.1", "Switch 1 - Power Supply A")
		m.Int("1.3.6.1.4.1.9.9.13.1.5.1.3.1", 1)
	default:
		m.Int("1.3.6.1.2.1.25.3.3.1.2.1", int64(d.CPU))
		m.Int("1.3.6.1.2.1.99.1.1.1.1.9", 8)
		m.Int("1.3.6.1.2.1.99.1.1.1.2.9", 9)
		m.Int("1.3.6.1.2.1.99.1.1.1.3.9", 0)
		m.Int("1.3.6.1.2.1.99.1.1.1.4.9", int64(d.Temp))
		m.Int("1.3.6.1.2.1.99.1.1.1.5.9", 1)
	}
}

func sortedKeys(m map[int]string) []int {
	var k []int
	for x := range m {
		k = append(k, x)
	}
	sort.Ints(k)
	return k
}
