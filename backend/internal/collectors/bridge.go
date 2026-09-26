package collectors

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

const (
	oidDot1qVlanStaticEntry = "1.3.6.1.2.1.17.7.1.4.3.1" // 1 name, 2 egress, 4 untagged
	oidDot1qPvid            = "1.3.6.1.2.1.17.7.1.4.5.1.1"
	oidDot1qTpFdbEntry      = "1.3.6.1.2.1.17.7.1.2.2.1" // 2 port, 3 status; index fdbId.mac
	oidDot1qVlanFdbID       = "1.3.6.1.2.1.17.7.1.4.2.1.3"
	oidDot1dTpFdbEntry      = "1.3.6.1.2.1.17.4.3.1" // 2 port, 3 status; index mac
)

var fdbStatus = map[int64]string{1: "other", 2: "invalid", 3: "learned", 4: "self", 5: "mgmt"}

// CollectVLANs reads IEEE 802.1Q VLAN names, port membership and PVIDs.
func CollectVLANs(ctx context.Context, s *Session, snap *model.Snapshot) error {
	rows, order, err := snmp.Table(ctx, s.Client, oidDot1qVlanStaticEntry, 1, 2, 4)
	if err != nil {
		return err
	}
	if snap.PortVLANs == nil {
		snap.PortVLANs = map[int][]model.PortVLAN{}
	}
	for _, idx := range order {
		id, err := strconv.Atoi(idx)
		if err != nil || id < 1 || id > 4094 {
			continue
		}
		r := rows[idx]
		name := r[1].String()
		snap.VLANs = append(snap.VLANs, model.VLAN{ID: id, Name: name})
		untagged := portSet(r[4].Bytes())
		for _, bp := range portList(r[2].Bytes()) {
			ifIndex := IfIndexForBridgePort(snap, bp)
			if ifIndex == 0 {
				continue
			}
			snap.PortVLANs[ifIndex] = append(snap.PortVLANs[ifIndex], model.PortVLAN{VLAN: id, Tagged: !untagged[bp]})
		}
	}
	if pv, err := s.Client.Walk(ctx, oidDot1qPvid); err == nil {
		for _, p := range pv {
			idx, _ := snmp.Suffix(p.OID, oidDot1qPvid)
			bp, _ := strconv.Atoi(idx)
			if it := snap.InterfaceByIndex(IfIndexForBridgePort(snap, bp)); it != nil {
				it.PVID = int(p.Int())
			}
		}
	}
	return nil
}

// portList decodes an 802.1Q PortList bitmap into 1-based bridge port numbers.
func portList(b []byte) []int {
	var out []int
	for i, octet := range b {
		for bit := 0; bit < 8; bit++ {
			if octet&(0x80>>bit) != 0 {
				out = append(out, i*8+bit+1)
			}
		}
	}
	return out
}

func portSet(b []byte) map[int]bool {
	m := map[int]bool{}
	for _, p := range portList(b) {
		m[p] = true
	}
	return m
}

// CollectFDB reads the forwarding database (MAC address table).
// Q-BRIDGE is preferred because it carries the VLAN; BRIDGE-MIB is the fallback.
func CollectFDB(ctx context.Context, s *Session, snap *model.Snapshot) error {
	fdbToVlan := map[int]int{}
	if m, err := s.Client.Walk(ctx, oidDot1qVlanFdbID); err == nil {
		for _, p := range m {
			idx, _ := snmp.Suffix(p.OID, oidDot1qVlanFdbID)
			parts := snmp.IndexInts(idx)
			if len(parts) == 2 {
				fdbToVlan[int(p.Int())] = parts[1]
			}
		}
	}
	rows, order, err := snmp.Table(ctx, s.Client, oidDot1qTpFdbEntry, 2, 3)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, idx := range order {
		parts := snmp.IndexInts(idx)
		if len(parts) != 7 {
			continue
		}
		fdbID := parts[0]
		mac := macFromIndex(parts[1:])
		vlan := fdbID
		if v, ok := fdbToVlan[fdbID]; ok {
			vlan = v
		}
		e := fdbEntry(snap, mac, vlan, rows[idx])
		if e != nil && !seen[e.MAC+"/"+strconv.Itoa(e.VLAN)] {
			seen[e.MAC+"/"+strconv.Itoa(e.VLAN)] = true
			snap.FDB = append(snap.FDB, *e)
		}
	}
	if len(order) > 0 {
		return nil
	}
	return CollectBridgeFDB(ctx, s.Client, snap, 0)
}

// CollectBridgeFDB reads BRIDGE-MIB dot1dTpFdbTable from client, tagging entries with vlan.
func CollectBridgeFDB(ctx context.Context, c snmp.Client, snap *model.Snapshot, vlan int) error {
	rows, order, err := snmp.Table(ctx, c, oidDot1dTpFdbEntry, 2, 3)
	if err != nil {
		return err
	}
	for _, idx := range order {
		parts := snmp.IndexInts(idx)
		if len(parts) != 6 {
			continue
		}
		if e := fdbEntry(snap, macFromIndex(parts), vlan, rows[idx]); e != nil {
			snap.FDB = append(snap.FDB, *e)
		}
	}
	return nil
}

func fdbEntry(snap *model.Snapshot, mac string, vlan int, r snmp.Row) *model.FDBEntry {
	if mac == "" {
		return nil
	}
	status := fdbStatus[r[3].Int()]
	if status == "invalid" || status == "self" {
		return nil
	}
	port := int(r[2].Int())
	if port == 0 {
		return nil
	}
	ifIndex := IfIndexForBridgePort(snap, port)
	if ifIndex == 0 {
		return nil
	}
	if status == "" {
		status = "learned"
	}
	return &model.FDBEntry{MAC: mac, VLAN: vlan, IfIndex: ifIndex, Status: status}
}

func macFromIndex(p []int) string {
	if len(p) != 6 {
		return ""
	}
	b := make(net.HardwareAddr, 6)
	for i, v := range p {
		if v < 0 || v > 255 {
			return ""
		}
		b[i] = byte(v)
	}
	return snmp.NormalizeMAC(b.String())
}

// MACToIndex renders a MAC as an OID index suffix ("0.224.252.18.52.86").
func MACToIndex(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.%d.%d", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5])
}

const (
	oidStpDesignatedRoot = "1.3.6.1.2.1.17.2.5.0"
	oidStpRootPort       = "1.3.6.1.2.1.17.2.7.0"
	oidStpPortState      = "1.3.6.1.2.1.17.2.15.1.3"
)

var stpStates = map[int64]string{1: "disabled", 2: "blocking", 3: "listening", 4: "learning", 5: "forwarding", 6: "broken"}

// CollectSTP reads BRIDGE-MIB spanning-tree root and per-port states.
func CollectSTP(ctx context.Context, s *Session, snap *model.Snapshot) error {
	res, err := s.Client.Get(ctx, oidStpDesignatedRoot, oidStpRootPort)
	if err != nil {
		return err
	}
	for _, p := range res {
		if !p.Exists() {
			continue
		}
		switch p.OID {
		case oidStpDesignatedRoot:
			if b := p.Bytes(); len(b) == 8 {
				prio := int(b[0])<<8 | int(b[1])
				snap.System.STPRoot = fmt.Sprintf("%d/%s", prio, net.HardwareAddr(b[2:]).String())
			}
		case oidStpRootPort:
			if bp := int(p.Int()); bp > 0 {
				snap.System.STPRootPort = IfIndexForBridgePort(snap, bp)
			}
		}
	}
	states, err := s.Client.Walk(ctx, oidStpPortState)
	if err != nil {
		return nil
	}
	for _, p := range states {
		idx, _ := snmp.Suffix(p.OID, oidStpPortState)
		bp, _ := strconv.Atoi(idx)
		if it := snap.InterfaceByIndex(IfIndexForBridgePort(snap, bp)); it != nil {
			it.STPState = stpStates[p.Int()]
		}
	}
	return nil
}
