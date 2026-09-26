package collectors

import (
	"context"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

const (
	oidIPNetToMediaEntry    = "1.3.6.1.2.1.4.22.1" // 2 physAddress, 4 type; index ifIndex.a.b.c.d
	oidIPNetToPhysicalEntry = "1.3.6.1.2.1.4.35.1" // 4 physAddress, 6 type; index ifIndex.type.len.addr
)

// CollectARP reads the IP→MAC neighbor cache (ARP table).
func CollectARP(ctx context.Context, s *Session, snap *model.Snapshot) error {
	seen := map[string]bool{}
	add := func(ifIndex int, ip, mac string) {
		if ip == "" || mac == "" || seen[ip+"|"+mac] {
			return
		}
		seen[ip+"|"+mac] = true
		snap.ARP = append(snap.ARP, model.ARPEntry{IP: ip, MAC: mac, IfIndex: ifIndex})
	}
	rows, order, err := snmp.Table(ctx, s.Client, oidIPNetToMediaEntry, 2, 4)
	if err != nil {
		return err
	}
	for _, idx := range order {
		parts := snmp.IndexInts(idx)
		if len(parts) != 5 {
			continue
		}
		r := rows[idx]
		if r[4].Int() == 2 { // invalid
			continue
		}
		add(parts[0], ipFromIndex(parts[1:]), r[2].MAC())
	}
	if len(order) > 0 {
		return nil
	}
	rows, order, err = snmp.Table(ctx, s.Client, oidIPNetToPhysicalEntry, 4, 6)
	if err != nil {
		return nil // optional MIB
	}
	for _, idx := range order {
		parts := snmp.IndexInts(idx)
		// ifIndex, addrType(1=ipv4), len(4), a.b.c.d
		if len(parts) != 7 || parts[1] != 1 || parts[2] != 4 {
			continue
		}
		r := rows[idx]
		if r[6].Int() == 2 {
			continue
		}
		add(parts[0], ipFromIndex(parts[3:]), r[4].MAC())
	}
	return nil
}
