package collectors

import (
	"context"
	"strconv"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

const (
	oidLldpLocPortEntry    = "1.0.8802.1.1.2.1.3.7.1"
	oidLldpRemEntry        = "1.0.8802.1.1.2.1.4.1.1"
	oidLldpRemManAddrEntry = "1.0.8802.1.1.2.1.4.2.1"
)

// LLDP capability bits (BITS encoding: first octet MSB is bit 0).
var lldpCaps = []string{"other", "repeater", "bridge", "wlan-ap", "router", "phone", "docsis", "station"}

func decodeCaps(b []byte) []string {
	var out []string
	for i, name := range lldpCaps {
		byteIdx, bit := i/8, 7-i%8
		if byteIdx < len(b) && b[byteIdx]&(1<<bit) != 0 {
			out = append(out, name)
		}
	}
	return out
}

func CollectLLDP(ctx context.Context, s *Session, snap *model.Snapshot) error {
	loc, _, err := snmp.Table(ctx, s.Client, oidLldpLocPortEntry, 2, 3, 4)
	if err != nil {
		return err
	}
	rem, order, err := snmp.Table(ctx, s.Client, oidLldpRemEntry, 4, 5, 6, 7, 8, 9, 10, 11, 12)
	if err != nil {
		return err
	}
	if len(order) == 0 {
		return nil
	}
	// management addresses: index = timeMark.localPort.remIndex.addrSubtype.len.addr...
	mgmt := map[string]string{}
	if ma, err := s.Client.Walk(ctx, oidLldpRemManAddrEntry+".3"); err == nil {
		for _, p := range ma {
			idx, _ := snmp.Suffix(p.OID, oidLldpRemManAddrEntry+".3")
			parts := snmp.IndexInts(idx)
			if len(parts) < 5 {
				continue
			}
			key := joinInts(parts[:3])
			subtype, alen := parts[3], parts[4]
			if subtype == 1 && alen == 4 && len(parts) >= 9 {
				if _, ok := mgmt[key]; !ok {
					mgmt[key] = ipFromIndex(parts[5:9])
				}
			}
		}
	}
	for _, idx := range order {
		parts := snmp.IndexInts(idx)
		if len(parts) < 3 {
			continue
		}
		localNum := parts[1]
		r := rem[idx]
		n := model.Neighbor{
			Protocol:  "lldp",
			ChassisID: formatChassisID(r[4].Int(), r[5]),
			PortID:    formatPortID(r[6].Int(), r[7]),
			PortDescr: r[8].String(),
			SysName:   r[9].String(),
			SysDescr:  r[10].String(),
			MgmtIP:    mgmt[joinInts(parts[:3])],
		}
		caps := r[12].Bytes()
		if len(caps) == 0 || allZero(caps) {
			caps = r[11].Bytes()
		}
		n.Capabilities = decodeCaps(caps)
		// Resolve local port.
		var locID, locDesc string
		if l, ok := loc[strconv.Itoa(localNum)]; ok {
			locID = formatPortID(l[2].Int(), l[3])
			locDesc = l[4].String()
		}
		if it := MatchPort(snap, localNum, locID, locDesc); it != nil {
			n.LocalIfIndex = it.IfIndex
			n.LocalPort = it.Name
		} else if locID != "" {
			n.LocalPort = locID
		} else {
			n.LocalPort = locDesc
		}
		snap.Neighbors = append(snap.Neighbors, n)
	}
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func formatPortID(subtype int64, p snmp.PDU) string {
	switch subtype {
	case 3: // macAddress
		if m := p.MAC(); m != "" {
			return m
		}
	case 4: // networkAddress
		b := p.Bytes()
		if len(b) == 5 && b[0] == 1 {
			return snmp.PDU{Value: b[1:]}.IP()
		}
	}
	return strings.TrimSpace(p.String())
}

// MatchPort resolves an LLDP/CDP local port reference to an interface.
func MatchPort(snap *model.Snapshot, portNum int, id, desc string) *model.Interface {
	for _, cand := range []string{id, desc} {
		if cand == "" {
			continue
		}
		if it := snap.InterfaceByName(cand); it != nil {
			return it
		}
		if full := ExpandIfName(cand); full != cand {
			if it := snap.InterfaceByName(full); it != nil {
				return it
			}
		}
	}
	// Local port number equal to ifIndex is common (Huawei, many others).
	if it := snap.InterfaceByIndex(portNum); it != nil {
		return it
	}
	// Match numeric suffix e.g. "Gi1/0/5" ↔ "GigabitEthernet1/0/5".
	for _, cand := range []string{id, desc} {
		short := ShortIfName(cand)
		if short == "" {
			continue
		}
		for i := range snap.Interfaces {
			if strings.EqualFold(ShortIfName(snap.Interfaces[i].Name), short) {
				return &snap.Interfaces[i]
			}
		}
	}
	return nil
}

var ifAbbrev = []struct{ short, long string }{
	{"hu", "HundredGigE"}, {"fo", "FortyGigabitEthernet"}, {"twe", "TwentyFiveGigE"},
	{"te", "TenGigabitEthernet"}, {"xge", "XGigabitEthernet"}, {"gi", "GigabitEthernet"},
	{"ge", "GigabitEthernet"}, {"fa", "FastEthernet"}, {"eth", "Ethernet"}, {"et", "Ethernet"},
	{"po", "Port-channel"}, {"mgmt", "MEth"},
}

// ExpandIfName turns "Gi1/0/1" into "GigabitEthernet1/0/1".
func ExpandIfName(n string) string {
	l := strings.ToLower(n)
	for _, a := range ifAbbrev {
		if strings.HasPrefix(l, a.short) && len(l) > len(a.short) && (l[len(a.short)] >= '0' && l[len(a.short)] <= '9') {
			return a.long + n[len(a.short):]
		}
	}
	return n
}

// ShortIfName normalizes an interface name to type-initial + numbering,
// e.g. "GigabitEthernet1/0/5" → "g1/0/5", "Gi1/0/5" → "g1/0/5".
func ShortIfName(n string) string {
	n = strings.TrimSpace(n)
	if n == "" {
		return ""
	}
	i := strings.IndexFunc(n, func(r rune) bool { return r >= '0' && r <= '9' })
	if i <= 0 {
		return ""
	}
	prefix := strings.ToLower(n[:i])
	kind := prefix[:1]
	switch {
	case strings.HasPrefix(prefix, "xg"), strings.HasPrefix(prefix, "te"):
		kind = "x"
	case strings.HasPrefix(prefix, "hu"), strings.HasPrefix(prefix, "100ge"):
		kind = "h"
	case strings.HasPrefix(prefix, "fo"), strings.HasPrefix(prefix, "40ge"):
		kind = "f4"
	case strings.HasPrefix(prefix, "fa"):
		kind = "fa"
	}
	return kind + strings.ToLower(n[i:])
}
