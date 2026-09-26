package collectors

import (
	"context"
	"strconv"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

const (
	oidIfEntry          = "1.3.6.1.2.1.2.2.1"
	oidIfXEntry         = "1.3.6.1.2.1.31.1.1.1"
	oidDot3DuplexStatus = "1.3.6.1.2.1.10.7.2.1.19"
	oidDot1dBasePortIf  = "1.3.6.1.2.1.17.1.4.1.2"
)

var ifStatus = map[int64]string{1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}

func CollectInterfaces(ctx context.Context, s *Session, snap *model.Snapshot) error {
	rows, order, err := snmp.Table(ctx, s.Client, oidIfEntry, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 16, 20)
	if err != nil {
		return err
	}
	xrows, _, err := snmp.Table(ctx, s.Client, oidIfXEntry, 1, 6, 10, 15, 18)
	if err != nil {
		xrows = nil // ifXTable is optional (very old agents)
	}
	var sysUp int64 = snap.System.UptimeSeconds
	ifaces := make([]model.Interface, 0, len(order))
	for _, idx := range order {
		n, err := strconv.Atoi(idx)
		if err != nil {
			continue
		}
		r := rows[idx]
		it := model.Interface{
			IfIndex:     n,
			Descr:       r[2].String(),
			Type:        int(r[3].Int()),
			MTU:         int(r[4].Int()),
			SpeedBps:    r[5].Uint(),
			MAC:         r[6].MAC(),
			AdminStatus: ifStatus[r[7].Int()],
			OperStatus:  ifStatus[r[8].Int()],
			InOctets:    r[10].Uint(),
			InErrors:    r[14].Uint(),
			OutOctets:   r[16].Uint(),
			OutErrors:   r[20].Uint(),
			Duplex:      "unknown",
			Medium:      "unknown",
		}
		if lc, ok := r[9]; ok && sysUp > 0 {
			it.LastChangeSeconds = int64(lc.Uint() / 100)
		}
		if x, ok := xrows[idx]; ok {
			if v := x[1].String(); v != "" {
				it.Name = v
			}
			if v, ok := x[6]; ok {
				it.InOctets = v.Uint()
			}
			if v, ok := x[10]; ok {
				it.OutOctets = v.Uint()
			}
			if v, ok := x[15]; ok && v.Uint() > 0 {
				it.SpeedBps = v.Uint() * 1_000_000
			}
			it.Alias = x[18].String()
		}
		if it.Name == "" {
			it.Name = it.Descr
		}
		ifaces = append(ifaces, it)
	}
	snap.Interfaces = ifaces

	if dup, err := s.Client.Walk(ctx, oidDot3DuplexStatus); err == nil {
		for _, p := range dup {
			idx, _ := snmp.Suffix(p.OID, oidDot3DuplexStatus)
			n, _ := strconv.Atoi(idx)
			if it := snap.InterfaceByIndex(n); it != nil {
				switch p.Int() {
				case 2:
					it.Duplex = "half"
				case 3:
					it.Duplex = "full"
				}
			}
		}
	}
	if bp, err := s.Client.Walk(ctx, oidDot1dBasePortIf); err == nil {
		for _, p := range bp {
			idx, _ := snmp.Suffix(p.OID, oidDot1dBasePortIf)
			port, _ := strconv.Atoi(idx)
			if it := snap.InterfaceByIndex(int(p.Int())); it != nil {
				it.BridgePort = port
			}
		}
	}
	return nil
}

// IfIndexForBridgePort maps a BRIDGE-MIB port number to an ifIndex.
func IfIndexForBridgePort(snap *model.Snapshot, port int) int {
	for _, it := range snap.Interfaces {
		if it.BridgePort == port {
			return it.IfIndex
		}
	}
	// Many agents (e.g. Huawei) omit dot1dBasePortIfIndex; fall back to identity when plausible.
	if it := snap.InterfaceByIndex(port); it != nil && it.Physical() {
		return port
	}
	return 0
}

// medium keywords seen in ifDescr / ENTITY descriptions / transceiver types.
var fiberWords = []string{"sfp", "xfp", "qsfp", "optic", "fiber", "fibre", "base-sx", "base-lx", "basesx", "baselx",
	"base-sr", "base-lr", "base-er", "base-zr", "basesr", "baselr", "1000base-x", "-fx", "basefx", "base-bx", "multimode", "single-mode", "singlemode"}
var copperWords = []string{"base-t", "baset", "rj45", "rj-45", "copper", "10/100/1000", "base-tx", "basetx"}

// ClassifyMedium returns fiber/copper/"" from free text.
func ClassifyMedium(text string) string {
	t := strings.ToLower(text)
	// a copper SFP ("SFP 1000BASE-T") is copper
	for _, w := range copperWords {
		if strings.Contains(t, w) {
			return "copper"
		}
	}
	for _, w := range fiberWords {
		if strings.Contains(t, w) {
			return "fiber"
		}
	}
	return ""
}

func deriveMedium(snap *model.Snapshot) {
	optic := map[int]model.Optic{}
	for _, o := range snap.Optics {
		optic[o.IfIndex] = o
	}
	entityText := map[int]string{}
	for _, e := range snap.Inventory {
		if e.AliasIfIndex > 0 {
			entityText[e.AliasIfIndex] += " " + e.Descr + " " + e.Model + " " + e.Name
		}
	}
	for i := range snap.Interfaces {
		it := &snap.Interfaces[i]
		switch it.Type {
		case 71:
			it.Medium = "wireless"
			continue
		case 24, 53, 131, 135, 136, 1, 166, 150:
			it.Medium = "virtual"
			continue
		case 161:
			it.Medium = "aggregate"
			continue
		}
		if o, ok := optic[it.IfIndex]; ok {
			if m := ClassifyMedium(o.Type + " " + o.PartNumber); m != "" {
				it.Medium = m
			} else {
				it.Medium = "fiber"
			}
			continue
		}
		if m := ClassifyMedium(entityText[it.IfIndex]); m != "" {
			it.Medium = m
			continue
		}
		if m := ClassifyMedium(it.Descr); m != "" {
			it.Medium = m
		}
	}
}
