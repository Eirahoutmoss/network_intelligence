package collectors

import (
	"context"
	"fmt"
	"net"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

const (
	oidInetCidrRouteEntry = "1.3.6.1.2.1.4.24.7.1" // 7 ifIndex, 9 proto, 12 metric1
	oidIPCidrRouteEntry   = "1.3.6.1.2.1.4.24.4.1" // 5 ifIndex, 7 proto, 11 metric1
	oidIPRouteEntry       = "1.3.6.1.2.1.4.21.1"   // 2 ifIndex, 3 metric1, 7 nextHop, 9 proto, 11 mask
	// MaxRoutes caps the routing table we store; full Internet tables are not useful here.
	MaxRoutes = 5000
)

var routeProto = map[int64]string{1: "other", 2: "connected", 3: "static", 4: "icmp", 5: "egp", 8: "rip",
	9: "isis", 13: "ospf", 14: "bgp", 16: "eigrp"}

// CollectRoutes reads the IPv4 routing table using the newest MIB the device supports.
func CollectRoutes(ctx context.Context, s *Session, snap *model.Snapshot) error {
	add := func(dest net.IP, prefix int, nh string, ifIndex int, proto int64, metric int64) {
		if len(snap.Routes) >= MaxRoutes || dest == nil {
			return
		}
		if nh == "" {
			nh = "0.0.0.0"
		}
		snap.Routes = append(snap.Routes, model.Route{
			Dest:     fmt.Sprintf("%s/%d", dest.Mask(net.CIDRMask(prefix, 32)), prefix),
			NextHop:  nh,
			IfIndex:  ifIndex,
			Protocol: routeProto[proto],
			Metric:   int(metric),
		})
	}
	// inetCidrRouteTable: destType.destLen?.dest.pfxLen.policy(len-prefixed OID).nhType.nhLen.nh
	rows, order, err := snmp.Table(ctx, s.Client, oidInetCidrRouteEntry, 7, 9, 12)
	if err == nil && len(order) > 0 {
		for _, idx := range order {
			p := snmp.IndexInts(idx)
			if len(p) < 2 || p[0] != 1 || p[1] != 4 || len(p) < 8 {
				continue
			}
			dest := net.ParseIP(ipFromIndex(p[2:6]))
			pfx := p[6]
			rest := p[7:]
			if len(rest) < 1 || len(rest) < 1+rest[0] {
				continue
			}
			rest = rest[1+rest[0]:]
			nh := ""
			if len(rest) >= 6 && rest[0] == 1 && rest[1] == 4 {
				nh = ipFromIndex(rest[2:6])
			}
			r := rows[idx]
			add(dest, pfx, nh, int(r[7].Int()), r[9].Int(), r[12].Int())
		}
		return nil
	}
	rows, order, err = snmp.Table(ctx, s.Client, oidIPCidrRouteEntry, 5, 7, 11)
	if err == nil && len(order) > 0 {
		for _, idx := range order {
			p := snmp.IndexInts(idx)
			if len(p) != 13 {
				continue
			}
			dest := net.ParseIP(ipFromIndex(p[0:4]))
			mask := net.ParseIP(ipFromIndex(p[4:8])).To4()
			if mask == nil {
				continue
			}
			r := rows[idx]
			add(dest, maskLen(mask), ipFromIndex(p[9:13]), int(r[5].Int()), r[7].Int(), r[11].Int())
		}
		return nil
	}
	rows, order, err = snmp.Table(ctx, s.Client, oidIPRouteEntry, 2, 3, 7, 9, 11)
	if err != nil {
		return err
	}
	for _, idx := range order {
		r := rows[idx]
		mask := net.ParseIP(r[11].IP()).To4()
		if mask == nil {
			continue
		}
		add(net.ParseIP(idx), maskLen(mask), r[7].IP(), int(r[2].Int()), r[9].Int(), r[3].Int())
	}
	return nil
}
