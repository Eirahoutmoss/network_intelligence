package collectors

import (
	"context"
	"math/bits"
	"net"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

const oidIPAddrEntry = "1.3.6.1.2.1.4.20.1"

func CollectIPAddresses(ctx context.Context, s *Session, snap *model.Snapshot) error {
	rows, order, err := snmp.Table(ctx, s.Client, oidIPAddrEntry, 2, 3)
	if err != nil {
		return err
	}
	for _, idx := range order {
		ip := net.ParseIP(idx).To4()
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		r := rows[idx]
		prefix := 32
		if m := net.ParseIP(r[3].IP()).To4(); m != nil {
			prefix = maskLen(m)
		}
		snap.IPs = append(snap.IPs, model.IPAddress{IP: ip.String(), PrefixLen: prefix, IfIndex: int(r[2].Int())})
	}
	return nil
}

func maskLen(m net.IP) int {
	n := 0
	for _, b := range m {
		n += bits.OnesCount8(b)
	}
	return n
}

// ipFromIndex decodes a dotted IPv4 from index parts.
func ipFromIndex(parts []int) string {
	if len(parts) != 4 {
		return ""
	}
	for _, p := range parts {
		if p < 0 || p > 255 {
			return ""
		}
	}
	return net.IPv4(byte(parts[0]), byte(parts[1]), byte(parts[2]), byte(parts[3])).String()
}

func joinInts(p []int) string {
	var b strings.Builder
	for i, v := range p {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(itoa(v))
	}
	return b.String()
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
