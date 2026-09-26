// Package snmp provides a small, transport-agnostic SNMP client abstraction.
//
// Collectors depend only on the Client interface, so the same collector code
// runs against a real device (gosnmp), a recorded fixture (snmprec files) or
// the in-process simulator.
package snmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind is the ASN.1/SNMP type of a value.
type Kind int

const (
	KindNull Kind = iota
	KindInteger
	KindOctetString
	KindOID
	KindIPAddress
	KindCounter32
	KindGauge32
	KindTimeTicks
	KindCounter64
	KindNoSuchObject
	KindNoSuchInstance
	KindEndOfMib
)

// PDU is a single varbind with a normalized value:
// Integer → int64, Counter/Gauge/TimeTicks → uint64, OctetString → []byte,
// OID/IPAddress → string.
type PDU struct {
	OID   string // numeric, without leading dot
	Kind  Kind
	Value any
}

// Exists reports whether the varbind holds a real value.
func (p PDU) Exists() bool {
	return p.Kind != KindNull && p.Kind != KindNoSuchObject && p.Kind != KindNoSuchInstance && p.Kind != KindEndOfMib
}

// Int returns the value as int64 (0 if not numeric).
func (p PDU) Int() int64 {
	switch v := p.Value.(type) {
	case int64:
		return v
	case uint64:
		return int64(v)
	case []byte:
		n, _ := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
		return n
	}
	return 0
}

// Uint returns the value as uint64 (0 if not numeric/negative).
func (p PDU) Uint() uint64 {
	switch v := p.Value.(type) {
	case uint64:
		return v
	case int64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	}
	return 0
}

// Bytes returns raw octets.
func (p PDU) Bytes() []byte {
	switch v := p.Value.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	}
	return nil
}

// String returns a printable representation. Octet strings that are not valid
// printable UTF-8 are rendered as colon-separated hex.
func (p PDU) String() string {
	switch v := p.Value.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		s := strings.TrimRight(string(v), "\x00")
		if isPrintable(s) {
			return strings.TrimSpace(s)
		}
		return HexString(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	}
	return fmt.Sprint(p.Value)
}

func isPrintable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
		if r == 0x7f {
			return false
		}
	}
	return true
}

// HexString renders bytes as aa:bb:cc.
func HexString(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, c := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexd[c>>4], hexd[c&0xf])
	}
	return string(out)
}

// MAC returns the value as a normalized MAC address, or "" if it is not one.
// Handles 6 raw octets and textual forms.
func (p PDU) MAC() string {
	b := p.Bytes()
	if len(b) == 6 {
		return net.HardwareAddr(b).String()
	}
	return NormalizeMAC(string(b))
}

// NormalizeMAC parses common textual MAC notations into aa:bb:cc:dd:ee:ff.
func NormalizeMAC(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	clean := strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(s)
	if len(clean) != 12 {
		return ""
	}
	for _, c := range clean {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(clean[i : i+2])
	}
	out := b.String()
	if out == "00:00:00:00:00:00" || out == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	return out
}

// IP returns an IPv4/IPv6 address from an IpAddress varbind or 4/16 raw octets.
func (p PDU) IP() string {
	switch v := p.Value.(type) {
	case string:
		if ip := net.ParseIP(v); ip != nil {
			return ip.String()
		}
	case []byte:
		if len(v) == 4 || len(v) == 16 {
			return net.IP(v).String()
		}
		if ip := net.ParseIP(string(v)); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// Client is the minimal SNMP operation set used by collectors.
type Client interface {
	Get(ctx context.Context, oids ...string) ([]PDU, error)
	// Walk returns every varbind lexicographically under root.
	Walk(ctx context.Context, root string) ([]PDU, error)
	Close() error
}

// Errors classified for user-facing messages.
var (
	ErrTimeout = errors.New("no SNMP response (device unreachable, wrong community/credentials, or ACL)")
	ErrAuth    = errors.New("SNMP authentication failed (check username/password/protocol)")
)

// GetOne fetches a single OID; returns ok=false when absent.
func GetOne(ctx context.Context, c Client, oid string) (PDU, bool, error) {
	res, err := c.Get(ctx, oid)
	if err != nil {
		return PDU{}, false, err
	}
	if len(res) == 0 || !res[0].Exists() {
		return PDU{}, false, nil
	}
	return res[0], true, nil
}

// Row is one conceptual table row keyed by column number.
type Row map[int]PDU

// Table walks the given columns of a table entry and groups them by index
// suffix. entry is the xxxEntry OID (e.g. "1.3.6.1.2.1.2.2.1").
func Table(ctx context.Context, c Client, entry string, cols ...int) (map[string]Row, []string, error) {
	rows := map[string]Row{}
	var order []string
	for _, col := range cols {
		base := entry + "." + strconv.Itoa(col)
		pdus, err := c.Walk(ctx, base)
		if err != nil {
			return nil, nil, err
		}
		for _, p := range pdus {
			idx, ok := Suffix(p.OID, base)
			if !ok || !p.Exists() {
				continue
			}
			r, ok := rows[idx]
			if !ok {
				r = Row{}
				rows[idx] = r
				order = append(order, idx)
			}
			r[col] = p
		}
	}
	SortOIDs(order)
	return rows, order, nil
}

// Suffix returns the index part of oid below base.
func Suffix(oid, base string) (string, bool) {
	oid = strings.TrimPrefix(oid, ".")
	base = strings.TrimPrefix(base, ".")
	if !strings.HasPrefix(oid, base+".") {
		return "", false
	}
	return oid[len(base)+1:], true
}

// ParseOID converts "1.3.6" into []int.
func ParseOID(s string) ([]int, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), ".")
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		out[i] = n
	}
	return out, nil
}

// CompareOID compares two numeric OIDs.
func CompareOID(a, b string) int {
	pa, _ := ParseOID(a)
	pb, _ := ParseOID(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	}
	return 0
}

// SortOIDs sorts OID index strings numerically (insertion sort on parsed ints
// would be slow for large tables; use sort.Slice with parsed cache).
func SortOIDs(s []string) {
	parsed := make(map[string][]int, len(s))
	for _, x := range s {
		parsed[x], _ = ParseOID(x)
	}
	less := func(a, b []int) bool {
		for i := 0; i < len(a) && i < len(b); i++ {
			if a[i] != b[i] {
				return a[i] < b[i]
			}
		}
		return len(a) < len(b)
	}
	sortStrings(s, func(i, j int) bool { return less(parsed[s[i]], parsed[s[j]]) })
}

// IndexInts splits an index suffix into ints.
func IndexInts(idx string) []int {
	v, _ := ParseOID(idx)
	return v
}

// IndexToString decodes an index-encoded string: either length-prefixed
// ("n.c1.c2..cn") or implied length when implied is true.
func IndexToString(parts []int, implied bool) (string, []int) {
	if implied {
		b := make([]byte, 0, len(parts))
		for _, p := range parts {
			b = append(b, byte(p))
		}
		return string(b), nil
	}
	if len(parts) == 0 {
		return "", nil
	}
	n := parts[0]
	if n > len(parts)-1 {
		n = len(parts) - 1
	}
	b := make([]byte, 0, n)
	for _, p := range parts[1 : 1+n] {
		b = append(b, byte(p))
	}
	return string(b), parts[1+n:]
}
