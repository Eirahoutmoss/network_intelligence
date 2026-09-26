package snmp

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// MIB is an ordered in-memory OID → value store. It backs fixture clients and
// the SNMP simulator.
type MIB struct {
	mu     sync.RWMutex
	byOID  map[string]PDU
	sorted []string
	parsed [][]int
	dirty  bool
}

func NewMIB() *MIB { return &MIB{byOID: map[string]PDU{}} }

// Set stores a value. Kind must match Value type conventions of PDU.
func (m *MIB) Set(oid string, kind Kind, value any) {
	oid = strings.TrimPrefix(oid, ".")
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byOID[oid]; !ok {
		m.dirty = true
	}
	m.byOID[oid] = PDU{OID: oid, Kind: kind, Value: value}
}

// Helpers for building fixtures.
func (m *MIB) Str(oid, v string)              { m.Set(oid, KindOctetString, []byte(v)) }
func (m *MIB) Octets(oid string, v []byte)    { m.Set(oid, KindOctetString, v) }
func (m *MIB) Int(oid string, v int64)        { m.Set(oid, KindInteger, v) }
func (m *MIB) Gauge(oid string, v uint64)     { m.Set(oid, KindGauge32, v) }
func (m *MIB) Counter(oid string, v uint64)   { m.Set(oid, KindCounter32, v) }
func (m *MIB) Counter64(oid string, v uint64) { m.Set(oid, KindCounter64, v) }
func (m *MIB) Ticks(oid string, v uint64)     { m.Set(oid, KindTimeTicks, v) }
func (m *MIB) OIDv(oid, v string)             { m.Set(oid, KindOID, strings.TrimPrefix(v, ".")) }
func (m *MIB) IPv(oid, v string)              { m.Set(oid, KindIPAddress, v) }

// Len returns the number of stored varbinds.
func (m *MIB) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byOID)
}

func (m *MIB) index() {
	if !m.dirty && m.sorted != nil {
		return
	}
	m.sorted = m.sorted[:0]
	for k := range m.byOID {
		m.sorted = append(m.sorted, k)
	}
	parsed := make(map[string][]int, len(m.sorted))
	for _, k := range m.sorted {
		parsed[k], _ = ParseOID(k)
	}
	sort.Slice(m.sorted, func(i, j int) bool { return lessInts(parsed[m.sorted[i]], parsed[m.sorted[j]]) })
	m.parsed = make([][]int, len(m.sorted))
	for i, k := range m.sorted {
		m.parsed[i] = parsed[k]
	}
	m.dirty = false
}

func lessInts(a, b []int) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// Lookup returns the exact varbind.
func (m *MIB) Lookup(oid string) (PDU, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.byOID[strings.TrimPrefix(oid, ".")]
	return p, ok
}

// Next returns the first varbind strictly after oid.
func (m *MIB) Next(oid string) (PDU, bool) {
	m.mu.Lock()
	m.index()
	m.mu.Unlock()
	m.mu.RLock()
	defer m.mu.RUnlock()
	target, _ := ParseOID(oid)
	i := sort.Search(len(m.parsed), func(i int) bool { return lessInts(target, m.parsed[i]) })
	if i >= len(m.sorted) {
		return PDU{}, false
	}
	return m.byOID[m.sorted[i]], true
}

// ParseSnmprec loads the snmpsim ".snmprec" text format: "oid|type|value".
func ParseSnmprec(r io.Reader) (*MIB, error) {
	m := NewMIB()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		parts := strings.SplitN(t, "|", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("line %d: expected oid|type|value", line)
		}
		oid, typ, val := parts[0], parts[1], parts[2]
		isHex := strings.HasSuffix(typ, "x")
		typ = strings.TrimSuffix(typ, "x")
		var raw []byte
		if isHex {
			b, err := hex.DecodeString(val)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad hex: %w", line, err)
			}
			raw = b
		} else {
			raw = []byte(val)
		}
		switch typ {
		case "2":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			m.Int(oid, n)
		case "4":
			m.Octets(oid, raw)
		case "5":
			m.Set(oid, KindNull, nil)
		case "6":
			m.OIDv(oid, val)
		case "64":
			if isHex && len(raw) == 4 {
				m.IPv(oid, fmt.Sprintf("%d.%d.%d.%d", raw[0], raw[1], raw[2], raw[3]))
			} else {
				m.IPv(oid, val)
			}
		case "65", "66", "67", "70":
			n, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", line, err)
			}
			kind := map[string]Kind{"65": KindCounter32, "66": KindGauge32, "67": KindTimeTicks, "70": KindCounter64}[typ]
			m.Set(oid, kind, n)
		case "68":
			m.Octets(oid, raw)
		default:
			return nil, fmt.Errorf("line %d: unsupported type %s", line, typ)
		}
	}
	return m, sc.Err()
}

// WriteSnmprec serializes the MIB in snmprec format (useful for exporting
// simulator labs as fixtures).
func (m *MIB) WriteSnmprec(w io.Writer) error {
	m.mu.Lock()
	m.index()
	keys := append([]string(nil), m.sorted...)
	m.mu.Unlock()
	bw := bufio.NewWriter(w)
	for _, k := range keys {
		p, _ := m.Lookup(k)
		var typ, val string
		switch p.Kind {
		case KindInteger:
			typ, val = "2", strconv.FormatInt(p.Value.(int64), 10)
		case KindOctetString:
			b := p.Bytes()
			if isPrintable(string(b)) && !strings.Contains(string(b), "\n") {
				typ, val = "4", string(b)
			} else {
				typ, val = "4x", hex.EncodeToString(b)
			}
		case KindOID:
			typ, val = "6", p.Value.(string)
		case KindIPAddress:
			typ, val = "64", p.Value.(string)
		case KindCounter32:
			typ, val = "65", strconv.FormatUint(p.Value.(uint64), 10)
		case KindGauge32:
			typ, val = "66", strconv.FormatUint(p.Value.(uint64), 10)
		case KindTimeTicks:
			typ, val = "67", strconv.FormatUint(p.Value.(uint64), 10)
		case KindCounter64:
			typ, val = "70", strconv.FormatUint(p.Value.(uint64), 10)
		default:
			typ, val = "5", ""
		}
		fmt.Fprintf(bw, "%s|%s|%s\n", k, typ, val)
	}
	return bw.Flush()
}

// MIBClient serves Get/Walk directly from a MIB (no network).
type MIBClient struct{ M *MIB }

func (c MIBClient) Close() error { return nil }

func (c MIBClient) Get(ctx context.Context, oids ...string) ([]PDU, error) {
	out := make([]PDU, 0, len(oids))
	for _, o := range oids {
		if p, ok := c.M.Lookup(o); ok {
			out = append(out, p)
		} else {
			out = append(out, PDU{OID: strings.TrimPrefix(o, "."), Kind: KindNoSuchObject})
		}
	}
	return out, ctx.Err()
}

func (c MIBClient) Walk(ctx context.Context, root string) ([]PDU, error) {
	root = strings.TrimPrefix(root, ".")
	var out []PDU
	cur := root
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, ok := c.M.Next(cur)
		if !ok || !strings.HasPrefix(p.OID, root+".") {
			break
		}
		out = append(out, p)
		cur = p.OID
	}
	return out, nil
}
