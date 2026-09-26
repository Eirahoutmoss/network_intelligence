// Package identity decides which Unified Device an observation belongs to.
//
// The same device appears in many sources (SNMP management IP, ARP, MAC
// tables, LLDP chassis IDs, DNS names). Observations carry identifying keys
// of different strength:
//
//   - strong: MAC address, LLDP chassis ID, hardware serial
//   - medium: SNMP sysName of a network device
//   - weak:   IP address (DHCP leases move between hosts)
//
// Resolution rules:
//  1. Strong keys win. If strong keys point at several devices, they are the
//     same device and are merged.
//  2. A medium key (sysName) matches only when no strong key disagrees.
//  3. A weak key (IP) matches only when the candidate has no conflicting MAC;
//     otherwise the IP is considered re-assigned and moves to the new owner.
package identity

import (
	"sort"
	"strings"
)

// KeyKind enumerates identifier types.
type KeyKind string

const (
	MAC     KeyKind = "mac"
	Chassis KeyKind = "chassis"
	Serial  KeyKind = "serial"
	SysName KeyKind = "sysname"
	IP      KeyKind = "ip"
)

func (k KeyKind) strength() int {
	switch k {
	case MAC, Chassis, Serial:
		return 3
	case SysName:
		return 2
	}
	return 1
}

// Key is one identifier.
type Key struct {
	Kind  KeyKind
	Value string
}

// Norm normalizes key values for comparison.
func (k Key) Norm() Key {
	v := strings.TrimSpace(k.Value)
	switch k.Kind {
	case MAC, Chassis, SysName, Serial:
		v = strings.ToLower(v)
	}
	return Key{k.Kind, v}
}

// Index looks up devices by key. Implementations must also report which MACs
// a device owns (for IP conflict detection).
type Index interface {
	Find(k Key) []int64
	MACs(id int64) []string
}

// Decision is the outcome of resolving one observation.
type Decision struct {
	DeviceID int64   // 0 → create a new device
	Merge    []int64 // other devices that are the same and must be merged into DeviceID
	// ReleaseIPs lists devices that must drop an IP because it moved.
	ReleaseIPs map[int64][]string
	Reason     string
}

// Resolve applies the rules to an observation's keys.
func Resolve(idx Index, keys []Key) Decision {
	var strong, medium, weak []Key
	for _, k := range keys {
		k = k.Norm()
		if k.Value == "" {
			continue
		}
		switch k.Kind.strength() {
		case 3:
			strong = append(strong, k)
		case 2:
			medium = append(medium, k)
		default:
			weak = append(weak, k)
		}
	}
	d := Decision{ReleaseIPs: map[int64][]string{}}
	found := map[int64]bool{}
	var reasons []string
	for _, k := range strong {
		for _, id := range idx.Find(k) {
			if !found[id] {
				reasons = append(reasons, string(k.Kind)+" "+k.Value)
			}
			found[id] = true
		}
	}
	if len(found) == 0 {
		for _, k := range medium {
			for _, id := range idx.Find(k) {
				found[id] = true
				reasons = append(reasons, string(k.Kind)+" "+k.Value)
			}
		}
	}
	obsMACs := map[string]bool{}
	for _, k := range strong {
		if k.Kind == MAC {
			obsMACs[k.Value] = true
		}
	}
	for _, k := range weak {
		for _, id := range idx.Find(k) {
			if found[id] {
				continue
			}
			if conflicts(idx.MACs(id), obsMACs) {
				d.ReleaseIPs[id] = append(d.ReleaseIPs[id], k.Value)
				continue
			}
			if len(found) == 0 {
				found[id] = true
				reasons = append(reasons, "ip "+k.Value)
			} else {
				// IP belongs to a device with no MAC evidence while we already
				// matched strongly: it is the same host seen only by IP.
				found[id] = true
				reasons = append(reasons, "ip "+k.Value+" (no conflicting MAC)")
			}
		}
	}
	ids := make([]int64, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) > 0 {
		d.DeviceID = ids[0] // keep the oldest record
		d.Merge = ids[1:]
	}
	d.Reason = strings.Join(reasons, ", ")
	return d
}

func conflicts(deviceMACs []string, obs map[string]bool) bool {
	if len(obs) == 0 || len(deviceMACs) == 0 {
		return false
	}
	for _, m := range deviceMACs {
		if obs[strings.ToLower(m)] {
			return false
		}
	}
	return true
}

// MemIndex is an in-memory Index used during a resolution pass.
type MemIndex struct {
	keys map[Key]map[int64]bool
	macs map[int64]map[string]bool
}

func NewMemIndex() *MemIndex {
	return &MemIndex{keys: map[Key]map[int64]bool{}, macs: map[int64]map[string]bool{}}
}

func (m *MemIndex) Add(id int64, k Key) {
	k = k.Norm()
	if k.Value == "" {
		return
	}
	if m.keys[k] == nil {
		m.keys[k] = map[int64]bool{}
	}
	m.keys[k][id] = true
	if k.Kind == MAC {
		if m.macs[id] == nil {
			m.macs[id] = map[string]bool{}
		}
		m.macs[id][k.Value] = true
	}
}

func (m *MemIndex) Remove(id int64, k Key) {
	k = k.Norm()
	delete(m.keys[k], id)
	if k.Kind == MAC {
		delete(m.macs[id], k.Value)
	}
}

// MergeInto re-points every key of drop to keep.
func (m *MemIndex) MergeInto(keep, drop int64) {
	for k, ids := range m.keys {
		if ids[drop] {
			delete(ids, drop)
			ids[keep] = true
			_ = k
		}
	}
	for mac := range m.macs[drop] {
		if m.macs[keep] == nil {
			m.macs[keep] = map[string]bool{}
		}
		m.macs[keep][mac] = true
	}
	delete(m.macs, drop)
}

func (m *MemIndex) Find(k Key) []int64 {
	k = k.Norm()
	var out []int64
	for id := range m.keys[k] {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (m *MemIndex) MACs(id int64) []string {
	var out []string
	for mac := range m.macs[id] {
		out = append(out, mac)
	}
	return out
}
