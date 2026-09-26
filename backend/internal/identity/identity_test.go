package identity

import "testing"

func TestNewDevice(t *testing.T) {
	idx := NewMemIndex()
	d := Resolve(idx, []Key{{MAC, "aa:bb:cc:dd:ee:ff"}, {IP, "10.20.30.45"}})
	if d.DeviceID != 0 || len(d.Merge) != 0 {
		t.Fatalf("%+v", d)
	}
}

// The context example: SNMP IP, ARP MAC, switch port, DHCP name, DNS name,
// OUI and OS all describe one device and must resolve to a single record.
func TestUnifiedAcrossSources(t *testing.T) {
	idx := NewMemIndex()
	// ARP created the endpoint first (MAC+IP)
	idx.Add(1, Key{MAC, "AA:BB:CC:DD:EE:FF"})
	idx.Add(1, Key{IP, "10.20.30.45"})
	// DNS/NetBIOS observation arrives keyed by IP only
	d := Resolve(idx, []Key{{IP, "10.20.30.45"}})
	if d.DeviceID != 1 {
		t.Fatalf("dns obs: %+v", d)
	}
	// FDB observation keyed by MAC only
	d = Resolve(idx, []Key{{MAC, "aa:bb:cc:dd:ee:ff"}})
	if d.DeviceID != 1 {
		t.Fatalf("fdb obs: %+v", d)
	}
}

func TestStrongKeysMerge(t *testing.T) {
	idx := NewMemIndex()
	// LLDP created SW-DIST-01 by chassis MAC; ARP created an endpoint for the same MAC's IP
	idx.Add(3, Key{Chassis, "00:1b:54:20:00:01"})
	idx.Add(3, Key{MAC, "00:1b:54:20:00:01"})
	idx.Add(7, Key{MAC, "00:1b:54:20:00:02"})
	d := Resolve(idx, []Key{{MAC, "00:1b:54:20:00:01"}, {MAC, "00:1b:54:20:00:02"}, {SysName, "SW-DIST-01"}})
	if d.DeviceID != 3 || len(d.Merge) != 1 || d.Merge[0] != 7 {
		t.Fatalf("%+v", d)
	}
	idx.MergeInto(3, 7)
	if got := idx.Find(Key{MAC, "00:1b:54:20:00:02"}); len(got) != 1 || got[0] != 3 {
		t.Fatalf("after merge %v", got)
	}
}

func TestIPReassignedToDifferentMAC(t *testing.T) {
	idx := NewMemIndex()
	idx.Add(1, Key{MAC, "aa:aa:aa:aa:aa:aa"})
	idx.Add(1, Key{IP, "10.0.0.50"})
	d := Resolve(idx, []Key{{MAC, "bb:bb:bb:bb:bb:bb"}, {IP, "10.0.0.50"}})
	if d.DeviceID != 0 {
		t.Fatalf("different MAC must not merge by IP: %+v", d)
	}
	if ips := d.ReleaseIPs[1]; len(ips) != 1 || ips[0] != "10.0.0.50" {
		t.Fatalf("old owner should release IP: %+v", d)
	}
}

func TestSysNameOnlyWithoutStrongConflict(t *testing.T) {
	idx := NewMemIndex()
	idx.Add(5, Key{SysName, "sw-core-01"})
	idx.Add(9, Key{MAC, "00:e0:fc:10:00:01"})
	// strong key found (9): sysName match on 5 is ignored
	d := Resolve(idx, []Key{{MAC, "00:e0:fc:10:00:01"}, {SysName, "SW-CORE-01"}})
	if d.DeviceID != 9 || len(d.Merge) != 0 {
		t.Fatalf("%+v", d)
	}
	// sysName alone matches
	d = Resolve(idx, []Key{{SysName, "SW-CORE-01"}})
	if d.DeviceID != 5 {
		t.Fatalf("%+v", d)
	}
}

func TestIPOnlyDeviceJoinsStrongMatch(t *testing.T) {
	idx := NewMemIndex()
	idx.Add(2, Key{MAC, "cc:cc:cc:cc:cc:cc"})
	idx.Add(4, Key{IP, "10.9.9.9"}) // e.g. created by a manual add without MAC
	d := Resolve(idx, []Key{{MAC, "cc:cc:cc:cc:cc:cc"}, {IP, "10.9.9.9"}})
	if d.DeviceID != 2 || len(d.Merge) != 1 || d.Merge[0] != 4 {
		t.Fatalf("%+v", d)
	}
}
