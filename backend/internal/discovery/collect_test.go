package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/lab"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/all"
)

func startLab(t *testing.T) (*lab.Running, *Collector) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l := lab.Campus()
	r, err := l.Start(ctx, "127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, &Collector{Dialer: snmp.NetDialer{Map: r.Addrs, Strict: true, Opt: snmp.Options{Timeout: time.Second}}, Registry: all.Registry()}
}

func v3(l *lab.Lab) credentials.SNMP {
	return credentials.SNMP{Username: l.V3User, AuthPassword: l.V3Pass}
}

func findIf(s *model.Snapshot, name string) *model.Interface { return s.InterfaceByName(name) }

func TestCollectHuaweiCore(t *testing.T) {
	r, c := startLab(t)
	var steps []Step
	snap, err := c.Collect(context.Background(), "10.20.99.1", v3(r.Lab), true, func(s Step) { steps = append(steps, s) })
	if err != nil {
		t.Fatal(err)
	}
	sys := snap.System
	if sys.Vendor != "Huawei" || sys.Model != "S6730-H24X6C" || sys.OSName != "VRP" || sys.Serial == "" || !sys.IsRouter {
		t.Fatalf("system: %+v", sys)
	}
	if sys.OSVersion != "8.191 V200R021C00SPC100" {
		t.Errorf("os version %q", sys.OSVersion)
	}
	if sys.CPUPercent == nil || *sys.CPUPercent != 14 {
		t.Errorf("cpu %v", sys.CPUPercent)
	}
	if len(snap.Interfaces) != 30 {
		t.Errorf("interfaces %d", len(snap.Interfaces))
	}
	up := findIf(snap, "XGigabitEthernet0/0/1")
	if up == nil || up.SpeedBps != 10_000_000_000 || up.Medium != "fiber" || up.Duplex != "full" {
		t.Errorf("uplink: %+v", up)
	}
	if fw := findIf(snap, "XGigabitEthernet0/0/24"); fw == nil || fw.Medium != "copper" {
		t.Errorf("copper SFP should be copper: %+v", fw)
	}
	if len(snap.Neighbors) != 3 {
		t.Fatalf("neighbors: %+v", snap.Neighbors)
	}
	var dist1 *model.Neighbor
	for i := range snap.Neighbors {
		if snap.Neighbors[i].SysName == "SW-DIST-01" {
			dist1 = &snap.Neighbors[i]
		}
	}
	if dist1 == nil || dist1.LocalPort != "XGigabitEthernet0/0/1" || dist1.PortID != "Te1/1/1" || dist1.MgmtIP != "10.20.99.2" || dist1.ChassisID != "00:1b:54:20:00:01" {
		t.Errorf("dist1 neighbor: %+v", dist1)
	}
	if len(snap.ARP) < 30 {
		t.Errorf("arp %d", len(snap.ARP))
	}
	if len(snap.Routes) != 8 {
		t.Errorf("routes %+v", snap.Routes)
	}
	var def bool
	for _, rt := range snap.Routes {
		if rt.Dest == "0.0.0.0/0" && rt.NextHop == "10.20.255.254" && rt.Protocol == "static" {
			def = true
		}
	}
	if !def {
		t.Errorf("default route missing: %+v", snap.Routes)
	}
	if len(snap.VLANs) != 6 {
		t.Errorf("vlans %+v", snap.VLANs)
	}
	if len(snap.FDB) == 0 {
		t.Error("no FDB")
	}
	var optic *model.Optic
	for i := range snap.Optics {
		if snap.Optics[i].IfIndex == up.IfIndex {
			optic = &snap.Optics[i]
		}
	}
	if optic == nil || optic.RxDBm == nil || optic.Serial != "HA20210300101" || optic.Vendor != "HUAWEI" {
		t.Errorf("optic: %+v", optic)
	} else if *optic.RxDBm > -2.8 || *optic.RxDBm < -3.0 { // 512 µW ≈ -2.91 dBm
		t.Errorf("rx dBm %v", *optic.RxDBm)
	}
	if len(snap.IPs) != 6 {
		t.Errorf("ips %+v", snap.IPs)
	}
	seen := map[string]string{}
	for _, s := range steps {
		seen[s.Key] = s.Status
	}
	for _, k := range []string{"reachable", "auth", "vendor", "interfaces", "lldp", "model"} {
		if seen[k] != "done" {
			t.Errorf("step %s = %q", k, seen[k])
		}
	}
	if len(snap.Errors) != 0 {
		t.Errorf("collector errors: %+v", snap.Errors)
	}
}

func TestCollectCiscoDistribution(t *testing.T) {
	r, c := startLab(t)
	snap, err := c.Collect(context.Background(), "10.20.99.2", v3(r.Lab), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if snap.System.Vendor != "Cisco" || snap.System.OSName != "IOS-XE" || snap.System.OSVersion != "17.9.4a" || snap.System.Model != "C9300-48P" {
		t.Fatalf("system %+v", snap.System)
	}
	lldp, cdp := 0, 0
	for _, n := range snap.Neighbors {
		switch n.Protocol {
		case "lldp":
			lldp++
			if n.LocalIfIndex == 0 {
				t.Errorf("unresolved local port: %+v", n)
			}
		case "cdp":
			cdp++
		}
	}
	if lldp != 3 || cdp != 0 { // CDP duplicates of LLDP adjacencies are suppressed
		t.Errorf("lldp=%d cdp=%d %+v", lldp, cdp, snap.Neighbors)
	}
	// per-VLAN FDB via SNMP contexts
	if len(snap.FDB) < 20 {
		t.Fatalf("fdb %d", len(snap.FDB))
	}
	te2 := findIf(snap, "TenGigabitEthernet1/1/2")
	found := false
	for _, f := range snap.FDB {
		if f.MAC == "f8:bc:12:a1:00:01" {
			found = f.IfIndex == te2.IfIndex && f.VLAN == 10
		}
	}
	if !found {
		t.Error("floor-1 PC MAC should be learned on Te1/1/2 VLAN 10")
	}
	if gi := findIf(snap, "GigabitEthernet1/0/5"); gi == nil || gi.PVID != 10 {
		t.Errorf("access vlan: %+v", gi)
	}
	if snap.System.CPUPercent == nil || snap.System.MemoryPercent == nil {
		t.Error("cisco health missing")
	}
}

func TestCollectHPEAndErrors(t *testing.T) {
	r, c := startLab(t)
	snap, err := c.Collect(context.Background(), "10.20.99.21", v3(r.Lab), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if snap.System.Vendor != "HP" && snap.System.Vendor != "HPE" {
		t.Errorf("vendor %q", snap.System.Vendor)
	}
	if snap.System.OSName != "ArubaOS-Switch" || snap.System.OSVersion != "YA.16.11.0015" {
		t.Errorf("hpe os %+v", snap.System)
	}
	if len(snap.Neighbors) != 1 || snap.Neighbors[0].SysName != "SW-DIST-02" || snap.Neighbors[0].LocalPort != "25" {
		t.Errorf("hpe lldp %+v", snap.Neighbors)
	}
	port1 := findIf(snap, "1")
	ok := false
	for _, f := range snap.FDB {
		if f.MAC == "00:14:22:30:00:01" && f.IfIndex == port1.IfIndex && f.VLAN == 30 {
			ok = true
		}
	}
	if !ok {
		t.Error("lab PC not on port 1")
	}
	// wrong password → auth error
	bad := v3(r.Lab)
	bad.AuthPassword = "wrong-password"
	if _, err := c.Collect(context.Background(), "10.20.99.21", bad, true, nil); err == nil || !contains(err.Error(), "authentication") {
		t.Errorf("expected auth failure, got %v", err)
	}
	// unknown host → unreachable
	if _, err := c.Collect(context.Background(), "10.20.255.254", v3(r.Lab), true, nil); err == nil {
		t.Error("expected unreachable")
	}
	// v2c also works
	if _, err := c.Collect(context.Background(), "10.20.99.11", credentials.SNMP{Community: "public"}, false, nil); err != nil {
		t.Errorf("v2c: %v", err)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestCollectSTP(t *testing.T) {
	r, c := startLab(t)
	snap, err := c.Collect(context.Background(), "10.20.99.11", v3(r.Lab), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if snap.System.STPRoot != "4096/00:e0:fc:10:00:01" {
		t.Errorf("stp root %q", snap.System.STPRoot)
	}
	up := findIf(snap, "XGigabitEthernet0/0/1")
	if up == nil || up.STPState != "forwarding" || snap.System.STPRootPort != up.IfIndex {
		t.Errorf("uplink stp: %+v root port %d", up, snap.System.STPRootPort)
	}
	if d := findIf(snap, "GigabitEthernet0/0/48"); d == nil || d.STPState != "disabled" {
		t.Errorf("down port stp: %+v", d)
	}
}

func TestSNMPv3Autodetect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := lab.Campus()
	m := l.Build()["10.20.99.11"]
	a := &snmp.Agent{MIB: m.Main, V3Users: map[string]snmp.V3User{"ops": {AuthProtocol: "SHA256", AuthPassword: "sha256-secret"}}}
	if err := a.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	go a.Serve(ctx)
	c := &Collector{Dialer: snmp.NetDialer{Map: map[string]string{"10.20.99.11": a.Addr().String()}, Strict: true, Opt: snmp.Options{Timeout: 500 * time.Millisecond}}, Registry: all.Registry()}
	var steps []Step
	snap, used, err := c.CollectWithCredential(ctx, "10.20.99.11", credentials.SNMP{Username: "ops", AuthPassword: "sha256-secret", Autodetect: true}, false, func(s Step) { steps = append(steps, s) })
	if err != nil {
		t.Fatalf("autodetect failed: %v", err)
	}
	if used.AuthProtocol != "SHA256" || used.SecurityLevel != "authNoPriv" || used.Autodetect {
		t.Fatalf("detected %+v", used)
	}
	if snap.System.Name != "SW-ACC-F1-01" {
		t.Fatalf("snapshot %+v", snap.System)
	}
	// Without autodetect the same credentials fail with a clear auth error.
	if _, err := c.Collect(ctx, "10.20.99.11", credentials.SNMP{Username: "ops", AuthPassword: "sha256-secret"}, false, nil); err == nil || !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected auth failure, got %v", err)
	}
	// A wrong password is still rejected after trying every combination.
	start := time.Now()
	if _, err := c.Collect(ctx, "10.20.99.11", credentials.SNMP{Username: "ops", AuthPassword: "wrong-password", Autodetect: true}, false, nil); err == nil {
		t.Fatal("wrong password accepted")
	}
	t.Logf("exhaustive attempt took %v", time.Since(start))
}
