package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/lab"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/metrics"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/testutil"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/all"
)

// RunLabDiscovery runs a full discovery of the campus lab into db. Exported
// for reuse by other packages' tests via a small wrapper.
func runLab(t *testing.T, db *storage.DB, active bool) (*Engine, int64) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l := lab.Campus()
	r, err := l.Start(ctx, "127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := credentials.NewSealer(testutil.Key())
	creds := credentials.NewStore(db, sealer)
	credID, err := creds.CreateSNMP(ctx, db, "lab", credentials.SNMP{Username: l.V3User, AuthPassword: l.V3Pass})
	if err != nil {
		t.Fatal(err)
	}
	log := testutil.Logger()
	e := &Engine{
		DB: db, Store: inventory.New(db, log), Creds: creds, Hub: NewHub(), Log: log, Metrics: metrics.New(),
		Collector: &Collector{Dialer: snmp.NetDialer{Map: r.Addrs, Strict: true, Opt: snmp.Options{Timeout: time.Second}}, Registry: all.Registry(), Log: log},
		Prober:    l.Prober(),
	}
	e.Start(ctx)
	id, err := e.Submit(ctx, "10.20.99.1", credID, Options{MaxDepth: 3, ActiveFingerprint: active, TryAllCredentials: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		var status string
		var errText *string
		if err := db.QueryRow(ctx, `SELECT status, error FROM discovery_runs WHERE id=$1`, id).Scan(&status, &errText); err != nil {
			t.Fatal(err)
		}
		if status == "completed" {
			break
		}
		if status == "failed" || status == "cancelled" {
			t.Fatalf("run %s: %v", status, *errText)
		}
		if time.Now().After(deadline) {
			t.Fatal("discovery timed out")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return e, id
}

func q1(t *testing.T, db *storage.DB, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func TestFullLabDiscovery(t *testing.T) {
	db := testutil.DB(t)
	_, runID := runLab(t, db, true)
	ctx := context.Background()

	// Every managed switch discovered through LLDP recursion (5 hops worth)
	if n := q1(t, db, `SELECT count(*) FROM devices WHERE managed`); n != 6 {
		t.Fatalf("managed devices = %d, want 6", n)
	}
	// FortiGate known only from LLDP → unmanaged firewall
	var fwType string
	var fwManaged bool
	if err := db.QueryRow(ctx, `SELECT device_type, managed FROM devices WHERE sys_name='FW-01'`).Scan(&fwType, &fwManaged); err != nil {
		t.Fatal(err)
	}
	if fwType != "firewall" || fwManaged {
		t.Errorf("FW-01: %s managed=%v", fwType, fwManaged)
	}
	// Switch types
	if n := q1(t, db, `SELECT count(*) FROM devices WHERE managed AND device_type='switch'`); n != 6 {
		t.Errorf("switches = %d", n)
	}
	// No duplicates: each lab endpoint MAC belongs to exactly one device
	if n := q1(t, db, `SELECT count(*) FROM (SELECT mac FROM device_macs GROUP BY mac HAVING count(DISTINCT device_id) > 1) x`); n != 0 {
		t.Errorf("%d MACs belong to several devices", n)
	}
	l := lab.Campus()
	if n := q1(t, db, `SELECT count(*) FROM devices WHERE NOT managed AND discovered_via IN ('arp','fdb','lldp')`); n < len(l.Endpoints) {
		t.Errorf("endpoints = %d, want >= %d", n, len(l.Endpoints))
	}
	// Attachment: LAB-PC-01 on SW-LAB-01 port 1, VLAN 30
	var sw, port string
	var vlan int
	err := db.QueryRow(ctx, `SELECT s.sys_name, a.port_name, a.vlan_id FROM attachments a JOIN devices s ON s.id=a.switch_id
		JOIN device_macs m ON m.device_id=a.device_id WHERE m.mac='00:14:22:30:00:01' AND a.ended_at IS NULL`).Scan(&sw, &port, &vlan)
	if err != nil || sw != "SW-LAB-01" || port != "1" || vlan != 30 {
		t.Errorf("LAB-PC-01 attachment: %s %s %d %v", sw, port, vlan, err)
	}
	// Every lab endpoint is attached to the right switch/port
	for _, ep := range l.Endpoints {
		var gotSw, gotPort string
		err := db.QueryRow(ctx, `SELECT s.sys_name, a.port_name FROM attachments a JOIN devices s ON s.id=a.switch_id
			JOIN device_macs m ON m.device_id=a.device_id WHERE m.mac=$1 AND a.ended_at IS NULL`, ep.MAC).Scan(&gotSw, &gotPort)
		if err != nil || gotSw != ep.Switch || gotPort != ep.Port {
			t.Errorf("%s: attached to %s %s (%v), want %s %s", ep.Name, gotSw, gotPort, err, ep.Switch, ep.Port)
		}
	}
	// Classification: Windows XP in the lab with high confidence
	if n := q1(t, db, `SELECT count(*) FROM devices WHERE os_name='Windows XP' AND os_confidence >= 0.9`); n != 4 {
		t.Errorf("Windows XP devices = %d", n)
	}
	if n := q1(t, db, `SELECT count(*) FROM devices WHERE device_type='printer'`); n != 5 {
		rows, _ := db.Query(ctx, `SELECT COALESCE(hostname,''), device_type, device_type_confidence FROM devices WHERE NOT managed ORDER BY 1`)
		for rows.Next() {
			var h, ty string
			var c float64
			rows.Scan(&h, &ty, &c)
			t.Logf("%s %s %.2f", h, ty, c)
		}
		rows.Close()
		t.Errorf("printers = %d", n)
	}
	if n := q1(t, db, `SELECT count(*) FROM devices WHERE device_type='printer' AND vendor ILIKE 'HP%'`); n != 2 {
		t.Errorf("HP printers = %d", n)
	}
	if n := q1(t, db, `SELECT count(*) FROM devices WHERE device_type='phone'`); n != 4 {
		t.Errorf("phones = %d", n)
	}
	if n := q1(t, db, `SELECT count(*) FROM devices WHERE device_type='access_point'`); n != 1 {
		t.Errorf("APs = %d", n)
	}
	if n := q1(t, db, `SELECT count(*) FROM devices WHERE device_type='camera'`); n != 1 {
		t.Errorf("cameras = %d", n)
	}
	// Evidence recorded
	if n := q1(t, db, `SELECT count(*) FROM evidence e JOIN devices d ON d.id=e.device_id WHERE d.os_name='Windows XP' AND e.attribute='os'`); n < 12 {
		t.Errorf("XP evidence rows = %d", n)
	}
	// Topology: 6 switch links (both-side LLDP deduped) + endpoint edges
	if n := q1(t, db, `SELECT count(*) FROM topology_edges e JOIN devices a ON a.id=e.a_device_id JOIN devices b ON b.id=e.b_device_id
		WHERE e.layer='physical' AND a.device_type IN ('switch','firewall') AND b.device_type IN ('switch','firewall')`); n != 6 {
		t.Errorf("infra links = %d", n)
	}
	if n := q1(t, db, `SELECT count(*) FROM topology_edges WHERE layer='physical' AND confidence >= 0.99`); n < 5 {
		t.Errorf("bidirectionally confirmed links = %d", n)
	}
	// uplinks marked
	if n := q1(t, db, `SELECT count(*) FROM interfaces WHERE is_uplink`); n != 11 {
		t.Errorf("uplinks = %d, want 11", n)
	}
	// run summary
	var steps int
	db.QueryRow(ctx, `SELECT jsonb_array_length(steps) FROM discovery_runs WHERE id=$1`, runID).Scan(&steps)
	if steps < 20 {
		t.Errorf("steps = %d", steps)
	}
	// Subnets learned from the core
	if n := q1(t, db, `SELECT count(*) FROM subnets`); n < 6 {
		t.Errorf("subnets = %d", n)
	}
}

func TestRediscoveryIsIdempotentAndTracksMoves(t *testing.T) {
	db := testutil.DB(t)
	e, _ := runLab(t, db, false)
	ctx := context.Background()
	before := q1(t, db, `SELECT count(*) FROM devices`)
	// Simulate a move: LAB-PC-02 currently on port 2 — pretend it was elsewhere before.
	if _, err := db.Exec(ctx, `UPDATE attachments SET port_name='9', interface_id=(SELECT id FROM interfaces WHERE name='9' AND device_id=attachments.switch_id)
		WHERE device_id=(SELECT device_id FROM device_macs WHERE mac='00:14:22:30:00:02') AND ended_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	st, err := e.Store.ResolveNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Moves != 1 || st.NewEndpoints != 0 {
		t.Errorf("stats %+v", st)
	}
	if after := q1(t, db, `SELECT count(*) FROM devices`); after != before {
		t.Errorf("devices %d → %d", before, after)
	}
	if n := q1(t, db, `SELECT count(*) FROM attachments WHERE ended_at IS NOT NULL`); n != 1 {
		t.Errorf("history rows = %d", n)
	}
	if n := q1(t, db, `SELECT count(*) FROM events WHERE kind='endpoint.moved'`); n != 1 {
		t.Errorf("move events = %d", n)
	}
}
