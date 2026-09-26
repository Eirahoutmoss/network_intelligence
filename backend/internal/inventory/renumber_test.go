package inventory_test

import (
	"context"
	"testing"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/testutil"
)

func snap(indexes map[string]int) *model.Snapshot {
	s := &model.Snapshot{System: model.System{Name: "SW-TEST", ChassisID: "00:e0:fc:99:00:01", ObjectID: "1.3.6.1.4.1.2011.2.23.1"}}
	for name, idx := range indexes {
		s.Interfaces = append(s.Interfaces, model.Interface{IfIndex: idx, Name: name, Type: 6, OperStatus: "up", AdminStatus: "up", Medium: "copper", Duplex: "full"})
	}
	return s
}

// A reboot that renumbers ifIndex must keep interface rows, so wall-jack
// mappings and attachment history survive.
func TestInterfaceRenumberingKeepsRows(t *testing.T) {
	db := testutil.DB(t)
	ctx := context.Background()
	st := inventory.New(db, testutil.Logger())
	dev, _, err := st.IngestSnapshot(ctx, snap(map[string]int{"Gi0/1": 1, "Gi0/2": 2, "Gi0/3": 3}), inventory.IngestOptions{MgmtIP: "10.9.9.9", Via: "seed", Full: true})
	if err != nil {
		t.Fatal(err)
	}
	var gi2 int64
	db.QueryRow(ctx, `SELECT id FROM interfaces WHERE device_id=$1 AND name='Gi0/2'`, dev).Scan(&gi2)
	var loc, jack int64
	db.QueryRow(ctx, `INSERT INTO locations(kind,name) VALUES ('room','R1') RETURNING id`).Scan(&loc)
	db.QueryRow(ctx, `INSERT INTO network_jacks(location_id,label,switch_device_id,switch_interface_id) VALUES ($1,'J1',$2,$3) RETURNING id`, loc, dev, gi2).Scan(&jack)

	// After "reboot": indexes swapped/shifted, one new port.
	if _, _, err := st.IngestSnapshot(ctx, snap(map[string]int{"Gi0/1": 3, "Gi0/2": 1, "Gi0/3": 2, "Gi0/4": 4}), inventory.IngestOptions{MgmtIP: "10.9.9.9", Via: "refresh", Full: true}); err != nil {
		t.Fatal(err)
	}
	var id int64
	var idx int
	if err := db.QueryRow(ctx, `SELECT id, if_index FROM interfaces WHERE device_id=$1 AND name='Gi0/2'`, dev).Scan(&id, &idx); err != nil {
		t.Fatal(err)
	}
	if id != gi2 || idx != 1 {
		t.Fatalf("Gi0/2 row id %d→%d index %d", gi2, id, idx)
	}
	var mapped *int64
	db.QueryRow(ctx, `SELECT switch_interface_id FROM network_jacks WHERE id=$1`, jack).Scan(&mapped)
	if mapped == nil || *mapped != gi2 {
		t.Fatalf("jack mapping lost: %v", mapped)
	}
	var n int
	db.QueryRow(ctx, `SELECT count(*) FROM interfaces WHERE device_id=$1`, dev).Scan(&n)
	if n != 4 {
		t.Fatalf("interfaces %d", n)
	}
}
