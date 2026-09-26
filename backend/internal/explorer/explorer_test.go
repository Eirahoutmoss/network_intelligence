package explorer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/explorer"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/labtest"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/locations"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/testutil"
)

func names(a *explorer.Answer) []string {
	var out []string
	for _, d := range a.Devices {
		out = append(out, d.Name)
	}
	return out
}

// TestMVPScenario runs the questions from the product brief (section 31)
// against a discovered lab network.
func TestMVPScenario(t *testing.T) {
	db := testutil.DB(t)
	labtest.Discover(t, db, true)
	ctx := context.Background()
	loc := &locations.Service{DB: db}
	res, err := loc.ImportFromSysLocation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Assigned != 6 {
		t.Fatalf("import: %+v", res)
	}
	ex := &explorer.Explorer{Store: inventory.New(db, testutil.Logger())}
	ask := func(q string) *explorer.Answer {
		t.Helper()
		a, err := ex.Ask(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return a
	}

	a := ask("Kaç switch var?")
	if a.Count != 6 || !strings.Contains(a.Text, "6 switch") {
		t.Errorf("switch count: %d %q", a.Count, a.Text)
	}
	a = ask("HP yazıcıları göster.")
	if a.Count != 2 {
		t.Errorf("HP printers: %d %v", a.Count, names(a))
	}
	a = ask("Laboratuvarda Windows XP kullanan cihazları göster.")
	if a.Count != 4 {
		t.Errorf("lab XP: %d %v notes=%v", a.Count, names(a), a.Notes)
	}
	for _, d := range a.Devices {
		if !strings.HasPrefix(strings.ToUpper(d.Name), "LAB-PC-") {
			t.Errorf("unexpected XP device %s", d.Name)
		}
	}
	a = ask("SW-CORE-01'in bağlı olduğu cihazları göster.")
	got := strings.Join(names(a), ",")
	if a.Count != 3 || !strings.Contains(got, "SW-DIST-01") || !strings.Contains(got, "FW-01") {
		t.Errorf("core neighbors: %v", got)
	}
	a = ask("Kaç tane Canon yazıcı var?")
	if a.Count != 2 {
		t.Errorf("canon printers %d %v", a.Count, names(a))
	}
	a = ask("10.20.30.0/24 ağında ne var?")
	if a.Count != 12 { // 11 lab hosts + the core gateway (10.20.30.1)
		t.Errorf("subnet: %d %v", a.Count, names(a))
	}
	a = ask("Fiber bağlantıları göster.")
	if a.Count != 4 || len(a.Connections) != 4 {
		t.Errorf("fiber links: %d %+v", a.Count, a.Connections)
	}
	a = ask("Kat 2'de kaç switch var?")
	if a.Count != 1 {
		t.Errorf("floor 2 switches: %d %v notes=%v", a.Count, names(a), a.Notes)
	}
	a = ask("SW-DIST-01 arkasındaki bilgisayarlar")
	if a.Count != 14 {
		t.Errorf("downstream PCs: %d", a.Count)
	}
	a = ask("How many IP phones?")
	if a.Count != 4 || a.Query.Lang != "en" {
		t.Errorf("phones %d", a.Count)
	}
	a = ask("merhaba dünya")
	if a.Recognized || len(a.Suggestions) == 0 {
		t.Errorf("unrecognized handling: %+v", a)
	}
	// Room/jack mapping: Room 214 jack 07 → SW-ACC-F2-01 Gi0/0/37 (F2-PC-214-07)
	var floor2 int64
	if err := db.QueryRow(ctx, `SELECT id FROM locations WHERE kind='floor' AND level=2`).Scan(&floor2); err != nil {
		t.Fatal(err)
	}
	room, err := loc.Create(ctx, locations.Location{ParentID: &floor2, Kind: "room", Name: "Room 214"})
	if err != nil {
		t.Fatal(err)
	}
	var ifID int64
	if err := db.QueryRow(ctx, `SELECT i.id FROM interfaces i JOIN devices d ON d.id=i.device_id WHERE d.sys_name='SW-ACC-F2-01' AND i.name='GigabitEthernet0/0/37'`).Scan(&ifID); err != nil {
		t.Fatal(err)
	}
	if _, err := loc.CreateJack(ctx, locations.Jack{LocationID: room, Label: "214-07", SwitchInterfaceID: &ifID}); err != nil {
		t.Fatal(err)
	}
	a = ask("Room 214 jack 07'ye ne bağlı?")
	if a.Count != 1 || a.Devices[0].Name != "f2-pc-214-07" && !strings.EqualFold(a.Devices[0].Name, "F2-PC-214-07") {
		t.Errorf("jack: %q %v", a.Text, names(a))
	}
	a = ask("Room 214'te ne var?")
	if a.Count != 1 {
		t.Errorf("room 214 contents: %d %v", a.Count, names(a))
	}
}
