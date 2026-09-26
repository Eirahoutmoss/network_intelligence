package topology

import "testing"

func TestDedupBothSides(t *testing.T) {
	in := []Edge{
		{A: 1, B: 2, APort: "XGigabitEthernet0/0/1", BPort: "Te1/1/1", Layer: "physical", Sources: []string{"lldp"}, Confidence: 0.9, Label: "reported_by:1"},
		{A: 2, B: 1, APort: "TenGigabitEthernet1/1/1", BPort: "XGigabitEthernet0/0/1", Layer: "physical", Sources: []string{"lldp"}, Confidence: 0.9, Label: "reported_by:2"},
		{A: 2, B: 1, APort: "TenGigabitEthernet1/1/1", BPort: "", Layer: "physical", Sources: []string{"cdp"}, Confidence: 0.85, Label: "reported_by:2"},
	}
	out := Dedup(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 edge, got %d: %+v", len(out), out)
	}
	e := out[0]
	if e.Confidence != 0.99 || len(e.Sources) != 2 {
		t.Fatalf("merged edge %+v", e)
	}
}

func TestDedupParallelLinks(t *testing.T) {
	in := []Edge{
		{A: 1, B: 2, APort: "GE0/0/1", BPort: "Gi1/0/1", Layer: "physical", Sources: []string{"lldp"}},
		{A: 1, B: 2, APort: "GE0/0/2", BPort: "Gi1/0/2", Layer: "physical", Sources: []string{"lldp"}},
	}
	if out := Dedup(in); len(out) != 2 {
		t.Fatalf("parallel links must stay separate: %+v", out)
	}
}

func campus() ([]Node, []Edge) {
	nodes := []Node{
		{ID: 1, Label: "CORE", Infra: true}, {ID: 2, Label: "DIST-01", Infra: true}, {ID: 3, Label: "DIST-02", Infra: true},
		{ID: 4, Label: "ACCESS-01", Infra: true}, {ID: 5, Label: "ACCESS-02", Infra: true}, {ID: 6, Label: "ACCESS-03", Infra: true},
		{ID: 10, Label: "pc1"}, {ID: 11, Label: "pc2"}, {ID: 12, Label: "printer"},
	}
	edges := []Edge{{A: 1, B: 2}, {A: 1, B: 3}, {A: 2, B: 4}, {A: 2, B: 5}, {A: 3, B: 6}, {A: 4, B: 10}, {A: 4, B: 11}, {A: 6, B: 12}}
	return nodes, edges
}

func TestLevelsAndDownstream(t *testing.T) {
	nodes, edges := campus()
	lv := Levels(nodes, edges)
	want := map[int64]int{1: 0, 2: 1, 3: 1, 4: 2, 5: 2, 6: 2, 10: 3, 11: 3, 12: 3}
	for id, l := range want {
		if lv[id] != l {
			t.Errorf("level[%d]=%d want %d", id, lv[id], l)
		}
	}
	ds := Downstream(edges, lv, 2)
	if len(ds) != 4 { // ACCESS-01, ACCESS-02, pc1, pc2
		t.Fatalf("downstream of DIST-01: %v", ds)
	}
	nb := Neighbors(edges, 1)
	if len(nb) != 2 {
		t.Fatalf("neighbors %v", nb)
	}
	pos := Layout(nodes, edges, lv)
	if pos[1][1] != 0 || pos[10][1] <= pos[4][1] {
		t.Fatalf("layout rows: %v", pos)
	}
}
