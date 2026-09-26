package explorer

import (
	"reflect"
	"testing"
)

var vocab = Vocabulary{
	Vendors:   []string{"HP", "Canon", "Huawei", "Cisco", "Dell", "Brother"},
	OSNames:   []string{"Windows XP", "Windows 7", "Windows 10/11"},
	Devices:   []string{"SW-CORE-01", "SW-DIST-01", "SW-LAB-01", "LAB-PC-01"},
	Locations: []string{"Building A", "Floor 2", "Room 214", "Laboratory"},
}

func TestParseExamples(t *testing.T) {
	two := 2
	cases := []struct {
		q    string
		want Query
	}{
		{"Kaç tane Canon yazıcı var?", Query{Intent: "count", Subject: "devices", Types: []string{"printer"}, Vendors: []string{"Canon"}, Lang: "tr"}},
		{"Laboratuvarda Windows XP kullanan cihazları göster.", Query{Intent: "list", Subject: "devices", OS: "windows xp", Location: "lab", Lang: "tr"}},
		{"Kat 2'de kaç switch var?", Query{Intent: "count", Subject: "devices", Types: []string{"switch"}, Floor: &two, Lang: "tr"}},
		{"SW-CORE-01'e bağlı cihazları göster.", Query{Intent: "list", Subject: "devices", ConnectedTo: "SW-CORE-01", Lang: "tr"}},
		{"10.20.30.0/24 ağında ne var?", Query{Intent: "list", Subject: "devices", Subnet: "10.20.30.0/24", Lang: "tr"}},
		{"Fiber bağlantıları göster.", Query{Intent: "list", Subject: "connections", Medium: "fiber", Lang: "tr"}},
		{"Room 214 jack 07'ye ne bağlı?", Query{Intent: "list", Subject: "jack", Room: "214", Jack: "07", Lang: "tr"}},
		{"HP cihazları göster.", Query{Intent: "list", Subject: "devices", Vendors: []string{"HP"}, Lang: "tr"}},
		{"Son 30 günde switch portu değişen cihazları göster.", Query{Intent: "list", Subject: "devices", PortChangedDays: 30, Lang: "tr"}},
		{"Kaç switch var?", Query{Intent: "count", Subject: "devices", Types: []string{"switch"}, Lang: "tr"}},
		{"HP yazıcıları göster.", Query{Intent: "list", Subject: "devices", Types: []string{"printer"}, Vendors: []string{"HP"}, Lang: "tr"}},
		{"Show HP printers", Query{Intent: "list", Subject: "devices", Types: []string{"printer"}, Vendors: []string{"HP"}, Lang: "en"}},
		{"How many switches are on floor 2?", Query{Intent: "count", Subject: "devices", Types: []string{"switch"}, Floor: &two, Lang: "en"}},
		{"214-07 prizinde ne var?", Query{Intent: "list", Subject: "jack", Room: "214", Jack: "07", Lang: "tr"}},
		{"Bu priz son 30 günde kaç farklı cihaz gördü? room 214 jack 07", Query{Intent: "count", Subject: "jack", Room: "214", Jack: "07", SeenDays: 30, Lang: "tr"}},
		{"Room 214'te ne var?", Query{Intent: "list", Subject: "devices", Room: "214", Lang: "tr"}},
		{"ikinci kattaki yazıcılar", Query{Intent: "list", Subject: "devices", Types: []string{"printer"}, Floor: &two, Lang: "tr"}},
		{"SW-DIST-01 arkasındaki tüm bilgisayarlar", Query{Intent: "list", Subject: "devices", Types: []string{"computer"}, ConnectedTo: "SW-DIST-01", Downstream: true, Lang: "tr"}},
		{"erişilemeyen cihazlar", Query{Intent: "list", Subject: "devices", Status: "down", Lang: "tr"}},
		{"vlan 30 cihazları", Query{Intent: "list", Subject: "devices", VLAN: 30, Lang: "tr"}},
	}
	for _, c := range cases {
		got := Parse(c.q, vocab)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q\n got  %+v\n want %+v", c.q, got, c.want)
		}
	}
}

func TestDescribe(t *testing.T) {
	q := Parse("Laboratuvarda Windows XP kullanan cihazları göster.", vocab)
	d := q.Describe()
	if len(d) != 2 || d[0] != "İşletim sistemi ≈ windows xp" {
		t.Fatalf("%v", d)
	}
	if !Parse("merhaba", vocab).Empty() {
		t.Fatal("expected empty")
	}
}
