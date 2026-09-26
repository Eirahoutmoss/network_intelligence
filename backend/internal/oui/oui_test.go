package oui

import "testing"

func TestLookup(t *testing.T) {
	cases := map[string]string{
		"00:e0:fc:12:34:56": "Huawei",
		"3c:d9:2b:00:00:01": "HP",
		"00:00:85:aa:bb:cc": "Canon",
		"00:1b:a9:00:00:00": "Brother",
		"00:00:0c:00:00:00": "Cisco",
	}
	for mac, want := range cases {
		e, ok := Lookup(mac)
		if !ok || e.Vendor != want {
			t.Errorf("%s → %+v want %s", mac, e, want)
		}
	}
	if Size() < 30000 {
		t.Fatalf("registry too small: %d", Size())
	}
}

func TestLocallyAdministered(t *testing.T) {
	if !IsLocallyAdministered("da:a1:19:00:00:01") || IsLocallyAdministered("00:e0:fc:00:00:01") {
		t.Fatal("LAA detection wrong")
	}
}
