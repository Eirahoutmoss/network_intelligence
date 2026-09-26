package deploy

import "testing"

func TestVirtualServiceSID(t *testing.T) {
	// Well-known: sc showsid TrustedInstaller
	if got := VirtualServiceSID("TrustedInstaller"); got != "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" {
		t.Fatalf("TrustedInstaller SID %s", got)
	}
	if VirtualServiceSID("nexus") != VirtualServiceSID("Nexus") {
		t.Fatal("service names are case-insensitive")
	}
}
