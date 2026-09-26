package classify

import (
	"testing"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/fingerprint"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
)

func TestWindowsXPHighConfidence(t *testing.T) {
	f := Facts{OUIVendor: "Dell", Hostnames: []string{"lab-pc-07"}, Obs: fingerprint.Observation{
		NetBIOSName: "LAB-PC-07", OpenPorts: []int{135, 139, 445}, TTL: 128, SMBDialect: "NT LM 0.12",
		SMBNativeOS: "Windows 5.1", DHCPVendor: "MSFT 5.0", DHCPParams: "1,15,3,6,44,46,47,31,33,249,43"}}
	os := OS(f)
	if os.Value != "Windows XP" || os.Confidence < 0.9 {
		t.Fatalf("got %+v", os)
	}
	sources := map[string]bool{}
	for _, e := range os.Evidence {
		sources[e.Source] = true
	}
	for _, s := range []string{"SMB", "NetBIOS", "TCP/IP fingerprint", "DHCP fingerprint"} {
		if !sources[s] {
			t.Errorf("missing evidence source %s: %+v", s, os.Evidence)
		}
	}
	dt := DeviceType(f)
	if dt.Value != model.TypeComputer || dt.Confidence < 0.7 {
		t.Fatalf("type %+v", dt)
	}
}

func TestWeakWindowsEvidenceReportsFamily(t *testing.T) {
	f := Facts{Obs: fingerprint.Observation{OpenPorts: []int{135, 445}, TTL: 128}}
	os := OS(f)
	if os.Value != "Windows NT family" {
		t.Fatalf("expected family, got %+v", os)
	}
	if os.Confidence < 0.5 || os.Confidence > 0.8 {
		t.Fatalf("confidence should be moderate: %v", os.Confidence)
	}
}

func TestNoEvidenceNoOS(t *testing.T) {
	if r := OS(Facts{}); r.Value != "" || r.Confidence != 0 {
		t.Fatalf("got %+v", r)
	}
	if r := DeviceType(Facts{}); r.Value != model.TypeUnknown {
		t.Fatalf("got %+v", r)
	}
}

func TestHPPrinterVsHPComputer(t *testing.T) {
	printer := DeviceType(Facts{OUIVendor: "HP", Hostnames: []string{"f1-prn-hp-01"}, Obs: fingerprint.Observation{
		OpenPorts: []int{80, 443, 515, 631, 9100}, HTTPTitle: "HP LaserJet Pro M404dn", SNMPIsPrinter: true}})
	if printer.Value != model.TypePrinter || printer.Confidence < 0.9 {
		t.Fatalf("printer: %+v", printer)
	}
	pc := DeviceType(Facts{OUIVendor: "HP", Hostnames: []string{"f2-pc-214-07"}, Obs: fingerprint.Observation{
		NetBIOSName: "F2-PC-214-07", OpenPorts: []int{135, 139, 445, 3389}, DHCPVendor: "MSFT 5.0"}})
	if pc.Value != model.TypeComputer || pc.Confidence < 0.8 {
		t.Fatalf("pc: %+v", pc)
	}
}

func TestNetworkDevices(t *testing.T) {
	sw := DeviceType(Facts{Managed: true, IsBridge: true, IsRouter: true, SysDescr: "Huawei Versatile Routing Platform Software\nHUAWEI S6730-H24X6C", Model: "S6730-H24X6C"})
	if sw.Value != model.TypeSwitch || sw.Confidence < 0.8 {
		t.Fatalf("switch %+v", sw)
	}
	fw := DeviceType(Facts{NeighborDesc: "FortiGate-100F v7.2.5,build1517", NeighborCaps: []string{"router"}})
	if fw.Value != model.TypeFirewall {
		t.Fatalf("firewall %+v", fw)
	}
	ap := DeviceType(Facts{OUIVendor: "Huawei", NeighborCaps: []string{"bridge", "wlan-ap"}, NeighborDesc: "Huawei AirEngine5760-10"})
	if ap.Value != model.TypeAccessPoint || ap.Confidence < 0.9 {
		t.Fatalf("ap %+v", ap)
	}
	phone := DeviceType(Facts{OUIVendor: "Yealink", NeighborCaps: []string{"bridge", "phone"}})
	if phone.Value != model.TypePhone {
		t.Fatalf("phone %+v", phone)
	}
	cam := DeviceType(Facts{OUIVendor: "Hikvision", Obs: fingerprint.Observation{OpenPorts: []int{80, 554}, HTTPServer: "App-webs/"}})
	if cam.Value != model.TypeCamera || cam.Confidence < 0.85 {
		t.Fatalf("camera %+v", cam)
	}
	rt := DeviceType(Facts{Managed: true, IsRouter: true, SysDescr: "Cisco IOS Software, ISR4300 Software (X86_64_LINUX_IOSD-UNIVERSALK9-M)"})
	if rt.Value != model.TypeRouter {
		t.Fatalf("router %+v", rt)
	}
}

func TestOSFromSysDescr(t *testing.T) {
	cases := map[string]string{
		"Hardware: Intel64 Family 6 Model 85 - Software: Windows Version 6.1 (Build 7601 Multiprocessor Free)": "Windows 7",
		"Hardware: x86 Family 6 Model 8 - Software: Windows Version 5.1 (Build 2600 Uniprocessor Free)":        "Windows XP",
		"Linux lab-srv-01 5.15.0-91-generic #101-Ubuntu SMP x86_64":                                            "Linux (Ubuntu)",
	}
	for d, want := range cases {
		r := OS(Facts{SysDescr: d})
		if r.Value != want || r.Confidence < 0.85 {
			t.Errorf("%q → %+v want %s", d, r, want)
		}
	}
	net := OS(Facts{NetworkOS: "VRP 8.191 V200R021C00SPC100"})
	if net.Value != "VRP 8.191 V200R021C00SPC100" || net.Confidence < 0.9 {
		t.Errorf("network os %+v", net)
	}
}

func TestWindows7ViaSMB(t *testing.T) {
	r := OS(Facts{Obs: fingerprint.Observation{SMBNativeOS: "Windows 7 Professional 7601 Service Pack 1", SMBDialect: "SMB 2.1",
		OpenPorts: []int{135, 139, 445, 3389}, NetBIOSName: "LAB-PC-05", TTL: 128}})
	if r.Value != "Windows 7" || r.Confidence < 0.85 {
		t.Fatalf("%+v", r)
	}
}

func TestVendor(t *testing.T) {
	v := Vendor(Facts{SNMPVendor: "Huawei", OUIVendor: "Huawei", OUIOrg: "HUAWEI TECHNOLOGIES"})
	if v.Value != "Huawei" || v.Confidence < 0.95 {
		t.Fatalf("%+v", v)
	}
	v = Vendor(Facts{OUIVendor: "Canon", OUIOrg: "CANON INC.", Obs: fingerprint.Observation{HTTPTitle: "Remote UI: Canon iR-ADV C5535"}})
	if v.Value != "Canon" || v.Confidence < 0.85 {
		t.Fatalf("%+v", v)
	}
}

func TestSambaIsNotWindows(t *testing.T) {
	r := OS(Facts{Obs: fingerprint.Observation{SMBNativeOS: "Windows 6.1", SMBLanMan: "Samba 4.19.5-Ubuntu", SMBDialect: "NT LM 0.12",
		OpenPorts: []int{22, 139, 445}, NetBIOSName: "LEGACYSRV"}})
	if r.Value == "Windows 7" || r.Value == "" {
		t.Fatalf("samba misclassified: %+v", r)
	}
	w := OS(Facts{Obs: fingerprint.Observation{SMBNativeOS: "Windows 10.0 Build 22631", SMBDialect: "SMB 3.0.2", OpenPorts: []int{135, 445}}})
	if w.Value != "Windows 11" {
		t.Fatalf("build-based version: %+v", w)
	}
}
