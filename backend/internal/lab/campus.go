package lab

import (
	"fmt"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/fingerprint"
)

var campusVLANs = map[int]string{10: "STAFF", 20: "PRINTERS", 30: "LAB", 40: "VOICE", 99: "MGMT"}

func huaweiPorts(prefix string, count int, speed uint64, startIf, startBP int, pvid int) []*Port {
	var out []*Port
	short := "GE"
	if prefix == "XGigabitEthernet" {
		short = "XGE"
	}
	for i := 1; i <= count; i++ {
		name := fmt.Sprintf("%s0/0/%d", prefix, i)
		out = append(out, &Port{IfIndex: startIf + i - 1, BridgePort: startBP + i - 1, LLDPNum: startIf + i - 1,
			Name: name, Short: name, Speed: speed, PVID: pvid,
			InOctets: uint64(i) * 91_234_567, OutOctets: uint64(i) * 47_123_456})
		_ = short
	}
	return out
}

func ciscoPorts(kind, short string, slot string, count int, speed uint64, startIf, startBP, startLLDP int, pvid int) []*Port {
	var out []*Port
	for i := 1; i <= count; i++ {
		out = append(out, &Port{IfIndex: startIf + i - 1, BridgePort: startBP + i - 1, LLDPNum: startLLDP + i - 1,
			Name: fmt.Sprintf("%s%s/%d", kind, slot, i), Short: fmt.Sprintf("%s%s/%d", short, slot, i),
			Speed: speed, PVID: pvid, InOctets: uint64(i) * 81_234_567, OutOctets: uint64(i) * 37_123_456})
	}
	return out
}

func hpePorts(count int, speed uint64, pvid int) []*Port {
	var out []*Port
	for i := 1; i <= count; i++ {
		n := fmt.Sprint(i)
		out = append(out, &Port{IfIndex: i, BridgePort: i, LLDPNum: i, Name: n, Short: n, Speed: speed, PVID: pvid,
			InOctets: uint64(i) * 61_234_567, OutOctets: uint64(i) * 27_123_456})
	}
	return out
}

func sfp(descr, vendor, part, serial string, rx, tx int64) *Optic {
	return &Optic{Descr: descr, Vendor: vendor, Part: part, Serial: serial, RxUW: rx, TxUW: tx}
}

var trunkAll = []int{10, 20, 30, 40, 99}

// uplink marks a port as a trunk with an optional transceiver.
func uplink(p *Port, alias string, o *Optic) {
	p.Trunk = trunkAll
	p.PVID = 1
	p.Up = true
	p.Alias = alias
	p.Optic = o
}

// Campus returns the default demo network:
//
//	SW-CORE-01 (Huawei S6730, L3 core)
//	 ├── SW-DIST-01 (Cisco C9300) ── SW-ACC-F1-01 (Huawei S5735, Floor 1)
//	 │                           └─ SW-ACC-F2-01 (Huawei S5735, Floor 2)
//	 ├── SW-DIST-02 (Huawei S5731) ── SW-LAB-01 (HPE 2530, Laboratory)
//	 └── FW-01 (FortiGate, not SNMP-managed; learned via LLDP)
func Campus() *Lab {
	l := &Lab{Community: "public", V3User: "prometheus", V3Pass: "nexus-demo-pass"}

	core := &Device{Name: "SW-CORE-01", MgmtIP: "10.20.99.1", ChassisMAC: "00:e0:fc:10:00:01", Family: "huawei",
		Descr:    "Huawei Versatile Routing Platform Software\r\nVRP (R) software, Version 8.191 (S6730 V200R021C00SPC100)\r\nCopyright (C) 2000-2021 HUAWEI TECH Co., Ltd.\r\nHUAWEI S6730-H24X6C",
		ObjectID: "1.3.6.1.4.1.2011.2.23.662", Model: "S6730-H24X6C", Serial: "2102353DLN10M3000123",
		Location: "Building A / Basement / Server Room", Router: true, Managed: true, CPU: 14, Mem: 41, Temp: 38,
		VLANs: map[int]string{10: "STAFF", 20: "PRINTERS", 30: "LAB", 40: "VOICE", 99: "MGMT", 100: "TRANSIT"}}
	core.Ports = huaweiPorts("XGigabitEthernet", 24, 10_000_000_000, 6, 1, 1)
	uplink(core.port("XGigabitEthernet0/0/1"), "to SW-DIST-01", sfp("10GBASE-SR SFP+ 850nm 300m", "HUAWEI", "OMXD30000", "HA20210300101", 512, 631))
	uplink(core.port("XGigabitEthernet0/0/2"), "to SW-DIST-02", sfp("10GBASE-LR SFP+ 1310nm 10km", "HUAWEI", "OSX010000", "HA20210300102", 389, 708))
	fwPort := core.port("XGigabitEthernet0/0/24")
	fwPort.Up, fwPort.PVID, fwPort.Alias = true, 100, "to FW-01"
	fwPort.Optic = sfp("1000BASE-T SFP copper", "HUAWEI", "SFP-1000BaseT", "HA20210300124", 0, 0)
	core.SVIs = []SVI{{100, 10, "10.20.10.1", 24}, {101, 20, "10.20.20.1", 24}, {102, 30, "10.20.30.1", 24},
		{103, 40, "10.20.40.1", 24}, {104, 99, "10.20.99.1", 24}, {105, 100, "10.20.255.1", 24}}
	core.Routes = []Route{
		{"0.0.0.0", "0.0.0.0", "10.20.255.254", 105, 3, 1},
		{"10.50.0.0", "255.255.0.0", "10.20.255.253", 105, 13, 20},
		{"10.20.10.0", "255.255.255.0", "0.0.0.0", 100, 2, 0},
		{"10.20.20.0", "255.255.255.0", "0.0.0.0", 101, 2, 0},
		{"10.20.30.0", "255.255.255.0", "0.0.0.0", 102, 2, 0},
		{"10.20.40.0", "255.255.255.0", "0.0.0.0", 103, 2, 0},
		{"10.20.99.0", "255.255.255.0", "0.0.0.0", 104, 2, 0},
		{"10.20.255.0", "255.255.255.0", "0.0.0.0", 105, 2, 0},
	}

	dist1 := &Device{Name: "SW-DIST-01", MgmtIP: "10.20.99.2", ChassisMAC: "00:1b:54:20:00:01", Family: "cisco", Parent: "SW-CORE-01",
		Descr:    "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)\r\nTechnical Support: http://www.cisco.com/techsupport\r\nCopyright (c) 1986-2023 by Cisco Systems, Inc.",
		ObjectID: "1.3.6.1.4.1.9.1.2494", Model: "C9300-48P", Serial: "FOC2331X0AB", Location: "Building A / Floor 1 / IDF-1",
		Managed: true, CPU: 7, Mem: 52, Temp: 34, VLANs: campusVLANs}
	dist1.Ports = append(ciscoPorts("GigabitEthernet", "Gi", "1/0", 48, 1_000_000_000, 9, 1, 1, 10),
		ciscoPorts("TenGigabitEthernet", "Te", "1/1", 4, 10_000_000_000, 61, 49, 49, 1)...)
	uplink(dist1.port("TenGigabitEthernet1/1/1"), "UPLINK-CORE", sfp("SFP-10GBase-SR", "CISCO-FINISAR", "SFP-10G-SR", "FNS22310AAA", 470, 580))
	uplink(dist1.port("TenGigabitEthernet1/1/2"), "DOWNLINK-ACC-F1", sfp("SFP-10GBase-SR", "CISCO-FINISAR", "SFP-10G-SR", "FNS22310AAB", 455, 590))
	uplink(dist1.port("TenGigabitEthernet1/1/3"), "DOWNLINK-ACC-F2", sfp("SFP-10GBase-SR", "CISCO-FINISAR", "SFP-10G-SR", "FNS22310AAC", 20, 600))
	dist1.SVIs = []SVI{{200, 99, "10.20.99.2", 24}}

	dist2 := &Device{Name: "SW-DIST-02", MgmtIP: "10.20.99.3", ChassisMAC: "00:e0:fc:30:00:01", Family: "huawei", Parent: "SW-CORE-01",
		Descr:    "S5731-H24T4XC\r\nHuawei Versatile Routing Platform Software\r\nVRP (R) software, Version 5.170 (S5731 V200R021C10SPC600)\r\nCopyright (C) 2000-2022 HUAWEI TECH Co., Ltd.",
		ObjectID: "1.3.6.1.4.1.2011.2.23.619", Model: "S5731-H24T4XC", Serial: "2102352VLS10L6000456",
		Location: "Building B / Floor 1 / IDF-B1", Managed: true, CPU: 9, Mem: 37, Temp: 41, VLANs: campusVLANs}
	dist2.Ports = append(huaweiPorts("GigabitEthernet", 24, 1_000_000_000, 6, 1, 30), huaweiPorts("XGigabitEthernet", 4, 10_000_000_000, 30, 25, 1)...)
	uplink(dist2.port("XGigabitEthernet0/0/1"), "to SW-CORE-01", sfp("10GBASE-LR SFP+ 1310nm 10km", "HUAWEI", "OSX010000", "HA20220100001", 402, 690))
	uplink(dist2.port("GigabitEthernet0/0/24"), "to SW-LAB-01", nil)
	dist2.SVIs = []SVI{{80, 99, "10.20.99.3", 24}}

	accF1 := &Device{Name: "SW-ACC-F1-01", MgmtIP: "10.20.99.11", ChassisMAC: "00:e0:fc:41:00:01", Family: "huawei", Parent: "SW-DIST-01",
		Descr:    "S5735-L48T4X-A1\r\nHuawei Versatile Routing Platform Software\r\nVRP (R) software, Version 5.170 (S5735 V200R019C00SPC500)\r\nCopyright (C) 2000-2020 HUAWEI TECH Co., Ltd.",
		ObjectID: "1.3.6.1.4.1.2011.2.23.614", Model: "S5735-L48T4X-A1", Serial: "2102353AQK10L9001001",
		Location: "Building A / Floor 1 / IDF-1", Managed: true, CPU: 5, Mem: 33, Temp: 36, VLANs: campusVLANs}
	accF1.Ports = append(huaweiPorts("GigabitEthernet", 48, 1_000_000_000, 6, 1, 10), huaweiPorts("XGigabitEthernet", 4, 10_000_000_000, 54, 49, 1)...)
	uplink(accF1.port("XGigabitEthernet0/0/1"), "to SW-DIST-01", sfp("10GBASE-SR SFP+ 850nm 300m", "HUAWEI", "OMXD30000", "HA20200900111", 498, 612))
	accF1.SVIs = []SVI{{90, 99, "10.20.99.11", 24}}

	accF2 := &Device{Name: "SW-ACC-F2-01", MgmtIP: "10.20.99.12", ChassisMAC: "00:e0:fc:42:00:01", Family: "huawei", Parent: "SW-DIST-01",
		Descr:    "S5735-L48T4X-A1\r\nHuawei Versatile Routing Platform Software\r\nVRP (R) software, Version 5.170 (S5735 V200R019C00SPC500)\r\nCopyright (C) 2000-2020 HUAWEI TECH Co., Ltd.",
		ObjectID: "1.3.6.1.4.1.2011.2.23.614", Model: "S5735-L48T4X-A1", Serial: "2102353AQK10L9001002",
		Location: "Building A / Floor 2 / IDF-2", Managed: true, CPU: 6, Mem: 35, Temp: 37, VLANs: campusVLANs}
	accF2.Ports = append(huaweiPorts("GigabitEthernet", 48, 1_000_000_000, 6, 1, 10), huaweiPorts("XGigabitEthernet", 4, 10_000_000_000, 54, 49, 1)...)
	uplink(accF2.port("XGigabitEthernet0/0/1"), "to SW-DIST-01", sfp("10GBASE-SR SFP+ 850nm 300m", "HUAWEI", "OMXD30000", "HA20200900112", 18, 605))
	accF2.SVIs = []SVI{{90, 99, "10.20.99.12", 24}}

	labSw := &Device{Name: "SW-LAB-01", MgmtIP: "10.20.99.21", ChassisMAC: "00:14:38:50:00:01", Family: "hpe", Parent: "SW-DIST-02",
		Descr:    "HP J9776A 2530-24G Switch, revision YA.16.11.0015, ROM YA.15.20 (/ws/swbuildm/rel_yakima_qaoff/code/build/lakes(swbuildm_rel_yakima_qaoff_rel_yakima))",
		ObjectID: "1.3.6.1.4.1.11.2.3.7.11.154", Model: "J9776A", Serial: "CN64GXX123", Location: "Building B / Floor 1 / Laboratory",
		Managed: true, CPU: 3, Temp: 32, VLANs: campusVLANs}
	labSw.Ports = hpePorts(28, 1_000_000_000, 30)
	uplink(labSw.port("25"), "to SW-DIST-02", nil)
	labSw.SVIs = []SVI{{130, 99, "10.20.99.21", 24}}

	fw := &Device{Name: "FW-01", MgmtIP: "10.20.255.254", ChassisMAC: "00:09:0f:60:00:01", Family: "fortinet", Parent: "SW-CORE-01",
		Descr: "FortiGate-100F v7.2.5,build1517,230606 (GA.F)", Model: "FortiGate-100F", Router: true, ExtraCaps: []string{"router"},
		Ports: []*Port{{IfIndex: 1, Name: "port1", Short: "port1", Speed: 1_000_000_000, Up: true}}}

	l.Devices = []*Device{core, dist1, dist2, accF1, accF2, labSw, fw}
	l.Links = []Link{
		{"SW-CORE-01", "XGigabitEthernet0/0/1", "SW-DIST-01", "TenGigabitEthernet1/1/1"},
		{"SW-CORE-01", "XGigabitEthernet0/0/2", "SW-DIST-02", "XGigabitEthernet0/0/1"},
		{"SW-CORE-01", "XGigabitEthernet0/0/24", "FW-01", "port1"},
		{"SW-DIST-01", "TenGigabitEthernet1/1/2", "SW-ACC-F1-01", "XGigabitEthernet0/0/1"},
		{"SW-DIST-01", "TenGigabitEthernet1/1/3", "SW-ACC-F2-01", "XGigabitEthernet0/0/1"},
		{"SW-DIST-02", "GigabitEthernet0/0/24", "SW-LAB-01", "25"},
	}

	win10 := func(name string) fingerprint.Observation {
		return fingerprint.Observation{Hostname: name + ".corp.example.local", HostnameSource: "dns", NetBIOSName: name,
			NetBIOSGroup: "CORP", OpenPorts: []int{135, 139, 445, 3389}, TTL: 128, SMBDialect: "SMB 3.1.1",
			DHCPVendor: "MSFT 5.0", DHCPParams: "1,3,6,15,31,33,43,44,46,47,119,121,249,252"}
	}
	winXP := func(name string) fingerprint.Observation {
		return fingerprint.Observation{Hostname: name + ".lab.example.local", HostnameSource: "dns", NetBIOSName: name,
			NetBIOSGroup: "LAB", OpenPorts: []int{135, 139, 445}, TTL: 128, SMBDialect: "NT LM 0.12",
			SMBNativeOS: "Windows 5.1", DHCPVendor: "MSFT 5.0", DHCPParams: "1,15,3,6,44,46,47,31,33,249,43"}
	}
	win7 := func(name string) fingerprint.Observation {
		return fingerprint.Observation{Hostname: name + ".lab.example.local", HostnameSource: "dns", NetBIOSName: name,
			NetBIOSGroup: "LAB", OpenPorts: []int{135, 139, 445, 3389}, TTL: 128, SMBDialect: "SMB 2.1",
			SMBNativeOS: "Windows 7 Professional 7601 Service Pack 1", DHCPVendor: "MSFT 5.0"}
	}
	add := func(e *Endpoint) { l.Endpoints = append(l.Endpoints, e) }

	// Floor 1 — staff PCs (Dell), printers, a camera
	for i := 1; i <= 6; i++ {
		n := fmt.Sprintf("ACC-PC-%02d", i)
		add(&Endpoint{Name: n, IP: fmt.Sprintf("10.20.10.%d", 20+i), MAC: fmt.Sprintf("f8:bc:12:a1:00:%02x", i),
			Switch: "SW-ACC-F1-01", Port: fmt.Sprintf("GigabitEthernet0/0/%d", i), VLAN: 10, Obs: win10(n)})
	}
	add(&Endpoint{Name: "F1-PRN-HP-01", IP: "10.20.20.11", MAC: "a0:d3:c1:20:00:11", Switch: "SW-ACC-F1-01", Port: "GigabitEthernet0/0/40", VLAN: 20,
		Obs: fingerprint.Observation{Hostname: "f1-prn-hp-01.corp.example.local", HostnameSource: "dns", OpenPorts: []int{80, 443, 515, 631, 9100}, TTL: 64,
			HTTPTitle: "HP LaserJet Pro M404dn", HTTPServer: "HP HTTP Server; HP LaserJet Pro M404dn",
			SNMPSysDescr: "HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153,EEPROM JSI23900013", SNMPIsPrinter: true}})
	add(&Endpoint{Name: "F1-PRN-CANON-01", IP: "10.20.20.12", MAC: "00:bb:c1:20:00:12", Switch: "SW-ACC-F1-01", Port: "GigabitEthernet0/0/41", VLAN: 20,
		Obs: fingerprint.Observation{Hostname: "f1-prn-canon-01.corp.example.local", HostnameSource: "dns", OpenPorts: []int{80, 443, 515, 631, 9100}, TTL: 64,
			HTTPTitle: "Remote UI: Canon iR-ADV C5535", SNMPSysDescr: "Canon iR-ADV C5535 /P", SNMPIsPrinter: true}})
	add(&Endpoint{Name: "F1-CAM-01", IP: "10.20.10.90", MAC: "04:03:12:20:00:90", Switch: "SW-ACC-F1-01", Port: "GigabitEthernet0/0/45", VLAN: 10,
		Obs: fingerprint.Observation{OpenPorts: []int{80, 554, 8000}, TTL: 64, HTTPServer: "App-webs/", HTTPTitle: "Hikvision"}})

	// Floor 2 — Room 214: HP computers, IP phones, AP, HP printer
	for i := 1; i <= 8; i++ {
		n := fmt.Sprintf("F2-PC-214-%02d", i)
		add(&Endpoint{Name: n, IP: fmt.Sprintf("10.20.10.%d", 120+i), MAC: fmt.Sprintf("10:b6:76:b2:00:%02x", i),
			Switch: "SW-ACC-F2-01", Port: fmt.Sprintf("GigabitEthernet0/0/%d", 30+i), VLAN: 10, Obs: win10(n)})
	}
	for i := 1; i <= 4; i++ {
		n := fmt.Sprintf("SEP-F2-%02d", i)
		add(&Endpoint{Name: n, IP: fmt.Sprintf("10.20.40.%d", 20+i), MAC: fmt.Sprintf("24:9a:d8:40:00:%02x", i),
			Switch: "SW-ACC-F2-01", Port: fmt.Sprintf("GigabitEthernet0/0/%d", 10+i), VLAN: 40,
			LLDPCaps: []string{"bridge", "phone"}, LLDPDescr: "Yealink SIP-T46U 108.86.0.20",
			Obs: fingerprint.Observation{OpenPorts: []int{80, 443, 5060}, TTL: 64, HTTPTitle: "Yealink T46U Phone"}})
	}
	add(&Endpoint{Name: "AP-F2-01", IP: "10.20.99.51", MAC: "28:6e:d4:99:00:51", Switch: "SW-ACC-F2-01", Port: "GigabitEthernet0/0/47", VLAN: 99,
		LLDPCaps: []string{"bridge", "wlan-ap"}, LLDPDescr: "Huawei AirEngine5760-10 V200R022C00",
		Obs: fingerprint.Observation{OpenPorts: []int{22, 443}, TTL: 64}})
	add(&Endpoint{Name: "F2-PRN-HP-01", IP: "10.20.20.21", MAC: "a0:d3:c1:20:00:21", Switch: "SW-ACC-F2-01", Port: "GigabitEthernet0/0/44", VLAN: 20,
		Obs: fingerprint.Observation{Hostname: "f2-prn-hp-01.corp.example.local", HostnameSource: "dns", OpenPorts: []int{80, 443, 631, 9100}, TTL: 64,
			HTTPTitle: "HP Color LaserJet MFP M479fdw", SNMPSysDescr: "HP ETHERNET MULTI-ENVIRONMENT", SNMPIsPrinter: true}})

	// Laboratory — legacy Windows XP machines, Windows 7, a Linux server, printers
	for i := 1; i <= 4; i++ {
		n := fmt.Sprintf("LAB-PC-%02d", i)
		add(&Endpoint{Name: n, IP: fmt.Sprintf("10.20.30.%d", 10+i), MAC: fmt.Sprintf("00:14:22:30:00:%02x", i),
			Switch: "SW-LAB-01", Port: fmt.Sprint(i), VLAN: 30, Obs: winXP(n)})
	}
	for i := 5; i <= 7; i++ {
		n := fmt.Sprintf("LAB-PC-%02d", i)
		add(&Endpoint{Name: n, IP: fmt.Sprintf("10.20.30.%d", 10+i), MAC: fmt.Sprintf("f8:bc:12:30:00:%02x", i),
			Switch: "SW-LAB-01", Port: fmt.Sprint(i), VLAN: 30, Obs: win7(n)})
	}
	add(&Endpoint{Name: "LAB-SRV-01", IP: "10.20.30.100", MAC: "0c:c4:7a:30:01:00", Switch: "SW-LAB-01", Port: "20", VLAN: 30,
		Obs: fingerprint.Observation{Hostname: "lab-srv-01.lab.example.local", HostnameSource: "dns", OpenPorts: []int{22, 80, 443}, TTL: 64,
			HTTPServer: "Apache/2.4.52 (Ubuntu)", SNMPSysDescr: "Linux lab-srv-01 5.15.0-91-generic #101-Ubuntu SMP x86_64"}})
	add(&Endpoint{Name: "LAB-PRN-BROTHER", IP: "10.20.30.50", MAC: "00:1b:a9:30:00:50", Switch: "SW-LAB-01", Port: "22", VLAN: 30,
		Obs: fingerprint.Observation{Hostname: "brn001ba9300050.lab.example.local", HostnameSource: "dns", OpenPorts: []int{80, 515, 631, 9100}, TTL: 64,
			HTTPTitle: "Brother HL-L6200DW series", SNMPSysDescr: "Brother NC-8700w, Firmware Ver.1.10  (19.05.02),MID 8CE-K07,FID 2", SNMPIsPrinter: true}})
	add(&Endpoint{Name: "LAB-PRN-CANON", IP: "10.20.30.51", MAC: "00:1e:8f:30:00:51", Switch: "SW-LAB-01", Port: "23", VLAN: 30,
		Obs: fingerprint.Observation{OpenPorts: []int{80, 515, 9100}, TTL: 64, HTTPTitle: "Canon LBP6230dw", SNMPIsPrinter: true, SNMPSysDescr: "Canon LBP6230dw /P"}})
	add(&Endpoint{Name: "LAB-IOT-01", IP: "10.20.30.200", MAC: "da:a1:19:30:02:00", Switch: "SW-LAB-01", Port: "24", VLAN: 30,
		Obs: fingerprint.Observation{}})
	return l
}
