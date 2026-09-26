package classify

import (
	"regexp"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
)

var (
	printerVendors = map[string]float64{"Brother": 0.45, "Kyocera": 0.55, "Lexmark": 0.6, "Xerox": 0.55, "Ricoh": 0.55,
		"Konica Minolta": 0.55, "Epson": 0.4, "Zebra": 0.5, "Sharp": 0.3, "Oki": 0.45, "Canon": 0.3, "Toshiba": 0.15}
	phoneVendors  = map[string]float64{"Yealink": 0.7, "Poly": 0.6, "Snom": 0.7, "Grandstream": 0.55, "Avaya": 0.45, "Mitel": 0.5}
	cameraVendors = map[string]float64{"Hikvision": 0.7, "Dahua": 0.7, "Axis": 0.65, "Bosch": 0.2}
	pcVendors     = map[string]float64{"Dell": 0.3, "Lenovo": 0.35, "Apple": 0.25, "Intel": 0.3, "ASUS": 0.3, "Gigabyte": 0.3,
		"MSI": 0.3, "Realtek": 0.2, "HP": 0.15, "Fujitsu": 0.25, "Microsoft": 0.15}
	serverVendors = map[string]float64{"Supermicro": 0.5}
	vmVendors     = map[string]float64{"VMware": 0.75, "QEMU": 0.7, "Oracle": 0.35, "Proxmox": 0.7}
	iotVendors    = map[string]float64{"Espressif": 0.7, "Sonos": 0.6, "Raspberry Pi": 0.4, "Amazon": 0.35, "Google": 0.3}
	mobileVendors = map[string]float64{"Samsung": 0.25, "Xiaomi": 0.4, "Honor": 0.5}
	storageVends  = map[string]float64{"Synology": 0.7, "QNAP": 0.7}
	upsVendors    = map[string]float64{"APC": 0.6, "Eaton": 0.4, "Schneider Electric": 0.3}
	apVendors     = map[string]float64{"Ubiquiti": 0.3, "Ruckus": 0.55, "Aruba": 0.25, "Cambium": 0.4}

	rePrinterHost = regexp.MustCompile(`(?i)(^|[-_.])(prn|prt|printer|print|yazici|mfp|brn[0-9a-f]{6})`)
	rePhoneHost   = regexp.MustCompile(`(?i)^(sep[0-9a-f]{6,}|phone|ipphone|voip|tel)[-_]?`)
	reServerHost  = regexp.MustCompile(`(?i)(^|[-_.])(srv|server|sunucu|dc\d|esx|vm|nas|db\d*)([-_.\d]|$)`)
	rePCHost      = regexp.MustCompile(`(?i)(^|[-_.])(pc|desktop|laptop|nb|ws|wks|client|bilgisayar)([-_.\d]|$)`)
	reAPHost      = regexp.MustCompile(`(?i)(^|[-_.])(ap|wap|wifi)[-_\d]`)
	reCamHost     = regexp.MustCompile(`(?i)(^|[-_.])(cam|camera|kamera|ipcam|nvr|dvr)[-_\d]`)
)

type modelRule struct {
	re  *regexp.Regexp
	typ string
	w   float64
}

// Network device model/OS signatures (sysDescr, LLDP descr, model names).
var modelRules = []modelRule{
	{regexp.MustCompile(`(?i)\b(fortigate|fortios|palo alto|pan-os|asa\s?\d|adaptive security appliance|firepower|fpr-?\d|usg\d|eudemon|checkpoint|check point|sonicwall|sophos|pfsense|opnsense|srx\d)`), model.TypeFirewall, 0.9},
	{regexp.MustCompile(`(?i)\b(airengine|aironet|air-ap|access point|unifi ap|uap-|ap\d{3,4}|instant ap|iap-)`), model.TypeAccessPoint, 0.85},
	{regexp.MustCompile(`(?i)\b(wireless lan controller|ac6\d{3}|wlc|air-ct|c98\d{2}-l)`), model.TypeWLC, 0.8},
	{regexp.MustCompile(`(?i)\b(catalyst|ws-c\d|c9[23]\d{2}|c3[68]\d{2}|c2960|nexus|n[3579]k|s[1-9]\d{3}[a-z]?-|ce\d{4,5}|procurve|aruba ?\d{4}|\d{4}-\d{2}g|j\d{4}a|jl\d{3}a|ex\d{4}|qfx|dcs-\d|crs\d{3}|css\d{3}|switch)`), model.TypeSwitch, 0.75},
	{regexp.MustCompile(`(?i)\b(isr\d|asr\d|c8[23]\d{2}|ar\d{3,4}|ne\d{2}|mx\d{2,3}|ccr\d{4}|rb\d{3,4}|router|edgerouter|vyos|routeros)`), model.TypeRouter, 0.7},
	{regexp.MustCompile(`(?i)\b(smart-ups|ups|network management card|powerware|galaxy)`), model.TypeUPS, 0.85},
	{regexp.MustCompile(`(?i)\b(diskstation|synology|qnap|netapp|data ontap|storeonce|powervault|equallogic)`), model.TypeStorage, 0.8},
}

var rePrinterTitle = regexp.MustCompile(`(?i)(laserjet|officejet|deskjet|pagewide|remote ui|imagerunner|ir-adv|i-sensys|lbp\d|mf\d{3}|brother (hl|mfc|dcp)|hl-l\d|ecosys|taskalfa|lexmark|workcentre|versalink|altalink|aficio|bizhub|epson (wf|et|l)\d|printer|zebra|jetdirect)`)
var reCameraTitle = regexp.MustCompile(`(?i)(hikvision|dahua|axis|ip camera|network camera|nvr|dvr|app-webs|webcam|onvif)`)
var rePhoneTitle = regexp.MustCompile(`(?i)(yealink|polycom|cisco ip phone|sip-t\d|snom|grandstream|avaya|mitel|unify|gxp\d)`)

// DeviceType classifies what kind of device this is.
func DeviceType(f Facts) Result {
	s := newScorer("device_type")
	o := f.Obs

	// --- managed network devices
	if f.Managed {
		if f.IsPrinter {
			s.add(model.TypePrinter, "SNMP", "device reports a printer (HOST-RESOURCES / Printer-MIB)", 0.95)
		}
		if f.IsBridge {
			s.add(model.TypeSwitch, "SNMP", "bridge MIB present (forwards Ethernet frames)", 0.55)
		}
		if f.IsRouter && !f.IsBridge {
			s.add(model.TypeRouter, "SNMP", "IP forwarding enabled", 0.5)
		}
		if f.IsRouter && f.IsBridge {
			s.add(model.TypeSwitch, "SNMP", "layer-3 switch (bridging and routing)", 0.2)
		}
	}
	for _, txt := range []struct{ src, text string }{
		{"SNMP sysDescr", f.SysDescr}, {"Model", f.Model}, {"LLDP/CDP announcement", f.NeighborDesc},
		{"SNMP sysDescr (probe)", o.SNMPSysDescr},
	} {
		if txt.text == "" {
			continue
		}
		for _, r := range modelRules {
			if m := r.re.FindString(txt.text); m != "" {
				s.add(r.typ, txt.src, "matches "+strings.TrimSpace(m), r.w)
				break
			}
		}
		if m := rePrinterTitle.FindString(txt.text); m != "" {
			s.add(model.TypePrinter, txt.src, "printer model "+m, 0.85)
		}
		if m := rePhoneTitle.FindString(txt.text); m != "" {
			s.add(model.TypePhone, txt.src, "phone model "+m, 0.8)
		}
	}
	// Linux/Windows hosts answering SNMP are servers or computers, not network gear.
	if l := lower(o.SNMPSysDescr + " " + f.SysDescr); strings.Contains(l, "linux") {
		s.add(model.TypeServer, "SNMP sysDescr", "Linux host with SNMP agent", 0.4)
	} else if strings.Contains(l, "windows") && strings.Contains(l, "hardware:") {
		s.add(model.TypeComputer, "SNMP sysDescr", "Windows host with SNMP agent", 0.4)
	}

	// --- LLDP/CDP capabilities announced by the device itself
	caps := map[string]bool{}
	for _, c := range f.NeighborCaps {
		caps[c] = true
	}
	switch {
	case caps["phone"]:
		s.add(model.TypePhone, "LLDP", "announces telephone capability", 0.9)
	case caps["wlan-ap"]:
		s.add(model.TypeAccessPoint, "LLDP", "announces WLAN access point capability", 0.9)
	case caps["router"] && caps["bridge"]:
		s.add(model.TypeSwitch, "LLDP", "announces bridge+router capability", 0.5)
		s.add(model.TypeRouter, "LLDP", "announces bridge+router capability", 0.3)
	case caps["bridge"]:
		s.add(model.TypeSwitch, "LLDP", "announces bridge capability", 0.6)
	case caps["router"]:
		s.add(model.TypeRouter, "LLDP", "announces router capability", 0.6)
	case caps["station"]:
		s.add(model.TypeComputer, "LLDP", "announces station capability", 0.4)
	}

	// --- active fingerprints
	if o.SNMPIsPrinter {
		s.add(model.TypePrinter, "SNMP probe", "Printer-MIB answered", 0.9)
	}
	if o.HasPort(9100) {
		s.add(model.TypePrinter, "Open ports", "raw printing port 9100 (JetDirect)", 0.6)
	}
	if o.HasPort(515) || o.HasPort(631) {
		s.add(model.TypePrinter, "Open ports", "LPD/IPP printing service", 0.35)
	}
	title := o.HTTPTitle + " " + o.HTTPServer
	if m := rePrinterTitle.FindString(title); m != "" {
		s.add(model.TypePrinter, "HTTP", "web interface: "+strings.TrimSpace(o.HTTPTitle+" "+o.HTTPServer), 0.8)
	}
	if m := reCameraTitle.FindString(title); m != "" {
		s.add(model.TypeCamera, "HTTP", "web interface looks like a camera ("+m+")", 0.75)
	}
	if m := rePhoneTitle.FindString(title); m != "" {
		s.add(model.TypePhone, "HTTP", "web interface of an IP phone ("+m+")", 0.75)
	}
	if o.HasPort(554) {
		s.add(model.TypeCamera, "Open ports", "RTSP video streaming (554)", 0.5)
	}
	if o.HasPort(5060) || o.HasPort(5061) {
		s.add(model.TypePhone, "Open ports", "SIP (5060)", 0.4)
	}
	windowsPorts := o.HasPort(135) || o.HasPort(139) || o.HasPort(445)
	if windowsPorts {
		s.add(model.TypeComputer, "Open ports", "Windows file sharing / RPC (135/139/445)", 0.5)
	}
	if o.HasPort(3389) {
		s.add(model.TypeComputer, "Open ports", "Remote Desktop (3389)", 0.3)
	}
	if o.NetBIOSName != "" {
		s.add(model.TypeComputer, "NetBIOS", "NetBIOS name "+o.NetBIOSName, 0.35)
	}
	if strings.HasPrefix(o.DHCPVendor, "MSFT") {
		s.add(model.TypeComputer, "DHCP", "Windows DHCP client ("+o.DHCPVendor+")", 0.55)
	}
	if n := lower(o.SMBNativeOS); strings.Contains(n, "server") {
		s.add(model.TypeServer, "SMB", "server edition: "+o.SMBNativeOS, 0.8)
	}
	if o.HasPort(22) && (o.HasPort(80) || o.HasPort(443)) && !windowsPorts && !o.HasPort(9100) && !o.HasPort(554) {
		s.add(model.TypeServer, "Open ports", "SSH and web services", 0.35)
	}

	// --- OUI vendor
	v := f.OUIVendor
	for _, t := range []struct {
		m   map[string]float64
		typ string
		why string
	}{
		{printerVendors, model.TypePrinter, "manufacturer mostly makes printers"},
		{phoneVendors, model.TypePhone, "manufacturer makes IP phones"},
		{cameraVendors, model.TypeCamera, "manufacturer makes IP cameras"},
		{pcVendors, model.TypeComputer, "manufacturer makes computers"},
		{serverVendors, model.TypeServer, "manufacturer makes server hardware"},
		{vmVendors, model.TypeVirtual, "virtual machine network adapter"},
		{iotVendors, model.TypeIoT, "manufacturer makes IoT devices"},
		{mobileVendors, model.TypeMobile, "manufacturer makes phones/tablets"},
		{storageVends, model.TypeStorage, "manufacturer makes storage"},
		{upsVendors, model.TypeUPS, "manufacturer makes UPS devices"},
		{apVendors, model.TypeAccessPoint, "manufacturer makes wireless equipment"},
	} {
		if w, ok := t.m[v]; ok {
			s.add(t.typ, "OUI", v+": "+t.why, w)
		}
	}
	if f.RandomMAC && len(s.cands) == 0 {
		s.add(model.TypeMobile, "MAC address", "randomized (private) MAC, typical for phones and laptops", 0.3)
	}

	// --- hostnames
	for _, h := range f.Hostnames {
		switch {
		case rePrinterHost.MatchString(h):
			s.add(model.TypePrinter, "Hostname", h, 0.5)
		case rePhoneHost.MatchString(h):
			s.add(model.TypePhone, "Hostname", h, 0.5)
		case reCamHost.MatchString(h):
			s.add(model.TypeCamera, "Hostname", h, 0.5)
		case reAPHost.MatchString(h):
			s.add(model.TypeAccessPoint, "Hostname", h, 0.4)
		case reServerHost.MatchString(h):
			s.add(model.TypeServer, "Hostname", h, 0.45)
		case rePCHost.MatchString(h):
			s.add(model.TypeComputer, "Hostname", h, 0.45)
		}
	}
	return s.best(0.25, model.TypeUnknown)
}
