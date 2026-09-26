// Package vendors holds vendor detection and the adapter contract.
//
// Standard MIB collection always runs first. An Adapter only adds what the
// standard MIBs cannot provide (vendor CPU/memory tables, optics DOM, CDP, ...)
// and parses vendor-specific strings (model, OS version). Vendor OIDs never
// leak into the core domain model.
package vendors

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/collectors"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
)

// Adapter extends discovery for one vendor family.
type Adapter interface {
	Name() string
	// Match reports whether this adapter handles the device.
	Match(sys model.System) bool
	// Enrich parses vendor-specific model / OS information into sys.
	Enrich(sys *model.System)
	// Collectors returns vendor collectors run after the standard ones.
	Collectors() []collectors.Collector
}

// Enterprise maps IANA private enterprise numbers (sysObjectID prefix
// 1.3.6.1.4.1.<n>) to a normalized vendor name.
var Enterprise = map[int]string{
	9: "Cisco", 11: "HP", 43: "3Com", 45: "Nortel", 171: "D-Link", 207: "Allied Telesis", 244: "Lantronix",
	253: "Xerox", 311: "Microsoft", 318: "APC", 367: "Ricoh", 534: "Eaton", 641: "Lexmark", 674: "Dell",
	705: "Eaton", 1248: "Epson", 1347: "Kyocera", 1588: "Brocade", 1602: "Canon", 1916: "Extreme Networks",
	1991: "Brocade", 2011: "Huawei", 2021: "Net-SNMP", 2272: "Nortel", 2435: "Brother", 2620: "Check Point",
	2636: "Juniper", 3076: "Cisco", 3224: "Juniper", 3375: "F5", 4413: "Broadcom", 4526: "Netgear",
	5596: "Tandberg", 5624: "Enterasys", 6027: "Force10", 6486: "Alcatel-Lucent", 6527: "Nokia",
	6876: "VMware", 6889: "Avaya", 8072: "Net-SNMP", 10002: "Ubiquiti", 10418: "Avocent",
	11863: "TP-Link", 12356: "Fortinet", 14179: "Cisco", 14525: "Trapeze", 14823: "Aruba", 14988: "MikroTik",
	17713: "Cambium", 18334: "Konica Minolta", 25053: "Ruckus", 25461: "Palo Alto Networks",
	25506: "H3C", 30065: "Arista", 30803: "Vyatta", 31926: "Siklu",
	33049: "Mellanox", 35265: "Eltex", 3902: "ZTE", 41112: "Ubiquiti",
	47196: "HPE", 1981: "EMC", 789: "NetApp", 6574: "Synology", 24681: "QNAP", 12325: "pfSense", 2604: "Sophos", 4329: "Siemens", 13742: "Raritan", 1718: "Sentry",
	3808: "CyberPower", 935: "Vertiv", 476: "Vertiv", 8691: "Moxa", 2356: "Lancom",
	890: "Zyxel", 3955: "Linksys", 850: "Tripp Lite", 17163: "Riverbed",
	29671: "Meraki", 5528: "Netbotz", 3417: "Blue Coat", 9148: "Acme Packet",
	6141: "Ciena", 193: "Ericsson", 94: "Nokia", 637: "Nokia", 800: "Alcatel-Lucent", 2352: "Ericsson",
	231: "Fujitsu", 211: "Fujitsu", 119: "NEC", 116: "Hitachi"}

var reEnterprise = regexp.MustCompile(`^\.?1\.3\.6\.1\.4\.1\.(\d+)`)

// EnterpriseOf extracts the enterprise number from a sysObjectID.
func EnterpriseOf(objectID string) int {
	m := reEnterprise.FindStringSubmatch(objectID)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// descrVendors are sysDescr substrings (lowercase) → vendor, used when the
// enterprise number is generic (e.g. net-snmp on an appliance).
var descrVendors = []struct{ needle, vendor string }{
	{"huawei", "Huawei"}, {"vrp", "Huawei"}, {"cisco", "Cisco"}, {"juniper", "Juniper"}, {"junos", "Juniper"},
	{"arista", "Arista"}, {"routeros", "MikroTik"}, {"mikrotik", "MikroTik"}, {"procurve", "HPE"},
	{"aruba", "Aruba"}, {"comware", "H3C"}, {"h3c", "H3C"}, {"fortigate", "Fortinet"}, {"palo alto", "Palo Alto Networks"},
	{"hp laserjet", "HP"}, {"hp ethernet", "HP"}, {"hp officejet", "HP"}, {"hp color laserjet", "HP"},
	{"canon", "Canon"}, {"brother", "Brother"}, {"kyocera", "Kyocera"}, {"ricoh", "Ricoh"}, {"xerox", "Xerox"},
	{"lexmark", "Lexmark"}, {"epson", "Epson"}, {"konica", "Konica Minolta"}, {"sharp", "Sharp"},
	{"ubiquiti", "Ubiquiti"}, {"unifi", "Ubiquiti"}, {"edgeos", "Ubiquiti"}, {"dell", "Dell"}, {"force10", "Dell"},
	{"extreme", "Extreme Networks"}, {"zyxel", "Zyxel"}, {"tp-link", "TP-Link"}, {"netgear", "Netgear"},
	{"d-link", "D-Link"}, {"ruijie", "Ruijie"}, {"zte", "ZTE"}, {"hikvision", "Hikvision"}, {"dahua", "Dahua"},
	{"axis", "Axis"}, {"apc", "APC"}, {"eaton", "Eaton"}, {"synology", "Synology"}, {"qnap", "QNAP"},
	{"vmware", "VMware"}, {"windows", "Microsoft"}, {"pfsense", "pfSense"}, {"opnsense", "OPNsense"},
}

// DetectVendor determines the vendor from sysObjectID and sysDescr.
// Returns the vendor and the source used ("sysObjectID" or "sysDescr").
func DetectVendor(sys model.System) (string, string) {
	if v := Enterprise[EnterpriseOf(sys.ObjectID)]; v != "" && v != "Net-SNMP" {
		return v, "sysObjectID"
	}
	l := strings.ToLower(sys.Descr)
	for _, d := range descrVendors {
		if strings.Contains(l, d.needle) {
			return d.vendor, "sysDescr"
		}
	}
	if Enterprise[EnterpriseOf(sys.ObjectID)] == "Net-SNMP" {
		return "", ""
	}
	return "", ""
}

// vendorAliases normalizes free-text manufacturer names (OUI registry, ENTITY
// mfgName, LLDP) into the short display names used across the product.
var vendorAliases = []struct{ needle, name string }{
	{"hewlett packard enterprise", "HPE"}, {"hewlett-packard enterprise", "HPE"}, {"aruba", "Aruba"},
	{"hewlett packard", "HP"}, {"hewlett-packard", "HP"}, {"hp inc", "HP"}, {"hp ", "HP"},
	{"huawei", "Huawei"}, {"honor device", "Honor"}, {"cisco meraki", "Meraki"}, {"cisco", "Cisco"},
	{"juniper", "Juniper"}, {"arista", "Arista"}, {"routerboard", "MikroTik"}, {"mikrotik", "MikroTik"},
	{"dell", "Dell"}, {"lenovo", "Lenovo"}, {"apple", "Apple"}, {"samsung", "Samsung"}, {"intel", "Intel"},
	{"canon", "Canon"}, {"brother", "Brother"}, {"kyocera", "Kyocera"}, {"ricoh", "Ricoh"}, {"xerox", "Xerox"},
	{"lexmark", "Lexmark"}, {"seiko epson", "Epson"}, {"epson", "Epson"}, {"konica minolta", "Konica Minolta"},
	{"sharp", "Sharp"}, {"toshiba", "Toshiba"}, {"oki electric", "Oki"}, {"zebra", "Zebra"},
	{"ubiquiti", "Ubiquiti"}, {"tp-link", "TP-Link"}, {"netgear", "Netgear"}, {"d-link", "D-Link"},
	{"zyxel", "Zyxel"}, {"fortinet", "Fortinet"}, {"palo alto", "Palo Alto Networks"}, {"h3c", "H3C"},
	{"new h3c", "H3C"}, {"ruijie", "Ruijie"}, {"zte", "ZTE"}, {"hangzhou hikvision", "Hikvision"},
	{"hikvision", "Hikvision"}, {"dahua", "Dahua"}, {"axis communications", "Axis"}, {"american power conversion", "APC"},
	{"schneider", "Schneider Electric"}, {"eaton", "Eaton"}, {"vmware", "VMware"}, {"microsoft", "Microsoft"},
	{"polycom", "Poly"}, {"yealink", "Yealink"}, {"grandstream", "Grandstream"}, {"avaya", "Avaya"},
	{"mitel", "Mitel"}, {"snom", "Snom"}, {"synology", "Synology"}, {"qnap", "QNAP"}, {"raspberry pi", "Raspberry Pi"},
	{"super micro", "Supermicro"}, {"supermicro", "Supermicro"}, {"asustek", "ASUS"}, {"giga-byte", "Gigabyte"},
	{"micro-star", "MSI"}, {"realtek", "Realtek"}, {"broadcom", "Broadcom"}, {"extreme networks", "Extreme Networks"},
	{"alcatel", "Alcatel-Lucent"}, {"nokia", "Nokia"}, {"ericsson", "Ericsson"}, {"fujitsu", "Fujitsu"},
	{"xiaomi", "Xiaomi"}, {"google", "Google"}, {"amazon", "Amazon"}, {"sonos", "Sonos"}, {"espressif", "Espressif"},
	{"oracle", "Oracle"}, {"qemu", "QEMU"}, {"proxmox", "Proxmox"}, {"ruckus", "Ruckus"}, {"cambium", "Cambium"},
	{"siemens", "Siemens"}, {"moxa", "Moxa"}, {"honeywell", "Honeywell"}, {"bosch", "Bosch"},
}

// NormalizeVendor maps a manufacturer string to a short display name.
func NormalizeVendor(s string) string {
	l := strings.ToLower(strings.TrimSpace(s)) + " "
	if strings.TrimSpace(l) == "" {
		return ""
	}
	for _, a := range vendorAliases {
		if strings.HasPrefix(l, a.needle) || strings.Contains(l, " "+a.needle) || strings.Contains(l, a.needle) && len(a.needle) > 4 {
			return a.name
		}
	}
	// Title-case the first word of unknown registrants ("ACME CORP" → "Acme").
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	w := strings.Trim(f[0], ",.")
	if len(w) <= 3 {
		return strings.ToUpper(w)
	}
	return strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
}

// Registry is an ordered list of adapters.
type Registry struct{ adapters []Adapter }

func NewRegistry(a ...Adapter) *Registry { return &Registry{adapters: a} }

// For returns the adapter matching sys, or nil.
func (r *Registry) For(sys model.System) Adapter {
	for _, a := range r.adapters {
		if a.Match(sys) {
			return a
		}
	}
	return nil
}

// FirstLine returns the first non-empty line of s.
func FirstLine(s string) string {
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r", "\n"), "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return ""
}
