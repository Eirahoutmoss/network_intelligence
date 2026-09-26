package classify

import (
	"regexp"
	"strconv"
	"strings"
)

// OS families. Specific versions roll up into a family; when evidence is not
// strong enough for a specific version the family is reported instead
// (e.g. "Windows NT family" at 61% rather than a guessed "Windows XP").
const (
	FamWindows = "Windows"
	FamLinux   = "Linux"
	FamNetwork = "Network OS"
	FamApple   = "Apple"
	FamPrinter = "Printer firmware"
)

var familyDisplay = map[string]string{
	FamWindows: "Windows NT family",
	FamLinux:   "Linux/Unix",
	FamNetwork: "Network OS",
	FamApple:   "Apple (macOS/iOS)",
	FamPrinter: "Printer firmware",
}

type osScorer struct {
	spec  map[string][]Evidence
	fam   map[string][]Evidence
	famOf map[string]string
}

func (s *osScorer) add(value, family, source, detail string, w float64) {
	if w <= 0 {
		return
	}
	e := Evidence{Attribute: "os", Value: value, Source: source, Detail: detail, Weight: w}
	if value != "" && value != family {
		s.spec[value] = append(s.spec[value], e)
		s.famOf[value] = family
		fe := e
		fe.Weight = w * 0.9
		s.fam[family] = append(s.fam[family], fe)
		return
	}
	e.Value = family
	s.fam[family] = append(s.fam[family], e)
}

// Windows version numbers (kernel NT version → marketing name).
func windowsName(ver string, build int, server bool) string {
	switch {
	case strings.HasPrefix(ver, "4.0"):
		return "Windows NT 4.0"
	case strings.HasPrefix(ver, "5.0"):
		return "Windows 2000"
	case strings.HasPrefix(ver, "5.1"):
		return "Windows XP"
	case strings.HasPrefix(ver, "5.2"):
		if server {
			return "Windows Server 2003"
		}
		return "Windows XP x64 / Server 2003"
	case strings.HasPrefix(ver, "6.0"):
		if server {
			return "Windows Server 2008"
		}
		return "Windows Vista"
	case strings.HasPrefix(ver, "6.1"):
		if server {
			return "Windows Server 2008 R2"
		}
		return "Windows 7"
	case strings.HasPrefix(ver, "6.2"):
		if server {
			return "Windows Server 2012"
		}
		return "Windows 8"
	case strings.HasPrefix(ver, "6.3"):
		if server {
			return "Windows Server 2012 R2"
		}
		return "Windows 8.1"
	case strings.HasPrefix(ver, "10."):
		if server {
			switch {
			case build >= 26100:
				return "Windows Server 2025"
			case build >= 20348:
				return "Windows Server 2022"
			case build >= 17763:
				return "Windows Server 2019"
			case build > 0:
				return "Windows Server 2016"
			}
			return "Windows Server 2016+"
		}
		if build >= 22000 {
			return "Windows 11"
		}
		if build > 0 {
			return "Windows 10"
		}
		return "Windows 10/11"
	}
	return ""
}

var (
	reWinSysDescr = regexp.MustCompile(`(?i)Software:\s*Windows.*?Version\s+([\d.]+)\s*\(Build\s+(\d+)`)
	reSMBWin      = regexp.MustCompile(`(?i)^Windows\s+(\d+\.\d+)(?:\s+Build\s+(\d+))?$`)
	reSMBName     = regexp.MustCompile(`(?i)Windows\s+(XP|2000|Vista|7|8\.1|8|10|11|Server\s+\d{4}(?:\s+R2)?)`)
	reLinuxKernel = regexp.MustCompile(`(?i)\bLinux\s+\S+\s+(\d+\.\d+[\w.\-]*)`)
	reIIS         = regexp.MustCompile(`(?i)Microsoft-IIS/(\d+\.\d+)`)
)

var iisOS = map[string]string{"5.0": "Windows 2000", "5.1": "Windows XP", "6.0": "Windows Server 2003",
	"7.0": "Windows Server 2008", "7.5": "Windows Server 2008 R2", "8.0": "Windows Server 2012", "8.5": "Windows Server 2012 R2"}

// DHCP option-55 parameter request lists of well-known clients.
var dhcpSigs = map[string]string{
	"1,15,3,6,44,46,47,31,33,249,43":             "Windows XP",
	"1,15,3,6,44,46,47,31,33,249,43,252":         "Windows XP",
	"1,15,3,6,44,46,47,31,33,121,249,43":         "Windows 7",
	"1,15,3,6,44,46,47,31,33,121,249,43,252":     "Windows 7",
	"1,3,6,15,31,33,43,44,46,47,119,121,249,252": "Windows 10/11",
	"1,121,3,6,15,119,252,95,44,46":              "macOS",
	"1,121,3,6,15,119,252":                       "iOS",
	"1,3,6,15,26,28,51,58,59,43":                 "Android",
	"1,28,2,3,15,6,119,12,44,47,26,121,42":       "Linux (Ubuntu)",
}

// OS classifies the operating system.
func OS(f Facts) Result {
	s := &osScorer{spec: map[string][]Evidence{}, fam: map[string][]Evidence{}, famOf: map[string]string{}}
	o := f.Obs

	if f.NetworkOS != "" {
		s.add(f.NetworkOS, FamNetwork, "SNMP sysDescr", "vendor software string", 0.95)
	}
	for _, d := range []struct{ src, text string }{{"SNMP sysDescr", f.SysDescr}, {"SNMP sysDescr (probe)", o.SNMPSysDescr}} {
		if d.text == "" {
			continue
		}
		if m := reWinSysDescr.FindStringSubmatch(d.text); m != nil {
			b, _ := strconv.Atoi(m[2])
			if n := windowsName(m[1], b, false); n != "" {
				s.add(n, FamWindows, d.src, strings.TrimSpace(m[0]), 0.9)
			}
		} else if m := reLinuxKernel.FindStringSubmatch(d.text); m != nil {
			name := "Linux"
			if strings.Contains(lower(d.text), "ubuntu") {
				name = "Linux (Ubuntu)"
			} else if strings.Contains(lower(d.text), ".el") {
				name = "Linux (RHEL family)"
			}
			s.add(name, FamLinux, d.src, "kernel "+m[1], 0.85)
		}
	}
	// SMB negotiate / session setup native OS string
	if strings.Contains(lower(o.SMBLanMan), "samba") {
		s.add("", FamLinux, "SMB", "Samba file server ("+o.SMBLanMan+")", 0.8)
	} else if n := strings.TrimSpace(o.SMBNativeOS); n != "" {
		server := strings.Contains(lower(n), "server")
		if m := reSMBWin.FindStringSubmatch(n); m != nil {
			build, _ := strconv.Atoi(m[2])
			if name := windowsName(m[1], build, server); name != "" {
				s.add(name, FamWindows, "SMB", "native OS \""+n+"\"", 0.8)
			}
		} else if m := reSMBName.FindStringSubmatch(n); m != nil {
			s.add("Windows "+m[1], FamWindows, "SMB", "native OS \""+n+"\"", 0.85)
		} else if strings.Contains(lower(n), "samba") || strings.Contains(lower(n), "unix") {
			s.add("", FamLinux, "SMB", "native OS \""+n+"\"", 0.6)
		}
	}
	switch o.SMBDialect {
	case "NT LM 0.12":
		s.add("", FamWindows, "SMB", "only SMB1 dialect offered (legacy Windows/NT)", 0.35)
	case "SMB 2.1":
		s.add("Windows 7", FamWindows, "SMB", "SMB 2.1 dialect (Windows 7 / 2008 R2 era)", 0.25)
	case "SMB 3.1.1", "SMB 3.0.2":
		s.add("", FamWindows, "SMB", o.SMBDialect+" dialect (Windows 8.1 / Server 2012 R2 or newer)", 0.3)
	}
	if o.NetBIOSName != "" && (o.HasPort(139) || o.HasPort(445)) {
		s.add("", FamWindows, "NetBIOS", "NetBIOS name "+o.NetBIOSName+" with SMB ports open", 0.55)
	}
	if o.HasPort(135) {
		s.add("", FamWindows, "Open ports", "Microsoft RPC endpoint mapper (135)", 0.45)
	}
	if o.HasPort(3389) {
		s.add("", FamWindows, "Open ports", "Remote Desktop (3389)", 0.35)
	}
	switch {
	case o.TTL > 64 && o.TTL <= 128:
		s.add("", FamWindows, "TCP/IP fingerprint", "initial TTL 128", 0.3)
	case o.TTL > 0 && o.TTL <= 64:
		s.add("", FamLinux, "TCP/IP fingerprint", "initial TTL 64", 0.15)
	case o.TTL > 128:
		s.add("", FamNetwork, "TCP/IP fingerprint", "initial TTL 255", 0.2)
	}
	if strings.HasPrefix(o.DHCPVendor, "MSFT") {
		s.add("", FamWindows, "DHCP fingerprint", "vendor class "+o.DHCPVendor, 0.5)
	}
	if name, ok := dhcpSigs[strings.ReplaceAll(o.DHCPParams, " ", "")]; ok {
		fam := FamWindows
		switch {
		case strings.HasPrefix(name, "Linux"), name == "Android":
			fam = FamLinux
		case name == "macOS", name == "iOS":
			fam = FamApple
		}
		s.add(name, fam, "DHCP fingerprint", "parameter request list matches "+name, 0.6)
	}
	if m := reIIS.FindStringSubmatch(o.HTTPServer); m != nil {
		if n := iisOS[m[1]]; n != "" {
			s.add(n, FamWindows, "HTTP banner", o.HTTPServer, 0.6)
		} else {
			s.add("", FamWindows, "HTTP banner", o.HTTPServer, 0.5)
		}
	} else if h := lower(o.HTTPServer); strings.Contains(h, "ubuntu") {
		s.add("Linux (Ubuntu)", FamLinux, "HTTP banner", o.HTTPServer, 0.5)
	} else if strings.Contains(h, "debian") || strings.Contains(h, "centos") || strings.Contains(h, "red hat") {
		s.add("", FamLinux, "HTTP banner", o.HTTPServer, 0.45)
	}
	if o.HasPort(22) && !o.HasPort(135) && !o.HasPort(445) {
		s.add("", FamLinux, "Open ports", "SSH without Windows services", 0.2)
	}
	if f.OUIVendor == "Apple" {
		s.add("", FamApple, "OUI", "Apple network adapter", 0.4)
	}
	return s.result()
}

func (s *osScorer) result() Result {
	// best family
	var bestFam string
	var bestFamScore, secondFam float64
	for fam, ev := range s.fam {
		sc := noisyOR(ev)
		if sc > bestFamScore || (sc == bestFamScore && fam < bestFam) {
			secondFam = bestFamScore
			bestFam, bestFamScore = fam, sc
		} else if sc > secondFam {
			secondFam = sc
		}
	}
	if bestFam == "" || bestFamScore < 0.3 {
		var all []Evidence
		for _, ev := range s.fam {
			all = append(all, ev...)
		}
		return Result{Value: "", Evidence: all}
	}
	famConf := bestFamScore * (1 - 0.5*secondFam)
	// best specific version within that family
	var bestSpec string
	var bestSpecScore, secondSpec float64
	for v, ev := range s.spec {
		if s.famOf[v] != bestFam {
			continue
		}
		sc := noisyOR(ev)
		if sc > bestSpecScore || (sc == bestSpecScore && v < bestSpec) {
			secondSpec = bestSpecScore
			bestSpec, bestSpecScore = v, sc
		} else if sc > secondSpec {
			secondSpec = sc
		}
	}
	var ev []Evidence
	for _, e := range s.fam[bestFam] {
		e.Value = bestFam
		ev = append(ev, e)
	}
	if bestSpec != "" && bestSpecScore >= 0.5 {
		specConf := bestSpecScore * (1 - 0.6*secondSpec)
		conf := 1 - (1-specConf)*(1-0.5*famConf)
		conf *= 1 - 0.5*secondFam
		// relabel evidence: specific evidence keeps its version name
		var out []Evidence
		for _, e := range s.spec[bestSpec] {
			out = append(out, e)
		}
		for _, e := range s.fam[bestFam] {
			dup := false
			for _, x := range out {
				if x.Source == e.Source && x.Detail == e.Detail {
					dup = true
				}
			}
			if !dup {
				e.Value = bestFam
				out = append(out, e)
			}
		}
		return Result{Value: bestSpec, Confidence: round2(conf), Evidence: sortEv(out)}
	}
	return Result{Value: familyDisplay[bestFam], Confidence: round2(famConf), Evidence: sortEv(ev)}
}

// Vendor picks the most credible manufacturer.
func Vendor(f Facts) Result {
	s := newScorer("vendor")
	if f.SNMPVendor != "" {
		s.add(f.SNMPVendor, "SNMP", "sysObjectID / sysDescr", 0.95)
	}
	if f.OUIVendor != "" {
		s.add(f.OUIVendor, "OUI", "MAC prefix registered to "+f.OUIOrg, 0.7)
	}
	for _, v := range []string{"HP", "Canon", "Brother", "Yealink", "Hikvision", "Kyocera", "Lexmark", "Xerox", "Epson", "Huawei", "Cisco", "Fortinet"} {
		for _, t := range []string{f.Obs.HTTPTitle, f.Obs.HTTPServer, f.NeighborDesc, f.Obs.SNMPSysDescr} {
			if t != "" && strings.Contains(lower(t), lower(v)) {
				s.add(v, "Banner", t, 0.6)
				break
			}
		}
	}
	return s.best(0.3, "")
}
