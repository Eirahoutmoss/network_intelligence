// Package explorer turns questions ("Kaç tane Canon yazıcı var?", "Show HP
// printers in the lab") into structured queries and answers them strictly
// from the database. The natural-language layer only produces filters; it
// never produces results.
package explorer

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
)

// Query is the structured form of a question. Every field is optional.
type Query struct {
	Intent          string   `json:"intent"`  // list|count
	Subject         string   `json:"subject"` // devices|connections|jack
	Types           []string `json:"types,omitempty"`
	Vendors         []string `json:"vendors,omitempty"`
	OS              string   `json:"os,omitempty"`
	Location        string   `json:"location,omitempty"` // free-text location term
	Floor           *int     `json:"floor,omitempty"`
	Room            string   `json:"room,omitempty"`
	Jack            string   `json:"jack,omitempty"`
	Subnet          string   `json:"subnet,omitempty"`
	IP              string   `json:"ip,omitempty"`
	MAC             string   `json:"mac,omitempty"`
	ConnectedTo     string   `json:"connected_to,omitempty"`
	Downstream      bool     `json:"downstream,omitempty"`
	Medium          string   `json:"medium,omitempty"` // fiber|copper
	PortChangedDays int      `json:"port_changed_days,omitempty"`
	NewDays         int      `json:"new_days,omitempty"`
	SeenDays        int      `json:"seen_days,omitempty"` // distinct devices seen on a jack/port in N days
	Status          string   `json:"status,omitempty"`    // up|down
	Managed         *bool    `json:"managed,omitempty"`
	VLAN            int      `json:"vlan,omitempty"`
	Text            string   `json:"text,omitempty"` // free-text name/hostname search
	Lang            string   `json:"lang"`           // tr|en (answer language)
}

// Vocabulary known at parse time (loaded from the database).
type Vocabulary struct {
	Vendors   []string // normalized vendor names present in the inventory
	OSNames   []string // os_name values present
	Devices   []string // device names (sys_name/display name/hostname)
	Locations []string // location names
}

// fold lowercases and removes Turkish diacritics for matching.
func fold(s string) string {
	r := strings.NewReplacer("İ", "i", "I", "ı", "Ş", "ş", "Ç", "ç", "Ğ", "ğ", "Ö", "ö", "Ü", "ü")
	s = strings.ToLower(r.Replace(s))
	return strings.NewReplacer("ı", "i", "ş", "s", "ç", "c", "ğ", "g", "ö", "o", "ü", "u", "â", "a", "’", "'").Replace(s)
}

// type synonyms (folded). Longer phrases first.
var typeWords = []struct {
	words []string
	typ   string
}{
	{[]string{"erisim noktasi", "erisim noktalari", "access point", "access points", "kablosuz erisim", "wifi ap", "wireless ap"}, model.TypeAccessPoint},
	{[]string{"guvenlik duvari", "firewall", "guvenlik duvarlari"}, model.TypeFirewall},
	{[]string{"ip telefon", "voip telefon", "telefon", "phone", "ip phone"}, model.TypePhone},
	{[]string{"yazici", "printer", "mfp", "yazdirici"}, model.TypePrinter},
	{[]string{"switch", "anahtar", "svic"}, model.TypeSwitch},
	{[]string{"yonlendirici", "router"}, model.TypeRouter},
	{[]string{"bilgisayar", "computer", "pc", "laptop", "masaustu", "desktop", "notebook", "is istasyonu", "workstation"}, model.TypeComputer},
	{[]string{"sunucu", "server"}, model.TypeServer},
	{[]string{"kamera", "camera", "ip kamera", "cctv"}, model.TypeCamera},
	{[]string{"ups", "kesintisiz guc"}, model.TypeUPS},
	{[]string{"nas", "depolama", "storage"}, model.TypeStorage},
	{[]string{"sanal makine", "virtual machine", "vm"}, model.TypeVirtual},
	{[]string{"iot", "akilli cihaz"}, model.TypeIoT},
	{[]string{"ap"}, model.TypeAccessPoint},
}

// location synonyms folded → canonical fragments matched against location names.
var locationSynonyms = map[string][]string{
	"laboratuvar": {"lab"}, "laboratuar": {"lab"}, "lab": {"lab"}, "laboratory": {"lab"},
	"sunucu odasi": {"server room", "sunucu"}, "server room": {"server room"},
	"bodrum": {"basement", "bodrum"}, "basement": {"basement"}, "cati": {"roof", "cati"}, "roof": {"roof"},
	"balkon": {"balcony", "balkon"}, "balcony": {"balcony"}, "zemin kat": {"ground", "zemin"},
	"muhasebe": {"muhasebe", "accounting"}, "idari": {"idari", "admin"}, "depo": {"depo", "warehouse"},
	"toplanti": {"toplanti", "meeting"}, "ogretmenler": {"ogretmen", "teacher"},
}

var ordinalsTR = map[string]int{"birinci": 1, "ikinci": 2, "ucuncu": 3, "dorduncu": 4, "besinci": 5, "altinci": 6, "yedinci": 7,
	"sekizinci": 8, "dokuzuncu": 9, "onuncu": 10, "first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5}

var (
	reCIDR      = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\b`)
	reIP        = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	reMAC       = regexp.MustCompile(`\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b`)
	reFloor     = regexp.MustCompile(`\b(?:kat|floor|level)\s*[-:]?\s*(\d{1,3})\b|\b(\d{1,3})\s*(?:\.|nci|inci|uncu|ncu|nd|rd|th|st)?\s*(?:kat|floor)\b`)
	reFloorOrd  = regexp.MustCompile(`\b(birinci|ikinci|ucuncu|dorduncu|besinci|altinci|yedinci|sekizinci|dokuzuncu|onuncu|first|second|third|fourth|fifth)\s+(?:kat|floor)`)
	reRoom      = regexp.MustCompile(`\b(?:room|oda|oda no|sinif|class(?:room)?)\s*[-:#]?\s*([0-9a-z][0-9a-z\-]*)`)
	reRoomAfter = regexp.MustCompile(`\b(\d{2,4})\s*(?:nolu|numarali|no'lu)?\s*(?:oda|odada|odasinda|odadaki)\b`)
	reJack      = regexp.MustCompile(`\b(?:jack|priz|port|soket|socket|outlet)\s*[-:#]?\s*([0-9a-z]*\d[0-9a-z]*(?:[-/][0-9a-z]+)?)`)
	reMovedPh   = regexp.MustCompile(`\b(?:switch\s+)?port\w*\s+(?:degis\w*|change\w*)|\b(?:changed|moved)\s+(?:switch\s+)?port\w*|\bswitch\s+port\w*`)
	reRoomJack  = regexp.MustCompile(`\b(\d{2,4})-(\d{1,3})\b`)
	reDays      = regexp.MustCompile(`\b(?:son|last|past)\s+(\d{1,4})\s*(gun|gunde|gunun|day|days|hafta|week|weeks|ay|month|months)`)
	reVLAN      = regexp.MustCompile(`\bvlan\s*(\d{1,4})\b`)
	reCount     = regexp.MustCompile(`\b(kac|how many|count|sayisi|sayi|number of|toplam)\b`)
)

// Parse turns a question into a Query using the vocabulary.
func Parse(question string, v Vocabulary) Query {
	q := Query{Intent: "list", Subject: "devices", Lang: detectLang(question)}
	raw := strings.TrimSpace(question)
	f := " " + fold(raw) + " "
	consumed := f

	mark := func(s string) {
		consumed = strings.Replace(consumed, s, strings.Repeat(" ", len(s)), 1)
	}
	if reCount.MatchString(f) {
		q.Intent = "count"
	}
	// addresses first (so numbers are not mistaken for rooms/floors)
	if m := reCIDR.FindStringSubmatch(f); m != nil {
		if _, n, err := net.ParseCIDR(m[1] + "/" + m[2]); err == nil {
			q.Subnet = n.String()
			mark(m[0])
		}
	} else if m := reIP.FindStringSubmatch(f); m != nil && net.ParseIP(m[1]) != nil {
		q.IP = m[1]
		mark(m[0])
	}
	if m := reMAC.FindStringSubmatch(f); m != nil {
		q.MAC = strings.ReplaceAll(m[1], "-", ":")
		mark(m[0])
	}
	if m := reVLAN.FindStringSubmatch(consumed); m != nil {
		q.VLAN, _ = strconv.Atoi(m[1])
		mark(m[0])
	}
	// time windows
	days := 0
	if m := reDays.FindStringSubmatch(consumed); m != nil {
		n, _ := strconv.Atoi(m[1])
		switch {
		case strings.HasPrefix(m[2], "hafta"), strings.HasPrefix(m[2], "week"):
			n *= 7
		case strings.HasPrefix(m[2], "ay"), strings.HasPrefix(m[2], "month"):
			n *= 30
		}
		days = n
		mark(m[0])
	}
	moved := containsAny(f, "port degis", "portu degis", "portunu degis", "yer degistir", "tasinan", "moved", "port change", "changed port", "switch port changed", "portu farkli")
	isNew := containsAny(f, " yeni ", " new ", "ilk kez", "first seen", "newly")
	if moved {
		if days == 0 {
			days = 30
		}
		q.PortChangedDays = days
		consumed = reMovedPh.ReplaceAllStringFunc(consumed, func(m string) string { return strings.Repeat(" ", len(m)) })
	} else if isNew {
		if days == 0 {
			days = 7
		}
		q.NewDays = days
	}
	// floors / rooms / jacks
	if m := reFloorOrd.FindStringSubmatch(consumed); m != nil {
		n := ordinalsTR[m[1]]
		q.Floor = &n
		mark(m[0])
	} else if m := reFloor.FindStringSubmatch(consumed); m != nil {
		s := m[1]
		if s == "" {
			s = m[2]
		}
		if n, err := strconv.Atoi(s); err == nil {
			q.Floor = &n
			mark(m[0])
		}
	}
	if m := reRoomJack.FindStringSubmatch(consumed); m != nil && containsAny(f, "priz", "jack", "soket", "socket", "outlet") {
		q.Room, q.Jack = m[1], m[2]
		mark(m[0])
	}
	if m := reRoom.FindStringSubmatch(consumed); m != nil && q.Room == "" {
		q.Room = strings.TrimSuffix(strings.Trim(m[1], "'-"), "te")
		q.Room = trimSuffixes(q.Room)
		mark(m[0])
	} else if m := reRoomAfter.FindStringSubmatch(consumed); m != nil && q.Room == "" {
		q.Room = m[1]
		mark(m[0])
	}
	if m := reJack.FindStringSubmatch(consumed); m != nil && q.Jack == "" {
		q.Jack = trimSuffixes(strings.Trim(m[1], "'"))
		mark(m[0])
	}
	if q.Jack != "" {
		q.Subject = "jack"
		if days > 0 && !moved {
			q.SeenDays = days
		}
	}
	// medium / connections
	if containsAny(f, "fiber", "fibre", "optik", "optical") {
		q.Medium = "fiber"
	} else if containsAny(f, "bakir", "copper", "utp") {
		q.Medium = "copper"
	}
	if q.Medium != "" && containsAny(f, "baglanti", "link", "connection", "kablo", "cable", "hat") {
		q.Subject = "connections"
	} else if q.Medium != "" && q.Subject == "devices" && !anyTypeWord(f) {
		q.Subject = "connections"
	}
	// device names ("SW-CORE-01'e bağlı")
	names := append([]string(nil), v.Devices...)
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, n := range names {
		fn := fold(n)
		if len(fn) < 3 {
			continue
		}
		if i := strings.Index(consumed, fn); i >= 0 && wordBoundary(consumed, i, len(fn)) {
			mark(fn)
			if containsAny(f, "bagli", "connected", "baglanan", "arkasinda", "behind", "downstream", "altinda", "komsu", "neighbor", "attached") {
				q.ConnectedTo = n
				q.Downstream = containsAny(f, "arkasinda", "behind", "downstream", "altinda", "tum", "all devices under")
			} else {
				q.Text = n
			}
			break
		}
	}
	// types
	for _, tw := range typeWords {
		for _, w := range tw.words {
			if hasWord(consumed, w) || hasWord(consumed, w+"lar") || hasWord(consumed, w+"ler") || hasWord(consumed, w+"s") || hasWord(consumed, w+"es") ||
				hasWordPrefix(consumed, w+"lar") || hasWordPrefix(consumed, w+"ler") || hasWordPrefix(consumed, w+"da") || hasWordPrefix(consumed, w+"de") {
				if !containsStr(q.Types, tw.typ) {
					q.Types = append(q.Types, tw.typ)
				}
				consumed = strings.ReplaceAll(consumed, w, strings.Repeat(" ", len(w)))
				break
			}
		}
	}
	// OS: prefer longest known os_name contained in the text, with aliases
	osAliases := map[string]string{"windows xp": "windows xp", " xp ": "windows xp", "windows 7": "windows 7", "win7": "windows 7",
		"windows 10": "windows 10", "windows 11": "windows 11", "windows server": "windows server", "linux": "linux",
		"ubuntu": "ubuntu", "windows": "windows", "macos": "macos", "vrp": "vrp", "ios-xe": "ios-xe", "junos": "junos", "eos": "eos"}
	osKeys := make([]string, 0, len(osAliases))
	for k := range osAliases {
		osKeys = append(osKeys, k)
	}
	sort.Slice(osKeys, func(i, j int) bool { return len(osKeys[i]) > len(osKeys[j]) })
	for _, k := range osKeys {
		if strings.Contains(consumed, k) {
			q.OS = osAliases[k]
			mark(strings.TrimSpace(k))
			break
		}
	}
	// vendors (longest first; match whole words, also Turkish suffixes: "HP'ler", "Canon'lar")
	vendors := append([]string(nil), v.Vendors...)
	for _, extra := range []string{"HP", "HPE", "Canon", "Brother", "Cisco", "Huawei", "Dell", "Lenovo", "Epson", "Kyocera", "Xerox", "Ricoh",
		"Lexmark", "Yealink", "Hikvision", "Dahua", "Fortinet", "Juniper", "Aruba", "Apple", "Samsung", "Ubiquiti", "MikroTik", "Supermicro", "Synology"} {
		if !containsFold(vendors, extra) {
			vendors = append(vendors, extra)
		}
	}
	sort.Slice(vendors, func(i, j int) bool { return len(vendors[i]) > len(vendors[j]) })
	for _, vn := range vendors {
		fv := fold(vn)
		if len(fv) < 2 {
			continue
		}
		if i := strings.Index(consumed, fv); i >= 0 && wordStart(consumed, i) && vendorEnd(consumed, i+len(fv)) {
			if !containsStr(q.Vendors, vn) {
				q.Vendors = append(q.Vendors, vn)
			}
			mark(fv)
		}
	}
	// location words
	if q.Room == "" {
		for syn, frags := range locationSynonyms {
			if hasWordPrefix(consumed, syn) {
				q.Location = frags[0]
				mark(syn)
				break
			}
		}
	}
	if q.Location == "" {
		locs := append([]string(nil), v.Locations...)
		sort.Slice(locs, func(i, j int) bool { return len(locs[i]) > len(locs[j]) })
		for _, l := range locs {
			fl := fold(l)
			if len(fl) >= 3 && strings.Contains(consumed, fl) {
				q.Location = l
				mark(fl)
				break
			}
		}
	}
	// status
	if containsAny(f, "kapali", "erisilemeyen", "ulasilamayan", "offline", " down ", "calismayan", "unreachable") {
		q.Status = "down"
	}
	if containsAny(f, "yonetilmeyen", "unmanaged") {
		b := false
		q.Managed = &b
	} else if containsAny(f, "yonetilen", "managed", "snmp ile") {
		b := true
		q.Managed = &b
	}
	return q
}

func trimSuffixes(s string) string {
	for _, suf := range []string{"'te", "'de", "'ta", "'da", "te", "de", "'ye", "'e", "'a", "ye", "deki", "teki"} {
		if len(s) > len(suf)+1 && strings.HasSuffix(s, suf) && strings.ContainsAny(s[:len(s)-len(suf)], "0123456789") {
			return strings.TrimSuffix(s, suf)
		}
	}
	return s
}

func detectLang(s string) string {
	l := fold(s)
	if strings.ContainsAny(s, "ıİşŞçÇğĞöÖüÜ") || containsAny(" "+l+" ", " kac ", " goster", " hangi", " var", " ne ", " bagli", " listele", " nerede", " tane ") {
		return "tr"
	}
	return "en"
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsFold(s []string, v string) bool {
	for _, x := range s {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func isWordChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}

func wordStart(s string, i int) bool { return i == 0 || !isWordChar(s[i-1]) }

func wordBoundary(s string, i, n int) bool {
	return wordStart(s, i) && (i+n >= len(s) || !isWordChar(s[i+n]) || s[i+n] == '\'')
}

// vendorEnd allows Turkish suffixes attached with an apostrophe ("HP'ler") or directly ("hpler").
func vendorEnd(s string, j int) bool {
	if j >= len(s) || !isWordChar(s[j]) {
		return true
	}
	rest := s[j:]
	for _, suf := range []string{"ler", "lar", "leri", "lari", "in", "nin", "un", "nun"} {
		if strings.HasPrefix(rest, suf) && (j+len(suf) >= len(s) || !isWordChar(s[j+len(suf)])) {
			return true
		}
	}
	return false
}

func hasWord(s, w string) bool {
	i := strings.Index(s, w)
	for i >= 0 {
		if wordBoundary(s, i, len(w)) {
			return true
		}
		n := strings.Index(s[i+1:], w)
		if n < 0 {
			return false
		}
		i += n + 1
	}
	return false
}

// hasWordPrefix matches w at a word start, allowing any suffix (Turkish inflection).
func hasWordPrefix(s, w string) bool {
	i := strings.Index(s, w)
	for i >= 0 {
		if wordStart(s, i) {
			return true
		}
		n := strings.Index(s[i+1:], w)
		if n < 0 {
			return false
		}
		i += n + 1
	}
	return false
}

func anyTypeWord(f string) bool {
	for _, tw := range typeWords {
		for _, w := range tw.words {
			if hasWordPrefix(f, w) {
				return true
			}
		}
	}
	return false
}

// Describe renders the interpretation as human-readable chips.
func (q Query) Describe() []string {
	tr := q.Lang == "tr"
	var out []string
	add := func(en, trs string, args ...any) {
		if tr {
			out = append(out, fmt.Sprintf(trs, args...))
		} else {
			out = append(out, fmt.Sprintf(en, args...))
		}
	}
	for _, t := range q.Types {
		add("Type = %s", "Tür = %s", TypeLabel(t, q.Lang))
	}
	for _, v := range q.Vendors {
		add("Vendor = %s", "Üretici = %s", v)
	}
	if q.OS != "" {
		add("OS ≈ %s", "İşletim sistemi ≈ %s", q.OS)
	}
	if q.Location != "" {
		add("Location ≈ %s", "Konum ≈ %s", q.Location)
	}
	if q.Floor != nil {
		add("Floor = %d", "Kat = %d", *q.Floor)
	}
	if q.Room != "" {
		add("Room = %s", "Oda = %s", q.Room)
	}
	if q.Jack != "" {
		add("Wall jack = %s", "Priz = %s", q.Jack)
	}
	if q.Subnet != "" {
		add("Network = %s", "Ağ = %s", q.Subnet)
	}
	if q.IP != "" {
		add("IP = %s", "IP = %s", q.IP)
	}
	if q.MAC != "" {
		add("MAC = %s", "MAC = %s", q.MAC)
	}
	if q.VLAN != 0 {
		add("VLAN = %d", "VLAN = %d", q.VLAN)
	}
	if q.ConnectedTo != "" {
		if q.Downstream {
			add("Behind %s", "%s arkasında", q.ConnectedTo)
		} else {
			add("Connected to %s", "%s cihazına bağlı", q.ConnectedTo)
		}
	}
	if q.Medium != "" {
		if tr {
			out = append(out, "Ortam = "+map[string]string{"fiber": "fiber", "copper": "bakır"}[q.Medium])
		} else {
			out = append(out, "Medium = "+q.Medium)
		}
	}
	if q.PortChangedDays > 0 {
		add("Switch port changed in last %d days", "Son %d günde switch portu değişti", q.PortChangedDays)
	}
	if q.NewDays > 0 {
		add("First seen in last %d days", "Son %d günde ilk kez görüldü", q.NewDays)
	}
	if q.SeenDays > 0 {
		add("Seen in last %d days", "Son %d günde görüldü", q.SeenDays)
	}
	if q.Status == "down" {
		add("Status = down", "Durum = erişilemiyor")
	}
	if q.Managed != nil {
		if *q.Managed {
			add("Managed (SNMP)", "Yönetilen (SNMP)")
		} else {
			add("Unmanaged", "Yönetilmeyen")
		}
	}
	if q.Text != "" {
		add("Name ≈ %s", "Ad ≈ %s", q.Text)
	}
	return out
}

// Empty reports whether no filter was recognized.
func (q Query) Empty() bool {
	return len(q.Types) == 0 && len(q.Vendors) == 0 && q.OS == "" && q.Location == "" && q.Floor == nil && q.Room == "" &&
		q.Jack == "" && q.Subnet == "" && q.IP == "" && q.MAC == "" && q.ConnectedTo == "" && q.Medium == "" &&
		q.PortChangedDays == 0 && q.NewDays == 0 && q.Status == "" && q.Managed == nil && q.Text == "" && q.VLAN == 0
}

var typeLabels = map[string][2]string{
	model.TypeRouter: {"router", "router"}, model.TypeSwitch: {"switch", "switch"}, model.TypeFirewall: {"firewall", "güvenlik duvarı"},
	model.TypeAccessPoint: {"access point", "erişim noktası"}, model.TypeWLC: {"wireless controller", "kablosuz denetleyici"},
	model.TypePrinter: {"printer", "yazıcı"}, model.TypeComputer: {"computer", "bilgisayar"}, model.TypeServer: {"server", "sunucu"},
	model.TypePhone: {"IP phone", "IP telefon"}, model.TypeCamera: {"camera", "kamera"}, model.TypeStorage: {"storage", "depolama"},
	model.TypeUPS: {"UPS", "UPS"}, model.TypeIoT: {"IoT device", "IoT cihazı"}, model.TypeVirtual: {"virtual machine", "sanal makine"},
	model.TypeMobile: {"mobile device", "mobil cihaz"}, model.TypeUnknown: {"unknown device", "bilinmeyen cihaz"},
}

// TypeLabel returns a display label for a device type.
func TypeLabel(t, lang string) string {
	l, ok := typeLabels[t]
	if !ok {
		return t
	}
	if lang == "tr" {
		return l[1]
	}
	return l[0]
}
