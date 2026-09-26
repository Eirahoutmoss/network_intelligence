package explorer

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/topology"
)

// Connection is a link in a connections answer.
type Connection struct {
	A          string   `json:"a"`
	AID        int64    `json:"a_id"`
	APort      string   `json:"a_port"`
	B          string   `json:"b"`
	BID        int64    `json:"b_id"`
	BPort      string   `json:"b_port"`
	Medium     string   `json:"medium"`
	SpeedBps   int64    `json:"speed_bps"`
	Sources    []string `json:"sources"`
	Confidence float64  `json:"confidence"`
}

// JackInfo describes a wall jack and what is behind it.
type JackInfo struct {
	ID         int64  `json:"id"`
	Label      string `json:"label"`
	Location   string `json:"location"`
	PatchPanel string `json:"patch_panel,omitempty"`
	PatchPort  *int   `json:"patch_port,omitempty"`
	Switch     string `json:"switch,omitempty"`
	SwitchID   *int64 `json:"switch_id,omitempty"`
	Port       string `json:"port,omitempty"`
	SeenCount  *int   `json:"seen_count,omitempty"`
}

// Answer is the explorer response. Every number in Text comes from Devices,
// Connections or Jacks — never from the interpreter.
type Answer struct {
	Question       string                `json:"question"`
	Query          Query                 `json:"query"`
	Interpretation []string              `json:"interpretation"`
	Interpreter    string                `json:"interpreter"` // rules|llm
	Text           string                `json:"text"`
	Count          int                   `json:"count"`
	Devices        []inventory.DeviceRow `json:"devices,omitempty"`
	Connections    []Connection          `json:"connections,omitempty"`
	Jacks          []JackInfo            `json:"jacks,omitempty"`
	Notes          []string              `json:"notes,omitempty"`
	Sources        []string              `json:"sources"`
	Recognized     bool                  `json:"recognized"`
	Suggestions    []string              `json:"suggestions,omitempty"`
}

// Explorer answers questions.
type Explorer struct {
	Store *inventory.Store
	LLM   Interpreter // optional
	Log   *slog.Logger
}

type location struct {
	id        int64
	name      string
	kind      string
	level     *int
	ancestors []int64
	path      string
}

func (e *Explorer) locations(ctx context.Context) ([]location, error) {
	rows, err := e.Store.DB.Query(ctx, `SELECT id, name, kind, level, ancestors, path FROM location_paths`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (location, error) {
		var l location
		err := r.Scan(&l.id, &l.name, &l.kind, &l.level, &l.ancestors, &l.path)
		return l, err
	})
}

// Vocabulary loads names known in the inventory.
func (e *Explorer) Vocabulary(ctx context.Context) (Vocabulary, error) {
	var v Vocabulary
	q := func(sql string) ([]string, error) {
		rows, err := e.Store.DB.Query(ctx, sql)
		if err != nil {
			return nil, err
		}
		return pgx.CollectRows(rows, pgx.RowTo[string])
	}
	var err error
	if v.Vendors, err = q(`SELECT DISTINCT vendor FROM device_view WHERE vendor IS NOT NULL`); err != nil {
		return v, err
	}
	if v.OSNames, err = q(`SELECT DISTINCT os_name FROM devices WHERE os_name IS NOT NULL`); err != nil {
		return v, err
	}
	if v.Devices, err = q(`SELECT DISTINCT n FROM (SELECT name AS n FROM device_view WHERE managed OR device_type IN ('switch','router','firewall','access_point','server','printer')
		UNION SELECT sys_name FROM devices WHERE sys_name IS NOT NULL UNION SELECT display_name FROM device_context WHERE display_name IS NOT NULL) x WHERE n IS NOT NULL`); err != nil {
		return v, err
	}
	if v.Locations, err = q(`SELECT DISTINCT name FROM locations`); err != nil {
		return v, err
	}
	return v, nil
}

var reNumber = regexp.MustCompile(`\d+`)

// Ask interprets and answers a question.
func (e *Explorer) Ask(ctx context.Context, question string) (*Answer, error) {
	v, err := e.Vocabulary(ctx)
	if err != nil {
		return nil, err
	}
	q := Parse(question, v)
	interp := "rules"
	if q.Empty() && e.LLM != nil {
		if lq, err := e.LLM.Interpret(ctx, question, v); err == nil && !lq.Empty() {
			q, interp = lq, "llm"
		} else if err != nil && e.Log != nil {
			e.Log.Warn("llm interpreter failed; using rules", "err", err)
		}
	}
	a, err := e.Run(ctx, q)
	if err != nil {
		return nil, err
	}
	a.Question, a.Interpreter = question, interp
	return a, nil
}

// Run executes a structured query (also used directly by the structured filter UI).
func (e *Explorer) Run(ctx context.Context, q Query) (*Answer, error) {
	a := &Answer{Query: q, Interpretation: q.Describe(), Recognized: !q.Empty()}
	tr := q.Lang == "tr"
	a.Sources = e.sources(ctx, tr)
	if q.Empty() {
		a.Text = pick(tr, "Soruyu anlayamadım. Aşağıdaki örneklerden birini deneyin ya da filtreleri kullanın.",
			"I could not interpret the question. Try one of the examples below or use the filters.")
		a.Suggestions = suggestions(tr)
		return a, nil
	}
	switch q.Subject {
	case "connections":
		return a, e.runConnections(ctx, q, a)
	case "jack":
		return a, e.runJack(ctx, q, a)
	}
	f := inventory.DeviceFilter{Types: q.Types, Vendors: q.Vendors, OS: q.OS, Subnet: q.Subnet, IP: q.IP, MAC: q.MAC, VLAN: q.VLAN,
		Status: q.Status, Managed: q.Managed, PortChangedDays: q.PortChangedDays, NewDays: q.NewDays, Text: q.Text, Limit: 1000}
	// locations
	if q.Location != "" || q.Floor != nil || q.Room != "" {
		ids, desc, err := e.resolveLocations(ctx, q)
		if err != nil {
			return nil, err
		}
		f.LocationIDs, f.RestrictLoc = ids, true
		if len(ids) == 0 {
			a.Notes = append(a.Notes, pick(tr,
				fmt.Sprintf("'%s' ile eşleşen bir konum tanımlı değil. Konumları Locations sayfasından ekleyebilirsiniz.", desc),
				fmt.Sprintf("No location matching '%s' is defined yet. Add locations on the Locations page.", desc)))
		}
	}
	// connected-to / downstream
	if q.ConnectedTo != "" {
		ids, err := e.connected(ctx, q.ConnectedTo, q.Downstream)
		if err != nil {
			return nil, err
		}
		f.IDs, f.RestrictIDs = ids, true
	}
	rows, total, err := e.Store.ListDevices(ctx, f)
	if err != nil {
		return nil, err
	}
	a.Devices, a.Count = rows, total
	a.Text = deviceAnswer(q, total)
	low := 0
	for _, d := range rows {
		if (len(q.Types) > 0 && d.TypeConfidence < 0.6 && !d.TypeOverridden) || (q.OS != "" && d.OSConfidence < 0.6) {
			low++
		}
	}
	if low > 0 {
		a.Notes = append(a.Notes, pick(tr,
			fmt.Sprintf("%d sonucun sınıflandırması düşük güvenlidir (<%%60); ayrıntılar için cihazın kanıtlarına bakın.", low),
			fmt.Sprintf("%d result(s) rely on low-confidence classification (<60%%); check the device evidence.", low)))
	}
	if total > len(rows) {
		a.Notes = append(a.Notes, pick(tr, fmt.Sprintf("İlk %d sonuç gösteriliyor.", len(rows)), fmt.Sprintf("Showing the first %d results.", len(rows))))
	}
	return a, nil
}

func pick(tr bool, t, e string) string {
	if tr {
		return t
	}
	return e
}

func suggestions(tr bool) []string {
	if tr {
		return []string{"Kaç switch var?", "HP yazıcıları göster", "Laboratuvarda Windows XP kullanan cihazları göster",
			"SW-CORE-01'e bağlı cihazları göster", "10.20.30.0/24 ağında ne var?", "Fiber bağlantıları göster",
			"Son 30 günde switch portu değişen cihazları göster", "Kat 2'de kaç switch var?"}
	}
	return []string{"How many switches are there?", "Show HP printers", "Windows XP devices in the lab",
		"Devices connected to SW-CORE-01", "What is in 10.20.30.0/24?", "Show fiber links", "Devices that changed switch port in the last 30 days"}
}

func (e *Explorer) sources(ctx context.Context, tr bool) []string {
	var last *time.Time
	var n int
	_ = e.Store.DB.QueryRow(ctx, `SELECT max(finished_at) FILTER (WHERE status='completed'), count(*) FILTER (WHERE status='completed') FROM discovery_runs`).Scan(&last, &n)
	var devices int
	_ = e.Store.DB.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&devices)
	if last == nil {
		return []string{pick(tr, "Henüz tamamlanmış keşif yok — sonuçlar boş olabilir.", "No completed discovery yet — results may be empty.")}
	}
	ago := time.Since(*last).Round(time.Minute)
	return []string{pick(tr,
		fmt.Sprintf("Kaynak: envanter veritabanı (%d cihaz), son keşif %s önce", devices, humanDur(ago, true)),
		fmt.Sprintf("Source: inventory database (%d devices), last discovery %s ago", devices, humanDur(ago, false)))}
}

func humanDur(d time.Duration, tr bool) string {
	switch {
	case d < time.Minute:
		return pick(tr, "1 dakikadan az", "less than a minute")
	case d < time.Hour:
		return fmt.Sprintf("%d %s", int(d.Minutes()), pick(tr, "dk", "min"))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d %s", int(d.Hours()), pick(tr, "saat", "h"))
	}
	return fmt.Sprintf("%d %s", int(d.Hours()/24), pick(tr, "gün", "days"))
}

func deviceAnswer(q Query, n int) string {
	tr := q.Lang == "tr"
	subject := pick(tr, "cihaz", "devices")
	if len(q.Types) == 1 {
		subject = TypeLabel(q.Types[0], q.Lang)
		if !tr && n != 1 {
			subject += "s"
		}
	}
	if len(q.Vendors) > 0 {
		subject = strings.Join(q.Vendors, "/") + " " + subject
	}
	if q.OS != "" {
		subject += pick(tr, " ("+q.OS+")", " running "+q.OS)
	}
	switch {
	case q.ConnectedTo != "" && q.Downstream:
		return pick(tr, fmt.Sprintf("%s arkasında %d %s var.", q.ConnectedTo, n, subject),
			fmt.Sprintf("%d %s behind %s.", n, subject, q.ConnectedTo))
	case q.ConnectedTo != "":
		return pick(tr, fmt.Sprintf("%s cihazına doğrudan bağlı %d %s var.", q.ConnectedTo, n, subject),
			fmt.Sprintf("%d %s directly connected to %s.", n, subject, q.ConnectedTo))
	case q.PortChangedDays > 0:
		return pick(tr, fmt.Sprintf("Son %d günde switch portu değişen %d %s var.", q.PortChangedDays, n, subject),
			fmt.Sprintf("%d %s changed switch port in the last %d days.", n, subject, q.PortChangedDays))
	case n == 0:
		return pick(tr, fmt.Sprintf("Eşleşen %s bulunamadı.", subject), fmt.Sprintf("No matching %s found.", subject))
	case q.Intent == "count":
		return pick(tr, fmt.Sprintf("Toplam %d %s var.", n, subject), fmt.Sprintf("There are %d %s.", n, subject))
	}
	return pick(tr, fmt.Sprintf("%d %s bulundu.", n, subject), fmt.Sprintf("Found %d %s.", n, subject))
}

// resolveLocations returns location ids (with subtrees) matching the query.
func (e *Explorer) resolveLocations(ctx context.Context, q Query) ([]int64, string, error) {
	locs, err := e.locations(ctx)
	if err != nil {
		return nil, "", err
	}
	match := func(pred func(location) bool) map[int64]bool {
		roots := map[int64]bool{}
		for _, l := range locs {
			if pred(l) {
				roots[l.id] = true
			}
		}
		// expand to subtrees
		out := map[int64]bool{}
		for _, l := range locs {
			for _, anc := range l.ancestors {
				if roots[anc] {
					out[l.id] = true
				}
			}
		}
		return out
	}
	var sets []map[int64]bool
	var desc []string
	if q.Location != "" {
		term := fold(q.Location)
		sets = append(sets, match(func(l location) bool { return strings.Contains(fold(l.name), term) }))
		desc = append(desc, q.Location)
	}
	if q.Floor != nil {
		n := *q.Floor
		sets = append(sets, match(func(l location) bool {
			if l.kind != "floor" {
				return false
			}
			if l.level != nil {
				return *l.level == n
			}
			for _, m := range reNumber.FindAllString(l.name, -1) {
				if v, _ := strconv.Atoi(m); v == n {
					return true
				}
			}
			return false
		}))
		desc = append(desc, fmt.Sprintf("floor %d", n))
	}
	if q.Room != "" {
		term := fold(q.Room)
		sets = append(sets, match(func(l location) bool {
			if l.kind != "room" && l.kind != "closet" && l.kind != "area" {
				return false
			}
			name := fold(l.name)
			return name == term || strings.Contains(name, term) && reNumber.MatchString(term)
		}))
		desc = append(desc, "room "+q.Room)
	}
	var ids []int64
	for id := range sets[0] {
		ok := true
		for _, s := range sets[1:] {
			ok = ok && s[id]
		}
		if ok {
			ids = append(ids, id)
		}
	}
	return ids, strings.Join(desc, ", "), nil
}

func (e *Explorer) deviceByName(ctx context.Context, name string) (int64, error) {
	var id int64
	err := e.Store.DB.QueryRow(ctx, `SELECT d.id FROM devices d LEFT JOIN device_context c ON c.device_id=d.id
		WHERE lower(c.display_name)=lower($1) OR lower(d.sys_name)=lower($1) OR lower(d.hostname)=lower($1)
		ORDER BY d.managed DESC, d.id LIMIT 1`, name).Scan(&id)
	return id, err
}

func (e *Explorer) connected(ctx context.Context, name string, downstream bool) ([]int64, error) {
	id, err := e.deviceByName(ctx, name)
	if err != nil {
		return []int64{}, nil
	}
	nodes, edges, err := e.Store.Graph(ctx, inventory.GraphFilter{Layer: "physical"})
	if err != nil {
		return nil, err
	}
	if !downstream {
		return topology.Neighbors(edges, id), nil
	}
	levels := map[int64]int{}
	for _, n := range nodes {
		levels[n.ID] = n.Level
	}
	return topology.Downstream(edges, levels, id), nil
}

func (e *Explorer) runConnections(ctx context.Context, q Query, a *Answer) error {
	tr := q.Lang == "tr"
	rows, err := e.Store.DB.Query(ctx, `SELECT a.id, COALESCE(ca.display_name, a.sys_name, host(a.mgmt_ip), '#'||a.id), COALESCE(e.a_port,''),
			b.id, COALESCE(cb.display_name, b.sys_name, b.hostname, '#'||b.id), COALESCE(e.b_port,''), COALESCE(e.medium,'unknown'),
			COALESCE(e.speed_bps,0), e.sources, e.confidence
		FROM topology_edges e JOIN devices a ON a.id=e.a_device_id JOIN devices b ON b.id=e.b_device_id
		LEFT JOIN device_context ca ON ca.device_id=a.id LEFT JOIN device_context cb ON cb.device_id=b.id
		WHERE e.layer='physical' AND ($1 = '' OR e.medium = $1)
		UNION ALL
		SELECT a.id, COALESCE(a.sys_name, '#'||a.id), COALESCE(m.a_port,''), b.id, COALESCE(b.sys_name, b.hostname, '#'||b.id), COALESCE(m.b_port,''),
			COALESCE(m.medium,'unknown'), 0, ARRAY['manual'], 1
		FROM manual_links m JOIN devices a ON a.id=m.a_device_id JOIN devices b ON b.id=m.b_device_id WHERE ($1 = '' OR m.medium = $1)
		ORDER BY 2, 3`, q.Medium)
	if err != nil {
		return err
	}
	conns, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Connection, error) {
		var c Connection
		err := r.Scan(&c.AID, &c.A, &c.APort, &c.BID, &c.B, &c.BPort, &c.Medium, &c.SpeedBps, &c.Sources, &c.Confidence)
		return c, err
	})
	if err != nil {
		return err
	}
	a.Connections, a.Count = conns, len(conns)
	m := q.Medium
	if tr {
		m = map[string]string{"fiber": "fiber", "copper": "bakır", "": ""}[q.Medium]
	}
	a.Text = pick(tr, fmt.Sprintf("%d %s bağlantı bulundu.", len(conns), m), fmt.Sprintf("Found %d %s links.", len(conns), m))
	a.Notes = append(a.Notes, pick(tr, "Ortam bilgisi takılı SFP modülleri ve port açıklamalarından çıkarılır; tespit edilemeyen bağlantılar 'unknown' görünür.",
		"Medium is derived from installed transceivers and port descriptions; undetermined links show as 'unknown'."))
	return nil
}

func (e *Explorer) runJack(ctx context.Context, q Query, a *Answer) error {
	tr := q.Lang == "tr"
	rows, err := e.Store.DB.Query(ctx, `SELECT j.id, j.label, lp.path, COALESCE(pp.name,''), j.patch_port, COALESCE(sw.sys_name,''), j.switch_device_id,
			COALESCE(i.name,''), j.switch_interface_id, COALESCE(lp.room,''), lp.name
		FROM network_jacks j JOIN location_paths lp ON lp.id=j.location_id
		LEFT JOIN patch_panels pp ON pp.id=j.patch_panel_id LEFT JOIN devices sw ON sw.id=j.switch_device_id
		LEFT JOIN interfaces i ON i.id=j.switch_interface_id`)
	if err != nil {
		return err
	}
	type jr struct {
		JackInfo
		ifID    *int64
		room    string
		locName string
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (jr, error) {
		var j jr
		err := r.Scan(&j.ID, &j.Label, &j.Location, &j.PatchPanel, &j.PatchPort, &j.Switch, &j.SwitchID, &j.Port, &j.ifID, &j.room, &j.locName)
		return j, err
	})
	if err != nil {
		return err
	}
	jack := strings.TrimLeft(fold(q.Jack), "0")
	room := fold(q.Room)
	var matched []jr
	for _, j := range all {
		label := fold(j.Label)
		lbl := strings.TrimLeft(label, "0")
		okJack := lbl == jack || strings.HasSuffix(label, "-"+q.Jack) || strings.HasSuffix(label, "-"+jack) || label == fold(q.Room+"-"+q.Jack)
		okRoom := room == "" || strings.Contains(fold(j.room), room) || strings.Contains(fold(j.Location), room) || strings.HasPrefix(label, room)
		if okJack && okRoom {
			matched = append(matched, j)
		}
	}
	if len(matched) == 0 {
		a.Text = pick(tr, fmt.Sprintf("'%s' için tanımlı bir priz bulunamadı. Prizleri Locations sayfasında switch portlarıyla eşleştirebilirsiniz.", strings.TrimSpace(q.Room+" "+q.Jack)),
			fmt.Sprintf("No wall jack '%s' is defined. Map jacks to switch ports on the Locations page.", strings.TrimSpace(q.Room+" "+q.Jack)))
		return nil
	}
	var ids []int64
	for _, j := range matched {
		info := j.JackInfo
		if j.ifID != nil && q.SeenDays > 0 {
			var n int
			if err := e.Store.DB.QueryRow(ctx, `SELECT count(DISTINCT device_id) FROM attachments WHERE interface_id=$1
				AND COALESCE(ended_at, now()) >= now() - make_interval(days => $2)`, *j.ifID, q.SeenDays).Scan(&n); err != nil {
				return err
			}
			info.SeenCount = &n
		}
		a.Jacks = append(a.Jacks, info)
		if j.ifID != nil {
			r, err := e.Store.DB.Query(ctx, `SELECT device_id FROM attachments WHERE interface_id=$1 AND ended_at IS NULL`, *j.ifID)
			if err != nil {
				return err
			}
			more, err := pgx.CollectRows(r, pgx.RowTo[int64])
			if err != nil {
				return err
			}
			ids = append(ids, more...)
		}
	}
	devs, total, err := e.Store.ListDevices(ctx, inventory.DeviceFilter{IDs: ids, RestrictIDs: true})
	if err != nil {
		return err
	}
	a.Devices, a.Count = devs, total
	j := a.Jacks[0]
	path := j.Location + " / " + j.Label
	chain := ""
	if j.PatchPanel != "" && j.PatchPort != nil {
		chain = fmt.Sprintf(" → %s / %d", j.PatchPanel, *j.PatchPort)
	}
	if j.Switch != "" {
		chain += " → " + j.Switch + " / " + j.Port
	}
	switch {
	case j.SeenCount != nil:
		a.Count = *j.SeenCount
		a.Text = pick(tr, fmt.Sprintf("%s%s: son %d günde %d farklı cihaz görüldü.", path, chain, q.SeenDays, *j.SeenCount),
			fmt.Sprintf("%s%s: %d distinct devices seen in the last %d days.", path, chain, *j.SeenCount, q.SeenDays))
	case j.Switch == "":
		a.Text = pick(tr, fmt.Sprintf("%s henüz bir switch portuyla eşleştirilmemiş.", path), fmt.Sprintf("%s is not mapped to a switch port yet.", path))
	case total == 0:
		a.Text = pick(tr, fmt.Sprintf("%s%s: şu anda bağlı cihaz görünmüyor.", path, chain), fmt.Sprintf("%s%s: no device currently seen.", path, chain))
	default:
		a.Text = pick(tr, fmt.Sprintf("%s%s: %d cihaz bağlı.", path, chain, total), fmt.Sprintf("%s%s: %d device(s) connected.", path, chain, total))
	}
	return nil
}
