package api

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/events"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/explorer"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/locations"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/settings"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/topology"
)

// ---- dashboard

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{}
	byType, err := collectMaps(ctx, s, `SELECT device_type AS type, count(*) AS count FROM device_view GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out["by_type"] = byType
	out["by_vendor"], _ = collectMaps(ctx, s, `SELECT COALESCE(vendor,'Unknown') AS vendor, count(*) AS count FROM device_view GROUP BY 1 ORDER BY 2 DESC LIMIT 12`)
	out["by_os"], _ = collectMaps(ctx, s, `SELECT os_name AS os, count(*) AS count FROM devices WHERE os_name IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10`)
	totals, _ := collectMaps(ctx, s, `SELECT count(*) AS devices, count(*) FILTER (WHERE managed) AS managed,
		count(*) FILTER (WHERE managed AND status='down') AS down, count(*) FILTER (WHERE NOT managed) AS endpoints,
		count(*) FILTER (WHERE first_seen > now() - interval '24 hours') AS new_24h,
		(SELECT count(*) FROM topology_edges WHERE layer='physical') AS links,
		(SELECT count(*) FROM subnets) AS subnets,
		(SELECT count(*) FROM alerts WHERE resolved_at IS NULL) AS open_alerts,
		(SELECT count(*) FROM locations) AS locations,
		(SELECT count(*) FROM devices d LEFT JOIN device_context c ON c.device_id=d.id WHERE c.location_id IS NULL AND d.managed) AS unplaced_switches
		FROM devices`)
	if len(totals) > 0 {
		out["totals"] = totals[0]
	}
	ev, _ := events.List(ctx, s.DB, 0, 12)
	if ev == nil {
		ev = []events.Event{}
	}
	out["recent_events"] = ev
	runs, _ := collectMaps(ctx, s, `SELECT id, host(seed_ip) AS seed_ip, status, summary, created_at, finished_at FROM discovery_runs ORDER BY id DESC LIMIT 5`)
	out["recent_runs"] = runs
	out["top_ports"], _ = collectMaps(ctx, s, `SELECT i.id, d.id AS device_id, COALESCE(c.display_name, d.sys_name) AS device, i.name AS port,
		GREATEST(COALESCE(i.in_bps,0), COALESCE(i.out_bps,0)) AS bps, i.speed_bps,
		CASE WHEN i.speed_bps > 0 THEN GREATEST(COALESCE(i.in_bps,0), COALESCE(i.out_bps,0)) / i.speed_bps * 100 END AS utilization
		FROM interfaces i JOIN devices d ON d.id=i.device_id LEFT JOIN device_context c ON c.device_id=d.id
		WHERE i.in_bps IS NOT NULL ORDER BY 5 DESC LIMIT 8`)
	writeJSON(w, http.StatusOK, out)
}

// ---- topology

func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := inventory.GraphFilter{Layer: q.Get("layer"), InfraOnly: q.Get("infra_only") == "true",
		LocationID: int64(queryInt(r, "location_id", 0)), FocusDeviceID: int64(queryInt(r, "focus", 0))}
	nodes, edges, err := s.Store.Graph(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if nodes == nil {
		nodes = []topology.Node{}
	}
	if edges == nil {
		edges = []topology.Edge{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges})
}

func (s *Server) saveLayout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Positions []struct {
			ID int64   `json:"id"`
			X  float64 `json:"x"`
			Y  float64 `json:"y"`
		} `json:"positions"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, p := range req.Positions {
		if _, err := s.DB.Exec(r.Context(), `INSERT INTO topology_layout(device_id, x, y) VALUES ($1,$2,$3)
			ON CONFLICT (device_id) DO UPDATE SET x=EXCLUDED.x, y=EXCLUDED.y, pinned=true, updated_at=now()`, p.ID, p.X, p.Y); err != nil {
			writeError(w, http.StatusBadRequest, "unknown device")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) resetLayout(w http.ResponseWriter, r *http.Request) {
	if _, err := s.DB.Exec(r.Context(), `DELETE FROM topology_layout`); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) createManualLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ADeviceID   int64  `json:"a_device_id"`
		APort       string `json:"a_port"`
		BDeviceID   int64  `json:"b_device_id"`
		BPort       string `json:"b_port"`
		Medium      string `json:"medium"`
		Description string `json:"description"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ADeviceID == 0 || req.BDeviceID == 0 || req.ADeviceID == req.BDeviceID {
		writeError(w, http.StatusBadRequest, "two different devices are required")
		return
	}
	var id int64
	if err := s.DB.QueryRow(r.Context(), `INSERT INTO manual_links(a_device_id,a_port,b_device_id,b_port,medium,description) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		req.ADeviceID, nzs(req.APort), req.BDeviceID, nzs(req.BPort), nzs(req.Medium), nzs(req.Description)).Scan(&id); err != nil {
		writeError(w, http.StatusBadRequest, "unknown device")
		return
	}
	auth.Audit(r.Context(), s.DB, "topology.link.created", fmt.Sprintf("link#%d", id), nil)
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) deleteManualLink(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	_, _ = s.DB.Exec(r.Context(), `DELETE FROM manual_links WHERE id=$1`, id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func nzs(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.TrimSpace(s)
}

func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	out, err := collectMaps(r.Context(), s, `SELECT e.id, e.layer, a.id AS a_id, COALESCE(ca.display_name, a.sys_name, a.hostname, host(a.mgmt_ip)) AS a_name, e.a_port,
			b.id AS b_id, COALESCE(cb.display_name, b.sys_name, b.hostname, host(b.mgmt_ip)) AS b_name, e.b_port,
			COALESCE(cb.device_type_override, b.device_type) AS b_type, COALESCE(ca.device_type_override, a.device_type) AS a_type,
			e.medium, e.speed_bps, e.sources, e.confidence, e.updated_at, false AS manual
		FROM topology_edges e JOIN devices a ON a.id=e.a_device_id JOIN devices b ON b.id=e.b_device_id
		LEFT JOIN device_context ca ON ca.device_id=a.id LEFT JOIN device_context cb ON cb.device_id=b.id
		WHERE ($1='' OR e.medium=$1) AND ($2='' OR e.layer=$2) AND ($3 = false OR (COALESCE(ca.device_type_override, a.device_type) IN ('switch','router','firewall','access_point') AND COALESCE(cb.device_type_override, b.device_type) IN ('switch','router','firewall','access_point')))
		UNION ALL
		SELECT m.id, 'physical', a.id, COALESCE(a.sys_name, a.hostname), m.a_port, b.id, COALESCE(b.sys_name, b.hostname), m.b_port, b.device_type, a.device_type,
			m.medium, NULL, ARRAY['manual'], 1, m.created_at, true FROM manual_links m JOIN devices a ON a.id=m.a_device_id JOIN devices b ON b.id=m.b_device_id
		WHERE ($1='' OR m.medium=$1)
		ORDER BY 4, 5`, r.URL.Query().Get("medium"), r.URL.Query().Get("layer"), r.URL.Query().Get("infra") == "true")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- explorer

func (s *Server) explore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Question string `json:"question"`
	}
	if err := decode(r, &req); err != nil || strings.TrimSpace(req.Question) == "" {
		writeError(w, http.StatusBadRequest, "question is required")
		return
	}
	if len(req.Question) > 500 {
		writeError(w, http.StatusBadRequest, "question is too long")
		return
	}
	a, err := s.Explorer.Ask(r.Context(), req.Question)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Metrics.Inc("nexus_explorer_queries_total", a.Interpreter)
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) exploreQuery(w http.ResponseWriter, r *http.Request) {
	var q explorer.Query
	if err := decode(r, &q); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if q.Intent == "" {
		q.Intent = "list"
	}
	if q.Subject == "" {
		q.Subject = "devices"
	}
	if q.Lang == "" {
		q.Lang = "en"
	}
	a, err := s.Explorer.Run(r.Context(), q)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a.Interpreter = "structured"
	writeJSON(w, http.StatusOK, a)
}

// ---- locations

func (s *Server) listLocations(w http.ResponseWriter, r *http.Request) {
	l, err := s.Locations.List(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if l == nil {
		l = []locations.Location{}
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) createLocation(w http.ResponseWriter, r *http.Request) {
	var l locations.Location
	if err := decode(r, &l); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.Locations.Create(r.Context(), l)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) updateLocation(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var l locations.Location
	if err := decode(r, &l); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Locations.Update(r.Context(), id, l); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteLocation(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.Locations.Delete(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	auth.Audit(r.Context(), s.DB, "location.deleted", fmt.Sprintf("location#%d", id), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) importSysLocation(w http.ResponseWriter, r *http.Request) {
	res, err := s.Locations.ImportFromSysLocation(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	auth.Audit(r.Context(), s.DB, "location.import", "", map[string]any{"created": res.Created, "assigned": res.Assigned})
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) listRacks(w http.ResponseWriter, r *http.Request) {
	v, err := s.Locations.Racks(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if v == nil {
		v = []locations.Rack{}
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createRack(w http.ResponseWriter, r *http.Request) {
	var v locations.Rack
	if err := decode(r, &v); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.Locations.CreateRack(r.Context(), v)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) deleteRack(w http.ResponseWriter, r *http.Request) {
	id, _ := idParam(r, "id")
	_ = s.Locations.DeleteRack(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listPatchPanels(w http.ResponseWriter, r *http.Request) {
	v, err := s.Locations.PatchPanels(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if v == nil {
		v = []locations.PatchPanel{}
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createPatchPanel(w http.ResponseWriter, r *http.Request) {
	var v locations.PatchPanel
	if err := decode(r, &v); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.Locations.CreatePatchPanel(r.Context(), v)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) deletePatchPanel(w http.ResponseWriter, r *http.Request) {
	id, _ := idParam(r, "id")
	_ = s.Locations.DeletePatchPanel(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listJacks(w http.ResponseWriter, r *http.Request) {
	v, err := s.Locations.Jacks(r.Context(), int64(queryInt(r, "location_id", 0)))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if v == nil {
		v = []locations.Jack{}
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createJack(w http.ResponseWriter, r *http.Request) {
	var v locations.Jack
	if err := decode(r, &v); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.Locations.CreateJack(r.Context(), v)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) updateJack(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var v locations.Jack
	if err := decode(r, &v); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Locations.UpdateJack(r.Context(), id, v); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteJack(w http.ResponseWriter, r *http.Request) {
	id, _ := idParam(r, "id")
	_ = s.Locations.DeleteJack(r.Context(), id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- events & alerts

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	ev, err := events.List(r.Context(), s.DB, int64(queryInt(r, "device_id", 0)), queryInt(r, "limit", 300))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ev == nil {
		ev = []events.Event{}
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	a, err := events.Alerts(r.Context(), s.DB, r.URL.Query().Get("all") == "true")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if a == nil {
		a = []events.Alert{}
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) ackAlert(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := events.Acknowledge(r.Context(), s.DB, id); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listSubnets(w http.ResponseWriter, r *http.Request) {
	out, err := collectMaps(r.Context(), s, `SELECT s.cidr::text AS cidr, host(s.gateway_ip) AS gateway_ip, s.gateway_device_id, d.sys_name AS gateway, s.vlan_id, s.name,
			(SELECT count(DISTINCT a.device_id) FROM device_addresses a WHERE a.ip <<= s.cidr) AS hosts, s.last_seen
		FROM subnets s LEFT JOIN devices d ON d.id=s.gateway_device_id ORDER BY s.cidr`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listVLANs(w http.ResponseWriter, r *http.Request) {
	out, err := collectMaps(r.Context(), s, `SELECT vlan_id AS id, min(name) AS name, count(DISTINCT device_id) AS switches,
			(SELECT count(*) FROM attachments a WHERE a.vlan_id=v.vlan_id AND a.ended_at IS NULL) AS endpoints
		FROM vlans v GROUP BY vlan_id ORDER BY vlan_id`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- reports

func (s *Server) inventoryCSV(w http.ResponseWriter, r *http.Request) {
	rows, _, err := s.Store.ListDevices(r.Context(), inventory.DeviceFilter{Limit: 5000, Sort: "ip"})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="nexus-inventory.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "name", "type", "type_confidence", "vendor", "model", "os", "os_confidence", "ip", "mac", "switch", "port", "vlan", "location", "managed", "status", "first_seen", "last_seen"})
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return csvSafe(*p)
	}
	for _, d := range rows {
		vlan := ""
		if d.VLAN != nil {
			vlan = strconv.Itoa(*d.VLAN)
		}
		_ = cw.Write([]string{strconv.FormatInt(d.ID, 10), csvSafe(d.Name), d.DeviceType, fmt.Sprintf("%.2f", d.TypeConfidence), str(d.Vendor), str(d.Model),
			str(d.OSName), fmt.Sprintf("%.2f", d.OSConfidence), str(d.IP), str(d.MAC), str(d.SwitchName), str(d.SwitchPort), vlan, str(d.LocationPath),
			strconv.FormatBool(d.Managed), d.Status, d.FirstSeen.Format("2006-01-02 15:04"), d.LastSeen.Format("2006-01-02 15:04")})
	}
	cw.Flush()
}

// csvSafe neutralizes spreadsheet formula injection.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (s *Server) reportSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{}
	out["type_vendor"], _ = collectMaps(ctx, s, `SELECT device_type AS type, COALESCE(vendor,'Unknown') AS vendor, count(*) AS count FROM device_view GROUP BY 1,2 ORDER BY 1, 3 DESC`)
	out["os"], _ = collectMaps(ctx, s, `SELECT COALESCE(os_name,'Unknown') AS os, count(*) AS count, round(avg(os_confidence)::numeric,2) AS avg_confidence FROM devices WHERE NOT managed GROUP BY 1 ORDER BY 2 DESC`)
	out["legacy_os"], _ = collectMaps(ctx, s, `SELECT v.id, v.name, v.os_name, v.os_confidence, v.ip, v.location_path FROM device_view v
		WHERE v.os_name ~* '(windows (xp|2000|vista|7|nt|server 2003|server 2008))' ORDER BY v.os_name, v.name`)
	out["firmware"], _ = collectMaps(ctx, s, `SELECT COALESCE(vendor,'?') AS vendor, COALESCE(model,'?') AS model, COALESCE(os_version,'?') AS version, count(*) AS count
		FROM devices WHERE managed GROUP BY 1,2,3 ORDER BY 1,2`)
	out["port_usage"], _ = collectMaps(ctx, s, `SELECT d.id, COALESCE(c.display_name, d.sys_name) AS switch,
		count(*) FILTER (WHERE i.if_type=6) AS ports, count(*) FILTER (WHERE i.if_type=6 AND i.oper_status='up') AS up,
		count(*) FILTER (WHERE i.if_type=6 AND i.oper_status<>'up') AS free
		FROM devices d JOIN interfaces i ON i.device_id=d.id LEFT JOIN device_context c ON c.device_id=d.id WHERE d.managed GROUP BY 1,2 ORDER BY 2`)
	out["unknown_devices"], _ = collectMaps(ctx, s, `SELECT id, name, vendor, ip, mac, switch_name, switch_port FROM device_view WHERE device_type='unknown' ORDER BY name LIMIT 200`)
	writeJSON(w, http.StatusOK, out)
}

// ---- CLI

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 16384,
	CheckOrigin: func(r *http.Request) bool {
		o := r.Header.Get("Origin")
		if o == "" {
			return true
		}
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	},
}

func (s *Server) cliSocket(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	proto := r.URL.Query().Get("protocol")
	if proto == "" {
		proto = "ssh"
	}
	target, err := s.CLI.Resolve(r.Context(), id, proto)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	u := auth.UserFrom(r.Context())
	auth.Audit(r.Context(), s.DB, "cli.open", fmt.Sprintf("device#%d", id), map[string]any{"protocol": proto})
	// The session outlives the HTTP request context.
	s.CLI.Serve(context.WithoutCancel(r.Context()), ws, u, target, clientIP(r), queryInt(r, "cols", 120), queryInt(r, "rows", 32))
}

func (s *Server) listCLISessions(w http.ResponseWriter, r *http.Request) {
	out, err := collectMaps(r.Context(), s, `SELECT c.id, c.username, c.device_id, COALESCE(d.sys_name, host(d.mgmt_ip)) AS device, c.protocol, c.remote_addr, c.client_addr,
		c.started_at, c.ended_at, c.end_reason, c.bytes_in, c.bytes_out FROM cli_sessions c LEFT JOIN devices d ON d.id=c.device_id ORDER BY c.id DESC LIMIT 200`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) cliTranscript(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var t []byte
	if err := s.DB.QueryRow(r.Context(), `SELECT COALESCE(transcript, ''::bytea) FROM cli_sessions WHERE id=$1`, id).Scan(&t); err != nil {
		s.fail(w, r, err)
		return
	}
	auth.Audit(r.Context(), s.DB, "cli.transcript.viewed", fmt.Sprintf("cli_session#%d", id), nil)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(t)
}

func (s *Server) terminateCLI(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ok := s.CLI.Terminate(id)
	auth.Audit(r.Context(), s.DB, "cli.terminated", fmt.Sprintf("cli_session#%d", id), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"terminated": ok})
}

// ---- settings

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Settings.Get(r.Context()))
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var st settings.Settings
	if err := decode(r, &st); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Settings.Put(r.Context(), st); err != nil {
		s.fail(w, r, err)
		return
	}
	auth.Audit(r.Context(), s.DB, "settings.updated", "", map[string]any{"telnet_allowed": st.TelnetAllowed, "active_fingerprinting": st.ActiveFingerprinting})
	writeJSON(w, http.StatusOK, s.Settings.Get(r.Context()))
}
