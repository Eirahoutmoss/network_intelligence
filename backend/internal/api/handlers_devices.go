package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/discovery"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/events"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/locations"
)

func chiID(r *http.Request) string { return chi.URLParam(r, "id") }

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := inventory.DeviceFilter{Text: q.Get("q"), OS: q.Get("os"), Status: q.Get("status"), Subnet: q.Get("subnet"),
		Tag: q.Get("tag"), Sort: q.Get("sort"), Limit: queryInt(r, "limit", 200), Offset: queryInt(r, "offset", 0),
		SwitchID: int64(queryInt(r, "switch_id", 0)), NewDays: queryInt(r, "new_days", 0), PortChangedDays: queryInt(r, "moved_days", 0),
		VLAN: queryInt(r, "vlan", 0)}
	if t := q.Get("type"); t != "" {
		f.Types = strings.Split(t, ",")
	}
	if v := q.Get("vendor"); v != "" {
		f.Vendors = strings.Split(v, ",")
	}
	switch q.Get("managed") {
	case "true":
		b := true
		f.Managed = &b
	case "false":
		b := false
		f.Managed = &b
	}
	if f.Subnet != "" {
		if _, n, err := net.ParseCIDR(f.Subnet); err == nil {
			f.Subnet = n.String()
		} else {
			writeError(w, http.StatusBadRequest, "invalid subnet")
			return
		}
	}
	if loc := queryInt(r, "location_id", 0); loc != 0 {
		rows, err := s.DB.Query(r.Context(), `SELECT id FROM location_paths WHERE $1 = ANY(ancestors)`, loc)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		f.LocationIDs, _ = pgx.CollectRows(rows, pgx.RowTo[int64])
		f.RestrictLoc = true
	}
	rows, total, err := s.Store.ListDevices(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rows == nil {
		rows = []inventory.DeviceRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": rows, "total": total})
}

type evidenceItem struct {
	Attribute string  `json:"attribute"`
	Value     string  `json:"value"`
	Source    string  `json:"source"`
	Detail    *string `json:"detail"`
	Weight    float64 `json:"weight"`
}

type deviceDetail struct {
	inventory.DeviceRow
	Facts       map[string]any            `json:"facts"`
	Addresses   []map[string]any          `json:"addresses"`
	MACs        []map[string]any          `json:"macs"`
	Hostnames   []map[string]any          `json:"hostnames"`
	Evidence    map[string][]evidenceItem `json:"evidence"`
	Context     locations.DeviceContext   `json:"context"`
	History     []map[string]any          `json:"attachment_history"`
	Sensors     []map[string]any          `json:"sensors"`
	Inventory   []map[string]any          `json:"inventory"`
	Fingerprint json.RawMessage           `json:"fingerprint"`
	Access      map[string]any            `json:"access"`
	Stats       map[string]int            `json:"stats"`
}

func collectMaps(ctx context.Context, s *Server, sql string, args ...any) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToMap)
	if out == nil {
		out = []map[string]any{}
	}
	return out, err
}

func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ctx := r.Context()
	row, err := s.Store.GetDeviceRow(ctx, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := deviceDetail{DeviceRow: row, Evidence: map[string][]evidenceItem{}}
	facts, err := collectMaps(ctx, s, `SELECT sys_name, sys_descr, sys_object_id, sys_contact, sys_location, serial, os_version, hardware_rev,
			host(mgmt_ip) AS mgmt_ip, uptime_seconds, cpu_percent, memory_percent, chassis_id, is_router, is_bridge, is_printer,
			oui_vendor, random_mac, vendor_source, vendor_confidence, last_discovered_at, last_polled_at, fingerprinted_at, discovered_via
		FROM devices WHERE id=$1`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(facts) > 0 {
		d.Facts = facts[0]
	}
	steps := []struct {
		dst *[]map[string]any
		sql string
	}{
		{&d.Addresses, `SELECT host(ip) AS ip, prefix_len, source, first_seen, last_seen FROM device_addresses WHERE device_id=$1 ORDER BY source='snmp' DESC, ip`},
		{&d.MACs, `SELECT mac::text AS mac, source, first_seen, last_seen FROM device_macs WHERE device_id=$1 ORDER BY source='snmp' DESC, mac`},
		{&d.Hostnames, `SELECT name, source, last_seen FROM device_hostnames WHERE device_id=$1 ORDER BY source`},
		{&d.History, `SELECT a.id, COALESCE(c.display_name, s.sys_name) AS switch, a.switch_id, a.port_name AS port, a.vlan_id AS vlan, a.source, a.confidence,
			a.started_at, a.last_seen, a.ended_at FROM attachments a JOIN devices s ON s.id=a.switch_id LEFT JOIN device_context c ON c.device_id=s.id
			WHERE a.device_id=$1 ORDER BY a.started_at DESC LIMIT 50`},
		{&d.Sensors, `SELECT kind, name, value, unit, status, updated_at FROM sensors WHERE device_id=$1 ORDER BY kind, name`},
		{&d.Inventory, `SELECT ent_index, parent_index, class, name, descr, model, serial, hw_rev, fw_rev, sw_rev, manufacturer FROM inventory_items
			WHERE device_id=$1 AND (class IN ('chassis','module','powerSupply','fan','stack','cpu') OR serial IS NOT NULL) ORDER BY ent_index`},
	}
	for _, st := range steps {
		if *st.dst, err = collectMaps(ctx, s, st.sql, id); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	ev, err := s.DB.Query(ctx, `SELECT attribute, value, source, detail, weight FROM evidence WHERE device_id=$1 ORDER BY attribute, weight DESC`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(ev, pgx.RowToStructByPos[evidenceItem])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, e := range items {
		d.Evidence[e.Attribute] = append(d.Evidence[e.Attribute], e)
	}
	if d.Context, err = s.Locations.GetContext(ctx, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var fp []byte
	var sshCred, telnetCred *int64
	var telnetEnabled bool
	var hostKey *string
	if err := s.DB.QueryRow(ctx, `SELECT fingerprint, ssh_credential_id, telnet_credential_id, telnet_enabled, ssh_host_key FROM devices WHERE id=$1`, id).
		Scan(&fp, &sshCred, &telnetCred, &telnetEnabled, &hostKey); err != nil {
		s.fail(w, r, err)
		return
	}
	d.Fingerprint = fp
	d.Access = map[string]any{"ssh_credential_id": sshCred, "telnet_credential_id": telnetCred, "telnet_enabled": telnetEnabled,
		"ssh_host_key": hostKey, "telnet_allowed": s.Settings.Get(ctx).TelnetAllowed}
	d.Stats = map[string]int{}
	for k, q := range map[string]string{
		"interfaces":    `SELECT count(*) FROM interfaces WHERE device_id=$1`,
		"interfaces_up": `SELECT count(*) FROM interfaces WHERE device_id=$1 AND oper_status='up'`,
		"neighbors":     `SELECT count(*) FROM neighbors WHERE device_id=$1`,
		"endpoints":     `SELECT count(*) FROM attachments WHERE switch_id=$1 AND ended_at IS NULL`,
		"fdb":           `SELECT count(*) FROM fdb_entries WHERE device_id=$1`,
		"arp":           `SELECT count(*) FROM arp_entries WHERE device_id=$1`,
		"routes":        `SELECT count(*) FROM routes WHERE device_id=$1`,
		"vlans":         `SELECT count(*) FROM vlans WHERE device_id=$1`,
		"open_alerts":   `SELECT count(*) FROM alerts WHERE device_id=$1 AND resolved_at IS NULL`,
	} {
		var n int
		_ = s.DB.QueryRow(ctx, q, id).Scan(&n)
		d.Stats[k] = n
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) deviceInterfaces(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	out, err := collectMaps(r.Context(), s, `SELECT i.id, i.if_index, i.name, i.descr, i.alias, i.if_type, i.mtu, i.speed_bps, i.mac::text AS mac,
			i.admin_status, i.oper_status, i.duplex, i.medium, i.pvid, i.in_bps, i.out_bps, i.in_errors::float8 AS in_errors, i.out_errors::float8 AS out_errors,
			i.is_uplink, i.last_change_seconds, i.updated_at,
			(SELECT jsonb_build_object('vendor',o.vendor,'part_number',o.part_number,'serial',o.serial,'type',o.module_type,'rx_dbm',o.rx_dbm,'tx_dbm',o.tx_dbm)
				FROM optics o WHERE o.interface_id=i.id) AS optic,
			(SELECT COALESCE(array_agg(v.vlan_id ORDER BY v.vlan_id), '{}') FROM interface_vlans v WHERE v.interface_id=i.id) AS vlans,
			(SELECT jsonb_build_object('device_id', n.remote_device_id, 'name', COALESCE(n.remote_sys_name, n.remote_chassis_id), 'port', n.remote_port_id, 'protocol', n.protocol)
				FROM neighbors n WHERE n.local_interface_id=i.id LIMIT 1) AS neighbor,
			(SELECT count(*) FROM attachments a WHERE a.interface_id=i.id AND a.ended_at IS NULL) AS attached,
			(SELECT count(DISTINCT f.mac) FROM fdb_entries f WHERE f.interface_id=i.id) AS mac_count,
			(SELECT j.label FROM network_jacks j WHERE j.switch_interface_id=i.id LIMIT 1) AS jack
		FROM interfaces i WHERE i.device_id=$1 ORDER BY i.if_index`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deviceNeighbors(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	out, err := collectMaps(r.Context(), s, `SELECT n.id, n.protocol, n.local_port, n.remote_chassis_id, n.remote_port_id, n.remote_port_descr, n.remote_sys_name,
			n.remote_sys_descr, n.remote_platform, host(n.remote_mgmt_ip) AS remote_mgmt_ip, n.remote_capabilities, n.remote_device_id, n.first_seen, n.last_seen,
			d.device_type AS remote_type, d.managed AS remote_managed
		FROM neighbors n LEFT JOIN devices d ON d.id=n.remote_device_id WHERE n.device_id=$1 ORDER BY n.local_port`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deviceEndpoints(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rows, _, err := s.Store.ListDevices(r.Context(), inventory.DeviceFilter{SwitchID: id, Sort: "switch", Limit: 2000})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rows == nil {
		rows = []inventory.DeviceRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

var tableQueries = map[string]string{
	"fdb": `SELECT f.mac::text AS mac, f.vlan_id AS vlan, i.name AS port, f.status, f.first_seen, f.last_seen, v.id AS device_id, v.name AS device
		FROM fdb_entries f LEFT JOIN interfaces i ON i.id=f.interface_id LEFT JOIN device_macs m ON m.mac=f.mac LEFT JOIN device_view v ON v.id=m.device_id
		WHERE f.device_id=$1 ORDER BY i.if_index, f.vlan_id, f.mac LIMIT 20000`,
	"arp": `SELECT host(a.ip) AS ip, a.mac::text AS mac, i.name AS interface, a.first_seen, a.last_seen, v.id AS device_id, v.name AS device
		FROM arp_entries a LEFT JOIN interfaces i ON i.id=a.interface_id LEFT JOIN device_macs m ON m.mac=a.mac LEFT JOIN device_view v ON v.id=m.device_id
		WHERE a.device_id=$1 ORDER BY a.ip LIMIT 20000`,
	"routes": `SELECT destination::text AS destination, host(next_hop) AS next_hop, if_index, protocol, metric FROM routes WHERE device_id=$1 ORDER BY destination`,
	"vlans":  `SELECT vlan_id AS id, name, (SELECT count(*) FROM interface_vlans iv JOIN interfaces i ON i.id=iv.interface_id WHERE i.device_id=$1 AND iv.vlan_id=v.vlan_id) AS ports FROM vlans v WHERE device_id=$1 ORDER BY vlan_id`,
	"raw":    `SELECT sys_descr, sys_object_id, chassis_id, fingerprint FROM devices WHERE id=$1`,
}

func (s *Server) deviceTable(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	q, ok := tableQueries[chi.URLParam(r, "table")]
	if !ok {
		writeError(w, http.StatusNotFound, "unknown table")
		return
	}
	out, err := collectMaps(r.Context(), s, q, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deviceEvents(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ev, err := events.List(r.Context(), s.DB, id, queryInt(r, "limit", 100))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ev == nil {
		ev = []events.Event{}
	}
	writeJSON(w, http.StatusOK, ev)
}

func (s *Server) interfaceMetrics(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	hours := queryInt(r, "hours", 24)
	out, err := collectMaps(r.Context(), s, `SELECT ts, in_bps, out_bps FROM interface_metrics WHERE interface_id=$1 AND ts > now() - make_interval(hours => $2) ORDER BY ts`, id, hours)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) setContext(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var c locations.DeviceContext
	if err := decode(r, &c); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Locations.SetContext(r.Context(), id, c); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auth.Audit(r.Context(), s.DB, "device.context", fmt.Sprintf("device#%d", id), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) setAccess(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		SSHCredentialID    *int64 `json:"ssh_credential_id"`
		TelnetCredentialID *int64 `json:"telnet_credential_id"`
		TelnetEnabled      bool   `json:"telnet_enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.TelnetEnabled && !auth.UserFrom(r.Context()).Can(auth.RoleAdmin) {
		writeError(w, http.StatusForbidden, "only admins can enable Telnet")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `UPDATE devices SET ssh_credential_id=$2, telnet_credential_id=$3, telnet_enabled=$4 WHERE id=$1`,
		id, req.SSHCredentialID, req.TelnetCredentialID, req.TelnetEnabled); err != nil {
		writeError(w, http.StatusBadRequest, "invalid credential")
		return
	}
	auth.Audit(r.Context(), s.DB, "device.access", fmt.Sprintf("device#%d", id), map[string]any{"telnet_enabled": req.TelnetEnabled})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) assignLocation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceIDs  []int64 `json:"device_ids"`
		LocationID *int64  `json:"location_id"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Locations.SetDeviceLocation(r.Context(), req.DeviceIDs, req.LocationID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `DELETE FROM devices WHERE id=$1`, id); err != nil {
		s.fail(w, r, err)
		return
	}
	auth.Audit(r.Context(), s.DB, "device.deleted", fmt.Sprintf("device#%d", id), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) resetHostKey(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `UPDATE devices SET ssh_host_key=NULL WHERE id=$1`, id); err != nil {
		s.fail(w, r, err)
		return
	}
	auth.Audit(r.Context(), s.DB, "device.ssh_host_key.reset", fmt.Sprintf("device#%d", id), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- Add Device (the main entry point)

type snmpInput struct {
	Version       string `json:"version"`
	Community     string `json:"community"`
	Username      string `json:"username"`
	Password      string `json:"password"` // auth password
	SecurityLevel string `json:"security_level"`
	AuthProtocol  string `json:"auth_protocol"`
	PrivProtocol  string `json:"priv_protocol"`
	PrivPassword  string `json:"priv_password"`
	Context       string `json:"context"`
	Port          int    `json:"port"`
}

type addDeviceReq struct {
	IP           string             `json:"ip"`
	CredentialID int64              `json:"credential_id"`
	SNMP         *snmpInput         `json:"snmp"`
	Options      *discovery.Options `json:"options"`
	SSH          *credentials.Login `json:"ssh"`
}

func (s *Server) addDevice(w http.ResponseWriter, r *http.Request) {
	var req addDeviceReq
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if net.ParseIP(req.IP) == nil {
		writeError(w, http.StatusBadRequest, "enter a valid IP address (e.g. 10.2.33.1)")
		return
	}
	ctx := r.Context()
	credID := req.CredentialID
	if credID == 0 {
		if req.SNMP == nil {
			writeError(w, http.StatusBadRequest, "SNMP credentials are required")
			return
		}
		in := req.SNMP
		c := credentials.SNMP{Version: in.Version, Community: in.Community, Username: strings.TrimSpace(in.Username), AuthPassword: in.Password,
			SecurityLevel: in.SecurityLevel, AuthProtocol: in.AuthProtocol, PrivProtocol: in.PrivProtocol, PrivPassword: in.PrivPassword,
			ContextName: in.Context, Port: in.Port}
		user := c.Username
		if c.Username == "" && c.Community == "" && in.Password != "" {
			// "password only" means a v2c community
			c.Community, c.AuthPassword = in.Password, ""
		}
		if user == "" {
			user = "community"
		}
		id, err := s.Creds.CreateSNMP(ctx, s.DB, credentials.DefaultName("snmp", user, req.IP), c)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		credID = id
	}
	var sshID int64
	if req.SSH != nil && req.SSH.Username != "" {
		var err error
		if sshID, err = s.Creds.CreateLogin(ctx, s.DB, credentials.DefaultName("ssh", req.SSH.Username, req.IP), credentials.KindSSH, *req.SSH); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	opt := discovery.DefaultOptions(req.IP)
	st := s.Settings.Get(ctx)
	opt.MaxDepth, opt.MaxDevices, opt.ActiveFingerprint = st.DefaultDepth, st.MaxDevices, st.ActiveFingerprinting
	if len(st.DefaultScope) > 0 {
		opt.Scope = st.DefaultScope
	}
	if req.Options != nil {
		o := *req.Options
		opt.MaxDepth, opt.ActiveFingerprint, opt.TryAllCredentials = o.MaxDepth, o.ActiveFingerprint, o.TryAllCredentials
		if len(o.Scope) > 0 {
			opt.Scope = o.Scope
		}
		if o.MaxDevices > 0 {
			opt.MaxDevices = o.MaxDevices
		}
	}
	opt.SSHCredentialID = sshID
	runID, err := s.Engine.Submit(ctx, req.IP, credID, opt, auth.UserFrom(ctx).ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auth.Audit(ctx, s.DB, "discovery.started", req.IP, map[string]any{"run_id": runID, "depth": opt.MaxDepth, "scope": opt.Scope})
	writeJSON(w, http.StatusAccepted, map[string]any{"run_id": runID, "credential_id": credID, "options": opt})
}

// ---- credentials

func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	recs, err := s.Creds.List(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if recs == nil {
		recs = []credentials.Record{}
	}
	writeJSON(w, http.StatusOK, recs)
}

func (s *Server) createCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string             `json:"name"`
		Kind  string             `json:"kind"`
		SNMP  *snmpInput         `json:"snmp"`
		Login *credentials.Login `json:"login"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var id int64
	var err error
	switch req.Kind {
	case credentials.KindSNMP:
		if req.SNMP == nil {
			err = errors.New("snmp settings are required")
			break
		}
		in := req.SNMP
		id, err = s.Creds.CreateSNMP(r.Context(), s.DB, req.Name, credentials.SNMP{Version: in.Version, Community: in.Community, Username: in.Username,
			AuthPassword: in.Password, SecurityLevel: in.SecurityLevel, AuthProtocol: in.AuthProtocol, PrivProtocol: in.PrivProtocol,
			PrivPassword: in.PrivPassword, ContextName: in.Context, Port: in.Port})
	case credentials.KindSSH, credentials.KindTelnet:
		if req.Login == nil {
			err = errors.New("login settings are required")
			break
		}
		id, err = s.Creds.CreateLogin(r.Context(), s.DB, req.Name, req.Kind, *req.Login)
	default:
		err = errors.New("kind must be snmp, ssh or telnet")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		_, _ = s.DB.Exec(r.Context(), `UPDATE credentials SET name=$2 WHERE id=$1`, id, fmt.Sprintf("%s #%d", strings.ToUpper(req.Kind), id))
	}
	auth.Audit(r.Context(), s.DB, "credential.created", fmt.Sprintf("credential#%d", id), map[string]any{"kind": req.Kind})
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.Creds.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	auth.Audit(r.Context(), s.DB, "credential.deleted", fmt.Sprintf("credential#%d", id), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

var _ = time.Second
