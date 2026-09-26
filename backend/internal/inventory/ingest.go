// Package inventory persists discovered facts and derives the unified device
// inventory, endpoint attachments and topology from them.
package inventory

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/events"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/identity"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/oui"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// Store is the inventory persistence layer.
type Store struct {
	DB  *storage.DB
	Log *slog.Logger
}

func New(db *storage.DB, log *slog.Logger) *Store { return &Store{DB: db, Log: log} }

// IngestOptions describe how a snapshot was obtained.
type IngestOptions struct {
	MgmtIP       string
	CredentialID int64
	Via          string // seed|lldp|cdp|poll
	Full         bool   // full discovery (replace L2/L3 tables) vs. poll
}

func nz(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func nzi(i int) any {
	if i == 0 {
		return nil
	}
	return i
}

// IsVirtualMAC reports first-hop-redundancy and other shared MACs that must
// never be used as identity keys.
func IsVirtualMAC(mac string) bool {
	return strings.HasPrefix(mac, "00:00:5e:00:01:") || strings.HasPrefix(mac, "00:00:5e:00:02:") ||
		strings.HasPrefix(mac, "00:00:0c:07:ac:") || strings.HasPrefix(mac, "00:00:0c:9f:f") ||
		strings.HasPrefix(mac, "00:05:73:a0:") || strings.HasPrefix(mac, "01:") || strings.HasPrefix(mac, "33:33:")
}

// snapshotKeys returns identity keys for a managed device.
func snapshotKeys(snap *model.Snapshot, mgmtIP string) []identity.Key {
	var keys []identity.Key
	sys := snap.System
	if sys.ChassisID != "" {
		keys = append(keys, identity.Key{Kind: identity.Chassis, Value: sys.ChassisID})
		if len(sys.ChassisID) == 17 {
			keys = append(keys, identity.Key{Kind: identity.MAC, Value: sys.ChassisID})
		}
	}
	if sys.Serial != "" {
		keys = append(keys, identity.Key{Kind: identity.Serial, Value: sys.Serial})
	}
	if sys.Name != "" {
		keys = append(keys, identity.Key{Kind: identity.SysName, Value: sys.Name})
	}
	for _, it := range snap.Interfaces {
		if it.MAC != "" && !IsVirtualMAC(it.MAC) {
			keys = append(keys, identity.Key{Kind: identity.MAC, Value: it.MAC})
		}
	}
	if mgmtIP != "" {
		keys = append(keys, identity.Key{Kind: identity.IP, Value: mgmtIP})
	}
	for _, ip := range snap.IPs {
		keys = append(keys, identity.Key{Kind: identity.IP, Value: ip.IP})
	}
	return keys
}

// loadIndex builds an identity index for devices matching any of keys.
func loadIndex(ctx context.Context, q storage.DBTX, keys []identity.Key) (*identity.MemIndex, error) {
	var macs, ips, chassis, serials, names []string
	for _, k := range keys {
		k = k.Norm()
		switch k.Kind {
		case identity.MAC:
			macs = append(macs, k.Value)
		case identity.IP:
			ips = append(ips, k.Value)
		case identity.Chassis:
			chassis = append(chassis, k.Value)
		case identity.Serial:
			serials = append(serials, k.Value)
		case identity.SysName:
			names = append(names, k.Value)
		}
	}
	rows, err := q.Query(ctx, `
		SELECT DISTINCT id FROM (
			SELECT device_id AS id FROM device_macs WHERE mac::text = ANY($1)
			UNION SELECT device_id FROM device_addresses WHERE host(ip) = ANY($2)
			UNION SELECT id FROM devices WHERE merged_into IS NULL AND (
				lower(chassis_id) = ANY($3) OR lower(serial) = ANY($4) OR lower(sys_name) = ANY($5) OR host(mgmt_ip) = ANY($2))
		) x`, macs, ips, chassis, serials, names)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	return loadIndexFor(ctx, q, ids)
}

func loadIndexFor(ctx context.Context, q storage.DBTX, ids []int64) (*identity.MemIndex, error) {
	idx := identity.NewMemIndex()
	if len(ids) == 0 {
		return idx, nil
	}
	rows, err := q.Query(ctx, `
		SELECT device_id, 'mac', mac::text FROM device_macs WHERE device_id = ANY($1)
		UNION ALL SELECT device_id, 'ip', host(ip) FROM device_addresses WHERE device_id = ANY($1)
		UNION ALL SELECT id, 'chassis', chassis_id FROM devices WHERE id = ANY($1) AND chassis_id IS NOT NULL
		UNION ALL SELECT id, 'serial', serial FROM devices WHERE id = ANY($1) AND serial IS NOT NULL AND serial <> ''
		UNION ALL SELECT id, 'sysname', sys_name FROM devices WHERE id = ANY($1) AND sys_name IS NOT NULL AND managed
		UNION ALL SELECT id, 'ip', host(mgmt_ip) FROM devices WHERE id = ANY($1) AND mgmt_ip IS NOT NULL`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var kind, val string
		if err := rows.Scan(&id, &kind, &val); err != nil {
			return nil, err
		}
		idx.Add(id, identity.Key{Kind: identity.KeyKind(kind), Value: val})
	}
	return idx, rows.Err()
}

// IngestSnapshot stores a managed device snapshot and returns its device id.
func (s *Store) IngestSnapshot(ctx context.Context, snap *model.Snapshot, opt IngestOptions) (id int64, created bool, err error) {
	err = pgx.BeginFunc(ctx, s.DB.Pool, func(tx pgx.Tx) error {
		keys := snapshotKeys(snap, opt.MgmtIP)
		idx, err := loadIndex(ctx, tx, keys)
		if err != nil {
			return err
		}
		dec := identity.Resolve(idx, keys)
		id = dec.DeviceID
		if id == 0 {
			if err := tx.QueryRow(ctx, `INSERT INTO devices(managed, discovered_via, status) VALUES (true,$1,'up') RETURNING id`, opt.Via).Scan(&id); err != nil {
				return err
			}
			created = true
		}
		for _, m := range dec.Merge {
			if err := MergeDevices(ctx, tx, id, m, "identity: "+dec.Reason); err != nil {
				return err
			}
		}
		for other, ips := range dec.ReleaseIPs {
			if _, err := tx.Exec(ctx, `DELETE FROM device_addresses WHERE device_id=$1 AND host(ip) = ANY($2)`, other, ips); err != nil {
				return err
			}
		}
		if err := s.writeDevice(ctx, tx, id, snap, opt); err != nil {
			return err
		}
		if err := s.writeInterfaces(ctx, tx, id, snap, opt.Full); err != nil {
			return err
		}
		if err := writeHealth(ctx, tx, id, snap); err != nil {
			return err
		}
		if opt.Full {
			if err := writeL2L3(ctx, tx, id, snap); err != nil {
				return err
			}
		}
		if created {
			name := snap.System.Name
			if name == "" {
				name = opt.MgmtIP
			}
			events.Record(ctx, tx, id, events.DeviceDiscovered, events.Info,
				fmt.Sprintf("%s discovered (%s %s)", name, snap.System.Vendor, snap.System.Model), map[string]any{"ip": opt.MgmtIP})
		}
		return nil
	})
	return id, created, err
}

func (s *Store) writeDevice(ctx context.Context, tx pgx.Tx, id int64, snap *model.Snapshot, opt IngestOptions) error {
	sys := snap.System
	var cred any
	if opt.CredentialID != 0 {
		cred = opt.CredentialID
	}
	ouiVendor := ""
	if sys.ChassisID != "" {
		if e, ok := oui.Lookup(sys.ChassisID); ok {
			ouiVendor = e.Vendor
		}
	}
	_, err := tx.Exec(ctx, `UPDATE devices SET
		sys_name=$2, sys_descr=$3, sys_object_id=$4, sys_contact=$5, sys_location=$6,
		vendor=COALESCE($7, vendor), model=COALESCE($8, model), serial=COALESCE($9, serial), os_version=$10, hardware_rev=$11,
		mgmt_ip=COALESCE($12::inet, mgmt_ip), uptime_seconds=$13, cpu_percent=$14, memory_percent=$15, chassis_id=COALESCE($16, chassis_id),
		managed=true, status='up', snmp_credential_id=COALESCE($17, snmp_credential_id), vendor_source=COALESCE($18, vendor_source),
		oui_vendor=COALESCE($20, oui_vendor), hostname=COALESCE(hostname, $2),
		is_router=$21, is_bridge=$22, is_printer=$23, stp_root=COALESCE($24, stp_root),
		last_seen=now(), last_polled_at=now(),
		last_discovered_at=CASE WHEN $19 THEN now() ELSE last_discovered_at END
		WHERE id=$1`,
		id, nz(sys.Name), nz(sys.Descr), nz(sys.ObjectID), nz(sys.Contact), nz(sys.Location),
		nz(sys.Vendor), nz(sys.Model), nz(sys.Serial), nz(strings.TrimSpace(sys.OSName+" "+sys.OSVersion)), nz(sys.HardwareRev),
		nz(opt.MgmtIP), sys.UptimeSeconds, sys.CPUPercent, sys.MemoryPercent, nz(strings.ToLower(sys.ChassisID)),
		cred, nz(sys.VendorSource), opt.Full, nz(ouiVendor), sys.IsRouter, sys.IsBridge, sys.IsPrinter, nz(sys.STPRoot))
	if err != nil {
		return fmt.Errorf("update device: %w", err)
	}
	// identity keys owned by this device (source snmp)
	if opt.MgmtIP != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO device_addresses(device_id, ip, prefix_len, source) VALUES ($1,$2,32,'snmp')
			ON CONFLICT (device_id, ip) DO UPDATE SET last_seen=now()`, id, opt.MgmtIP); err != nil {
			return err
		}
	}
	for _, ip := range snap.IPs {
		if _, err := tx.Exec(ctx, `INSERT INTO device_addresses(device_id, ip, prefix_len, if_index, source) VALUES ($1,$2,$3,$4,'snmp')
			ON CONFLICT (device_id, ip) DO UPDATE SET last_seen=now(), prefix_len=EXCLUDED.prefix_len, if_index=EXCLUDED.if_index`,
			id, ip.IP, ip.PrefixLen, nzi(ip.IfIndex)); err != nil {
			return err
		}
	}
	macs := map[string]bool{}
	if len(sys.ChassisID) == 17 && net.ParseIP(sys.ChassisID) == nil {
		macs[strings.ToLower(sys.ChassisID)] = true
	}
	for _, it := range snap.Interfaces {
		if it.MAC != "" && !IsVirtualMAC(it.MAC) {
			macs[it.MAC] = true
		}
	}
	for m := range macs {
		if _, err := tx.Exec(ctx, `INSERT INTO device_macs(device_id, mac, source) VALUES ($1,$2,'snmp')
			ON CONFLICT (device_id, mac) DO UPDATE SET last_seen=now()`, id, m); err != nil {
			return err
		}
	}
	if sys.Name != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO device_hostnames(device_id, name, source) VALUES ($1,$2,'snmp')
			ON CONFLICT (device_id, name, source) DO UPDATE SET last_seen=now()`, id, sys.Name); err != nil {
			return err
		}
	}
	return nil
}

type prevIface struct {
	id        int64
	oper      string
	admin     string
	inOctets  float64
	outOctets float64
	updated   time.Time
	uplink    bool
	name      string
}

func (s *Store) writeInterfaces(ctx context.Context, tx pgx.Tx, devID int64, snap *model.Snapshot, full bool) error {
	prev := map[int]prevIface{}
	rows, err := tx.Query(ctx, `SELECT if_index, id, COALESCE(oper_status,''), COALESCE(admin_status,''), COALESCE(in_octets,0)::float8, COALESCE(out_octets,0)::float8, updated_at, is_uplink, COALESCE(name,'')
		FROM interfaces WHERE device_id=$1`, devID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var idx int
		var p prevIface
		if err := rows.Scan(&idx, &p.id, &p.oper, &p.admin, &p.inOctets, &p.outOctets, &p.updated, &p.uplink, &p.name); err != nil {
			rows.Close()
			return err
		}
		prev[idx] = p
	}
	rows.Close()
	now := time.Now()
	seen := make([]int32, 0, len(snap.Interfaces))
	for _, it := range snap.Interfaces {
		seen = append(seen, int32(it.IfIndex))
		var inBps, outBps any
		if p, ok := prev[it.IfIndex]; ok {
			dt := now.Sub(p.updated).Seconds()
			if dt > 5 && float64(it.InOctets) >= p.inOctets && float64(it.OutOctets) >= p.outOctets {
				inBps = (float64(it.InOctets) - p.inOctets) * 8 / dt
				outBps = (float64(it.OutOctets) - p.outOctets) * 8 / dt
			}
			if p.oper == "up" && it.OperStatus == "down" && it.AdminStatus == "up" {
				sev := events.Warning
				if p.uplink {
					sev = events.Critical
				}
				events.Record(ctx, tx, devID, events.InterfaceDown, sev, fmt.Sprintf("%s went down", it.Name), map[string]any{"if_index": it.IfIndex})
				if p.uplink {
					events.Open(ctx, tx, devID, "uplink_down", it.Name, events.Critical, fmt.Sprintf("Uplink %s is down", it.Name))
				}
			}
			if p.oper == "down" && it.OperStatus == "up" {
				events.Record(ctx, tx, devID, events.InterfaceUp, events.Info, fmt.Sprintf("%s came up", it.Name), map[string]any{"if_index": it.IfIndex})
				events.Resolve(ctx, tx, devID, "uplink_down", it.Name)
			}
		}
		var mac any
		if it.MAC != "" {
			mac = it.MAC
		}
		var ifID int64
		err := tx.QueryRow(ctx, `INSERT INTO interfaces(device_id, if_index, name, descr, alias, if_type, mtu, speed_bps, mac, admin_status, oper_status,
				duplex, medium, pvid, in_octets, out_octets, in_errors, out_errors, in_bps, out_bps, last_change_seconds, stp_state, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$23,now())
			ON CONFLICT (device_id, if_index) DO UPDATE SET name=EXCLUDED.name, descr=EXCLUDED.descr, alias=EXCLUDED.alias,
				if_type=EXCLUDED.if_type, mtu=EXCLUDED.mtu, speed_bps=EXCLUDED.speed_bps, mac=EXCLUDED.mac,
				admin_status=EXCLUDED.admin_status, oper_status=EXCLUDED.oper_status, duplex=EXCLUDED.duplex,
				medium=CASE WHEN EXCLUDED.medium='unknown' AND $22 = false THEN interfaces.medium ELSE EXCLUDED.medium END,
				pvid=COALESCE(EXCLUDED.pvid, interfaces.pvid), in_octets=EXCLUDED.in_octets, out_octets=EXCLUDED.out_octets,
				in_errors=EXCLUDED.in_errors, out_errors=EXCLUDED.out_errors, in_bps=EXCLUDED.in_bps, out_bps=EXCLUDED.out_bps,
				last_change_seconds=EXCLUDED.last_change_seconds,
				stp_state=CASE WHEN $22 THEN EXCLUDED.stp_state ELSE interfaces.stp_state END, updated_at=now()
			RETURNING id`,
			devID, it.IfIndex, nz(it.Name), nz(it.Descr), nz(it.Alias), it.Type, it.MTU, int64(min(it.SpeedBps, 1<<62)), mac,
			nz(it.AdminStatus), nz(it.OperStatus), it.Duplex, it.Medium, nzi(it.PVID),
			fmt.Sprint(it.InOctets), fmt.Sprint(it.OutOctets), fmt.Sprint(it.InErrors), fmt.Sprint(it.OutErrors), inBps, outBps,
			it.LastChangeSeconds, full, nz(it.STPState)).Scan(&ifID)
		if err != nil {
			return fmt.Errorf("interface %s: %w", it.Name, err)
		}
		if inBps != nil {
			if _, err := tx.Exec(ctx, `INSERT INTO interface_metrics(interface_id, ts, in_bps, out_bps, in_errors, out_errors)
				VALUES ($1, now(), $2, $3, $4, $5) ON CONFLICT DO NOTHING`, ifID, inBps, outBps, fmt.Sprint(it.InErrors), fmt.Sprint(it.OutErrors)); err != nil {
				return err
			}
		}
	}
	if full {
		if _, err := tx.Exec(ctx, `DELETE FROM interfaces WHERE device_id=$1 AND NOT (if_index = ANY($2))`, devID, seen); err != nil {
			return err
		}
	}
	return nil
}

func writeHealth(ctx context.Context, tx pgx.Tx, devID int64, snap *model.Snapshot) error {
	if len(snap.Sensors) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM sensors WHERE device_id=$1`, devID); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, se := range snap.Sensors {
			k := se.Kind + "|" + se.Name
			if seen[k] {
				continue
			}
			seen[k] = true
			if _, err := tx.Exec(ctx, `INSERT INTO sensors(device_id, kind, name, value, unit, status) VALUES ($1,$2,$3,$4,$5,$6)`,
				devID, se.Kind, se.Name, se.Value, nz(se.Unit), nz(se.Status)); err != nil {
				return err
			}
			if se.Kind == "temperature" && se.Status == "critical" {
				events.Open(ctx, tx, devID, "temperature", se.Name, events.Critical, fmt.Sprintf("%s temperature critical", se.Name))
			} else if se.Kind == "temperature" {
				events.Resolve(ctx, tx, devID, "temperature", se.Name)
			}
		}
	}
	if c := snap.System.CPUPercent; c != nil {
		if *c >= 90 {
			if events.Open(ctx, tx, devID, "cpu", "", events.Warning, fmt.Sprintf("CPU usage %.0f%%", *c)) {
				events.Record(ctx, tx, devID, events.HighCPU, events.Warning, fmt.Sprintf("CPU usage %.0f%%", *c), nil)
			}
		} else if *c < 80 {
			events.Resolve(ctx, tx, devID, "cpu", "")
		}
	}
	return nil
}

func ifMap(ctx context.Context, tx pgx.Tx, devID int64) (map[int]int64, error) {
	rows, err := tx.Query(ctx, `SELECT if_index, id FROM interfaces WHERE device_id=$1`, devID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int]int64{}
	for rows.Next() {
		var idx int
		var id int64
		if err := rows.Scan(&idx, &id); err != nil {
			return nil, err
		}
		m[idx] = id
	}
	return m, rows.Err()
}

func nzID(m map[int]int64, idx int) any {
	if id, ok := m[idx]; ok {
		return id
	}
	return nil
}

func writeL2L3(ctx context.Context, tx pgx.Tx, devID int64, snap *model.Snapshot) error {
	ifs, err := ifMap(ctx, tx, devID)
	if err != nil {
		return err
	}
	b := &pgx.Batch{}
	// inventory
	b.Queue(`DELETE FROM inventory_items WHERE device_id=$1`, devID)
	for _, e := range snap.Inventory {
		b.Queue(`INSERT INTO inventory_items(device_id, ent_index, parent_index, class, name, descr, model, serial, hw_rev, fw_rev, sw_rev, manufacturer)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING`,
			devID, e.Index, e.ParentIndex, nz(e.Class), nz(e.Name), nz(e.Descr), nz(e.Model), nz(e.Serial), nz(e.HWRev), nz(e.FWRev), nz(e.SWRev), nz(e.Manufacturer))
	}
	// optics
	b.Queue(`DELETE FROM optics WHERE interface_id IN (SELECT id FROM interfaces WHERE device_id=$1)`, devID)
	for _, o := range snap.Optics {
		port := ""
		if it := snap.InterfaceByIndex(o.IfIndex); it != nil {
			port = it.Name
		}
		// Weak received light on a live link usually means a dirty/damaged fiber or a failing optic.
		if o.RxDBm != nil && port != "" {
			if *o.RxDBm < -18 {
				if events.Open(ctx, tx, devID, "optic_rx_low", port, events.Warning, fmt.Sprintf("Low optical receive power on %s: %.1f dBm", port, *o.RxDBm)) {
					events.Record(ctx, tx, devID, events.OpticLowPower, events.Warning, fmt.Sprintf("Low optical receive power on %s: %.1f dBm", port, *o.RxDBm), nil)
				}
			} else {
				events.Resolve(ctx, tx, devID, "optic_rx_low", port)
			}
		}
		if id, ok := ifs[o.IfIndex]; ok {
			b.Queue(`INSERT INTO optics(interface_id, vendor, part_number, serial, module_type, wavelength_nm, rx_dbm, tx_dbm, temperature_c)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (interface_id) DO NOTHING`,
				id, nz(o.Vendor), nz(o.PartNumber), nz(o.Serial), nz(o.Type), nzi(o.WavelengthNm), o.RxDBm, o.TxDBm, o.TempC)
		}
	}
	// VLANs
	b.Queue(`DELETE FROM vlans WHERE device_id=$1`, devID)
	for _, v := range snap.VLANs {
		b.Queue(`INSERT INTO vlans(device_id, vlan_id, name) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, devID, v.ID, nz(v.Name))
	}
	b.Queue(`DELETE FROM interface_vlans WHERE interface_id IN (SELECT id FROM interfaces WHERE device_id=$1)`, devID)
	for idx, pvs := range snap.PortVLANs {
		id, ok := ifs[idx]
		if !ok {
			continue
		}
		for _, pv := range pvs {
			b.Queue(`INSERT INTO interface_vlans(interface_id, vlan_id, tagged) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, id, pv.VLAN, pv.Tagged)
		}
	}
	// neighbors (preserve first_seen of adjacencies that persist)
	prevSeen := map[string]time.Time{}
	nrows, err := tx.Query(ctx, `SELECT protocol||'|'||COALESCE(local_port,'')||'|'||COALESCE(remote_chassis_id,''), first_seen FROM neighbors WHERE device_id=$1`, devID)
	if err != nil {
		return err
	}
	for nrows.Next() {
		var k string
		var t time.Time
		if err := nrows.Scan(&k, &t); err != nil {
			nrows.Close()
			return err
		}
		prevSeen[k] = t
	}
	nrows.Close()
	b.Queue(`DELETE FROM neighbors WHERE device_id=$1`, devID)
	for _, n := range snap.Neighbors {
		var mgmt any
		if n.MgmtIP != "" {
			mgmt = n.MgmtIP
		}
		caps := n.Capabilities
		if caps == nil {
			caps = []string{}
		}
		first := time.Now()
		if t, ok := prevSeen[n.Protocol+"|"+n.LocalPort+"|"+strings.ToLower(n.ChassisID)]; ok {
			first = t
		}
		b.Queue(`INSERT INTO neighbors(device_id, protocol, local_interface_id, local_port, remote_chassis_id, remote_port_id, remote_port_descr,
				remote_sys_name, remote_sys_descr, remote_platform, remote_mgmt_ip, remote_capabilities, first_seen)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			devID, n.Protocol, nzID(ifs, n.LocalIfIndex), nz(n.LocalPort), nz(strings.ToLower(n.ChassisID)), nz(n.PortID), nz(n.PortDescr),
			nz(n.SysName), nz(n.SysDescr), nz(n.Platform), mgmt, caps, first)
	}
	// FDB
	for _, f := range snap.FDB {
		b.Queue(`INSERT INTO fdb_entries(device_id, mac, vlan_id, interface_id, status) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (device_id, mac, vlan_id) DO UPDATE SET interface_id=EXCLUDED.interface_id, status=EXCLUDED.status, last_seen=now()`,
			devID, f.MAC, f.VLAN, nzID(ifs, f.IfIndex), f.Status)
	}
	b.Queue(`DELETE FROM fdb_entries WHERE device_id=$1 AND last_seen < now()`, devID)
	// ARP
	for _, a := range snap.ARP {
		b.Queue(`INSERT INTO arp_entries(device_id, ip, mac, interface_id) VALUES ($1,$2,$3,$4)
			ON CONFLICT (device_id, ip, mac) DO UPDATE SET interface_id=EXCLUDED.interface_id, last_seen=now()`,
			devID, a.IP, a.MAC, nzID(ifs, a.IfIndex))
	}
	b.Queue(`DELETE FROM arp_entries WHERE device_id=$1 AND last_seen < now()`, devID)
	// routes
	b.Queue(`DELETE FROM routes WHERE device_id=$1`, devID)
	for _, r := range snap.Routes {
		b.Queue(`INSERT INTO routes(device_id, destination, next_hop, if_index, protocol, metric) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			devID, r.Dest, r.NextHop, nzi(r.IfIndex), nz(r.Protocol), r.Metric)
	}
	// subnets from L3 interface addresses
	for _, ip := range snap.IPs {
		if ip.PrefixLen <= 0 || ip.PrefixLen >= 31 {
			continue
		}
		_, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.IP, ip.PrefixLen))
		if err != nil {
			continue
		}
		vlan := 0
		if it := snap.InterfaceByIndex(ip.IfIndex); it != nil {
			fmt.Sscanf(strings.TrimPrefix(strings.TrimPrefix(it.Name, "Vlanif"), "Vlan"), "%d", &vlan)
		}
		b.Queue(`INSERT INTO subnets(cidr, gateway_device_id, gateway_ip, vlan_id) VALUES ($1,$2,$3,$4)
			ON CONFLICT (cidr) DO UPDATE SET gateway_device_id=EXCLUDED.gateway_device_id, gateway_ip=EXCLUDED.gateway_ip,
				vlan_id=COALESCE(EXCLUDED.vlan_id, subnets.vlan_id), last_seen=now()`, n.String(), devID, ip.IP, nzi(vlan))
	}
	br := tx.SendBatch(ctx, b)
	for i := 0; i < b.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return fmt.Errorf("write L2/L3 (stmt %d): %w", i, err)
		}
	}
	return br.Close()
}
