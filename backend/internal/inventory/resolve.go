package inventory

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/collectors"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/events"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/identity"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/oui"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// ResolveStats summarizes a resolution pass.
type ResolveStats struct {
	NeighborDevices int `json:"neighbor_devices"`
	Endpoints       int `json:"endpoints"`
	NewEndpoints    int `json:"new_endpoints"`
	Attachments     int `json:"attachments"`
	Moves           int `json:"moves"`
	Merges          int `json:"merges"`
	Uplinks         int `json:"uplinks"`
}

// shortName normalizes a system name for matching (drops domain suffix).
func shortName(n string) string {
	n = strings.TrimSpace(strings.ToLower(n))
	if n == "" || net.ParseIP(n) != nil {
		return n
	}
	if i := strings.IndexByte(n, '.'); i > 0 {
		return n[:i]
	}
	return n
}

// loadAllIndex loads identity keys for every device.
func loadAllIndex(ctx context.Context, q storage.DBTX) (*identity.MemIndex, error) {
	rows, err := q.Query(ctx, `SELECT id FROM devices`)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	idx, err := loadIndexFor(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	// short sysnames for neighbor matching
	rows, err = q.Query(ctx, `SELECT id, sys_name FROM devices WHERE sys_name IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n string
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		idx.Add(id, identity.Key{Kind: identity.SysName, Value: shortName(n)})
	}
	return idx, rows.Err()
}

type resolver struct {
	tx    pgx.Tx
	idx   *identity.MemIndex
	stats *ResolveStats
}

// resolve finds or creates the device for keys. create supplies the INSERT.
func (r *resolver) resolve(ctx context.Context, keys []identity.Key, create func() (int64, error)) (int64, bool, error) {
	dec := identity.Resolve(r.idx, keys)
	id := dec.DeviceID
	created := false
	if id == 0 {
		var err error
		if id, err = create(); err != nil {
			return 0, false, err
		}
		created = true
	}
	for _, m := range dec.Merge {
		if err := MergeDevices(ctx, r.tx, id, m, dec.Reason); err != nil {
			return 0, false, err
		}
		r.idx.MergeInto(id, m)
		r.stats.Merges++
	}
	for other, ips := range dec.ReleaseIPs {
		if _, err := r.tx.Exec(ctx, `DELETE FROM device_addresses WHERE device_id=$1 AND host(ip) = ANY($2) AND source <> 'snmp'`, other, ips); err != nil {
			return 0, false, err
		}
		for _, ip := range ips {
			r.idx.Remove(other, identity.Key{Kind: identity.IP, Value: ip})
		}
	}
	for _, k := range keys {
		r.idx.Add(id, k)
	}
	return id, created, nil
}

func (r *resolver) addMAC(ctx context.Context, id int64, mac, source string) error {
	if mac == "" || IsVirtualMAC(mac) {
		return nil
	}
	_, err := r.tx.Exec(ctx, `INSERT INTO device_macs(device_id, mac, source) VALUES ($1,$2,$3)
		ON CONFLICT (device_id, mac) DO UPDATE SET last_seen=now()`, id, mac, source)
	return err
}

func (r *resolver) addIP(ctx context.Context, id int64, ip, source string) error {
	if net.ParseIP(ip) == nil {
		return nil
	}
	_, err := r.tx.Exec(ctx, `INSERT INTO device_addresses(device_id, ip, source) VALUES ($1,$2,$3)
		ON CONFLICT (device_id, ip) DO UPDATE SET last_seen=now()`, id, ip, source)
	return err
}

// ResolveNetwork derives neighbor devices, endpoints, uplinks and attachments
// from the stored L2/L3 tables of all managed devices.
func (s *Store) ResolveNetwork(ctx context.Context) (ResolveStats, error) {
	var st ResolveStats
	err := pgx.BeginFunc(ctx, s.DB.Pool, func(tx pgx.Tx) error {
		// serialize resolution passes
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7263542)`); err != nil {
			return err
		}
		idx, err := loadAllIndex(ctx, tx)
		if err != nil {
			return err
		}
		r := &resolver{tx: tx, idx: idx, stats: &st}
		if err := r.neighbors(ctx); err != nil {
			return fmt.Errorf("neighbors: %w", err)
		}
		if err := r.uplinks(ctx); err != nil {
			return fmt.Errorf("uplinks: %w", err)
		}
		if err := r.endpoints(ctx); err != nil {
			return fmt.Errorf("endpoints: %w", err)
		}
		if err := r.attachments(ctx); err != nil {
			return fmt.Errorf("attachments: %w", err)
		}
		return r.ouiVendors(ctx)
	})
	return st, err
}

type nbRow struct {
	id                                int64
	deviceID                          int64
	protocol, chassis, sysName, descr string
	platform, mgmt, portID, portDescr string
	caps                              []string
}

func (r *resolver) neighbors(ctx context.Context) error {
	rows, err := r.tx.Query(ctx, `SELECT id, device_id, protocol, COALESCE(remote_chassis_id,''), COALESCE(remote_sys_name,''),
		COALESCE(remote_sys_descr,''), COALESCE(remote_platform,''), COALESCE(host(remote_mgmt_ip),''),
		COALESCE(remote_port_id,''), COALESCE(remote_port_descr,''), remote_capabilities FROM neighbors ORDER BY id`)
	if err != nil {
		return err
	}
	nbs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (nbRow, error) {
		var n nbRow
		err := row.Scan(&n.id, &n.deviceID, &n.protocol, &n.chassis, &n.sysName, &n.descr, &n.platform, &n.mgmt, &n.portID, &n.portDescr, &n.caps)
		return n, err
	})
	if err != nil {
		return err
	}
	for _, n := range nbs {
		var keys []identity.Key
		if n.chassis != "" {
			keys = append(keys, identity.Key{Kind: identity.Chassis, Value: n.chassis})
			if mac := normalizeMAC(n.chassis); mac != "" {
				keys = append(keys, identity.Key{Kind: identity.MAC, Value: mac})
			}
		}
		if sn := shortName(n.sysName); sn != "" && !isMACLike(sn) {
			keys = append(keys, identity.Key{Kind: identity.SysName, Value: sn})
		}
		if n.mgmt != "" {
			keys = append(keys, identity.Key{Kind: identity.IP, Value: n.mgmt})
		}
		if len(keys) == 0 {
			continue
		}
		id, created, err := r.resolve(ctx, keys, func() (int64, error) {
			var id int64
			var mgmt any
			if n.mgmt != "" {
				mgmt = n.mgmt
			}
			descr := n.descr
			if descr == "" {
				descr = n.platform
			}
			err := r.tx.QueryRow(ctx, `INSERT INTO devices(managed, discovered_via, sys_name, hostname, sys_descr, chassis_id, mgmt_ip, status)
				VALUES (false, $1, $2, $2, $3, $4, $5, 'unknown') RETURNING id`,
				n.protocol, nz(n.sysName), nz(descr), nz(n.chassis), mgmt).Scan(&id)
			return id, err
		})
		if err != nil {
			return err
		}
		if id == n.deviceID {
			continue // a device seeing itself (e.g. stacked ports); ignore
		}
		if created {
			r.stats.NeighborDevices++
			events.Record(ctx, r.tx, id, events.DeviceDiscovered, events.Info,
				fmt.Sprintf("%s found as %s neighbor", firstNonEmpty(n.sysName, n.chassis), strings.ToUpper(n.protocol)), nil)
		} else {
			// enrich unmanaged records with what the neighbor announces
			if _, err := r.tx.Exec(ctx, `UPDATE devices SET sys_name=COALESCE(sys_name,$2), sys_descr=COALESCE(sys_descr,$3),
				mgmt_ip=COALESCE(mgmt_ip,$4::inet), chassis_id=COALESCE(chassis_id,$5), last_seen=now() WHERE id=$1 AND NOT managed`,
				id, nz(n.sysName), nz(firstNonEmpty(n.descr, n.platform)), nz(n.mgmt), nz(n.chassis)); err != nil {
				return err
			}
		}
		if mac := normalizeMAC(n.chassis); mac != "" {
			if err := r.addMAC(ctx, id, mac, n.protocol); err != nil {
				return err
			}
		}
		if n.mgmt != "" {
			if err := r.addIP(ctx, id, n.mgmt, n.protocol); err != nil {
				return err
			}
		}
		if n.sysName != "" {
			if _, err := r.tx.Exec(ctx, `INSERT INTO device_hostnames(device_id,name,source) VALUES ($1,$2,$3) ON CONFLICT (device_id,name,source) DO UPDATE SET last_seen=now()`,
				id, n.sysName, n.protocol); err != nil {
				return err
			}
		}
		remoteIf, err := r.matchRemotePort(ctx, id, n.portID, n.portDescr)
		if err != nil {
			return err
		}
		if _, err := r.tx.Exec(ctx, `UPDATE neighbors SET remote_device_id=$2, remote_interface_id=$3 WHERE id=$1`, n.id, id, remoteIf); err != nil {
			return err
		}
	}
	return nil
}

func (r *resolver) matchRemotePort(ctx context.Context, devID int64, portID, portDescr string) (any, error) {
	rows, err := r.tx.Query(ctx, `SELECT id, COALESCE(name,''), COALESCE(descr,''), COALESCE(alias,''), COALESCE(mac::text,'') FROM interfaces WHERE device_id=$1`, devID)
	if err != nil {
		return nil, err
	}
	type ifr struct {
		id                      int64
		name, descr, alias, mac string
	}
	ifs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ifr, error) {
		var i ifr
		err := row.Scan(&i.id, &i.name, &i.descr, &i.alias, &i.mac)
		return i, err
	})
	if err != nil || len(ifs) == 0 {
		return nil, err
	}
	for _, cand := range []string{portID, portDescr} {
		if cand == "" {
			continue
		}
		full := strings.ToLower(collectors.ExpandIfName(cand))
		c := strings.ToLower(cand)
		for _, i := range ifs {
			if strings.ToLower(i.name) == c || strings.ToLower(i.descr) == c || strings.ToLower(i.name) == full || (i.mac != "" && i.mac == normalizeMAC(cand)) {
				return i.id, nil
			}
		}
		short := collectors.ShortIfName(cand)
		for _, i := range ifs {
			if short != "" && strings.EqualFold(collectors.ShortIfName(i.name), short) {
				return i.id, nil
			}
		}
	}
	return nil, nil
}

// uplinks marks inter-switch ports: ports with a network-device neighbor, or
// carrying many MAC addresses (likely an unmanaged switch behind it).
func (r *resolver) uplinks(ctx context.Context) error {
	if _, err := r.tx.Exec(ctx, `UPDATE interfaces SET is_uplink=false WHERE is_uplink`); err != nil {
		return err
	}
	tag, err := r.tx.Exec(ctx, `UPDATE interfaces i SET is_uplink=true FROM neighbors n
		LEFT JOIN devices d ON d.id=n.remote_device_id
		WHERE n.local_interface_id=i.id AND (
			d.managed OR d.device_type IN ('switch','router','firewall','wireless_controller')
			OR (('bridge' = ANY(n.remote_capabilities) OR 'router' = ANY(n.remote_capabilities))
			    AND NOT ('phone' = ANY(n.remote_capabilities) OR 'wlan-ap' = ANY(n.remote_capabilities) OR 'station' = ANY(n.remote_capabilities))))`)
	if err != nil {
		return err
	}
	r.stats.Uplinks = int(tag.RowsAffected())
	return nil
}

type arpPair struct{ ip, mac string }

func (r *resolver) endpoints(ctx context.Context) error {
	rows, err := r.tx.Query(ctx, `SELECT DISTINCT host(ip), mac::text FROM arp_entries ORDER BY 1`)
	if err != nil {
		return err
	}
	pairs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (arpPair, error) {
		var p arpPair
		err := row.Scan(&p.ip, &p.mac)
		return p, err
	})
	if err != nil {
		return err
	}
	// MACs answering for many IPs (proxy ARP, routers) are not endpoint identities.
	ipsPerMAC := map[string]int{}
	for _, p := range pairs {
		ipsPerMAC[p.mac]++
	}
	create := func(via string) func() (int64, error) {
		return func() (int64, error) {
			var id int64
			err := r.tx.QueryRow(ctx, `INSERT INTO devices(managed, discovered_via, status) VALUES (false,$1,'up') RETURNING id`, via).Scan(&id)
			return id, err
		}
	}
	for _, p := range pairs {
		if IsVirtualMAC(p.mac) {
			continue
		}
		keys := []identity.Key{{Kind: identity.MAC, Value: p.mac}}
		if ipsPerMAC[p.mac] <= 4 {
			keys = append(keys, identity.Key{Kind: identity.IP, Value: p.ip})
		}
		id, created, err := r.resolve(ctx, keys, create("arp"))
		if err != nil {
			return err
		}
		if created {
			r.stats.NewEndpoints++
		}
		r.stats.Endpoints++
		if err := r.addMAC(ctx, id, p.mac, "arp"); err != nil {
			return err
		}
		if ipsPerMAC[p.mac] <= 4 {
			if err := r.addIP(ctx, id, p.ip, "arp"); err != nil {
				return err
			}
		}
		if _, err := r.tx.Exec(ctx, `UPDATE devices SET last_seen=now(), status='up' WHERE id=$1 AND NOT managed`, id); err != nil {
			return err
		}
	}
	// MACs seen only in forwarding tables
	rows, err = r.tx.Query(ctx, `SELECT DISTINCT f.mac::text FROM fdb_entries f JOIN interfaces i ON i.id=f.interface_id WHERE NOT i.is_uplink`)
	if err != nil {
		return err
	}
	macs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, mac := range macs {
		if IsVirtualMAC(mac) {
			continue
		}
		if len(r.idx.Find(identity.Key{Kind: identity.MAC, Value: mac})) > 0 {
			continue
		}
		id, created, err := r.resolve(ctx, []identity.Key{{Kind: identity.MAC, Value: mac}}, create("fdb"))
		if err != nil {
			return err
		}
		if created {
			r.stats.NewEndpoints++
			r.stats.Endpoints++
		}
		if err := r.addMAC(ctx, id, mac, "fdb"); err != nil {
			return err
		}
	}
	return nil
}

type fdbCand struct {
	mac      string
	switchID int64
	ifID     int64
	port     string
	vlan     int
	count    int
}

func (r *resolver) attachments(ctx context.Context) error {
	rows, err := r.tx.Query(ctx, `
		WITH counts AS (SELECT interface_id, count(DISTINCT mac) n FROM fdb_entries GROUP BY interface_id)
		SELECT f.mac::text, f.device_id, f.interface_id, COALESCE(i.name,''), f.vlan_id, c.n
		FROM fdb_entries f JOIN interfaces i ON i.id=f.interface_id JOIN counts c ON c.interface_id=f.interface_id
		WHERE NOT i.is_uplink AND f.status <> 'self'`)
	if err != nil {
		return err
	}
	cands, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (fdbCand, error) {
		var c fdbCand
		err := row.Scan(&c.mac, &c.switchID, &c.ifID, &c.port, &c.vlan, &c.count)
		return c, err
	})
	if err != nil {
		return err
	}
	type choice struct {
		fdbCand
		source string
		conf   float64
	}
	best := map[int64]choice{}
	for _, c := range cands {
		ids := r.idx.Find(identity.Key{Kind: identity.MAC, Value: c.mac})
		if len(ids) == 0 || ids[0] == c.switchID {
			continue
		}
		id := ids[0]
		conf := 0.4
		switch {
		case c.count == 1:
			conf = 0.95
		case c.count <= 3:
			conf = 0.85
		case c.count <= 16:
			conf = 0.6
		}
		cur, ok := best[id]
		if !ok || c.count < cur.count {
			best[id] = choice{c, "fdb", conf}
		}
	}
	// LLDP-announced endpoints (phones, APs) are authoritative.
	rows, err = r.tx.Query(ctx, `SELECT n.remote_device_id, n.device_id, n.local_interface_id, COALESCE(n.local_port,''), COALESCE(i.pvid,0)
		FROM neighbors n JOIN interfaces i ON i.id=n.local_interface_id
		WHERE n.remote_device_id IS NOT NULL AND NOT i.is_uplink`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var devID, sw, ifID int64
		var port string
		var vlan int
		if err := rows.Scan(&devID, &sw, &ifID, &port, &vlan); err != nil {
			rows.Close()
			return err
		}
		c := best[devID]
		if c.vlan != 0 {
			vlan = c.vlan
		}
		best[devID] = choice{fdbCand{mac: c.mac, switchID: sw, ifID: ifID, port: port, vlan: vlan, count: 1}, "lldp", 0.98}
	}
	rows.Close()

	ids := make([]int64, 0, len(best))
	for id := range best {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		c := best[id]
		var curID, curSwitch int64
		var curIf *int64
		err := r.tx.QueryRow(ctx, `SELECT id, switch_id, interface_id FROM attachments WHERE device_id=$1 AND ended_at IS NULL`, id).Scan(&curID, &curSwitch, &curIf)
		var mac any
		if c.mac != "" {
			mac = c.mac
		}
		switch {
		case err == pgx.ErrNoRows:
			_, err = r.tx.Exec(ctx, `INSERT INTO attachments(device_id, switch_id, interface_id, port_name, vlan_id, mac, source, confidence)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, c.switchID, c.ifID, c.port, nzi(c.vlan), mac, c.source, c.conf)
		case err != nil:
			return err
		case curSwitch == c.switchID && curIf != nil && *curIf == c.ifID:
			_, err = r.tx.Exec(ctx, `UPDATE attachments SET last_seen=now(), vlan_id=COALESCE($2, vlan_id), confidence=$3, source=$4, port_name=$5 WHERE id=$1`,
				curID, nzi(c.vlan), c.conf, c.source, c.port)
		default:
			if _, err = r.tx.Exec(ctx, `UPDATE attachments SET ended_at=now() WHERE id=$1`, curID); err != nil {
				return err
			}
			_, err = r.tx.Exec(ctx, `INSERT INTO attachments(device_id, switch_id, interface_id, port_name, vlan_id, mac, source, confidence)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, c.switchID, c.ifID, c.port, nzi(c.vlan), mac, c.source, c.conf)
			if err == nil {
				r.stats.Moves++
				var swName string
				_ = r.tx.QueryRow(ctx, `SELECT COALESCE(sys_name, host(mgmt_ip), '') FROM devices WHERE id=$1`, c.switchID).Scan(&swName)
				events.Record(ctx, r.tx, id, events.EndpointMoved, events.Info,
					fmt.Sprintf("Moved to %s %s", swName, c.port), map[string]any{"switch_id": c.switchID, "port": c.port})
			}
		}
		if err != nil {
			return err
		}
		r.stats.Attachments++
	}
	return nil
}

// ouiVendors sets manufacturer and randomized-MAC flags from each device's MACs.
func (r *resolver) ouiVendors(ctx context.Context) error {
	rows, err := r.tx.Query(ctx, `SELECT device_id, array_agg(mac::text ORDER BY source='snmp' DESC, first_seen) FROM device_macs GROUP BY device_id`)
	if err != nil {
		return err
	}
	type dm struct {
		id   int64
		macs []string
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (dm, error) {
		var d dm
		err := row.Scan(&d.id, &d.macs)
		return d, err
	})
	if err != nil {
		return err
	}
	b := &pgx.Batch{}
	for _, d := range all {
		vendor, random := "", true
		for _, m := range d.macs {
			if oui.IsLocallyAdministered(m) {
				continue
			}
			random = false
			if e, ok := oui.Lookup(m); ok {
				vendor = e.Vendor
				break
			}
		}
		b.Queue(`UPDATE devices SET oui_vendor=$2, random_mac=$3 WHERE id=$1`, d.id, nz(vendor), random && len(d.macs) > 0)
	}
	return r.tx.SendBatch(ctx, b).Close()
}

func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	clean := strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(s)
	if len(clean) != 12 {
		return ""
	}
	for _, c := range clean {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(clean[i : i+2])
	}
	return b.String()
}

func isMACLike(s string) bool { return normalizeMAC(s) != "" }

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
