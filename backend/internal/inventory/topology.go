package inventory

import (
	"context"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/topology"
)

// RebuildTopology recomputes derived topology edges from neighbors,
// attachments and shared L3 subnets. Manual links are kept separately and
// merged in at read time.
func (s *Store) RebuildTopology(ctx context.Context) (int, error) {
	var edges []topology.Edge
	// L1/L2 adjacency from LLDP/CDP
	rows, err := s.DB.Query(ctx, `SELECT n.device_id, n.remote_device_id, n.protocol, n.local_interface_id, COALESCE(li.name, n.local_port, ''),
			n.remote_interface_id, COALESCE(ri.name, n.remote_port_id, ''), COALESCE(li.speed_bps, ri.speed_bps, 0),
			COALESCE(NULLIF(li.medium,'unknown'), NULLIF(ri.medium,'unknown'), 'unknown')
		FROM neighbors n
		LEFT JOIN interfaces li ON li.id=n.local_interface_id
		LEFT JOIN interfaces ri ON ri.id=n.remote_interface_id
		WHERE n.remote_device_id IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var e topology.Edge
		var proto string
		if err := rows.Scan(&e.A, &e.B, &proto, &e.AIfID, &e.APort, &e.BIfID, &e.BPort, &e.SpeedBps, &e.Medium); err != nil {
			rows.Close()
			return 0, err
		}
		e.Layer = "physical"
		e.Sources = []string{proto}
		e.Confidence = 0.9
		e.Label = fmt.Sprintf("reported_by:%d", e.A)
		edges = append(edges, e)
	}
	rows.Close()
	// endpoint attachments (MAC table / LLDP-MED)
	rows, err = s.DB.Query(ctx, `SELECT a.switch_id, a.device_id, a.interface_id, COALESCE(a.port_name,''), a.source, a.confidence,
			COALESCE(i.speed_bps,0), COALESCE(i.medium,'unknown')
		FROM attachments a LEFT JOIN interfaces i ON i.id=a.interface_id WHERE a.ended_at IS NULL`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var e topology.Edge
		var src string
		if err := rows.Scan(&e.A, &e.B, &e.AIfID, &e.APort, &src, &e.Confidence, &e.SpeedBps, &e.Medium); err != nil {
			rows.Close()
			return 0, err
		}
		e.Layer = "physical"
		e.Sources = []string{src}
		e.Label = fmt.Sprintf("reported_by:%d", e.A)
		edges = append(edges, e)
	}
	rows.Close()
	// L3 adjacency: managed devices with addresses in the same subnet
	rows, err = s.DB.Query(ctx, `SELECT a.device_id, host(a.ip), a.prefix_len FROM device_addresses a JOIN devices d ON d.id=a.device_id
		WHERE d.managed AND a.source='snmp' AND a.prefix_len BETWEEN 8 AND 30 AND d.is_router`)
	if err != nil {
		return 0, err
	}
	bySubnet := map[string][]int64{}
	for rows.Next() {
		var id int64
		var ip string
		var pl int
		if err := rows.Scan(&id, &ip, &pl); err != nil {
			rows.Close()
			return 0, err
		}
		if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip, pl)); err == nil {
			bySubnet[n.String()] = appendUnique(bySubnet[n.String()], id)
		}
	}
	rows.Close()
	for subnet, ids := range bySubnet {
		for i := 0; i < len(ids); i++ {
			for j := i + 1; j < len(ids); j++ {
				edges = append(edges, topology.Edge{A: ids[i], B: ids[j], Layer: "l3", Sources: []string{"subnet " + subnet}, Confidence: 0.8, APort: subnet, BPort: subnet})
			}
		}
	}
	edges = topology.Dedup(edges)
	err = pgx.BeginFunc(ctx, s.DB.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM topology_edges`); err != nil {
			return err
		}
		b := &pgx.Batch{}
		for _, e := range edges {
			b.Queue(`INSERT INTO topology_edges(a_device_id, a_interface_id, a_port, b_device_id, b_interface_id, b_port, layer, sources, speed_bps, medium, confidence)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
				e.A, e.AIfID, nz(e.APort), e.B, e.BIfID, nz(e.BPort), e.Layer, e.Sources, e.SpeedBps, nz(e.Medium), e.Confidence)
		}
		return tx.SendBatch(ctx, b).Close()
	})
	return len(edges), err
}

func appendUnique(s []int64, v int64) []int64 {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// GraphFilter narrows the topology view.
type GraphFilter struct {
	Layer         string // physical|l3|"" (all)
	InfraOnly     bool
	LocationID    int64 // include devices within this location subtree
	Search        string
	FocusDeviceID int64 // only this device, its neighbors and downstream
}

// Graph returns nodes and edges for the UI, including manual links and
// user-defined positions.
func (s *Store) Graph(ctx context.Context, f GraphFilter) ([]topology.Node, []topology.Edge, error) {
	rows, err := s.DB.Query(ctx, `SELECT d.id, COALESCE(c.display_name, d.sys_name, d.hostname, host(d.mgmt_ip), (SELECT host(ip) FROM device_addresses WHERE device_id=d.id LIMIT 1), (SELECT mac::text FROM device_macs WHERE device_id=d.id LIMIT 1), '#'||d.id),
			COALESCE(c.device_type_override, d.device_type), COALESCE(d.vendor, d.oui_vendor, ''), COALESCE(d.model,''),
			COALESCE(host(d.mgmt_ip), (SELECT host(ip) FROM device_addresses WHERE device_id=d.id ORDER BY source='snmp' DESC LIMIT 1), ''),
			d.managed, d.status, c.location_id, COALESCE(l.path,''), COALESCE(l.floor,''), COALESCE(l.building,''),
			COALESCE((SELECT array_agg(tag ORDER BY tag) FROM device_tags t WHERE t.device_id=d.id), '{}'),
			tl.x, tl.y, COALESCE(tl.pinned,false)
		FROM devices d
		LEFT JOIN device_context c ON c.device_id=d.id
		LEFT JOIN location_paths l ON l.id=c.location_id
		LEFT JOIN topology_layout tl ON tl.device_id=d.id`)
	if err != nil {
		return nil, nil, err
	}
	var nodes []topology.Node
	for rows.Next() {
		var n topology.Node
		if err := rows.Scan(&n.ID, &n.Label, &n.Type, &n.Vendor, &n.Model, &n.IP, &n.Managed, &n.Status, &n.LocationID, &n.Location, &n.Floor, &n.Building,
			&n.Tags, &n.X, &n.Y, &n.Pinned); err != nil {
			rows.Close()
			return nil, nil, err
		}
		n.Infra = n.Managed || model.IsNetworkInfra(n.Type)
		nodes = append(nodes, n)
	}
	rows.Close()
	rows, err = s.DB.Query(ctx, `SELECT a_device_id, b_device_id, a_interface_id, b_interface_id, COALESCE(a_port,''), COALESCE(b_port,''), layer, sources,
		COALESCE(speed_bps,0), COALESCE(medium,''), confidence FROM topology_edges
		UNION ALL
		SELECT a_device_id, b_device_id, NULL, NULL, COALESCE(a_port,''), COALESCE(b_port,''), 'physical', ARRAY['manual'], 0, COALESCE(medium,''), 1 FROM manual_links`)
	if err != nil {
		return nil, nil, err
	}
	var edges []topology.Edge
	for rows.Next() {
		var e topology.Edge
		if err := rows.Scan(&e.A, &e.B, &e.AIfID, &e.BIfID, &e.APort, &e.BPort, &e.Layer, &e.Sources, &e.SpeedBps, &e.Medium, &e.Confidence); err != nil {
			rows.Close()
			return nil, nil, err
		}
		e.Manual = len(e.Sources) == 1 && e.Sources[0] == "manual"
		edges = append(edges, e)
	}
	rows.Close()
	edges = topology.Dedup(edges)

	levels := topology.Levels(nodes, filterLayer(edges, "physical"))
	for i := range nodes {
		nodes[i].Level = levels[nodes[i].ID]
	}
	// filters
	keep := map[int64]bool{}
	for _, n := range nodes {
		keep[n.ID] = true
	}
	if f.LocationID != 0 {
		ids, err := s.locationSubtree(ctx, f.LocationID)
		if err != nil {
			return nil, nil, err
		}
		for _, n := range nodes {
			keep[n.ID] = n.LocationID != nil && ids[*n.LocationID]
		}
	}
	if f.InfraOnly {
		for _, n := range nodes {
			keep[n.ID] = keep[n.ID] && n.Infra
		}
	}
	if f.FocusDeviceID != 0 {
		focus := map[int64]bool{f.FocusDeviceID: true}
		for _, id := range topology.Neighbors(edges, f.FocusDeviceID) {
			focus[id] = true
		}
		for _, id := range topology.Downstream(filterLayer(edges, "physical"), levels, f.FocusDeviceID) {
			focus[id] = true
		}
		for id := range keep {
			keep[id] = keep[id] && focus[id]
		}
	}
	var outNodes []topology.Node
	deg := map[int64]int{}
	var outEdges []topology.Edge
	for _, e := range edges {
		if f.Layer != "" && e.Layer != f.Layer {
			continue
		}
		if keep[e.A] && keep[e.B] {
			outEdges = append(outEdges, e)
			deg[e.A]++
			deg[e.B]++
		}
	}
	for _, n := range nodes {
		if keep[n.ID] {
			n.Degree = deg[n.ID]
			outNodes = append(outNodes, n)
		}
	}
	pos := topology.Layout(outNodes, filterLayer(outEdges, "physical"), levels)
	for i := range outNodes {
		if outNodes[i].X == nil {
			p := pos[outNodes[i].ID]
			x, y := p[0], p[1]
			outNodes[i].X, outNodes[i].Y = &x, &y
		}
	}
	return outNodes, outEdges, nil
}

func filterLayer(edges []topology.Edge, layer string) []topology.Edge {
	var out []topology.Edge
	for _, e := range edges {
		if e.Layer == layer {
			out = append(out, e)
		}
	}
	return out
}

// locationSubtree returns the ids of a location and all its descendants.
func (s *Store) locationSubtree(ctx context.Context, id int64) (map[int64]bool, error) {
	rows, err := s.DB.Query(ctx, `SELECT id FROM location_paths WHERE $1 = ANY(ancestors)`, id)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	m := map[int64]bool{}
	for _, x := range ids {
		m[x] = true
	}
	return m, nil
}
