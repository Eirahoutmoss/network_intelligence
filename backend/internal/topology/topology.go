// Package topology models the network as a graph and provides the pure graph
// algorithms used by the API and the UI (deduplication, hierarchy, layout).
package topology

import (
	"fmt"
	"sort"
	"strings"
)

// Node is a device in the graph.
type Node struct {
	ID         int64    `json:"id"`
	Label      string   `json:"label"`
	Type       string   `json:"type"`
	Vendor     string   `json:"vendor,omitempty"`
	Model      string   `json:"model,omitempty"`
	IP         string   `json:"ip,omitempty"`
	Managed    bool     `json:"managed"`
	Status     string   `json:"status"`
	Location   string   `json:"location,omitempty"`
	Floor      string   `json:"floor,omitempty"`
	Building   string   `json:"building,omitempty"`
	LocationID *int64   `json:"location_id,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	X          *float64 `json:"x,omitempty"`
	Y          *float64 `json:"y,omitempty"`
	Pinned     bool     `json:"pinned"`
	Level      int      `json:"level"`
	Infra      bool     `json:"infra"`
	Degree     int      `json:"degree"`
}

// Edge is a link between two nodes.
type Edge struct {
	ID         string   `json:"id"`
	A          int64    `json:"a"`
	B          int64    `json:"b"`
	APort      string   `json:"a_port,omitempty"`
	BPort      string   `json:"b_port,omitempty"`
	AIfID      *int64   `json:"a_interface_id,omitempty"`
	BIfID      *int64   `json:"b_interface_id,omitempty"`
	Layer      string   `json:"layer"` // physical|l2|l3
	Sources    []string `json:"sources"`
	SpeedBps   int64    `json:"speed_bps,omitempty"`
	Medium     string   `json:"medium,omitempty"`
	Confidence float64  `json:"confidence"`
	Manual     bool     `json:"manual"`
	Label      string   `json:"label,omitempty"`
}

// Key identifies a link independent of direction.
func (e Edge) Key() string {
	a := fmt.Sprintf("%d|%s", e.A, strings.ToLower(e.APort))
	b := fmt.Sprintf("%d|%s", e.B, strings.ToLower(e.BPort))
	if a > b {
		a, b = b, a
	}
	return e.Layer + "|" + a + "|" + b
}

// Reverse swaps the endpoints.
func (e Edge) Reverse() Edge {
	e.A, e.B = e.B, e.A
	e.APort, e.BPort = e.BPort, e.APort
	e.AIfID, e.BIfID = e.BIfID, e.AIfID
	return e
}

// Dedup merges edges reported from both ends (LLDP on A about B and on B
// about A) or by several protocols. A port known on only one side is filled
// from the other report. Seeing a link from both sides raises confidence.
func Dedup(in []Edge) []Edge {
	type acc struct {
		e     Edge
		sides map[int64]bool
	}
	// First pass groups by device pair, then matches ports loosely.
	byPair := map[string][]*acc{}
	var order []*acc
	for _, e := range in {
		if e.A == e.B {
			continue
		}
		if e.A > e.B {
			e = e.Reverse()
		}
		pair := fmt.Sprintf("%s|%d|%d", e.Layer, e.A, e.B)
		var match *acc
		for _, x := range byPair[pair] {
			if portCompat(x.e.APort, e.APort) && portCompat(x.e.BPort, e.BPort) {
				match = x
				break
			}
		}
		if match == nil {
			a := &acc{e: e, sides: map[int64]bool{}}
			a.e.Sources = append([]string(nil), e.Sources...)
			for _, s := range e.Sources {
				_ = s
			}
			a.sides[sideOf(e)] = true
			byPair[pair] = append(byPair[pair], a)
			order = append(order, a)
			continue
		}
		m := &match.e
		if m.APort == "" {
			m.APort, m.AIfID = e.APort, e.AIfID
		}
		if m.BPort == "" {
			m.BPort, m.BIfID = e.BPort, e.BIfID
		}
		if m.AIfID == nil {
			m.AIfID = e.AIfID
		}
		if m.BIfID == nil {
			m.BIfID = e.BIfID
		}
		for _, s := range e.Sources {
			if !contains(m.Sources, s) {
				m.Sources = append(m.Sources, s)
			}
		}
		if e.SpeedBps > 0 && (m.SpeedBps == 0 || e.SpeedBps < m.SpeedBps) {
			m.SpeedBps = e.SpeedBps
		}
		if m.Medium == "" || m.Medium == "unknown" {
			m.Medium = e.Medium
		}
		if e.Confidence > m.Confidence {
			m.Confidence = e.Confidence
		}
		m.Manual = m.Manual || e.Manual
		match.sides[sideOf(e)] = true
	}
	out := make([]Edge, 0, len(order))
	for _, a := range order {
		if len(a.sides) > 1 && a.e.Confidence < 0.99 {
			a.e.Confidence = 0.99
		}
		sort.Strings(a.e.Sources)
		a.e.ID = a.e.Key()
		out = append(out, a.e)
	}
	return out
}

// sideOf encodes which device reported the edge (stored in Label by callers
// as "reported_by:<id>"); unknown reporters count as one side.
func sideOf(e Edge) int64 {
	var id int64
	if strings.HasPrefix(e.Label, "reported_by:") {
		fmt.Sscanf(strings.TrimPrefix(e.Label, "reported_by:"), "%d", &id)
	}
	return id
}

func portCompat(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	return strings.EqualFold(a, b) || strings.EqualFold(normPort(a), normPort(b))
}

func normPort(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	i := strings.IndexFunc(p, func(r rune) bool { return r >= '0' && r <= '9' })
	if i < 0 {
		return p
	}
	prefix := p[:i]
	switch {
	case strings.HasPrefix(prefix, "xg"), strings.HasPrefix(prefix, "te"):
		prefix = "x"
	case strings.HasPrefix(prefix, "gi"), strings.HasPrefix(prefix, "ge"):
		prefix = "g"
	case strings.HasPrefix(prefix, "fa"):
		prefix = "f"
	}
	return prefix + p[i:]
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Levels assigns hierarchy levels via BFS over infrastructure nodes starting
// from roots (the most connected infra node when roots is empty). Endpoints
// get their switch's level + 1.
func Levels(nodes []Node, edges []Edge) map[int64]int {
	adj := map[int64][]int64{}
	infra := map[int64]bool{}
	deg := map[int64]int{}
	for _, n := range nodes {
		if n.Infra {
			infra[n.ID] = true
		}
	}
	for _, e := range edges {
		adj[e.A] = append(adj[e.A], e.B)
		adj[e.B] = append(adj[e.B], e.A)
		if infra[e.A] && infra[e.B] {
			deg[e.A]++
			deg[e.B]++
		}
	}
	level := map[int64]int{}
	// Candidate roots: the graph center of each infra component (minimum
	// eccentricity), ties broken by degree. The core is rarely the node with the
	// most links, but it is the one closest to everything.
	infraAdj := map[int64][]int64{}
	for _, e := range edges {
		if infra[e.A] && infra[e.B] {
			infraAdj[e.A] = append(infraAdj[e.A], e.B)
			infraAdj[e.B] = append(infraAdj[e.B], e.A)
		}
	}
	ecc := map[int64]int{}
	for id := range infra {
		dist := map[int64]int{id: 0}
		q := []int64{id}
		far := 0
		for len(q) > 0 {
			c := q[0]
			q = q[1:]
			for _, nb := range infraAdj[c] {
				if _, ok := dist[nb]; !ok {
					dist[nb] = dist[c] + 1
					if dist[nb] > far {
						far = dist[nb]
					}
					q = append(q, nb)
				}
			}
		}
		ecc[id] = far
	}
	var infraIDs []int64
	for id := range infra {
		infraIDs = append(infraIDs, id)
	}
	sort.Slice(infraIDs, func(i, j int) bool {
		a, b := infraIDs[i], infraIDs[j]
		if ecc[a] != ecc[b] {
			return ecc[a] < ecc[b]
		}
		if deg[a] != deg[b] {
			return deg[a] > deg[b]
		}
		return a < b
	})
	for _, root := range infraIDs {
		if _, done := level[root]; done {
			continue
		}
		level[root] = 0
		queue := []int64{root}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, nb := range adj[cur] {
				if _, ok := level[nb]; ok || !infra[nb] {
					continue
				}
				level[nb] = level[cur] + 1
				queue = append(queue, nb)
			}
		}
	}
	for _, n := range nodes {
		if _, ok := level[n.ID]; ok {
			continue
		}
		best := -1
		for _, nb := range adj[n.ID] {
			if l, ok := level[nb]; ok && infra[nb] && (best < 0 || l < best) {
				best = l
			}
		}
		level[n.ID] = best + 1
	}
	return level
}

// Neighbors returns node IDs directly connected to id.
func Neighbors(edges []Edge, id int64) []int64 {
	seen := map[int64]bool{}
	var out []int64
	for _, e := range edges {
		var o int64
		switch id {
		case e.A:
			o = e.B
		case e.B:
			o = e.A
		default:
			continue
		}
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Downstream returns every node reachable from id without passing through
// nodes at a lower or equal hierarchy level (i.e. "everything behind" a switch).
func Downstream(edges []Edge, levels map[int64]int, id int64) []int64 {
	adj := map[int64][]int64{}
	for _, e := range edges {
		adj[e.A] = append(adj[e.A], e.B)
		adj[e.B] = append(adj[e.B], e.A)
	}
	seen := map[int64]bool{id: true}
	queue := []int64{id}
	var out []int64
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, nb := range adj[cur] {
			if seen[nb] || levels[nb] <= levels[cur] {
				continue
			}
			seen[nb] = true
			out = append(out, nb)
			queue = append(queue, nb)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Layout computes a deterministic layered layout for nodes without pinned
// positions: levels become rows, children are placed under their parents.
func Layout(nodes []Node, edges []Edge, levels map[int64]int) map[int64][2]float64 {
	const dx, dy = 190.0, 170.0
	rows := map[int][]Node{}
	maxLevel := 0
	for _, n := range nodes {
		l := levels[n.ID]
		rows[l] = append(rows[l], n)
		if l > maxLevel {
			maxLevel = l
		}
	}
	parent := map[int64]int64{}
	for _, e := range edges {
		la, lb := levels[e.A], levels[e.B]
		if la < lb {
			if _, ok := parent[e.B]; !ok {
				parent[e.B] = e.A
			}
		} else if lb < la {
			if _, ok := parent[e.A]; !ok {
				parent[e.A] = e.B
			}
		}
	}
	pos := map[int64][2]float64{}
	for l := 0; l <= maxLevel; l++ {
		row := rows[l]
		// order by parent x, then infra first, then label
		sort.SliceStable(row, func(i, j int) bool {
			pi, pj := pos[parent[row[i].ID]][0], pos[parent[row[j].ID]][0]
			if pi != pj {
				return pi < pj
			}
			if row[i].Infra != row[j].Infra {
				return row[i].Infra
			}
			return row[i].Label < row[j].Label
		})
		width := float64(len(row)-1) * dx
		for i, n := range row {
			pos[n.ID] = [2]float64{float64(i)*dx - width/2, float64(l) * dy}
		}
	}
	return pos
}
