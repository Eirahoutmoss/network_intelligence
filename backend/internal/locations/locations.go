// Package locations manages the user-defined physical context: buildings,
// floors, rooms, racks, patch panels and wall jacks, plus per-device context
// (custom name, description, tags, placement). Nothing here modifies
// machine-discovered facts.
package locations

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

type Service struct{ DB *storage.DB }

type Location struct {
	ID          int64   `json:"id"`
	ParentID    *int64  `json:"parent_id"`
	Kind        string  `json:"kind"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	Level       *int    `json:"level"`
	Path        string  `json:"path"`
	DeviceCount int     `json:"device_count"`
}

type Rack struct {
	ID          int64   `json:"id"`
	LocationID  int64   `json:"location_id"`
	Name        string  `json:"name"`
	Units       int     `json:"units"`
	Description *string `json:"description"`
}

type PatchPanel struct {
	ID         int64  `json:"id"`
	LocationID int64  `json:"location_id"`
	RackID     *int64 `json:"rack_id"`
	Name       string `json:"name"`
	PortCount  int    `json:"port_count"`
}

type Jack struct {
	ID                int64   `json:"id"`
	LocationID        int64   `json:"location_id"`
	Location          string  `json:"location"`
	Label             string  `json:"label"`
	PatchPanelID      *int64  `json:"patch_panel_id"`
	PatchPanel        *string `json:"patch_panel"`
	PatchPort         *int    `json:"patch_port"`
	SwitchDeviceID    *int64  `json:"switch_device_id"`
	Switch            *string `json:"switch"`
	SwitchInterfaceID *int64  `json:"switch_interface_id"`
	Port              *string `json:"port"`
	Description       *string `json:"description"`
	CurrentDevices    int     `json:"current_devices"`
}

var validKinds = map[string]bool{"site": true, "building": true, "floor": true, "room": true, "closet": true, "area": true}

func (s *Service) List(ctx context.Context) ([]Location, error) {
	rows, err := s.DB.Query(ctx, `SELECT l.id, l.parent_id, l.kind, l.name, l.description, l.level, lp.path, lp.ancestors
		FROM locations l JOIN location_paths lp ON lp.id=l.id ORDER BY lp.path`)
	if err != nil {
		return nil, err
	}
	var ancestors [][]int64
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Location, error) {
		var l Location
		var anc []int64
		err := r.Scan(&l.ID, &l.ParentID, &l.Kind, &l.Name, &l.Description, &l.Level, &l.Path, &anc)
		ancestors = append(ancestors, anc)
		return l, err
	})
	if err != nil || len(out) == 0 {
		return out, err
	}
	// Count devices per location once, then roll the counts up the tree.
	direct := map[int64]int{}
	crow, err := s.DB.Query(ctx, `SELECT location_id, count(*) FROM device_view WHERE location_id IS NOT NULL GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	for crow.Next() {
		var id int64
		var n int
		if err := crow.Scan(&id, &n); err != nil {
			crow.Close()
			return nil, err
		}
		direct[id] = n
	}
	crow.Close()
	total := map[int64]int{}
	for i, l := range out {
		for _, a := range ancestors[i] {
			total[a] += direct[l.ID]
		}
	}
	for i := range out {
		out[i].DeviceCount = total[out[i].ID]
	}
	return out, nil
}

var reLevel = regexp.MustCompile(`-?\d+`)

// floorLevel infers a floor number from its name ("Floor 2", "2. Kat", "Basement" → -1, "Ground"/"Zemin" → 0).
func floorLevel(name string) *int {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "basement") || strings.Contains(l, "bodrum"):
		v := -1
		return &v
	case strings.Contains(l, "ground") || strings.Contains(l, "zemin"):
		v := 0
		return &v
	}
	if m := reLevel.FindString(name); m != "" {
		v, _ := strconv.Atoi(m)
		return &v
	}
	return nil
}

func (s *Service) Create(ctx context.Context, l Location) (int64, error) {
	l.Name = strings.TrimSpace(l.Name)
	if l.Name == "" {
		return 0, errors.New("name is required")
	}
	if !validKinds[l.Kind] {
		return 0, fmt.Errorf("invalid kind %q", l.Kind)
	}
	if l.Kind == "floor" && l.Level == nil {
		l.Level = floorLevel(l.Name)
	}
	var id int64
	err := s.DB.QueryRow(ctx, `INSERT INTO locations(parent_id, kind, name, description, level) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		l.ParentID, l.Kind, l.Name, l.Description, l.Level).Scan(&id)
	return id, err
}

func (s *Service) Update(ctx context.Context, id int64, l Location) error {
	if !validKinds[l.Kind] {
		return fmt.Errorf("invalid kind %q", l.Kind)
	}
	if l.ParentID != nil {
		// prevent cycles
		var cyc bool
		if err := s.DB.QueryRow(ctx, `SELECT $1 = ANY(ancestors) FROM location_paths WHERE id=$2`, id, *l.ParentID).Scan(&cyc); err != nil {
			return err
		}
		if cyc {
			return errors.New("a location cannot be moved under itself")
		}
	}
	if l.Kind == "floor" && l.Level == nil {
		l.Level = floorLevel(l.Name)
	}
	_, err := s.DB.Exec(ctx, `UPDATE locations SET parent_id=$2, kind=$3, name=$4, description=$5, level=$6 WHERE id=$1`,
		id, l.ParentID, l.Kind, strings.TrimSpace(l.Name), l.Description, l.Level)
	return err
}

func (s *Service) Delete(ctx context.Context, id int64) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM locations WHERE id=$1`, id)
	return err
}

// ---- racks & patch panels

func (s *Service) Racks(ctx context.Context) ([]Rack, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, location_id, name, units, description FROM racks ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Rack])
}

func (s *Service) CreateRack(ctx context.Context, r Rack) (int64, error) {
	if strings.TrimSpace(r.Name) == "" || r.LocationID == 0 {
		return 0, errors.New("name and location are required")
	}
	if r.Units <= 0 {
		r.Units = 42
	}
	var id int64
	err := s.DB.QueryRow(ctx, `INSERT INTO racks(location_id, name, units, description) VALUES ($1,$2,$3,$4) RETURNING id`,
		r.LocationID, r.Name, r.Units, r.Description).Scan(&id)
	return id, err
}

func (s *Service) DeleteRack(ctx context.Context, id int64) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM racks WHERE id=$1`, id)
	return err
}

func (s *Service) PatchPanels(ctx context.Context) ([]PatchPanel, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, location_id, rack_id, name, port_count FROM patch_panels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[PatchPanel])
}

func (s *Service) CreatePatchPanel(ctx context.Context, p PatchPanel) (int64, error) {
	if strings.TrimSpace(p.Name) == "" || p.LocationID == 0 {
		return 0, errors.New("name and location are required")
	}
	if p.PortCount <= 0 {
		p.PortCount = 24
	}
	var id int64
	err := s.DB.QueryRow(ctx, `INSERT INTO patch_panels(location_id, rack_id, name, port_count) VALUES ($1,$2,$3,$4) RETURNING id`,
		p.LocationID, p.RackID, p.Name, p.PortCount).Scan(&id)
	return id, err
}

func (s *Service) DeletePatchPanel(ctx context.Context, id int64) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM patch_panels WHERE id=$1`, id)
	return err
}

// ---- jacks

func (s *Service) Jacks(ctx context.Context, locationID int64) ([]Jack, error) {
	rows, err := s.DB.Query(ctx, `SELECT j.id, j.location_id, lp.path, j.label, j.patch_panel_id, pp.name, j.patch_port, j.switch_device_id,
			COALESCE(c.display_name, sw.sys_name), j.switch_interface_id, i.name, j.description,
			(SELECT count(*) FROM attachments a WHERE a.interface_id=j.switch_interface_id AND a.ended_at IS NULL)
		FROM network_jacks j JOIN location_paths lp ON lp.id=j.location_id
		LEFT JOIN patch_panels pp ON pp.id=j.patch_panel_id LEFT JOIN devices sw ON sw.id=j.switch_device_id
		LEFT JOIN device_context c ON c.device_id=sw.id LEFT JOIN interfaces i ON i.id=j.switch_interface_id
		WHERE ($1=0 OR $1 = ANY(lp.ancestors)) ORDER BY lp.path, j.label`, locationID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Jack])
}

func (s *Service) validateJack(ctx context.Context, j *Jack) error {
	j.Label = strings.TrimSpace(j.Label)
	if j.Label == "" || j.LocationID == 0 {
		return errors.New("label and location are required")
	}
	if j.SwitchInterfaceID != nil {
		var dev int64
		if err := s.DB.QueryRow(ctx, `SELECT device_id FROM interfaces WHERE id=$1`, *j.SwitchInterfaceID).Scan(&dev); err != nil {
			return errors.New("unknown switch interface")
		}
		j.SwitchDeviceID = &dev
	}
	return nil
}

func (s *Service) CreateJack(ctx context.Context, j Jack) (int64, error) {
	if err := s.validateJack(ctx, &j); err != nil {
		return 0, err
	}
	var id int64
	err := s.DB.QueryRow(ctx, `INSERT INTO network_jacks(location_id, label, patch_panel_id, patch_port, switch_device_id, switch_interface_id, description)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`, j.LocationID, j.Label, j.PatchPanelID, j.PatchPort, j.SwitchDeviceID, j.SwitchInterfaceID, j.Description).Scan(&id)
	if err != nil && strings.Contains(err.Error(), "duplicate") {
		return 0, errors.New("a jack with this label already exists in the location")
	}
	return id, err
}

func (s *Service) UpdateJack(ctx context.Context, id int64, j Jack) error {
	if err := s.validateJack(ctx, &j); err != nil {
		return err
	}
	_, err := s.DB.Exec(ctx, `UPDATE network_jacks SET location_id=$2, label=$3, patch_panel_id=$4, patch_port=$5, switch_device_id=$6,
		switch_interface_id=$7, description=$8 WHERE id=$1`, id, j.LocationID, j.Label, j.PatchPanelID, j.PatchPort, j.SwitchDeviceID, j.SwitchInterfaceID, j.Description)
	return err
}

func (s *Service) DeleteJack(ctx context.Context, id int64) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM network_jacks WHERE id=$1`, id)
	return err
}

// ---- device context

type DeviceContext struct {
	DisplayName        *string  `json:"display_name"`
	Description        *string  `json:"description"`
	Department         *string  `json:"department"`
	DeviceTypeOverride *string  `json:"device_type_override"`
	LocationID         *int64   `json:"location_id"`
	RackID             *int64   `json:"rack_id"`
	RackUnit           *int     `json:"rack_unit"`
	Tags               []string `json:"tags"`
}

func emptyToNil(p *string) *string {
	if p == nil || strings.TrimSpace(*p) == "" {
		return nil
	}
	t := strings.TrimSpace(*p)
	return &t
}

func (s *Service) GetContext(ctx context.Context, deviceID int64) (DeviceContext, error) {
	var c DeviceContext
	err := s.DB.QueryRow(ctx, `SELECT display_name, description, department, device_type_override, location_id, rack_id, rack_unit
		FROM device_context WHERE device_id=$1`, deviceID).Scan(&c.DisplayName, &c.Description, &c.Department, &c.DeviceTypeOverride, &c.LocationID, &c.RackID, &c.RackUnit)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return c, err
	}
	rows, err := s.DB.Query(ctx, `SELECT tag FROM device_tags WHERE device_id=$1 ORDER BY tag`, deviceID)
	if err != nil {
		return c, err
	}
	c.Tags, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if c.Tags == nil {
		c.Tags = []string{}
	}
	return c, err
}

// SetContext replaces the user context of a device.
func (s *Service) SetContext(ctx context.Context, deviceID int64, c DeviceContext) error {
	c.DisplayName, c.Description, c.Department = emptyToNil(c.DisplayName), emptyToNil(c.Description), emptyToNil(c.Department)
	c.DeviceTypeOverride = emptyToNil(c.DeviceTypeOverride)
	if c.DeviceTypeOverride != nil {
		ok := false
		for _, t := range model.DeviceTypes {
			ok = ok || t == *c.DeviceTypeOverride
		}
		if !ok {
			return fmt.Errorf("invalid device type %q", *c.DeviceTypeOverride)
		}
	}
	return pgx.BeginFunc(ctx, s.DB.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO device_context(device_id, display_name, description, department, device_type_override, location_id, rack_id, rack_unit, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
			ON CONFLICT (device_id) DO UPDATE SET display_name=EXCLUDED.display_name, description=EXCLUDED.description, department=EXCLUDED.department,
				device_type_override=EXCLUDED.device_type_override, location_id=EXCLUDED.location_id, rack_id=EXCLUDED.rack_id,
				rack_unit=EXCLUDED.rack_unit, updated_at=now()`,
			deviceID, c.DisplayName, c.Description, c.Department, c.DeviceTypeOverride, c.LocationID, c.RackID, c.RackUnit); err != nil {
			return err
		}
		if c.Tags != nil {
			if _, err := tx.Exec(ctx, `DELETE FROM device_tags WHERE device_id=$1`, deviceID); err != nil {
				return err
			}
			for _, t := range c.Tags {
				if t = strings.TrimSpace(t); t != "" {
					if _, err := tx.Exec(ctx, `INSERT INTO device_tags(device_id, tag) VALUES ($1,$2) ON CONFLICT DO NOTHING`, deviceID, t); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

// SetDeviceLocation assigns many devices to a location in one call.
func (s *Service) SetDeviceLocation(ctx context.Context, ids []int64, locationID *int64) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO device_context(device_id, location_id) SELECT unnest($1::bigint[]), $2
		ON CONFLICT (device_id) DO UPDATE SET location_id=EXCLUDED.location_id, updated_at=now()`, ids, locationID)
	return err
}

// ImportResult summarizes an import from SNMP sysLocation.
type ImportResult struct {
	Created  int `json:"created"`
	Assigned int `json:"assigned"`
}

// ImportFromSysLocation proposes structure from the discovered SNMP
// sysLocation strings ("Building A / Floor 2 / IDF-2") and assigns the
// devices that do not already have a user-set location. It is an explicit
// user action, not something discovery does silently.
func (s *Service) ImportFromSysLocation(ctx context.Context) (ImportResult, error) {
	var res ImportResult
	err := pgx.BeginFunc(ctx, s.DB.Pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id, d.sys_location FROM devices d LEFT JOIN device_context c ON c.device_id=d.id
			WHERE d.managed AND COALESCE(d.sys_location,'') <> '' AND c.location_id IS NULL`)
		if err != nil {
			return err
		}
		type item struct {
			id  int64
			loc string
		}
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.id, &it.loc); err != nil {
				rows.Close()
				return err
			}
			items = append(items, it)
		}
		rows.Close()
		for _, it := range items {
			parts := splitLocation(it.loc)
			if len(parts) == 0 {
				continue
			}
			var parent *int64
			for i, p := range parts {
				kind := guessKind(p, i, len(parts))
				var id int64
				err := tx.QueryRow(ctx, `SELECT id FROM locations WHERE lower(name)=lower($1) AND parent_id IS NOT DISTINCT FROM $2`, p, parent).Scan(&id)
				if errors.Is(err, pgx.ErrNoRows) {
					var lvl *int
					if kind == "floor" {
						lvl = floorLevel(p)
					}
					if err := tx.QueryRow(ctx, `INSERT INTO locations(parent_id, kind, name, level) VALUES ($1,$2,$3,$4) RETURNING id`, parent, kind, p, lvl).Scan(&id); err != nil {
						return err
					}
					res.Created++
				} else if err != nil {
					return err
				}
				parent = &id
			}
			if _, err := tx.Exec(ctx, `INSERT INTO device_context(device_id, location_id) VALUES ($1,$2)
				ON CONFLICT (device_id) DO UPDATE SET location_id=EXCLUDED.location_id, updated_at=now()`, it.id, *parent); err != nil {
				return err
			}
			res.Assigned++
		}
		return nil
	})
	return res, err
}

func splitLocation(s string) []string {
	var parts []string
	for _, p := range regexp.MustCompile(`\s*[/>|;,]\s*`).Split(strings.TrimSpace(s), -1) {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) > 6 {
		parts = parts[:6]
	}
	return parts
}

func guessKind(name string, idx, n int) string {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "building") || strings.Contains(l, "bina") || strings.Contains(l, "blok") || strings.Contains(l, "block"):
		return "building"
	case strings.Contains(l, "floor") || strings.Contains(l, "kat") || strings.Contains(l, "basement") || strings.Contains(l, "bodrum") || strings.Contains(l, "zemin"):
		return "floor"
	case strings.Contains(l, "idf") || strings.Contains(l, "mdf") || strings.Contains(l, "closet") || strings.Contains(l, "kabinet") || strings.Contains(l, "dolap"):
		return "closet"
	case strings.Contains(l, "room") || strings.Contains(l, "oda") || strings.Contains(l, "lab") || strings.Contains(l, "server"):
		return "room"
	case idx == 0 && n > 1:
		return "building"
	case idx == 1 && n > 2:
		return "floor"
	}
	return "room"
}
