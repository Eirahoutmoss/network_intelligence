package inventory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// DeviceRow is a device as shown in lists.
type DeviceRow struct {
	ID                   int64      `json:"id"`
	Name                 string     `json:"name"`
	Hostname             *string    `json:"hostname"`
	DeviceType           string     `json:"device_type"`
	TypeConfidence       float64    `json:"device_type_confidence"`
	TypeOverridden       bool       `json:"type_overridden"`
	Vendor               *string    `json:"vendor"`
	Model                *string    `json:"model"`
	OSName               *string    `json:"os_name"`
	OSConfidence         float64    `json:"os_confidence"`
	IP                   *string    `json:"ip"`
	MAC                  *string    `json:"mac"`
	Managed              bool       `json:"managed"`
	Status               string     `json:"status"`
	DiscoveredVia        string     `json:"discovered_via"`
	FirstSeen            time.Time  `json:"first_seen"`
	LastSeen             time.Time  `json:"last_seen"`
	SwitchID             *int64     `json:"switch_id"`
	SwitchName           *string    `json:"switch_name"`
	SwitchPort           *string    `json:"switch_port"`
	VLAN                 *int       `json:"vlan"`
	AttachmentConfidence *float64   `json:"attachment_confidence"`
	Jack                 *string    `json:"jack"`
	LocationID           *int64     `json:"location_id"`
	LocationSource       *string    `json:"location_source"`
	LocationPath         *string    `json:"location_path"`
	Tags                 []string   `json:"tags"`
	MovedAt              *time.Time `json:"moved_at,omitempty"`
	PreviousPort         *string    `json:"previous_port,omitempty"`
}

// DeviceFilter narrows device lists (used by the Devices page and Explorer).
type DeviceFilter struct {
	IDs             []int64
	RestrictIDs     bool // when true, an empty IDs list yields no rows
	Types           []string
	Vendors         []string
	OS              string
	LocationIDs     []int64
	RestrictLoc     bool
	Subnet          string
	IP              string
	MAC             string
	VLAN            int
	Status          string
	Managed         *bool
	PortChangedDays int
	NewDays         int
	Text            string
	SwitchID        int64
	Tag             string
	Sort            string
	Limit           int
	Offset          int
}

const deviceCols = `v.id, v.name, v.hostname, v.device_type, v.device_type_confidence, v.type_overridden, v.vendor, v.model, v.os_name,
	v.os_confidence, v.ip, v.mac, v.managed, v.status, v.discovered_via, v.first_seen, v.last_seen, v.switch_id, v.switch_name,
	v.switch_port, v.vlan_id, v.attachment_confidence, v.jack, v.location_id, v.location_source, v.location_path, v.tags`

func scanDevice(r pgx.Row, extra ...any) (DeviceRow, error) {
	var d DeviceRow
	dest := []any{&d.ID, &d.Name, &d.Hostname, &d.DeviceType, &d.TypeConfidence, &d.TypeOverridden, &d.Vendor, &d.Model, &d.OSName,
		&d.OSConfidence, &d.IP, &d.MAC, &d.Managed, &d.Status, &d.DiscoveredVia, &d.FirstSeen, &d.LastSeen, &d.SwitchID, &d.SwitchName,
		&d.SwitchPort, &d.VLAN, &d.AttachmentConfidence, &d.Jack, &d.LocationID, &d.LocationSource, &d.LocationPath, &d.Tags}
	err := r.Scan(append(dest, extra...)...)
	return d, err
}

// ListDevices returns matching devices and the total count.
func (s *Store) ListDevices(ctx context.Context, f DeviceFilter) ([]DeviceRow, int, error) {
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if f.RestrictIDs || len(f.IDs) > 0 {
		where = append(where, "v.id = ANY("+arg(f.IDs)+")")
	}
	if len(f.Types) > 0 {
		where = append(where, "v.device_type = ANY("+arg(f.Types)+")")
	}
	if len(f.Vendors) > 0 {
		var pats []string
		for _, v := range f.Vendors {
			pats = append(pats, v+"%")
		}
		where = append(where, "v.vendor ILIKE ANY("+arg(pats)+")")
	}
	if f.OS != "" {
		where = append(where, "v.os_name ILIKE "+arg("%"+f.OS+"%"))
	}
	if f.RestrictLoc || len(f.LocationIDs) > 0 {
		where = append(where, "v.location_id = ANY("+arg(f.LocationIDs)+")")
	}
	if f.Subnet != "" {
		where = append(where, "EXISTS (SELECT 1 FROM device_addresses a WHERE a.device_id=v.id AND a.ip <<= "+arg(f.Subnet)+"::cidr)")
	}
	if f.IP != "" {
		where = append(where, "EXISTS (SELECT 1 FROM device_addresses a WHERE a.device_id=v.id AND a.ip = "+arg(f.IP)+"::inet)")
	}
	if f.MAC != "" {
		where = append(where, "EXISTS (SELECT 1 FROM device_macs m WHERE m.device_id=v.id AND m.mac = "+arg(f.MAC)+"::macaddr)")
	}
	if f.VLAN != 0 {
		where = append(where, "v.vlan_id = "+arg(f.VLAN))
	}
	if f.Status != "" {
		where = append(where, "v.status = "+arg(f.Status))
	}
	if f.Managed != nil {
		where = append(where, "v.managed = "+arg(*f.Managed))
	}
	if f.NewDays > 0 {
		where = append(where, "v.first_seen >= now() - make_interval(days => "+arg(f.NewDays)+")")
	}
	if f.SwitchID != 0 {
		where = append(where, "v.switch_id = "+arg(f.SwitchID))
	}
	if f.Tag != "" {
		where = append(where, arg(f.Tag)+" = ANY(v.tags)")
	}
	if t := strings.TrimSpace(f.Text); t != "" {
		p := arg("%" + t + "%")
		where = append(where, fmt.Sprintf(`(v.name ILIKE %[1]s OR v.hostname ILIKE %[1]s OR v.ip ILIKE %[1]s OR v.mac ILIKE %[1]s
			OR v.vendor ILIKE %[1]s OR v.model ILIKE %[1]s OR v.os_name ILIKE %[1]s OR v.serial ILIKE %[1]s OR v.description ILIKE %[1]s
			OR EXISTS (SELECT 1 FROM device_addresses a WHERE a.device_id=v.id AND host(a.ip) ILIKE %[1]s))`, p))
	}
	extraCols := ", NULL::timestamptz, NULL::text"
	join := ""
	if f.PortChangedDays > 0 {
		join = ` JOIN LATERAL (SELECT a.ended_at, a.port_name, s.sys_name FROM attachments a JOIN devices s ON s.id=a.switch_id
			WHERE a.device_id=v.id AND a.ended_at >= now() - make_interval(days => ` + arg(f.PortChangedDays) + `)
			ORDER BY a.ended_at DESC LIMIT 1) mv ON true`
		extraCols = ", mv.ended_at, COALESCE(mv.sys_name,'') || ' ' || COALESCE(mv.port_name,'')"
	}
	w := ""
	if len(where) > 0 {
		w = " WHERE " + strings.Join(where, " AND ")
	}
	order := map[string]string{
		"name": "lower(v.name)", "type": "v.device_type, lower(v.name)", "vendor": "v.vendor NULLS LAST, lower(v.name)",
		"ip": "v.ip::inet NULLS LAST", "last_seen": "v.last_seen DESC", "first_seen": "v.first_seen DESC",
		"switch": "v.switch_name NULLS LAST, v.switch_port",
	}[f.Sort]
	if order == "" {
		order = "v.managed DESC, v.device_type, v.ip::inet NULLS LAST, lower(v.name)"
	}
	if f.Limit <= 0 || f.Limit > 5000 {
		f.Limit = 500
	}
	var total int
	if err := s.DB.QueryRow(ctx, "SELECT count(*) FROM device_view v"+join+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := "SELECT " + deviceCols + extraCols + " FROM device_view v" + join + w + " ORDER BY " + order +
		fmt.Sprintf(" LIMIT %d OFFSET %d", f.Limit, max(f.Offset, 0))
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []DeviceRow
	for rows.Next() {
		var moved *time.Time
		var prev *string
		d, err := scanDevice(rows, &moved, &prev)
		if err != nil {
			return nil, 0, err
		}
		d.MovedAt, d.PreviousPort = moved, prev
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// GetDeviceRow returns one device row.
func (s *Store) GetDeviceRow(ctx context.Context, id int64) (DeviceRow, error) {
	return scanDevice(s.DB.QueryRow(ctx, "SELECT "+deviceCols+" FROM device_view v WHERE v.id=$1", id))
}
