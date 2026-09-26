// Package events records network events and manages alerts.
package events

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// Severities.
const (
	Info     = "info"
	Warning  = "warning"
	Critical = "critical"
)

// Event kinds.
const (
	DeviceDiscovered   = "device.discovered"
	DeviceDown         = "device.down"
	DeviceUp           = "device.up"
	InterfaceDown      = "interface.down"
	InterfaceUp        = "interface.up"
	EndpointNew        = "endpoint.new"
	EndpointMoved      = "endpoint.moved"
	DevicesMerged      = "identity.merged"
	DiscoveryCompleted = "discovery.completed"
	DiscoveryFailed    = "discovery.failed"
	HighCPU            = "health.cpu"
	HighTemperature    = "health.temperature"
	OpticLowPower      = "optic.low_power"
)

type Event struct {
	ID       int64          `json:"id"`
	TS       time.Time      `json:"ts"`
	DeviceID *int64         `json:"device_id"`
	Device   string         `json:"device,omitempty"`
	Kind     string         `json:"kind"`
	Severity string         `json:"severity"`
	Message  string         `json:"message"`
	Detail   map[string]any `json:"detail"`
}

type Alert struct {
	ID           int64      `json:"id"`
	DeviceID     *int64     `json:"device_id"`
	Device       string     `json:"device,omitempty"`
	Rule         string     `json:"rule"`
	Subject      string     `json:"subject"`
	Severity     string     `json:"severity"`
	Message      string     `json:"message"`
	OpenedAt     time.Time  `json:"opened_at"`
	ResolvedAt   *time.Time `json:"resolved_at"`
	Acknowledged bool       `json:"acknowledged"`
}

// Record inserts an event.
func Record(ctx context.Context, q storage.DBTX, deviceID int64, kind, severity, msg string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	var dev any
	if deviceID != 0 {
		dev = deviceID
	}
	if _, err := q.Exec(ctx, `INSERT INTO events(device_id,kind,severity,message,detail) VALUES ($1,$2,$3,$4,$5)`,
		dev, kind, severity, msg, detail); err != nil {
		slog.Warn("record event", "err", err, "kind", kind)
	}
}

// Open raises an alert if one is not already open for (device, rule, subject).
// Returns true when a new alert was opened.
func Open(ctx context.Context, q storage.DBTX, deviceID int64, rule, subject, severity, msg string) bool {
	tag, err := q.Exec(ctx, `INSERT INTO alerts(device_id,rule,subject,severity,message) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (device_id, rule, subject) WHERE resolved_at IS NULL DO NOTHING`, deviceID, rule, subject, severity, msg)
	if err != nil {
		slog.Warn("open alert", "err", err)
		return false
	}
	return tag.RowsAffected() > 0
}

// Resolve closes an open alert. Returns true if one was closed.
func Resolve(ctx context.Context, q storage.DBTX, deviceID int64, rule, subject string) bool {
	tag, err := q.Exec(ctx, `UPDATE alerts SET resolved_at=now() WHERE device_id=$1 AND rule=$2 AND subject=$3 AND resolved_at IS NULL`,
		deviceID, rule, subject)
	return err == nil && tag.RowsAffected() > 0
}

// List returns recent events, optionally for a device.
func List(ctx context.Context, q storage.DBTX, deviceID int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := q.Query(ctx, `SELECT e.id,e.ts,e.device_id,COALESCE(c.display_name,d.sys_name,d.hostname,host(d.mgmt_ip),''),e.kind,e.severity,e.message,e.detail
		FROM events e LEFT JOIN devices d ON d.id=e.device_id LEFT JOIN device_context c ON c.device_id=e.device_id
		WHERE ($1=0 OR e.device_id=$1) ORDER BY e.ts DESC, e.id DESC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Event, error) {
		var e Event
		err := r.Scan(&e.ID, &e.TS, &e.DeviceID, &e.Device, &e.Kind, &e.Severity, &e.Message, &e.Detail)
		return e, err
	})
}

// Alerts lists alerts (open only unless all).
func Alerts(ctx context.Context, q storage.DBTX, all bool) ([]Alert, error) {
	rows, err := q.Query(ctx, `SELECT a.id,a.device_id,COALESCE(c.display_name,d.sys_name,d.hostname,host(d.mgmt_ip),''),a.rule,a.subject,a.severity,a.message,a.opened_at,a.resolved_at,a.acknowledged
		FROM alerts a LEFT JOIN devices d ON d.id=a.device_id LEFT JOIN device_context c ON c.device_id=a.device_id
		WHERE ($1 OR a.resolved_at IS NULL) ORDER BY a.resolved_at IS NULL DESC, a.opened_at DESC LIMIT 500`, all)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alert, error) {
		var a Alert
		err := r.Scan(&a.ID, &a.DeviceID, &a.Device, &a.Rule, &a.Subject, &a.Severity, &a.Message, &a.OpenedAt, &a.ResolvedAt, &a.Acknowledged)
		return a, err
	})
}

// Acknowledge marks an alert acknowledged.
func Acknowledge(ctx context.Context, q storage.DBTX, id int64) error {
	_, err := q.Exec(ctx, `UPDATE alerts SET acknowledged=true WHERE id=$1`, id)
	return err
}
