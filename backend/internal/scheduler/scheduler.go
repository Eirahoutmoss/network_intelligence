// Package scheduler runs periodic monitoring: lightweight SNMP polls of
// managed devices (status, interfaces, health), scheduled re-discovery and
// data retention.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/discovery"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/events"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/metrics"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

type Scheduler struct {
	DB           *storage.DB
	Store        *inventory.Store
	Creds        *credentials.Store
	Collector    *discovery.Collector
	Engine       *discovery.Engine
	Log          *slog.Logger
	Metrics      *metrics.Registry
	PollInterval time.Duration
	Rediscover   time.Duration
	Retention    time.Duration
	Workers      int
}

// Start runs the loops until ctx ends.
func (s *Scheduler) Start(ctx context.Context) {
	if s.Workers <= 0 {
		s.Workers = 4
	}
	go s.loop(ctx, s.PollInterval, s.PollAll)
	if s.Rediscover > 0 {
		go s.loop(ctx, s.Rediscover, func(ctx context.Context) {
			if _, err := s.Engine.SubmitRefresh(ctx, 0); err != nil {
				s.Log.Info("scheduled rediscovery skipped", "reason", err)
			}
		})
	}
	go s.loop(ctx, time.Hour, s.cleanup)
}

func (s *Scheduler) loop(ctx context.Context, every time.Duration, f func(context.Context)) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f(ctx)
		}
	}
}

type pollTarget struct {
	id     int64
	ip     string
	credID int64
	name   string
	status string
}

// PollAll polls every managed device once.
func (s *Scheduler) PollAll(ctx context.Context) {
	rows, err := s.DB.Query(ctx, `SELECT id, host(mgmt_ip), snmp_credential_id, COALESCE(sys_name, host(mgmt_ip)), status
		FROM devices WHERE managed AND mgmt_ip IS NOT NULL AND snmp_credential_id IS NOT NULL`)
	if err != nil {
		s.Log.Error("poll: list devices", "err", err)
		return
	}
	targets, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (pollTarget, error) {
		var t pollTarget
		err := r.Scan(&t.id, &t.ip, &t.credID, &t.name, &t.status)
		return t, err
	})
	if err != nil {
		return
	}
	sem := make(chan struct{}, s.Workers)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t pollTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			s.PollOne(ctx, t)
		}(t)
	}
	wg.Wait()
}

func (s *Scheduler) PollOne(ctx context.Context, t pollTarget) {
	start := time.Now()
	cred, err := s.Creds.SNMP(ctx, t.credID)
	if err == nil {
		sn, cerr := s.Collector.Collect(ctx, t.ip, cred, false, nil)
		err = cerr
		if err == nil {
			_, _, err = s.Store.IngestSnapshot(ctx, sn, inventory.IngestOptions{MgmtIP: t.ip, CredentialID: t.credID, Via: "poll", Full: false})
		}
	}
	dur := time.Since(start)
	if s.Metrics != nil {
		s.Metrics.Observe("nexus_poll_duration_seconds", dur.Seconds())
		if err != nil {
			s.Metrics.Inc("nexus_poll_errors_total", errorKind(err))
		}
	}
	var errText any
	if err != nil {
		errText = err.Error()
	}
	_, _ = s.DB.Exec(ctx, `INSERT INTO poll_runs(device_id, kind, duration_ms, ok, error) VALUES ($1,'poll',$2,$3,$4)`,
		t.id, dur.Milliseconds(), err == nil, errText)
	if err == nil {
		if t.status == "down" {
			events.Record(ctx, s.DB, t.id, events.DeviceUp, events.Info, t.name+" is reachable again", nil)
			events.Resolve(ctx, s.DB, t.id, "device_down", "")
		}
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	// Two consecutive failures mark the device down (avoids flapping on one lost packet).
	var fails int
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM (SELECT ok FROM poll_runs WHERE device_id=$1 ORDER BY started_at DESC LIMIT 2) x WHERE NOT ok`, t.id).Scan(&fails)
	if fails >= 2 && t.status != "down" {
		_, _ = s.DB.Exec(ctx, `UPDATE devices SET status='down' WHERE id=$1`, t.id)
		msg := fmt.Sprintf("%s is not answering SNMP", t.name)
		events.Record(ctx, s.DB, t.id, events.DeviceDown, events.Critical, msg, map[string]any{"error": err.Error()})
		events.Open(ctx, s.DB, t.id, "device_down", "", events.Critical, msg)
	}
	s.Log.Warn("poll failed", "device", t.name, "ip", t.ip, "err", err)
}

func errorKind(err error) string {
	switch {
	case errors.Is(err, discovery.ErrAuthFailed):
		return "auth"
	case errors.Is(err, discovery.ErrUnreachable):
		return "timeout"
	}
	return "error"
}

func (s *Scheduler) cleanup(ctx context.Context) {
	ret := s.Retention
	if ret <= 0 {
		ret = 7 * 24 * time.Hour
	}
	for _, q := range []string{
		`DELETE FROM interface_metrics WHERE ts < now() - $1::interval`,
		`DELETE FROM poll_runs WHERE started_at < now() - $1::interval`,
		`DELETE FROM events WHERE ts < now() - ($1::interval * 13)`,
		`DELETE FROM auth_sessions WHERE expires_at < now()`,
	} {
		arg := fmt.Sprintf("%d seconds", int(ret.Seconds()))
		if q == `DELETE FROM auth_sessions WHERE expires_at < now()` {
			_, _ = s.DB.Exec(ctx, q)
			continue
		}
		if _, err := s.DB.Exec(ctx, q, arg); err != nil {
			s.Log.Warn("retention cleanup", "err", err)
		}
	}
}
