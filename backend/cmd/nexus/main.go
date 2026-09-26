// Command nexus runs the Network Intelligence Platform server.
//
//	nexus            start the server (default)
//	nexus migrate    apply database migrations and exit
//	nexus lab-export DIR   write the simulated lab as snmprec fixtures
//	nexus version
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/api"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/cli"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/config"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/discovery"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/explorer"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/fingerprint"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/lab"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/locations"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/metrics"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/scheduler"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/settings"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/all"
)

var version = "dev"

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "migrate":
		err = migrateOnly()
	case "lab-export":
		if len(os.Args) < 3 {
			err = errors.New("usage: nexus lab-export DIR")
		} else {
			err = labExport(os.Args[2])
		}
	case "version", "--version", "-v":
		fmt.Println("nexus", version)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(level))
	opts := &slog.HandlerOptions{Level: lvl}
	if format == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func migrateOnly() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel, cfg.LogFormat)
	db, err := storage.Open(context.Background(), cfg.DatabaseURL, log)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Migrate(context.Background(), log)
}

func labExport(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	l := lab.Campus()
	for ip, m := range l.Build() {
		f, err := os.Create(filepath.Join(dir, ip+".snmprec"))
		if err != nil {
			return err
		}
		if err := m.Main.WriteSnmprec(f); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}
	fmt.Println("wrote", len(l.Build()), "fixtures to", dir)
	return nil
}

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	api.Version = version
	log := newLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := storage.Open(ctx, cfg.DatabaseURL, log)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Migrate(ctx, log); err != nil {
		return err
	}
	sealer, err := credentials.NewSealer(cfg.MasterKey)
	if err != nil {
		return err
	}
	creds := credentials.NewStore(db, sealer)
	authSvc := &auth.Service{DB: db, TTL: cfg.SessionTTL, Secure: cfg.CookieSecure, Log: log}
	if err := authSvc.Bootstrap(ctx, cfg.AdminUser, cfg.AdminPass); err != nil {
		return err
	}
	reg := metrics.New()
	store := inventory.New(db, log)
	settingsSvc := &settings.Service{DB: db}

	dialer := snmp.NetDialer{Opt: snmp.Options{Timeout: cfg.SNMPTimeout, Retries: cfg.SNMPRetries}}
	var prober fingerprint.Prober = fingerprint.NetProber{Dialer: dialer}
	var cliDial func(context.Context, string, string) (net.Conn, error)
	var defaultSSH int64

	if cfg.SimulatorListen != "" {
		// Demo mode: an in-process simulated campus answers SNMP and SSH for
		// its 10.20.x.x addresses. Real networks are still reachable.
		l := lab.Campus()
		running, err := l.Start(ctx, "127.0.0.1", log)
		if err != nil {
			return fmt.Errorf("simulator: %w", err)
		}
		sshMap, err := l.StartSSH(ctx, "127.0.0.1")
		if err != nil {
			return fmt.Errorf("simulator ssh: %w", err)
		}
		dialer.Map = running.Addrs
		prober = simProber{lab: l.Prober(), real: fingerprint.NetProber{Dialer: dialer}, labIPs: labIPs(l)}
		cliDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			if a, ok := sshMap[addr]; ok {
				return d.DialContext(ctx, network, a)
			}
			return d.DialContext(ctx, network, addr)
		}
		defaultSSH, err = ensureDemoSSH(ctx, db, creds)
		if err != nil {
			return err
		}
		log.Warn("SIMULATOR MODE: simulated campus network is active",
			"seed_ip", "10.20.99.1", "snmp_username", l.V3User, "snmp_password", l.V3Pass, "agents", len(running.Addrs))
	}

	collector := &discovery.Collector{Dialer: dialer, Registry: all.Registry(), Log: log}
	engine := &discovery.Engine{DB: db, Store: store, Creds: creds, Collector: collector, Prober: prober,
		Hub: discovery.NewHub(), Log: log, Metrics: reg, DefaultSSHCredential: defaultSSH}
	engine.Start(ctx)

	var llm explorer.Interpreter
	if cfg.AnthropicAPIKey != "" {
		llm = explorer.NewLLM(cfg.AnthropicAPIKey, cfg.LLMModel)
		log.Info("LLM query interpreter enabled", "model", cfg.LLMModel)
	}
	cliSvc := &cli.Service{DB: db, Creds: creds, Log: log, IdleTimeout: cfg.CLIIdleTimeout, MaxDuration: cfg.CLIMaxDuration, Dial: cliDial,
		TelnetAllowed: func(ctx context.Context) bool { return settingsSvc.Get(ctx).TelnetAllowed }}

	sched := &scheduler.Scheduler{DB: db, Store: store, Creds: creds, Collector: collector, Engine: engine, Log: log, Metrics: reg,
		PollInterval: cfg.PollInterval, Rediscover: cfg.RediscoverEvery, Retention: cfg.MetricsRetention, Workers: cfg.DiscoveryWorkers}
	sched.Start(ctx)

	registerGauges(reg, db)
	srv := &api.Server{DB: db, Auth: authSvc, Creds: creds, Store: store, Engine: engine,
		Explorer:  &explorer.Explorer{Store: store, LLM: llm, Log: log},
		Locations: &locations.Service{DB: db}, CLI: cliSvc, Settings: settingsSvc, Metrics: reg, Log: log,
		WebDir: cfg.WebDir, Simulator: cfg.SimulatorListen != "", LLM: llm != nil}
	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv.Router(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "version", version, "web_dir", cfg.WebDir)
		errCh <- httpSrv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutCtx)
}

func registerGauges(reg *metrics.Registry, db *storage.DB) {
	q := func(sql string) func() float64 {
		return func() float64 {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var v float64
			_ = db.QueryRow(ctx, sql).Scan(&v)
			return v
		}
	}
	reg.Help("nexus_devices", "Devices in the inventory")
	reg.Gauge("nexus_devices", q(`SELECT count(*) FROM devices`))
	reg.Gauge("nexus_managed_devices", q(`SELECT count(*) FROM devices WHERE managed`))
	reg.Gauge("nexus_endpoints", q(`SELECT count(*) FROM devices WHERE NOT managed`))
	reg.Gauge("nexus_topology_edges", q(`SELECT count(*) FROM topology_edges`))
	reg.Gauge("nexus_open_alerts", q(`SELECT count(*) FROM alerts WHERE resolved_at IS NULL`))
	reg.Gauge("nexus_discovery_queue_depth", q(`SELECT count(*) FROM discovery_runs WHERE status IN ('queued','running')`))
	reg.Gauge("nexus_db_latency_seconds", func() float64 {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = db.Ping(ctx)
		return time.Since(start).Seconds()
	})
}

func labIPs(l *lab.Lab) map[string]bool {
	m := map[string]bool{}
	for _, e := range l.Endpoints {
		m[e.IP] = true
	}
	return m
}

// simProber answers for lab endpoints and probes anything else for real.
type simProber struct {
	lab    fingerprint.Prober
	real   fingerprint.Prober
	labIPs map[string]bool
}

func (p simProber) Probe(ctx context.Context, ip string, opt fingerprint.Options) fingerprint.Observation {
	if p.labIPs[ip] || strings.HasPrefix(ip, "10.20.") {
		return p.lab.Probe(ctx, ip, opt)
	}
	return p.real.Probe(ctx, ip, opt)
}

func ensureDemoSSH(ctx context.Context, db *storage.DB, creds *credentials.Store) (int64, error) {
	var id int64
	err := db.QueryRow(ctx, `SELECT id FROM credentials WHERE kind='ssh' AND name='Lab simulator SSH'`).Scan(&id)
	if err == nil {
		return id, nil
	}
	return creds.CreateLogin(ctx, db, "Lab simulator SSH", credentials.KindSSH, credentials.Login{Username: lab.SSHUser, Password: lab.SSHPass})
}
