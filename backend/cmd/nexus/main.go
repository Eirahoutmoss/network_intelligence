// Command nexus runs the Network Intelligence Platform server.
//
//	nexus [--config FILE] COMMAND
//
//	nexus            start the server (default)
//	nexus migrate    apply database migrations and exit
//	nexus backup     write a backup file
//	nexus restore    restore a backup file (server must be stopped)
//	nexus diagnostics write a redacted diagnostic bundle
//	nexus lab-export DIR   write the simulated lab as snmprec fixtures
//	nexus version
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/logfile"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/metrics"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/pgembed"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/scheduler"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/settings"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/all"
)

var version = "dev"

func main() {
	args, cfgPath := configFlag(os.Args[1:])
	if cfgPath == "" {
		cfgPath = os.Getenv("NEXUS_CONFIG")
	}
	if cfgPath != "" {
		if err := config.LoadFile(cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		err = serve(ctx, nil)
		stop()
	case "migrate":
		err = migrateOnly()
	case "backup":
		err = backupCommand(args)
	case "restore":
		err = restoreCommand(args)
	case "diagnostics":
		err = diagnosticsCommand(args)
	case "lab-export":
		if len(args) < 1 {
			err = errors.New("usage: nexus lab-export DIR")
		} else {
			err = labExport(args[0])
		}
	case "version", "--version", "-v":
		fmt.Println("nexus", version)
	default:
		var handled bool
		handled, err = platformCommand(cmd, args)
		if !handled {
			err = fmt.Errorf("unknown command %q", cmd)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// configFlag extracts "--config PATH" / "--config=PATH" from args.
func configFlag(args []string) ([]string, string) {
	var out []string
	path := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config" && i+1 < len(args):
			path = args[i+1]
			i++
		case strings.HasPrefix(a, "--config="):
			path = strings.TrimPrefix(a, "--config=")
		default:
			out = append(out, a)
		}
	}
	return out, path
}

// quietWriter ignores write errors (a Windows service has no console).
type quietWriter struct{ w io.Writer }

func (q quietWriter) Write(p []byte) (int, error) {
	_, _ = q.w.Write(p)
	return len(p), nil
}

func newLogger(level, format string, extra ...io.Writer) *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(level))
	opts := &slog.HandlerOptions{Level: lvl}
	ws := []io.Writer{quietWriter{os.Stdout}}
	for _, w := range extra {
		ws = append(ws, quietWriter{w})
	}
	out := io.MultiWriter(ws...)
	if format == "text" {
		return slog.New(slog.NewTextHandler(out, opts))
	}
	return slog.New(slog.NewJSONHandler(out, opts))
}

func migrateOnly() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel, cfg.LogFormat)
	ctx := context.Background()
	db, done, err := openDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer done()
	return db.Migrate(ctx, log)
}

// openDatabase connects to the configured database, starting the embedded
// PostgreSQL first when configured. done closes the pool and stops the
// embedded server.
//
// With attach, a running embedded server (owned by the service) is used as is
// and left running.
func openDatabase(ctx context.Context, cfg *config.Config, log *slog.Logger, attach ...bool) (*storage.DB, func(), error) {
	var pg *pgembed.Server
	url := cfg.DatabaseURL
	if cfg.Embedded() {
		pg = embeddedServer(cfg, log)
		attached := false
		if len(attach) > 0 && attach[0] {
			ok, err := pg.Attach(ctx)
			if err != nil {
				return nil, nil, fmt.Errorf("connect to the running embedded database: %w", err)
			}
			attached = ok
		}
		if attached {
			url = pg.URL("nexus")
			pg = nil // not ours to stop
		} else if err := pg.Start(ctx); err != nil {
			return nil, nil, err
		}
	}
	if pg != nil {
		if err := pg.EnsureDatabase(ctx, "nexus"); err != nil {
			_ = pg.Stop(context.Background())
			return nil, nil, err
		}
		url = pg.URL("nexus")
	}
	db, err := storage.Open(ctx, url, log)
	if err != nil {
		if pg != nil {
			_ = pg.Stop(context.Background())
		}
		return nil, nil, err
	}
	return db, func() {
		db.Close()
		if pg != nil {
			if err := pg.Stop(context.Background()); err != nil {
				log.Error("stopping embedded database", "err", err)
			}
		}
	}, nil
}

func embeddedServer(cfg *config.Config, log *slog.Logger) *pgembed.Server {
	logDir := ""
	if cfg.LogFile != "" {
		logDir = filepath.Dir(cfg.LogFile)
	}
	return &pgembed.Server{BinDir: cfg.PGBin, DataDir: cfg.PGData, LogDir: logDir, Port: cfg.PGPort, Password: cfg.PGPassword, Log: log}
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

// serve runs the server until ctx is cancelled. ready, when set, is called
// once the HTTP listener accepts connections.
func serve(ctx context.Context, ready func(addr string)) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	api.Version = version
	// Installer tests: make exactly one version fail to start to exercise
	// upgrade rollback. Has no effect unless the variable names this version.
	if v := os.Getenv("NEXUS_TEST_FAIL_VERSION"); v != "" && v == version {
		return fmt.Errorf("simulated startup failure of version %s (NEXUS_TEST_FAIL_VERSION)", version)
	}
	var extra []io.Writer
	if cfg.LogFile != "" {
		lf, err := logfile.Open(cfg.LogFile, 20<<20, 5)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		defer lf.Close()
		extra = append(extra, lf)
	}
	log := newLogger(cfg.LogLevel, cfg.LogFormat, extra...)
	slog.SetDefault(log)
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	db, closeDB, err := openDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeDB()
	if cfg.Embedded() {
		go watchEmbedded(ctx, cancel, embeddedServer(cfg, log), db, log)
	}
	if err := backupBeforeMigrate(ctx, cfg, db, log); err != nil {
		return err
	}
	if err := db.Migrate(ctx, log); err != nil {
		return err
	}
	go autoBackups(ctx, cfg, db, log, 7)
	sealer, err := credentials.NewSealer(cfg.MasterKey)
	if err != nil {
		return err
	}
	creds := credentials.NewStore(db, sealer)
	authSvc := &auth.Service{DB: db, TTL: cfg.SessionTTL, Secure: cfg.CookieSecure, Log: log}
	if cfg.FirstRunSetup == "local" && cfg.AdminPass == "" {
		if n, err := authSvc.UserCount(ctx); err == nil && n == 0 {
			log.Info("no users yet: create the administrator from the web UI on this computer")
		}
	} else if err := authSvc.Bootstrap(ctx, cfg.AdminUser, cfg.AdminPass); err != nil {
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
		// The simulated network is ours to probe: enable active identification by default.
		demo := settings.Defaults()
		demo.ActiveFingerprinting = true
		if err := settingsSvc.EnsureDefaults(ctx, demo); err != nil {
			return err
		}
		log.Warn("SIMULATOR MODE: simulated campus network is active",
			"seed_ip", "10.20.99.1", "snmp_username", l.V3User, "agents", len(running.Addrs))
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
		WebDir: cfg.WebDir, Simulator: cfg.SimulatorListen != "", LLM: llm != nil,
		FirstRunSetup: cfg.FirstRunSetup == "local", Diagnostics: newDiagnostics(cfg, db, creds), Backup: backupFunc(cfg, db)}
	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv.Router(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w (another program is using this port; change NEXUS_LISTEN)", cfg.ListenAddr, err)
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "version", version, "web_dir", cfg.WebDir, "embedded_db", cfg.Embedded())
		errCh <- httpSrv.Serve(ln)
	}()
	if ready != nil {
		ready(ln.Addr().String())
	}
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		shutCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		_ = httpSrv.Shutdown(shutCtx)
		c()
		return cause
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	return httpSrv.Shutdown(shutCtx)
}

// watchEmbedded stops the server when the embedded database dies, so the
// service manager restarts everything together. A database is declared dead
// only when it stops answering and pg_ctl confirms it is not running.
func watchEmbedded(ctx context.Context, cancel context.CancelCauseFunc, pg *pgembed.Server, db *storage.DB, log *slog.Logger) {
	failures := 0
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, c := context.WithTimeout(ctx, 5*time.Second)
		err := db.Ping(pctx)
		c()
		if err == nil || ctx.Err() != nil {
			failures = 0
			continue
		}
		if !pg.Stopped(ctx) {
			log.Warn("embedded database not answering", "err", err)
			continue
		}
		failures++
		log.Error("embedded database is not running", "checks_failed", failures)
		if failures >= 2 {
			cancel(errors.New("embedded database stopped unexpectedly; see postgres logs"))
			return
		}
	}
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
