// Package pgembed runs a private PostgreSQL instance for single-host
// installations (the Windows installer). The server only listens on
// 127.0.0.1, uses SCRAM authentication with a generated password and is
// started and stopped through pg_ctl, which on Windows also drops
// administrator rights before starting postgres.
package pgembed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Superuser is the database role created by initdb.
const Superuser = "nexus"

// Server describes one embedded PostgreSQL data directory.
type Server struct {
	BinDir   string // directory containing initdb, pg_ctl and postgres
	DataDir  string
	LogDir   string // server logs (rotated daily by PostgreSQL)
	Port     int    // preferred port; a free one is chosen when it is taken
	Password string
	Log      *slog.Logger

	port int // port actually in use
}

func (s *Server) exe(name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if s.BinDir == "" {
		return name
	}
	return filepath.Join(s.BinDir, name)
}

func (s *Server) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// Initialized reports whether the data directory holds a cluster.
func (s *Server) Initialized() bool {
	_, err := os.Stat(filepath.Join(s.DataDir, "PG_VERSION"))
	return err == nil
}

// MajorVersion returns the PostgreSQL major version of the data directory.
func (s *Server) MajorVersion() (string, error) {
	b, err := os.ReadFile(filepath.Join(s.DataDir, "PG_VERSION"))
	return strings.TrimSpace(string(b)), err
}

// BinaryMajorVersion returns the major version of the bundled binaries.
func (s *Server) BinaryMajorVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, s.exe("postgres"), "--version")
	cmd.WaitDelay = 5 * time.Second
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("postgres --version: %w", err)
	}
	// "postgres (PostgreSQL) 16.15"
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return "", errors.New("unexpected postgres --version output")
	}
	v := f[len(f)-1]
	major, _, _ := strings.Cut(v, ".")
	return major, nil
}

// Init creates the cluster when the data directory is empty.
func (s *Server) Init(ctx context.Context) error {
	if s.Initialized() {
		return nil
	}
	if s.Password == "" {
		return errors.New("embedded database password is empty")
	}
	if err := os.MkdirAll(filepath.Dir(s.DataDir), 0o700); err != nil {
		return err
	}
	// The password reaches initdb through a short-lived file, never the command line.
	pw, err := os.CreateTemp(filepath.Dir(s.DataDir), ".pwfile-*")
	if err != nil {
		return err
	}
	defer os.Remove(pw.Name())
	if _, err := pw.WriteString(s.Password + "\n"); err != nil {
		pw.Close()
		return err
	}
	pw.Close()
	cmd := exec.CommandContext(ctx, s.exe("initdb"), "-D", s.DataDir, "-U", Superuser, "--pwfile", pw.Name(),
		"-A", "scram-sha-256", "-E", "UTF8", "--locale=C", "--no-instructions")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = 5 * time.Second
	hideWindow(cmd)
	s.log().Info("initializing embedded database", "data_dir", s.DataDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("initdb failed: %w: %s", err, lastLines(out.String(), 8))
	}
	f, err := os.OpenFile(filepath.Join(s.DataDir, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString("\n# Managed by Nexus: runtime settings are written to nexus.conf on every start.\ninclude_if_exists = 'nexus.conf'\n")
	return err
}

// FreePort returns preferred when it can be bound on 127.0.0.1, otherwise
// a free port chosen by the operating system.
func FreePort(preferred int) (int, error) {
	if preferred > 0 {
		if l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(preferred))); err == nil {
			l.Close()
			return preferred, nil
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func (s *Server) writeRuntimeConf() error {
	logDir := s.LogDir
	if logDir == "" {
		logDir = "log"
	}
	conf := fmt.Sprintf(`# Written by Nexus on every start. Do not edit.
listen_addresses = '127.0.0.1'
port = %d
max_connections = 50
password_encryption = 'scram-sha-256'
logging_collector = on
log_directory = '%s'
log_filename = 'postgres-%%a.log'
log_truncate_on_rotation = on
log_rotation_age = 1d
log_rotation_size = 0
log_line_prefix = '%%m [%%p] %%q%%u@%%d '
log_min_duration_statement = 5000
`, s.port, strings.ReplaceAll(filepath.ToSlash(logDir), "'", "''"))
	return os.WriteFile(filepath.Join(s.DataDir, "nexus.conf"), []byte(conf), 0o600)
}

// Start runs the server (initializing it first if needed) and waits until it
// accepts connections.
func (s *Server) Start(ctx context.Context) error {
	if err := s.Init(ctx); err != nil {
		return err
	}
	if dv, err := s.MajorVersion(); err == nil {
		if bv, err := s.BinaryMajorVersion(ctx); err == nil && bv != dv {
			return fmt.Errorf("the database was created by PostgreSQL %s but this Nexus bundles PostgreSQL %s; restore a backup into a new data directory to upgrade", dv, bv)
		}
	}
	if s.running(ctx) {
		// Left over from an unclean stop: shut it down so it restarts with current settings.
		s.log().Warn("embedded database already running, restarting it")
		_ = s.Stop(ctx)
	}
	port, err := FreePort(s.Port)
	if err != nil {
		return err
	}
	if s.Port > 0 && port != s.Port {
		s.log().Warn("embedded database port in use, using another", "preferred", s.Port, "port", port)
	}
	s.port = port
	if s.LogDir != "" {
		if err := os.MkdirAll(s.LogDir, 0o700); err != nil {
			return err
		}
	}
	if err := s.writeRuntimeConf(); err != nil {
		return err
	}
	startLog := filepath.Join(s.DataDir, "startup.log")
	if s.LogDir != "" {
		startLog = filepath.Join(s.LogDir, "postgres-startup.log")
	}
	// No stdout/stderr handles for pg_ctl start: on Windows the postgres
	// process inherits them for its whole life, so a pipe would block Run
	// forever and a file would stay locked. Startup errors are in startLog.
	cmd := exec.CommandContext(ctx, s.exe("pg_ctl"), "start", "-D", s.DataDir, "-l", startLog, "-w", "-t", "120", "-s")
	cmd.WaitDelay = 5 * time.Second
	hideWindow(cmd)
	if err := cmd.Run(); err != nil {
		tail, _ := os.ReadFile(startLog)
		return fmt.Errorf("embedded database did not start: %w: %s", err, lastLines(string(tail), 8))
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		err := s.ping(ctx, "postgres")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("embedded database not accepting connections: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	s.log().Info("embedded database started", "port", s.port)
	return nil
}

func (s *Server) running(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, s.exe("pg_ctl"), "status", "-D", s.DataDir)
	hideWindow(cmd)
	return cmd.Run() == nil
}

// Attach connects to an already running server (for example the one owned by
// the Nexus service) by reading its port from postmaster.pid. It returns
// false when no server is running.
func (s *Server) Attach(ctx context.Context) (bool, error) {
	if !s.running(ctx) {
		return false, nil
	}
	b, err := os.ReadFile(filepath.Join(s.DataDir, "postmaster.pid"))
	if err != nil {
		return false, err
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if len(lines) < 4 {
		return false, errors.New("unexpected postmaster.pid format")
	}
	port, err := strconv.Atoi(strings.TrimSpace(lines[3]))
	if err != nil {
		return false, fmt.Errorf("postmaster.pid port: %w", err)
	}
	s.port = port
	return true, s.ping(ctx, "postgres")
}

// Running reports whether the server process is alive.
func (s *Server) Running(ctx context.Context) bool { return s.running(ctx) }

// Stopped reports true only when pg_ctl positively states that no server is
// running (exit status 3). Errors such as an inaccessible data directory
// are not treated as a stopped server.
func (s *Server) Stopped(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, s.exe("pg_ctl"), "status", "-D", s.DataDir)
	hideWindow(cmd)
	err := cmd.Run()
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 3
}

// Stop performs a fast shutdown (active transactions are rolled back, data
// is flushed) and waits for it.
func (s *Server) Stop(ctx context.Context) error {
	if !s.running(ctx) {
		return nil
	}
	cmd := exec.Command(s.exe("pg_ctl"), "stop", "-D", s.DataDir, "-m", "fast", "-w", "-t", "60", "-s")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = 5 * time.Second
	hideWindow(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stop embedded database: %w: %s", err, strings.TrimSpace(out.String()))
	}
	s.log().Info("embedded database stopped")
	return nil
}

// ActualPort returns the port the server listens on (after Start).
func (s *Server) ActualPort() int { return s.port }

// URL returns a connection URL for database db.
func (s *Server) URL(db string) string {
	u := url.URL{Scheme: "postgres", User: url.UserPassword(Superuser, s.Password),
		Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(s.port)), Path: "/" + db,
		RawQuery: "sslmode=disable&application_name=nexus"}
	return u.String()
}

func (s *Server) ping(ctx context.Context, db string) error {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := pgx.Connect(c, s.URL(db))
	if err != nil {
		return err
	}
	return conn.Close(c)
}

// EnsureDatabase creates database name when it does not exist.
func (s *Server) EnsureDatabase(ctx context.Context, name string) error {
	conn, err := pgx.Connect(ctx, s.URL("postgres"))
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = conn.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()+` ENCODING 'UTF8' TEMPLATE template0`)
	return err
}

// DropDatabase removes database name (used by restore).
func (s *Server) DropDatabase(ctx context.Context, name string) error {
	conn, err := pgx.Connect(ctx, s.URL("postgres"))
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`)
	return err
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
