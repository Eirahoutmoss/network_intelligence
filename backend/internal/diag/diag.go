package diag

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/platform"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// Status of a check.
const (
	OK      = "ok"
	Warning = "warning"
	Failed  = "failed"
)

// Check is one health check result.
type Check struct {
	Component string `json:"component"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	Hint      string `json:"hint,omitempty"`
}

// Runner collects health information about a running installation.
type Runner struct {
	DB         *storage.DB
	Version    string
	StartedAt  time.Time
	ListenAddr string
	WebDir     string
	DataDir    string // embedded database directory (optional)
	LogFile    string // application log (optional)
	BackupDir  string
	Embedded   bool
	// CredentialCheck tries to decrypt stored credentials: total and failed.
	CredentialCheck func(ctx context.Context) (total, failed int, err error)
	// Env returns configuration (NEXUS_* variables); values are redacted.
	Env      func() map[string]string
	Redactor *Redactor
}

// Run executes all health checks.
func (r *Runner) Run(ctx context.Context) []Check {
	var out []Check
	add := func(c Check) { out = append(out, c) }

	add(Check{Component: "Application", Status: OK, Detail: fmt.Sprintf("Nexus %s, running since %s", r.Version, r.StartedAt.Format(time.RFC3339))})

	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	start := time.Now()
	err := r.DB.Ping(cctx)
	cancel()
	if err != nil {
		add(Check{Component: "Database", Status: Failed, Detail: err.Error(), Hint: "Check that the Nexus service is running and see the postgres logs."})
	} else {
		lat := time.Since(start)
		st := OK
		if lat > 500*time.Millisecond {
			st = Warning
		}
		var size int64
		_ = r.DB.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&size)
		kind := "external PostgreSQL"
		if r.Embedded {
			kind = "embedded PostgreSQL"
		}
		add(Check{Component: "Database", Status: st, Detail: fmt.Sprintf("%s reachable in %d ms, size %s", kind, lat.Milliseconds(), human(uint64(size)))})
	}

	if pending, err := r.DB.Pending(ctx); err != nil {
		add(Check{Component: "Schema", Status: Failed, Detail: err.Error()})
	} else if len(pending) > 0 {
		add(Check{Component: "Schema", Status: Failed, Detail: "pending migrations: " + strings.Join(pending, ", "), Hint: "Restart the Nexus service to apply them."})
	} else {
		applied, _ := r.DB.Applied(ctx)
		last := ""
		if len(applied) > 0 {
			last = applied[len(applied)-1]
		}
		add(Check{Component: "Schema", Status: OK, Detail: fmt.Sprintf("%d migrations applied (latest %s)", len(applied), last)})
	}

	if r.WebDir != "" {
		if _, err := os.Stat(filepath.Join(r.WebDir, "index.html")); err != nil {
			add(Check{Component: "Web interface", Status: Failed, Detail: "index.html not found in " + r.WebDir, Hint: "Repair the installation."})
		} else {
			add(Check{Component: "Web interface", Status: OK, Detail: "served from " + r.WebDir})
		}
	}

	add(r.listenCheck())

	for _, d := range []struct{ name, path string }{{"Data disk", r.DataDir}, {"Backup disk", r.BackupDir}} {
		if d.path == "" {
			continue
		}
		free, total, err := platform.DiskFree(existingParent(d.path))
		switch {
		case err != nil:
			add(Check{Component: d.name, Status: Warning, Detail: err.Error()})
		case free < 1<<30:
			add(Check{Component: d.name, Status: Failed, Detail: fmt.Sprintf("only %s free of %s", human(free), human(total)), Hint: "Free disk space; the database stops writing when the disk is full."})
		case free < 5<<30:
			add(Check{Component: d.name, Status: Warning, Detail: fmt.Sprintf("%s free of %s", human(free), human(total))})
		default:
			add(Check{Component: d.name, Status: OK, Detail: fmt.Sprintf("%s free of %s", human(free), human(total))})
		}
	}

	if r.BackupDir != "" {
		add(backupCheck(r.BackupDir))
	}

	if r.CredentialCheck != nil {
		total, failed, err := r.CredentialCheck(ctx)
		switch {
		case err != nil:
			add(Check{Component: "Credential encryption", Status: Warning, Detail: err.Error()})
		case failed > 0:
			add(Check{Component: "Credential encryption", Status: Failed, Detail: fmt.Sprintf("%d of %d stored credentials cannot be decrypted with the current master key", failed, total),
				Hint: "The master key changed (e.g. restore on another computer). Re-enter these credentials or restore with the backup passphrase."})
		default:
			add(Check{Component: "Credential encryption", Status: OK, Detail: fmt.Sprintf("%d stored credentials readable (AES-256-GCM)", total)})
		}
	}

	var failedRuns int
	var lastErr *string
	_ = r.DB.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='failed'), (SELECT error FROM discovery_runs WHERE status='failed' ORDER BY id DESC LIMIT 1)
		FROM (SELECT status FROM discovery_runs ORDER BY id DESC LIMIT 10) r`).Scan(&failedRuns, &lastErr)
	if failedRuns > 0 && lastErr != nil {
		add(Check{Component: "Discovery", Status: Warning, Detail: fmt.Sprintf("%d of the last 10 runs failed; last error: %s", failedRuns, r.redact(*lastErr))})
	} else {
		add(Check{Component: "Discovery", Status: OK, Detail: "recent discovery runs completed"})
	}
	return out
}

func (r *Runner) redact(s string) string {
	if r.Redactor != nil {
		return r.Redactor.Redact(s)
	}
	return Redact(s)
}

func (r *Runner) listenCheck() Check {
	host, port, err := net.SplitHostPort(r.ListenAddr)
	if err != nil {
		return Check{Component: "Network access", Status: Warning, Detail: r.ListenAddr}
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return Check{Component: "Network access", Status: OK, Detail: "web interface only reachable on this computer (http://localhost:" + port + ")"}
	}
	return Check{Component: "Network access", Status: OK, Detail: "web interface reachable from the network on port " + port,
		Hint: "Protect it with a firewall rule limited to administrator networks and HTTPS via a reverse proxy."}
}

func backupCheck(dir string) Check {
	files, _ := filepath.Glob(filepath.Join(dir, "*.nxbackup"))
	var newest time.Time
	for _, f := range files {
		if st, err := os.Stat(f); err == nil && st.ModTime().After(newest) {
			newest = st.ModTime()
		}
	}
	switch {
	case newest.IsZero():
		return Check{Component: "Backups", Status: Warning, Detail: "no backup yet in " + dir, Hint: "A daily backup is written automatically while Nexus runs."}
	case time.Since(newest) > 48*time.Hour:
		return Check{Component: "Backups", Status: Warning, Detail: "newest backup is from " + newest.Format(time.RFC3339)}
	}
	return Check{Component: "Backups", Status: OK, Detail: fmt.Sprintf("%d backups, newest %s", len(files), newest.Format(time.RFC3339))}
}

func existingParent(p string) string {
	for {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

func human(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Bundle writes a zip with checks, platform facts, redacted configuration,
// database statistics and redacted log tails. No secrets are included.
func (r *Runner) Bundle(ctx context.Context, w io.Writer) error {
	zw := zip.NewWriter(w)
	put := func(name string, v any) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		_, err = f.Write([]byte(r.redact(string(b))))
		return err
	}
	checks := r.Run(ctx)
	summary := map[string]any{"version": r.Version, "generated_at": time.Now().UTC(), "started_at": r.StartedAt,
		"listen": r.ListenAddr, "embedded_db": r.Embedded, "platform": platform.Info()}
	if err := put("summary.json", summary); err != nil {
		return err
	}
	if err := put("checks.json", checks); err != nil {
		return err
	}
	if r.Env != nil {
		env := r.Env()
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=%s\n", k, env[k])
		}
		f, err := zw.Create("config.txt")
		if err != nil {
			return err
		}
		if _, err := io.WriteString(f, r.redact(b.String())); err != nil {
			return err
		}
	}
	if err := put("database.json", r.dbStats(ctx)); err != nil {
		return err
	}
	if err := put("discovery_runs.json", r.runs(ctx)); err != nil {
		return err
	}
	if r.LogFile != "" {
		logs, _ := filepath.Glob(filepath.Join(filepath.Dir(r.LogFile), "*.log"))
		for _, l := range logs {
			if err := r.tailInto(zw, "logs/"+filepath.Base(l), l, 2<<20); err != nil {
				return err
			}
		}
	}
	return zw.Close()
}

func (r *Runner) dbStats(ctx context.Context) map[string]any {
	out := map[string]any{}
	applied, _ := r.DB.Applied(ctx)
	pending, _ := r.DB.Pending(ctx)
	out["migrations_applied"], out["migrations_pending"] = applied, pending
	var ver string
	_ = r.DB.QueryRow(ctx, `SHOW server_version`).Scan(&ver)
	out["server_version"] = ver
	rows, err := r.DB.Query(ctx, `SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY relname`)
	if err == nil {
		counts := map[string]int64{}
		for rows.Next() {
			var n string
			var c int64
			if rows.Scan(&n, &c) == nil {
				counts[n] = c
			}
		}
		rows.Close()
		out["table_rows_estimate"] = counts
	}
	return out
}

func (r *Runner) runs(ctx context.Context) []map[string]any {
	rows, err := r.DB.Query(ctx, `SELECT id, host(seed_ip), status, error, summary, created_at, finished_at FROM discovery_runs ORDER BY id DESC LIMIT 20`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id int64
		var seed, status string
		var errText *string
		var summary map[string]any
		var created time.Time
		var finished *time.Time
		if rows.Scan(&id, &seed, &status, &errText, &summary, &created, &finished) == nil {
			out = append(out, map[string]any{"id": id, "seed": seed, "status": status, "error": errText, "summary": summary, "created_at": created, "finished_at": finished})
		}
	}
	return out
}

// tailInto copies the last max bytes of file, line by line, redacted.
func (r *Runner) tailInto(zw *zip.Writer, name, file string, max int64) error {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > max {
		_, _ = f.Seek(st.Size()-max, io.SeekStart)
	}
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if _, err := io.WriteString(w, r.redact(sc.Text())+"\n"); err != nil {
			return err
		}
	}
	return nil
}

// OfflineBundle writes what can be collected without a database.
func OfflineBundle(w io.Writer, version string, cause error, logFile string, env map[string]string, red *Redactor) error {
	r := &Runner{Version: version, LogFile: logFile, Redactor: red}
	zw := zip.NewWriter(w)
	f, err := zw.Create("summary.json")
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(map[string]any{"version": version, "generated_at": time.Now().UTC(), "database_error": cause.Error(), "platform": platform.Info()}, "", "  ")
	if _, err := f.Write([]byte(r.redact(string(b)))); err != nil {
		return err
	}
	var sb strings.Builder
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&sb, "%s=%s\n", k, env[k])
	}
	if f, err = zw.Create("config.txt"); err != nil {
		return err
	}
	if _, err := io.WriteString(f, r.redact(sb.String())); err != nil {
		return err
	}
	if logFile != "" {
		logs, _ := filepath.Glob(filepath.Join(filepath.Dir(logFile), "*.log"))
		for _, l := range logs {
			if err := r.tailInto(zw, "logs/"+filepath.Base(l), l, 2<<20); err != nil {
				return err
			}
		}
	}
	return zw.Close()
}
