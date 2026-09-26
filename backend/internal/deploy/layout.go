// Package deploy is the installation layer for single-host deployments (the
// Windows installer): directory layout, secret generation, configuration,
// port selection, preflight checks, health verification and the structured
// install log. It contains no discovery or inventory logic.
package deploy

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Layout describes where an installation keeps its files.
//
//	ProgramDir\app\<version>\  binaries, web UI, PostgreSQL (read-only)
//	DataRoot\config\nexus.env  configuration (no secrets)
//	DataRoot\secrets\          master key, database password
//	DataRoot\data\db\          PostgreSQL data directory
//	DataRoot\logs\             application, database and install logs
//	DataRoot\backups\          automatic and manual backups
type Layout struct {
	ProgramDir string
	AppDir     string
	DataRoot   string
}

func (l Layout) ConfigDir() string     { return filepath.Join(l.DataRoot, "config") }
func (l Layout) ConfigFile() string    { return filepath.Join(l.ConfigDir(), "nexus.env") }
func (l Layout) SecretsDir() string    { return filepath.Join(l.DataRoot, "secrets") }
func (l Layout) MasterKeyFile() string { return filepath.Join(l.SecretsDir(), "master.key") }
func (l Layout) DBPasswordFile() string {
	return filepath.Join(l.SecretsDir(), "db.password")
}
func (l Layout) DataDir() string   { return filepath.Join(l.DataRoot, "data") }
func (l Layout) PGDataDir() string { return filepath.Join(l.DataDir(), "db") }
func (l Layout) LogDir() string    { return filepath.Join(l.DataRoot, "logs") }
func (l Layout) LogFile() string   { return filepath.Join(l.LogDir(), "nexus.log") }
func (l Layout) BackupDir() string { return filepath.Join(l.DataRoot, "backups") }
func (l Layout) Exe() string       { return filepath.Join(l.AppDir, exeName("nexus")) }
func (l Layout) WebDir() string    { return filepath.Join(l.AppDir, "web") }
func (l Layout) PGBinDir() string  { return filepath.Join(l.AppDir, "pgsql", "bin") }

// MkdirAll creates every directory of the layout.
func (l Layout) MkdirAll() error {
	for _, d := range []string{l.DataRoot, l.ConfigDir(), l.SecretsDir(), l.DataDir(), l.LogDir(), l.BackupDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	return nil
}

// HasData reports whether a database already exists (upgrade or reinstall).
func (l Layout) HasData() bool {
	_, err := os.Stat(filepath.Join(l.PGDataDir(), "PG_VERSION"))
	return err == nil
}

// randomSecret returns n random bytes, base64 encoded.
func randomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// EnsureSecrets creates the master key and database password when missing.
// Existing secrets are never replaced: the master key decrypts stored
// credentials and the password belongs to the existing database.
func (l Layout) EnsureSecrets() (created []string, err error) {
	for _, s := range []struct {
		path string
		size int
	}{{l.MasterKeyFile(), 32}, {l.DBPasswordFile(), 32}} {
		if st, err := os.Stat(s.path); err == nil && st.Size() > 0 {
			continue
		}
		v, err := randomSecret(s.size)
		if err != nil {
			return created, err
		}
		if err := writeFileAtomic(s.path, []byte(v+"\n"), 0o600); err != nil {
			return created, err
		}
		created = append(created, filepath.Base(s.path))
	}
	if l.HasData() {
		for _, c := range created {
			if c == "master.key" {
				return created, errors.New("a new master key was generated for an existing database: stored credentials cannot be decrypted (restore secrets\\master.key from a backup)")
			}
		}
	}
	return created, nil
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// DefaultPort is the preferred web port; Alternatives are tried when it is taken.
const DefaultPort = 8080

// Alternatives are tried in order when the preferred port is busy.
var Alternatives = []int{8080, 8480, 8888, 18080, 28080, 9080, 8081, 8082, 8090}

// Env is an ordered set of KEY=VALUE settings.
type Env map[string]string

// ReadEnv parses a nexus.env file; a missing file yields an empty Env.
func ReadEnv(path string) (Env, error) {
	env := Env{}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return env, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			env[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return env, sc.Err()
}

// ListenPort returns the port of NEXUS_LISTEN (0 when unset).
func (e Env) ListenPort() int {
	l := e["NEXUS_LISTEN"]
	i := strings.LastIndex(l, ":")
	if i < 0 {
		return 0
	}
	n, _ := strconv.Atoi(l[i+1:])
	return n
}

// LAN reports whether the web interface listens beyond this computer.
func (e Env) LAN() bool {
	l := e["NEXUS_LISTEN"]
	return l != "" && !strings.HasPrefix(l, "127.0.0.1:") && !strings.HasPrefix(l, "localhost:") && !strings.HasPrefix(l, "[::1]:")
}

// URL is the address to open in a browser on this computer.
func (e Env) URL() string {
	return fmt.Sprintf("http://localhost:%d/", e.ListenPort())
}

// BuildEnv merges the previous configuration with the new application
// directory and installer options. Settings the installer does not manage
// (e.g. NEXUS_POLL_INTERVAL added by an administrator) are preserved.
func BuildEnv(prev Env, l Layout, port int, lan bool, simulator bool) Env {
	env := Env{}
	for k, v := range prev {
		env[k] = v
	}
	host := "127.0.0.1"
	if lan {
		host = "0.0.0.0"
	}
	env["NEXUS_LISTEN"] = fmt.Sprintf("%s:%d", host, port)
	env["NEXUS_WEB_DIR"] = l.WebDir()
	env["NEXUS_PG_BIN"] = l.PGBinDir()
	env["NEXUS_PG_DATA"] = l.PGDataDir()
	env["NEXUS_PG_PASSWORD_FILE"] = l.DBPasswordFile()
	env["NEXUS_MASTER_KEY_FILE"] = l.MasterKeyFile()
	env["NEXUS_LOG_FILE"] = l.LogFile()
	env["NEXUS_BACKUP_DIR"] = l.BackupDir()
	env["NEXUS_FIRST_RUN_SETUP"] = "local"
	if _, ok := env["NEXUS_LOG_FORMAT"]; !ok {
		env["NEXUS_LOG_FORMAT"] = "json"
	}
	if simulator {
		env["NEXUS_SIMULATOR"] = "1"
	} else {
		delete(env, "NEXUS_SIMULATOR")
	}
	// Secrets never live in the configuration file.
	for _, k := range []string{"NEXUS_MASTER_KEY", "NEXUS_PG_PASSWORD", "NEXUS_ADMIN_PASSWORD", "NEXUS_DATABASE_URL"} {
		delete(env, k)
	}
	return env
}

// Write stores the configuration (no secrets; paths to secret files only).
func (e Env) Write(path string) error {
	keys := make([]string, 0, len(e))
	for k := range e {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Nexus configuration. Written by the installer; settings you add are kept on upgrade.\r\n")
	b.WriteString("# Secrets are not stored here: see the *_FILE entries. Restart the Nexus service after changes.\r\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\r\n", k, e[k])
	}
	return writeFileAtomic(path, []byte(b.String()), 0o640)
}
