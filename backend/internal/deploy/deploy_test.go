package deploy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testLayout(t *testing.T) Layout {
	root := t.TempDir()
	return Layout{ProgramDir: filepath.Join(root, "Program Files", "Nexus"), AppDir: filepath.Join(root, "Program Files", "Nexus", "app", "1.0.0"), DataRoot: filepath.Join(root, "ProgramData", "Nexus")}
}

func TestSecretsAreGeneratedOnceAndKept(t *testing.T) {
	l := testLayout(t)
	if err := l.MkdirAll(); err != nil {
		t.Fatal(err)
	}
	created, err := l.EnsureSecrets()
	if err != nil || len(created) != 2 {
		t.Fatalf("created %v %v", created, err)
	}
	key1, _ := os.ReadFile(l.MasterKeyFile())
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(key1)))
	if err != nil || len(raw) != 32 {
		t.Fatalf("master key is not 32 random bytes: %v", err)
	}
	st, _ := os.Stat(l.MasterKeyFile())
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("master key mode %v", st.Mode())
	}
	created, err = l.EnsureSecrets()
	key2, _ := os.ReadFile(l.MasterKeyFile())
	if err != nil || len(created) != 0 || !bytes.Equal(key1, key2) {
		t.Fatal("existing secrets must never be replaced")
	}
	// Data exists but the key was lost: refuse instead of silently creating a new one.
	os.Remove(l.MasterKeyFile())
	os.MkdirAll(l.PGDataDir(), 0o700)
	os.WriteFile(filepath.Join(l.PGDataDir(), "PG_VERSION"), []byte("16\n"), 0o600)
	if _, err := l.EnsureSecrets(); err == nil {
		t.Fatal("expected an error for a missing key with existing data")
	}
}

func TestBuildEnvKeepsUserSettingsAndDropsSecrets(t *testing.T) {
	l := testLayout(t)
	prev := Env{"NEXUS_POLL_INTERVAL": "10m", "NEXUS_LISTEN": "0.0.0.0:9000", "NEXUS_MASTER_KEY": "should-not-survive", "NEXUS_SIMULATOR": "1",
		"NEXUS_WEB_DIR": `C:\old\app\0.9.0\web`}
	env := BuildEnv(prev, l, 8480, false, false)
	if env["NEXUS_POLL_INTERVAL"] != "10m" {
		t.Error("user setting lost")
	}
	if _, ok := env["NEXUS_MASTER_KEY"]; ok {
		t.Error("secret kept in config")
	}
	if env["NEXUS_LISTEN"] != "127.0.0.1:8480" || env.LAN() || env.ListenPort() != 8480 || env.URL() != "http://localhost:8480/" {
		t.Errorf("listen %q", env["NEXUS_LISTEN"])
	}
	if env["NEXUS_WEB_DIR"] != l.WebDir() || env["NEXUS_PG_BIN"] != l.PGBinDir() {
		t.Error("paths not moved to the new version")
	}
	if _, ok := env["NEXUS_SIMULATOR"]; ok {
		t.Error("simulator not disabled")
	}
	if env["NEXUS_FIRST_RUN_SETUP"] != "local" || env["NEXUS_MASTER_KEY_FILE"] != l.MasterKeyFile() {
		t.Error("missing managed settings")
	}
	lan := BuildEnv(prev, l, 8480, true, true)
	if !lan.LAN() || lan["NEXUS_SIMULATOR"] != "1" {
		t.Error("lan/simulator")
	}
	// round trip through the file
	p := filepath.Join(t.TempDir(), "nexus.env")
	if err := env.Write(p); err != nil {
		t.Fatal(err)
	}
	back, err := ReadEnv(p)
	if err != nil || len(back) != len(env) {
		t.Fatalf("round trip %v %v", back, err)
	}
	for k, v := range env {
		if back[k] != v {
			t.Errorf("%s: %q != %q", k, back[k], v)
		}
	}
	if missing, err := ReadEnv(filepath.Join(t.TempDir(), "none")); err != nil || len(missing) != 0 {
		t.Error("missing file should be empty")
	}
}

func TestChoosePort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	busy := l.Addr().(*net.TCPAddr).Port
	p, preferred := ChoosePort("127.0.0.1", busy, 0)
	if preferred || p == busy || p == 0 {
		t.Fatalf("busy port chosen: %d", p)
	}
	// our own running service holds the current port: keep it
	if p, preferred := ChoosePort("127.0.0.1", busy, busy); p != busy || !preferred {
		t.Fatalf("current port not kept: %d", p)
	}
}

func TestWaitHealthy(t *testing.T) {
	ready := time.Now().Add(1500 * time.Millisecond)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			if time.Now().Before(ready) {
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(Health{Status: "degraded"})
				return
			}
			json.NewEncoder(w).Encode(Health{Status: "ok", Database: true, Version: "1.0.0"})
			return
		}
		w.Write([]byte("<!doctype html><html></html>"))
	}))
	defer srv.Close()
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	h, err := WaitHealthy(context.Background(), port, 10*time.Second, nil)
	if err != nil || h.Version != "1.0.0" {
		t.Fatalf("%v %v", h, err)
	}
	if _, err := WaitHealthy(context.Background(), 1, 2*time.Second, nil); err == nil {
		t.Fatal("closed port reported healthy")
	}
}

func TestInstallLog(t *testing.T) {
	var out bytes.Buffer
	p := filepath.Join(t.TempDir(), "logs", "install.log")
	lg, err := OpenLog(p, &out)
	if err != nil {
		t.Fatal(err)
	}
	lg.Step("install", "Database", "initialized")
	err = lg.Fail("verify", "Health check", "timeout", "See the log.")
	lg.Close()
	if err == nil || !strings.Contains(out.String(), "✓ Database: initialized") || !strings.Contains(out.String(), "✗ Health check: timeout") {
		t.Fatalf("output %q", out.String())
	}
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var e Entry
	if len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &e) != nil || e.Phase != "verify" || e.Severity != Error || e.Hint == "" {
		t.Fatalf("log %q", b)
	}
}

func TestPreflight(t *testing.T) {
	l := testLayout(t)
	rep := Preflight(PreflightInput{Layout: l})
	if rep.Port == 0 || rep.Upgrade || rep.HasData {
		t.Fatalf("%+v", rep)
	}
	var comps []string
	for _, r := range rep.Results {
		comps = append(comps, r.Component)
	}
	for _, want := range []string{"Program disk", "Data disk", "Port", "Network", "Docker / WSL"} {
		if !strings.Contains(strings.Join(comps, ","), want) {
			t.Errorf("missing check %s in %v", want, comps)
		}
	}
	// existing data without master key blocks the installation
	l.MkdirAll()
	os.MkdirAll(l.PGDataDir(), 0o700)
	os.WriteFile(filepath.Join(l.PGDataDir(), "PG_VERSION"), []byte("16\n"), 0o600)
	if rep := Preflight(PreflightInput{Layout: l}); !rep.Blocking || !rep.HasData {
		t.Fatalf("missing master key not blocking: %+v", rep)
	}
}
