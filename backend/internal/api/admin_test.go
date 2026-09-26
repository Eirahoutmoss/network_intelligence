package api_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/api"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/backup"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/diag"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/metrics"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/settings"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/testutil"
)

func setupFresh(t *testing.T, remote bool) (*httptest.Server, *credentials.Store) {
	db := testutil.DB(t)
	log := testutil.Logger()
	sealer, _ := credentials.NewSealer(testutil.Key())
	creds := credentials.NewStore(db, sealer)
	srv := &api.Server{DB: db, Auth: &auth.Service{DB: db, TTL: time.Hour, Log: log}, Creds: creds, Settings: &settings.Service{DB: db},
		Metrics: metrics.New(), Log: log, FirstRunSetup: true,
		Diagnostics: &diag.Runner{DB: db, Version: "test", StartedAt: time.Now(), ListenAddr: "127.0.0.1:8080", CredentialCheck: creds.Verify,
			Env: func() map[string]string {
				return map[string]string{"NEXUS_PG_PASSWORD": "db-secret-value-123", "NEXUS_LISTEN": "127.0.0.1:8080"}
			}},
		Backup: func(ctx context.Context, w io.Writer, pass string) error {
			_, err := backup.Write(ctx, db, w, backup.Options{AppVersion: "test", MasterKey: testutil.Key(), Passphrase: pass})
			return err
		}}
	h := srv.Router()
	if remote {
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = "10.1.2.3:40000"
			inner.ServeHTTP(w, r)
		})
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, creds
}

func TestFirstRunSetup(t *testing.T) {
	ts, _ := setupFresh(t, false)
	c := newClient(t, ts.URL)
	var st struct{ Required, Allowed bool }
	c.json("GET", "/api/setup", nil, &st)
	if !st.Required || !st.Allowed {
		t.Fatalf("status %+v", st)
	}
	if code := c.json("POST", "/api/setup", map[string]string{"username": "admin", "password": "short"}, nil); code != http.StatusBadRequest {
		t.Fatalf("weak password: %d", code)
	}
	// concurrent attempts: exactly one wins
	var wg sync.WaitGroup
	codes := make([]int, 5)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cc := newClient(t, ts.URL)
			codes[i] = cc.json("POST", "/api/setup", map[string]string{"username": "admin" + string(rune('a'+i)), "password": "a-long-admin-pass"}, nil)
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, code := range codes {
		if code == http.StatusOK {
			ok++
		} else if code != http.StatusConflict {
			t.Errorf("unexpected code %d", code)
		}
	}
	if ok != 1 {
		t.Fatalf("%d setups succeeded: %v", ok, codes)
	}
	c.json("GET", "/api/setup", nil, &st)
	if st.Required {
		t.Fatal("setup still required")
	}
	// the winner is signed in as admin
	var me struct{ User auth.User }
	cc := newClient(t, ts.URL)
	for i, code := range codes {
		if code == http.StatusOK {
			if cc.json("POST", "/api/auth/login", map[string]string{"username": "admin" + string(rune('a'+i)), "password": "a-long-admin-pass"}, &me) != http.StatusOK || me.User.Role != auth.RoleAdmin {
				t.Fatalf("login after setup: %+v", me)
			}
		}
	}
	// CSRF header is still required
	if code, _ := newClient(t, ts.URL).do("POST", "/api/setup", map[string]string{"username": "x", "password": "a-long-admin-pass"}, false); code != http.StatusForbidden {
		t.Errorf("setup without CSRF header: %d", code)
	}
}

func TestSetupRefusedFromNetwork(t *testing.T) {
	ts, _ := setupFresh(t, true)
	c := newClient(t, ts.URL)
	var st struct{ Required, Allowed bool }
	c.json("GET", "/api/setup", nil, &st)
	if !st.Required || st.Allowed {
		t.Fatalf("status %+v", st)
	}
	if code := c.json("POST", "/api/setup", map[string]string{"username": "admin", "password": "a-long-admin-pass"}, nil); code != http.StatusForbidden {
		t.Fatalf("remote setup: %d", code)
	}
}

func TestDiagnosticsAndBackup(t *testing.T) {
	ts, creds := setupFresh(t, false)
	c := newClient(t, ts.URL)
	if code := c.json("POST", "/api/setup", map[string]string{"username": "admin", "password": "a-long-admin-pass"}, nil); code != http.StatusOK {
		t.Fatal(code)
	}
	if _, err := creds.CreateSNMP(context.Background(), creds.DB(), "x", credentials.SNMP{Username: "u", AuthPassword: "snmp-secret-pass"}); err != nil {
		t.Fatal(err)
	}
	var res struct {
		Status string
		Checks []diag.Check
	}
	if code := c.json("GET", "/api/admin/diagnostics", nil, &res); code != http.StatusOK || len(res.Checks) < 4 {
		t.Fatalf("diagnostics %d %+v", code, res)
	}
	code, body := c.do("GET", "/api/admin/diagnostics/bundle", nil, true)
	if code != http.StatusOK {
		t.Fatalf("bundle %d %s", code, body)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if strings.Contains(string(b), "db-secret-value-123") {
			t.Errorf("%s leaks a secret", f.Name)
		}
	}
	for _, n := range []string{"summary.json", "checks.json", "config.txt", "database.json"} {
		if !names[n] {
			t.Errorf("bundle misses %s", n)
		}
	}
	// backup download, with a passphrase in the body (never the URL)
	code, body = c.do("POST", "/api/admin/backup", map[string]string{"passphrase": "a very long passphrase"}, true)
	if code != http.StatusOK {
		t.Fatalf("backup %d %s", code, body)
	}
	m, _, err := backup.ReadManifest(bytes.NewReader(body), int64(len(body)))
	if err != nil || m.WrappedKey == nil {
		t.Fatalf("backup manifest %+v %v", m, err)
	}
	if code, _ := c.do("POST", "/api/admin/backup", map[string]string{"passphrase": "short"}, true); code != http.StatusBadRequest {
		t.Errorf("short passphrase: %d", code)
	}
	// viewers cannot reach admin endpoints
	var u struct{ ID int64 }
	if c.json("POST", "/api/users", map[string]string{"username": "v", "password": "viewer-pass-123", "role": "viewer"}, &u) >= 300 {
		t.Fatal("create viewer")
	}
	v := newClient(t, ts.URL)
	v.json("POST", "/api/auth/login", map[string]string{"username": "v", "password": "viewer-pass-123"}, nil)
	if code := v.json("GET", "/api/admin/diagnostics", nil, nil); code != http.StatusForbidden {
		t.Errorf("viewer diagnostics: %d", code)
	}
	if code, _ := v.do("POST", "/api/admin/backup", map[string]string{}, true); code != http.StatusForbidden {
		t.Errorf("viewer backup: %d", code)
	}
	for _, c := range res.Checks {
		if c.Component == "Credential encryption" && c.Status != diag.OK {
			t.Errorf("credential check %+v", c)
		}
	}
	if b, _ := json.Marshal(res); strings.Contains(string(b), "snmp-secret-pass") {
		t.Error("diagnostics leak a credential")
	}
}
