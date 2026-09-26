package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/api"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/cli"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/discovery"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/explorer"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/lab"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/locations"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/metrics"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/settings"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/testutil"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/all"
)

type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func (c *client) do(method, path string, body any, csrf bool) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if csrf {
		req.Header.Set("X-Requested-With", "nexus")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (c *client) json(method, path string, body any, out any) int {
	c.t.Helper()
	code, b := c.do(method, path, body, true)
	if out != nil && code < 300 {
		if err := json.Unmarshal(b, out); err != nil {
			c.t.Fatalf("%s %s: %v: %s", method, path, err, b)
		}
	}
	return code
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, http: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

func setup(t *testing.T) (*httptest.Server, *lab.Lab) {
	db := testutil.DB(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := testutil.Logger()
	l := lab.Campus()
	running, err := l.Start(ctx, "127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	sshMap, _ := l.StartSSH(ctx, "127.0.0.1")
	sealer, _ := credentials.NewSealer(testutil.Key())
	creds := credentials.NewStore(db, sealer)
	authSvc := &auth.Service{DB: db, TTL: time.Hour, Log: log}
	if err := authSvc.Bootstrap(ctx, "admin", "admin-pass-123"); err != nil {
		t.Fatal(err)
	}
	if _, err := authSvc.CreateUser(ctx, "viewer", "viewer-pass-123", auth.RoleViewer); err != nil {
		t.Fatal(err)
	}
	store := inventory.New(db, log)
	reg := metrics.New()
	sshCred, _ := creds.CreateLogin(ctx, db, "lab ssh", credentials.KindSSH, credentials.Login{Username: lab.SSHUser, Password: lab.SSHPass})
	engine := &discovery.Engine{DB: db, Store: store, Creds: creds, Hub: discovery.NewHub(), Log: log, Metrics: reg, Prober: l.Prober(),
		DefaultSSHCredential: sshCred,
		Collector:            &discovery.Collector{Dialer: snmp.NetDialer{Map: running.Addrs, Strict: true, Opt: snmp.Options{Timeout: time.Second}}, Registry: all.Registry(), Log: log}}
	engine.Start(ctx)
	st := &settings.Service{DB: db}
	srv := &api.Server{DB: db, Auth: authSvc, Creds: creds, Store: store, Engine: engine, Explorer: &explorer.Explorer{Store: store},
		Locations: &locations.Service{DB: db}, Settings: st, Metrics: reg, Log: log, Simulator: true,
		CLI: &cli.Service{DB: db, Creds: creds, Log: log, TelnetAllowed: func(ctx context.Context) bool { return st.Get(ctx).TelnetAllowed },
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, sshMap[addr])
			}}}
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)
	return ts, l
}

func TestAPIEndToEnd(t *testing.T) {
	ts, l := setup(t)
	c := newClient(t, ts.URL)

	if code, _ := c.do("GET", "/api/health", nil, false); code != 200 {
		t.Fatalf("health %d", code)
	}
	if code, _ := c.do("GET", "/api/devices", nil, false); code != 401 {
		t.Fatalf("unauthenticated devices: %d", code)
	}
	if code := c.json("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "wrong"}, nil); code != 401 {
		t.Fatalf("bad login: %d", code)
	}
	if code := c.json("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "admin-pass-123"}, nil); code != 200 {
		t.Fatalf("login: %d", code)
	}
	// CSRF guard
	if code, _ := c.do("POST", "/api/devices", map[string]string{"ip": "10.20.99.1"}, false); code != 403 {
		t.Fatalf("csrf: %d", code)
	}
	// Add Device — the simple path: IP + SNMP username + password.
	var add struct {
		RunID int64 `json:"run_id"`
	}
	if code := c.json("POST", "/api/devices", map[string]any{"ip": "10.20.99.1",
		"snmp": map[string]string{"username": l.V3User, "password": l.V3Pass}}, &add); code != 202 || add.RunID == 0 {
		t.Fatalf("add device: %d", code)
	}
	// Follow the SSE stream until the run finishes.
	req, _ := http.NewRequest("GET", ts.URL+"/api/discovery/runs/"+itoa(add.RunID)+"/stream", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	final := ""
	labels := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var m struct {
			Status string          `json:"status"`
			Step   *discovery.Step `json:"step"`
		}
		_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m)
		if m.Step != nil {
			labels[m.Step.Label] = true
		}
		if m.Status == "completed" || m.Status == "failed" {
			final = m.Status
			break
		}
	}
	resp.Body.Close()
	if final != "completed" {
		t.Fatalf("run ended %q", final)
	}
	for _, want := range []string{"SNMP authenticated", "Huawei detected", "Model detected", "LLDP neighbors", "Topology updated"} {
		if !labels[want] {
			t.Errorf("missing progress step %q", want)
		}
	}
	var list struct {
		Devices []inventory.DeviceRow `json:"devices"`
		Total   int                   `json:"total"`
	}
	c.json("GET", "/api/devices?type=switch", nil, &list)
	if list.Total != 6 {
		t.Fatalf("switches %d", list.Total)
	}
	var detail map[string]any
	c.json("GET", "/api/devices/"+itoa(list.Devices[0].ID), nil, &detail)
	if detail["evidence"] == nil || detail["facts"] == nil {
		t.Fatalf("detail %v", detail)
	}
	var ifaces []map[string]any
	c.json("GET", "/api/devices/"+itoa(list.Devices[0].ID)+"/interfaces", nil, &ifaces)
	if len(ifaces) == 0 {
		t.Fatal("no interfaces")
	}
	var ans explorer.Answer
	c.json("POST", "/api/explore", map[string]string{"question": "Kaç switch var?"}, &ans)
	if ans.Count != 6 {
		t.Fatalf("explore %d %q", ans.Count, ans.Text)
	}
	var topo struct {
		Nodes []map[string]any `json:"nodes"`
		Edges []map[string]any `json:"edges"`
	}
	c.json("GET", "/api/topology", nil, &topo)
	if len(topo.Nodes) < 40 || len(topo.Edges) < 40 {
		t.Fatalf("topology %d nodes %d edges", len(topo.Nodes), len(topo.Edges))
	}
	var dash map[string]any
	if code := c.json("GET", "/api/dashboard", nil, &dash); code != 200 {
		t.Fatalf("dashboard %d", code)
	}
	// Credentials never leak secrets.
	_, body := c.do("GET", "/api/credentials", nil, false)
	if bytes.Contains(body, []byte(l.V3Pass)) || !bytes.Contains(body, []byte(l.V3User)) {
		t.Fatalf("credential listing: %s", body)
	}
	// CSV report
	code, csv := c.do("GET", "/api/reports/inventory.csv", nil, false)
	if code != 200 || !bytes.Contains(csv, []byte("SW-CORE-01")) {
		t.Fatalf("csv %d", code)
	}
	// Metrics
	_, m := c.do("GET", "/metrics", nil, false)
	if !bytes.Contains(m, []byte("nexus_discovery_runs_total")) {
		t.Fatalf("metrics: %s", m)
	}

	// CLI through the API (cookie auth over WebSocket).
	var core int64
	for _, d := range list.Devices {
		if d.Name == "SW-CORE-01" {
			core = d.ID
		}
	}
	u, _ := http.NewRequest("GET", ts.URL, nil)
	hdr := http.Header{"Origin": {ts.URL}}
	for _, ck := range c.http.Jar.Cookies(u.URL) {
		hdr.Add("Cookie", ck.Name+"="+ck.Value)
	}
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http")+"/api/devices/"+itoa(core)+"/cli?protocol=ssh", hdr)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	var out strings.Builder
	deadline := time.Now().Add(5 * time.Second)
	ws.WriteJSON(map[string]string{"type": "input", "data": "display lldp neighbor brief\r"})
	for !strings.Contains(out.String(), "SW-DIST-02") && time.Now().Before(deadline) {
		ws.SetReadDeadline(deadline)
		var msg struct{ Type, Data, Message string }
		if err := ws.ReadJSON(&msg); err != nil {
			t.Fatalf("ws read: %v %q", err, out.String())
		}
		if msg.Type == "output" {
			b, _ := base64.StdEncoding.DecodeString(msg.Data)
			out.Write(b)
		}
	}
	ws.Close()
	if !strings.Contains(out.String(), "SW-DIST-02") {
		t.Fatalf("cli output %q", out.String())
	}
	// Cross-origin WebSocket is rejected.
	bad := http.Header{"Origin": {"http://evil.example"}}
	for _, ck := range c.http.Jar.Cookies(u.URL) {
		bad.Add("Cookie", ck.Name+"="+ck.Value)
	}
	if _, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http")+"/api/devices/"+itoa(core)+"/cli", bad); err == nil {
		t.Fatal("cross-origin websocket accepted")
	}

	// Viewer cannot start discovery or read credentials.
	v := newClient(t, ts.URL)
	v.json("POST", "/api/auth/login", map[string]string{"username": "viewer", "password": "viewer-pass-123"}, nil)
	if code := v.json("POST", "/api/devices", map[string]any{"ip": "10.20.99.1"}, nil); code != 403 {
		t.Fatalf("viewer add device: %d", code)
	}
	if code, _ := v.do("GET", "/api/credentials", nil, false); code != 403 {
		t.Fatalf("viewer credentials: %d", code)
	}
	if code := v.json("GET", "/api/devices", nil, &list); code != 200 {
		t.Fatalf("viewer list: %d", code)
	}
}

func itoa(n int64) string { return strings.TrimSpace(strings.Trim(jsonNum(n), "\"")) }

func jsonNum(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
