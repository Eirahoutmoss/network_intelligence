package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/lab"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/testutil"
)

func TestParseTelnet(t *testing.T) {
	var pending []byte
	in := []byte{'h', 'i', iac, will, optEcho, iac, do, 24, 'x', iac, iac, iac}
	data, replies := parseTelnet(in, &pending)
	if string(data) != "hix\xff" {
		t.Fatalf("data %q", data)
	}
	if !bytes.Equal(replies, []byte{iac, do, optEcho, iac, wont, 24}) {
		t.Fatalf("replies %v", replies)
	}
	if !bytes.Equal(pending, []byte{iac}) {
		t.Fatalf("pending %v", pending)
	}
}

// TestSSHSessionThroughWebSocket drives the full browser→WebSocket→backend→SSH
// path against the lab's simulated console and checks audit + host key TOFU.
func TestSSHSessionThroughWebSocket(t *testing.T) {
	db := testutil.DB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := lab.Campus()
	sshMap, err := l.StartSSH(ctx, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := credentials.NewSealer(testutil.Key())
	creds := credentials.NewStore(db, sealer)
	credID, err := creds.CreateLogin(ctx, db, "ssh", credentials.KindSSH, credentials.Login{Username: lab.SSHUser, Password: lab.SSHPass})
	if err != nil {
		t.Fatal(err)
	}
	var devID, userID int64
	db.QueryRow(ctx, `INSERT INTO devices(managed, sys_name, mgmt_ip, ssh_credential_id) VALUES (true,'SW-CORE-01','10.20.99.1',$1) RETURNING id`, credID).Scan(&devID)
	db.QueryRow(ctx, `INSERT INTO users(username,password_hash,role) VALUES ('op','x','operator') RETURNING id`).Scan(&userID)
	svc := &Service{DB: db, Creds: creds, Log: testutil.Logger(), IdleTimeout: time.Minute,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, sshMap[addr])
		}}
	user := &auth.User{ID: userID, Username: "op", Role: auth.RoleOperator}
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, err := svc.Resolve(r.Context(), devID, "ssh")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		svc.Serve(context.Background(), ws, user, target, r.RemoteAddr, 100, 30)
	}))
	defer srv.Close()
	ws, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	read := func(until string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(out.String(), until) {
			if time.Now().After(deadline) {
				t.Fatalf("timeout waiting for %q, got %q", until, out.String())
			}
			ws.SetReadDeadline(deadline)
			var m serverMsg
			if err := ws.ReadJSON(&m); err != nil {
				t.Fatalf("read: %v (got %q)", err, out.String())
			}
			if m.Type == "error" {
				t.Fatalf("server error: %s", m.Message)
			}
			if m.Type == "output" {
				b, _ := base64.StdEncoding.DecodeString(m.Data)
				out.Write(b)
			}
		}
	}
	read("<SW-CORE-01>")
	ws.WriteJSON(clientMsg{Type: "input", Data: "display version\r"})
	read("V200R021C00SPC100")
	ws.WriteJSON(clientMsg{Type: "input", Data: "quit\r"})
	read("Bye.")
	ws.Close()
	time.Sleep(300 * time.Millisecond)
	var reason string
	var transcript []byte
	var bytesIn int
	if err := db.QueryRow(ctx, `SELECT COALESCE(end_reason,''), transcript, bytes_in FROM cli_sessions WHERE device_id=$1`, devID).Scan(&reason, &transcript, &bytesIn); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(transcript), "V200R021C00SPC100") || bytesIn == 0 || reason == "" {
		t.Fatalf("audit: reason=%q in=%d transcript=%q", reason, bytesIn, transcript)
	}
	var hk *string
	db.QueryRow(ctx, `SELECT ssh_host_key FROM devices WHERE id=$1`, devID).Scan(&hk)
	if hk == nil || !strings.HasPrefix(*hk, "SHA256:") {
		t.Fatalf("host key not pinned: %v", hk)
	}
	// A changed host key is rejected.
	db.Exec(ctx, `UPDATE devices SET ssh_host_key='SHA256:bogus' WHERE id=$1`, devID)
	target, _ := svc.Resolve(ctx, devID, "ssh")
	if _, err := svc.dialSSH(ctx, target, 80, 24); err != ErrHostKeyMismatch {
		t.Fatalf("expected host key mismatch, got %v", err)
	}
	// Telnet refused unless enabled globally and per device.
	if _, err := svc.Resolve(ctx, devID, "telnet"); err == nil {
		t.Fatal("telnet should be refused")
	}
}
