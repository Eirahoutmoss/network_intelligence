package pgembed

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Requires NEXUS_TEST_PG_BIN (e.g. /usr/lib/postgresql/16/bin); PostgreSQL
// refuses to run as root, so run this test as an unprivileged user.
func TestLifecycle(t *testing.T) {
	bin := os.Getenv("NEXUS_TEST_PG_BIN")
	if bin == "" || os.Geteuid() == 0 {
		t.Skip("set NEXUS_TEST_PG_BIN and run as a non-root user")
	}
	dir := t.TempDir()
	ctx := context.Background()
	// occupy the preferred port to exercise the fallback
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	pref := busy.Addr().(*net.TCPAddr).Port
	s := &Server{BinDir: bin, DataDir: filepath.Join(dir, "db"), LogDir: filepath.Join(dir, "logs"), Port: pref, Password: "p'w\"d @/:?x"}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop(context.Background()) })
	if s.ActualPort() == pref {
		t.Fatal("expected a different port")
	}
	if err := s.EnsureDatabase(ctx, "nexus"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureDatabase(ctx, "nexus"); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, s.URL("nexus"))
	if err != nil {
		t.Fatal(err)
	}
	var listen string
	_ = conn.QueryRow(ctx, "SHOW listen_addresses").Scan(&listen)
	conn.Close(ctx)
	if listen != "127.0.0.1" {
		t.Errorf("listen_addresses %q", listen)
	}
	// wrong password is rejected (SCRAM)
	bad := *s
	bad.Password = "wrong"
	if err := bad.ping(ctx, "nexus"); err == nil {
		t.Error("wrong password accepted")
	}
	// restart keeps data and picks the preferred port once free
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	busy.Close()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if s.ActualPort() != pref {
		t.Errorf("port %d, want %s", s.ActualPort(), strconv.Itoa(pref))
	}
	if !s.Running(ctx) {
		t.Error("not running")
	}
	if _, err := os.Stat(filepath.Join(dir, "logs")); err != nil {
		t.Error(err)
	}
}
