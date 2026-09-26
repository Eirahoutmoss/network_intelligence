package backup

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/labtest"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/testutil"
)

// emptyDB creates (or recreates) a sibling database for restores.
func emptyDB(t *testing.T, src *storage.DB) *storage.DB {
	t.Helper()
	ctx := context.Background()
	u, _ := url.Parse(os.Getenv("NEXUS_TEST_DATABASE_URL"))
	name := strings.TrimPrefix(u.Path, "/") + "_restore"
	if _, err := src.Exec(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := storage.Open(ctx, u.String(), testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func counts(t *testing.T, db *storage.DB) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, tb := range []string{"devices", "interfaces", "neighbors", "attachments", "topology_edges", "credentials", "users", "evidence", "fdb_entries", "locations"} {
		var n int64
		if err := db.QueryRow(context.Background(), `SELECT count(*) FROM `+tb).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[tb] = n
	}
	return out
}

func TestRoundTrip(t *testing.T) {
	src := testutil.DB(t)
	env := labtest.Discover(t, src, true)
	ctx := context.Background()
	if _, err := src.Exec(ctx, `INSERT INTO users(username,password_hash,role) VALUES ('admin','x','admin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Exec(ctx, `INSERT INTO auth_sessions(token_hash,user_id,expires_at) SELECT 'h', id, now()+interval '1h' FROM users LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	var loc int64
	if err := src.QueryRow(ctx, `INSERT INTO locations(kind,name) VALUES ('building','HQ') RETURNING id`).Scan(&loc); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Exec(ctx, `INSERT INTO locations(kind,name,parent_id) VALUES ('floor','1',$1)`, loc); err != nil {
		t.Fatal(err)
	}
	before := counts(t, src)

	var buf bytes.Buffer
	m, err := Write(ctx, src, &buf, Options{AppVersion: "test", MasterKey: testutil.Key(), Passphrase: "correct horse battery"})
	if err != nil {
		t.Fatal(err)
	}
	if m.KeyFingerprint == "" || m.WrappedKey == nil || len(m.Schema) == 0 {
		t.Fatalf("manifest %+v", m)
	}
	// the backup never contains plaintext lab credentials or the master key
	raw := buf.Bytes()
	for _, secret := range []string{env.Lab.V3Pass, string(testutil.Key())} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("backup contains a secret")
		}
	}
	for _, tb := range m.Tables {
		if tb.Name == "auth_sessions" || tb.Name == "schema_migrations" {
			t.Fatalf("%s must not be exported", tb.Name)
		}
	}

	// Restore on an installation with a different master key, with the passphrase.
	newKey := []byte("fedcba9876543210fedcba9876543210")
	dst := emptyDB(t, src)
	res, err := Restore(ctx, dst, bytes.NewReader(raw), int64(len(raw)), RestoreOptions{MasterKey: newKey, Passphrase: "correct horse battery", Log: testutil.Logger()})
	if err != nil {
		t.Fatal(err)
	}
	if res.CredentialsResealed != int(before["credentials"]) || res.CredentialsUnusable != 0 {
		t.Fatalf("result %+v", res)
	}
	after := counts(t, dst)
	for k, v := range before {
		if after[k] != v {
			t.Errorf("%s: %d rows, want %d", k, after[k], v)
		}
	}
	// credentials decrypt with the new key
	sealer, _ := credentials.NewSealer(newKey)
	store := credentials.NewStore(dst, sealer)
	snmp, err := store.SNMP(ctx, env.CredID)
	if err != nil || snmp.AuthPassword != env.Lab.V3Pass {
		t.Fatalf("credential after reseal: %v", err)
	}
	// sequences continue after the restored ids
	var id int64
	if err := dst.QueryRow(ctx, `INSERT INTO locations(kind,name) VALUES ('site','new') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if id <= loc+1 {
		t.Errorf("sequence not reset: id %d", id)
	}
	var sessions int
	_ = dst.QueryRow(ctx, `SELECT count(*) FROM auth_sessions`).Scan(&sessions)
	if sessions != 0 {
		t.Error("sessions restored")
	}

	// A second restore into a non-empty database is refused.
	if _, err := Restore(ctx, dst, bytes.NewReader(raw), int64(len(raw)), RestoreOptions{MasterKey: newKey}); err == nil {
		t.Error("restore into non-empty database accepted")
	}
	// Wrong passphrase fails; no passphrase restores but flags unusable credentials.
	dst2 := emptyDB(t, src)
	if _, err := Restore(ctx, dst2, bytes.NewReader(raw), int64(len(raw)), RestoreOptions{MasterKey: newKey, Passphrase: "wrong passphrase!!"}); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("wrong passphrase: %v", err)
	}
	dst3 := emptyDB(t, src)
	res, err = Restore(ctx, dst3, bytes.NewReader(raw), int64(len(raw)), RestoreOptions{MasterKey: newKey})
	if err != nil || res.CredentialsUnusable == 0 || len(res.Warnings) == 0 {
		t.Fatalf("restore without passphrase: %+v %v", res, err)
	}
	// Same key: nothing to reseal.
	dst4 := emptyDB(t, src)
	res, err = Restore(ctx, dst4, bytes.NewReader(raw), int64(len(raw)), RestoreOptions{MasterKey: testutil.Key()})
	if err != nil || res.CredentialsResealed != 0 || res.CredentialsUnusable != 0 {
		t.Fatalf("same key: %+v %v", res, err)
	}
}

func TestRejectsGarbage(t *testing.T) {
	b := []byte("not a zip")
	if _, _, err := ReadManifest(bytes.NewReader(b), int64(len(b))); err == nil {
		t.Fatal("garbage accepted")
	}
}
