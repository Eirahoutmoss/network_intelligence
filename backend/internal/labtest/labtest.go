// Package labtest runs a full discovery of the simulated campus lab into a
// test database. Used by integration tests of several packages.
package labtest

import (
	"context"
	"testing"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/discovery"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/lab"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/metrics"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/testutil"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/all"
)

// Env is a discovered lab.
type Env struct {
	Lab     *lab.Lab
	Running *lab.Running
	Engine  *discovery.Engine
	Creds   *credentials.Store
	CredID  int64
	RunID   int64
}

// Discover starts the lab, runs discovery from the core and waits for completion.
func Discover(t testing.TB, db *storage.DB, active bool) *Env {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l := lab.Campus()
	r, err := l.Start(ctx, "127.0.0.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := credentials.NewSealer(testutil.Key())
	creds := credentials.NewStore(db, sealer)
	credID, err := creds.CreateSNMP(ctx, db, "lab", credentials.SNMP{Username: l.V3User, AuthPassword: l.V3Pass})
	if err != nil {
		t.Fatal(err)
	}
	log := testutil.Logger()
	e := &discovery.Engine{
		DB: db, Store: inventory.New(db, log), Creds: creds, Hub: discovery.NewHub(), Log: log, Metrics: metrics.New(),
		Collector: &discovery.Collector{Dialer: snmp.NetDialer{Map: r.Addrs, Strict: true, Opt: snmp.Options{Timeout: time.Second}}, Registry: all.Registry(), Log: log},
		Prober:    l.Prober(),
	}
	e.Start(ctx)
	id, err := e.Submit(ctx, "10.20.99.1", credID, discovery.Options{MaxDepth: 3, ActiveFingerprint: active, TryAllCredentials: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		var status string
		var errText *string
		if err := db.QueryRow(ctx, `SELECT status, error FROM discovery_runs WHERE id=$1`, id).Scan(&status, &errText); err != nil {
			t.Fatal(err)
		}
		if status == "completed" {
			break
		}
		if status == "failed" || status == "cancelled" {
			t.Fatalf("run %s: %v", status, *errText)
		}
		if time.Now().After(deadline) {
			t.Fatal("discovery timed out")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return &Env{Lab: l, Running: r, Engine: e, Creds: creds, CredID: credID, RunID: id}
}
