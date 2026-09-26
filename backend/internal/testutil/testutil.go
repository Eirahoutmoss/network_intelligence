// Package testutil provides a disposable PostgreSQL schema for integration tests.
package testutil

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// DB returns a freshly migrated database or skips the test when
// NEXUS_TEST_DATABASE_URL is not set. The public schema is reset.
func DB(t testing.TB) *storage.DB {
	t.Helper()
	url := os.Getenv("NEXUS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("NEXUS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := storage.Open(ctx, url, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, log); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

// Logger returns a quiet logger (set NEXUS_TEST_VERBOSE=1 for output).
func Logger() *slog.Logger {
	if os.Getenv("NEXUS_TEST_VERBOSE") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Key returns a fixed 32-byte test master key.
func Key() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}
