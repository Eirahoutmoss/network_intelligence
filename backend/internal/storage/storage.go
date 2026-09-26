// Package storage owns the PostgreSQL connection pool and schema migrations.
package storage

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Eirahoutmoss/network_intelligence/backend/migrations"
)

// DB wraps a pgx pool.
type DB struct {
	*pgxpool.Pool
}

// Open connects to PostgreSQL, retrying for up to 60s so the service can start
// before the database container is ready.
func Open(ctx context.Context, url string, log *slog.Logger) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if cfg.MaxConns < 10 {
		cfg.MaxConns = 10
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				return &DB{pool}, nil
			}
			pool.Close()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("connect database: %w", err)
		}
		log.Warn("database not ready, retrying", "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// Migrations returns the versions embedded in this binary, in order.
func Migrations() ([]string, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			out = append(out, strings.TrimSuffix(e.Name(), ".sql"))
		}
	}
	sort.Strings(out)
	return out, nil
}

// Applied returns the migration versions recorded in the database.
func (db *DB) Applied(ctx context.Context) ([]string, error) {
	var exists bool
	if err := db.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		return nil, err
	}
	rows, err := db.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Pending returns embedded migrations not yet applied.
func (db *DB) Pending(ctx context.Context) ([]string, error) {
	all, err := Migrations()
	if err != nil {
		return nil, err
	}
	applied, err := db.Applied(ctx)
	if err != nil {
		return nil, err
	}
	done := map[string]bool{}
	for _, v := range applied {
		done[v] = true
	}
	var out []string
	for _, v := range all {
		if !done[v] {
			out = append(out, v)
		}
	}
	return out, nil
}

// Migrate applies pending migrations in lexical order inside a transaction each.
func (db *DB) Migrate(ctx context.Context, log *slog.Logger) error {
	return db.MigrateTo(ctx, log, "")
}

// MigrateTo applies pending migrations up to and including version upTo
// ("" = all).
func (db *DB) MigrateTo(ctx context.Context, log *slog.Logger, upTo string) error {
	if _, err := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	// Serialize concurrent starters. Advisory locks are per-connection, so hold one.
	conn, err := db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(7263541)`); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(7263541)`)

	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, f := range files {
		version := strings.TrimSuffix(f, ".sql")
		if upTo != "" && version > upTo {
			break
		}
		var exists bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		body, err := fs.ReadFile(migrations.FS, f)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, db.Pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, version)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", f, err)
		}
		log.Info("applied migration", "version", version)
	}
	return nil
}

// DBTX is satisfied by *pgxpool.Pool and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
