// Package backup exports and restores the Nexus database without external
// tools (no pg_dump), so it works the same for the Windows installation with
// its embedded PostgreSQL and for Docker/Linux deployments.
//
// A backup is a zip file:
//
//	manifest.json        format, application and schema versions, row counts,
//	                     master-key fingerprint, optional passphrase-wrapped key
//	data/<table>.copy    PostgreSQL COPY text format
//
// Stored device credentials stay encrypted with the master key; a backup never
// contains plaintext secrets. Sessions are not exported.
package backup

import (
	"archive/zip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// Format is the backup file format version.
const Format = 1

// Extension is the conventional file extension.
const Extension = ".nxbackup"

// skipped tables: migration bookkeeping is rebuilt, sessions are secrets.
var skipped = map[string]bool{"schema_migrations": true, "auth_sessions": true}

// Table describes one exported table.
type Table struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	Rows    int64    `json:"rows"`
}

// WrappedKey is the master key encrypted with a passphrase (Argon2id + AES-256-GCM).
type WrappedKey struct {
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Time       uint32 `json:"time"`
	MemoryKiB  uint32 `json:"memory_kib"`
	Threads    uint8  `json:"threads"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Manifest describes a backup.
type Manifest struct {
	Format         int         `json:"format"`
	App            string      `json:"app"`
	AppVersion     string      `json:"app_version"`
	Schema         []string    `json:"schema"`
	CreatedAt      time.Time   `json:"created_at"`
	Reason         string      `json:"reason,omitempty"`
	Tables         []Table     `json:"tables"`
	KeyFingerprint string      `json:"key_fingerprint"`
	WrappedKey     *WrappedKey `json:"wrapped_key,omitempty"`
}

// SchemaVersion is the latest migration contained in the backup.
func (m *Manifest) SchemaVersion() string {
	if len(m.Schema) == 0 {
		return ""
	}
	return m.Schema[len(m.Schema)-1]
}

// Options control Write.
type Options struct {
	AppVersion string
	MasterKey  []byte
	// Passphrase, when set, stores the master key wrapped with it so the
	// backup can be restored on a machine with a different key.
	Passphrase string
	Reason     string
}

// Write exports a consistent snapshot of the database to w.
func Write(ctx context.Context, db *storage.DB, w io.Writer, opt Options) (*Manifest, error) {
	if len(opt.MasterKey) != 32 {
		return nil, errors.New("master key required")
	}
	applied, err := db.Applied(ctx)
	if err != nil {
		return nil, err
	}
	m := &Manifest{Format: Format, App: "nexus", AppVersion: opt.AppVersion, Schema: applied,
		CreatedAt: time.Now().UTC(), Reason: opt.Reason, KeyFingerprint: credentials.KeyFingerprint(opt.MasterKey)}
	if opt.Passphrase != "" {
		if m.WrappedKey, err = wrapKey(opt.MasterKey, opt.Passphrase); err != nil {
			return nil, err
		}
	}
	conn, err := db.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	tables, err := listTables(ctx, tx)
	if err != nil {
		return nil, err
	}
	zw := zip.NewWriter(w)
	for _, t := range tables {
		f, err := zw.Create("data/" + t.Name + ".copy")
		if err != nil {
			return nil, err
		}
		cols := quoteCols(t.Columns)
		tag, err := tx.Conn().PgConn().CopyTo(ctx, f,
			fmt.Sprintf("COPY (SELECT %s FROM %s) TO STDOUT", cols, pgx.Identifier{t.Name}.Sanitize()))
		if err != nil {
			return nil, fmt.Errorf("export %s: %w", t.Name, err)
		}
		t.Rows = tag.RowsAffected()
		m.Tables = append(m.Tables, t)
	}
	mf, err := zw.Create("manifest.json")
	if err != nil {
		return nil, err
	}
	enc := json.NewEncoder(mf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return m, zw.Close()
}

func listTables(ctx context.Context, q pgx.Tx) ([]Table, error) {
	rows, err := q.Query(ctx, `
		SELECT c.table_name, array_agg(c.column_name::text ORDER BY c.ordinal_position)
		FROM information_schema.columns c
		JOIN information_schema.tables t ON t.table_schema=c.table_schema AND t.table_name=c.table_name
		WHERE c.table_schema='public' AND t.table_type='BASE TABLE' AND c.is_generated='NEVER'
		GROUP BY c.table_name ORDER BY c.table_name`)
	if err != nil {
		return nil, err
	}
	var out []Table
	for rows.Next() {
		var t Table
		if err := rows.Scan(&t.Name, &t.Columns); err != nil {
			return nil, err
		}
		if !skipped[t.Name] {
			out = append(out, t)
		}
	}
	return out, rows.Err()
}

func quoteCols(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = pgx.Identifier{c}.Sanitize()
	}
	return strings.Join(q, ",")
}

// ReadManifest returns the manifest of a backup file.
func ReadManifest(r io.ReaderAt, size int64) (*Manifest, *zip.Reader, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, nil, fmt.Errorf("not a Nexus backup: %w", err)
	}
	f, err := zr.Open("manifest.json")
	if err != nil {
		return nil, nil, errors.New("not a Nexus backup: manifest.json missing")
	}
	defer f.Close()
	var m Manifest
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("invalid backup manifest: %w", err)
	}
	if m.App != "nexus" || m.Format < 1 {
		return nil, nil, errors.New("not a Nexus backup")
	}
	if m.Format > Format {
		return nil, nil, fmt.Errorf("backup format %d is newer than this Nexus supports (%d); upgrade Nexus first", m.Format, Format)
	}
	return &m, zr, nil
}

// RestoreOptions control Restore.
type RestoreOptions struct {
	MasterKey  []byte // key of this installation
	Passphrase string // unwraps the backup's key when it differs
	Log        *slog.Logger
}

// Result summarizes a restore.
type Result struct {
	Tables              int      `json:"tables"`
	Rows                int64    `json:"rows"`
	CredentialsResealed int      `json:"credentials_resealed"`
	CredentialsUnusable int      `json:"credentials_unusable"`
	Warnings            []string `json:"warnings,omitempty"`
}

// Restore loads a backup into db, which must be an empty database. It
// migrates the schema to the backup's version, loads the data and then
// applies the remaining migrations of this binary.
func Restore(ctx context.Context, db *storage.DB, r io.ReaderAt, size int64, opt RestoreOptions) (*Result, error) {
	log := opt.Log
	if log == nil {
		log = slog.Default()
	}
	m, zr, err := ReadManifest(r, size)
	if err != nil {
		return nil, err
	}
	known, err := storage.Migrations()
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, v := range known {
		have[v] = true
	}
	for _, v := range m.Schema {
		if !have[v] {
			return nil, fmt.Errorf("backup was made by a newer Nexus (schema %s); install that version or newer to restore it", v)
		}
	}
	if applied, err := db.Applied(ctx); err != nil {
		return nil, err
	} else if len(applied) > 0 {
		return nil, errors.New("restore needs an empty database")
	}
	if err := db.MigrateTo(ctx, log, m.SchemaVersion()); err != nil {
		return nil, err
	}
	res := &Result{}
	err = pgx.BeginFunc(ctx, db.Pool, func(tx pgx.Tx) error {
		current, err := listTables(ctx, tx)
		if err != nil {
			return err
		}
		curCols := map[string]map[string]bool{}
		var names []string
		for _, t := range current {
			cs := map[string]bool{}
			for _, c := range t.Columns {
				cs[c] = true
			}
			curCols[t.Name] = cs
			names = append(names, pgx.Identifier{t.Name}.Sanitize())
		}
		// Migrations may seed rows; the backup is authoritative.
		if len(names) > 0 {
			if _, err := tx.Exec(ctx, `TRUNCATE `+strings.Join(names, ",")+` RESTART IDENTITY CASCADE`); err != nil {
				return err
			}
		}
		order, err := loadOrder(ctx, tx, m.Tables)
		if err != nil {
			return err
		}
		for _, t := range order {
			cs, ok := curCols[t.Name]
			if !ok {
				res.Warnings = append(res.Warnings, "table "+t.Name+" no longer exists; skipped")
				continue
			}
			for _, c := range t.Columns {
				if !cs[c] {
					return fmt.Errorf("column %s.%s missing after migrating to %s", t.Name, c, m.SchemaVersion())
				}
			}
			f, err := zr.Open("data/" + t.Name + ".copy")
			if err != nil {
				return fmt.Errorf("backup is missing data for %s", t.Name)
			}
			tag, err := tx.Conn().PgConn().CopyFrom(ctx, f,
				fmt.Sprintf("COPY %s (%s) FROM STDIN", pgx.Identifier{t.Name}.Sanitize(), quoteCols(t.Columns)))
			f.Close()
			if err != nil {
				return fmt.Errorf("restore %s: %w", t.Name, err)
			}
			if tag.RowsAffected() != t.Rows {
				return fmt.Errorf("restore %s: %d rows loaded, manifest says %d", t.Name, tag.RowsAffected(), t.Rows)
			}
			res.Tables++
			res.Rows += tag.RowsAffected()
		}
		if err := resetSequences(ctx, tx); err != nil {
			return err
		}
		return reseal(ctx, tx, m, opt, res)
	})
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx, log); err != nil {
		return res, fmt.Errorf("data restored but upgrading the schema failed: %w", err)
	}
	return res, nil
}

// loadOrder sorts tables so referenced tables load before referencing ones.
func loadOrder(ctx context.Context, tx pgx.Tx, tables []Table) ([]Table, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT c.conrelid::regclass::text, c.confrelid::regclass::text
		FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
		WHERE c.contype='f' AND n.nspname='public' AND c.conrelid <> c.confrelid`)
	if err != nil {
		return nil, err
	}
	deps := map[string][]string{}
	for rows.Next() {
		var child, parent string
		if err := rows.Scan(&child, &parent); err != nil {
			return nil, err
		}
		deps[strings.Trim(child, `"`)] = append(deps[strings.Trim(child, `"`)], strings.Trim(parent, `"`))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	byName := map[string]Table{}
	var names []string
	for _, t := range tables {
		byName[t.Name] = t
		names = append(names, t.Name)
	}
	sort.Strings(names)
	state := map[string]int{} // 1 visiting, 2 done
	var out []Table
	var visit func(string) error
	visit = func(n string) error {
		switch state[n] {
		case 1:
			return fmt.Errorf("circular foreign keys involving %s", n)
		case 2:
			return nil
		}
		state[n] = 1
		for _, p := range deps[n] {
			if _, ok := byName[p]; ok {
				if err := visit(p); err != nil {
					return err
				}
			}
		}
		state[n] = 2
		out = append(out, byName[n])
		return nil
	}
	for _, n := range names {
		if err := visit(n); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func resetSequences(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `
		SELECT c.relname, a.attname, pg_get_serial_sequence(quote_ident(c.relname), a.attname)
		FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
		WHERE n.nspname='public' AND c.relkind='r' AND pg_get_serial_sequence(quote_ident(c.relname), a.attname) IS NOT NULL`)
	if err != nil {
		return err
	}
	type seq struct{ table, col, seq string }
	var seqs []seq
	for rows.Next() {
		var s seq
		if err := rows.Scan(&s.table, &s.col, &s.seq); err != nil {
			return err
		}
		seqs = append(seqs, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range seqs {
		q := fmt.Sprintf(`SELECT setval($1, COALESCE((SELECT max(%s) FROM %s), 0) + 1, false)`,
			pgx.Identifier{s.col}.Sanitize(), pgx.Identifier{s.table}.Sanitize())
		if _, err := tx.Exec(ctx, q, s.seq); err != nil {
			return fmt.Errorf("reset sequence %s: %w", s.seq, err)
		}
	}
	return nil
}

// reseal re-encrypts stored credentials when the backup came from an
// installation with a different master key.
func reseal(ctx context.Context, tx pgx.Tx, m *Manifest, opt RestoreOptions, res *Result) error {
	if len(opt.MasterKey) != 32 || m.KeyFingerprint == credentials.KeyFingerprint(opt.MasterKey) {
		return nil
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM credentials`).Scan(&n); err != nil || n == 0 {
		return err
	}
	if m.WrappedKey == nil || opt.Passphrase == "" {
		res.CredentialsUnusable = n
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%d stored credentials were encrypted with another master key (fingerprint %s) and cannot be used; re-enter them or restore with the backup passphrase", n, m.KeyFingerprint))
		return nil
	}
	oldKey, err := unwrapKey(m.WrappedKey, opt.Passphrase)
	if err != nil {
		return err
	}
	if credentials.KeyFingerprint(oldKey) != m.KeyFingerprint {
		return errors.New("the backup's wrapped key does not match its fingerprint")
	}
	from, err := credentials.NewSealer(oldKey)
	if err != nil {
		return err
	}
	to, err := credentials.NewSealer(opt.MasterKey)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id, kind, secret FROM credentials`)
	if err != nil {
		return err
	}
	type cred struct {
		id     int64
		kind   string
		secret []byte
	}
	var all []cred
	for rows.Next() {
		var c cred
		if err := rows.Scan(&c.id, &c.kind, &c.secret); err != nil {
			return err
		}
		all = append(all, c)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range all {
		aad := credentials.AAD(c.id, c.kind)
		plain, err := from.Open(c.secret, aad)
		if err != nil {
			res.CredentialsUnusable++
			continue
		}
		sealed, err := to.Seal(plain, aad)
		clear(plain)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE credentials SET secret=$2 WHERE id=$1`, c.id, sealed); err != nil {
			return err
		}
		res.CredentialsResealed++
	}
	return nil
}

func deriveKEK(pass string, salt []byte, t, mem uint32, threads uint8) []byte {
	return argon2.IDKey([]byte(pass), salt, t, mem, threads, 32)
}

func wrapKey(key []byte, pass string) (*WrappedKey, error) {
	if len(pass) < 12 {
		return nil, errors.New("backup passphrase must be at least 12 characters")
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	w := &WrappedKey{KDF: "argon2id", Time: 3, MemoryKiB: 64 * 1024, Threads: 2}
	gcm, err := newGCM(deriveKEK(pass, salt, w.Time, w.MemoryKiB, w.Threads))
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding
	w.Salt, w.Nonce = b.EncodeToString(salt), b.EncodeToString(nonce)
	w.Ciphertext = b.EncodeToString(gcm.Seal(nil, nonce, key, []byte("nexus-backup-key")))
	return w, nil
}

func unwrapKey(w *WrappedKey, pass string) ([]byte, error) {
	if w.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported key wrapping %q", w.KDF)
	}
	b := base64.StdEncoding
	salt, err1 := b.DecodeString(w.Salt)
	nonce, err2 := b.DecodeString(w.Nonce)
	ct, err3 := b.DecodeString(w.Ciphertext)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("corrupt wrapped key: %w", err)
	}
	if w.MemoryKiB > 1<<21 || w.Time > 20 {
		return nil, errors.New("wrapped key parameters out of range")
	}
	gcm, err := newGCM(deriveKEK(pass, salt, w.Time, w.MemoryKiB, w.Threads))
	if err != nil {
		return nil, err
	}
	key, err := gcm.Open(nil, nonce, ct, []byte("nexus-backup-key"))
	if err != nil {
		return nil, errors.New("wrong backup passphrase")
	}
	return key, nil
}

func newGCM(k []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}
