package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/backup"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/config"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// readPassphrase reads a passphrase from a file, NEXUS_BACKUP_PASSPHRASE or
// the terminal. It is never taken from the command line.
func readPassphrase(file string, prompt bool, confirm bool) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if v := os.Getenv("NEXUS_BACKUP_PASSPHRASE"); v != "" {
		return v, nil
	}
	if !prompt {
		return "", nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no terminal to ask for the passphrase; use --passphrase-file")
	}
	fmt.Fprint(os.Stderr, "Backup passphrase: ")
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Repeat passphrase: ")
		q, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(p) != string(q) {
			return "", errors.New("passphrases do not match")
		}
	}
	return string(p), nil
}

func cliLogger(*config.Config) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func backupCommand(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "backup file (default: backup directory or current directory)")
	passFile := fs.String("passphrase-file", "", "file with a passphrase; the master key is then included, wrapped with it")
	withKey := fs.Bool("include-key", false, "include the master key protected by a passphrase (asked interactively)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	pass, err := readPassphrase(*passFile, *withKey, true)
	if err != nil {
		return err
	}
	if *withKey && pass == "" {
		return errors.New("--include-key needs a passphrase")
	}
	ctx := context.Background()
	db, done, err := openDatabase(ctx, cfg, cliLogger(cfg), true)
	if err != nil {
		return err
	}
	defer done()
	path := *out
	if path == "" {
		dir := cfg.BackupDir
		if dir == "" {
			dir = "."
		}
		path = filepath.Join(dir, "nexus-"+time.Now().Format("20060102-150405")+backup.Extension)
	}
	m, err := writeBackupFile(ctx, db, cfg, path, pass, "manual")
	if err != nil {
		return err
	}
	var rows int64
	for _, t := range m.Tables {
		rows += t.Rows
	}
	fmt.Printf("Backup written: %s\n  %d tables, %d rows, schema %s, key fingerprint %s, master key included: %v\n",
		path, len(m.Tables), rows, m.SchemaVersion(), m.KeyFingerprint, m.WrappedKey != nil)
	if m.WrappedKey == nil {
		fmt.Println("  Stored device credentials can only be used with this installation's master key.")
	}
	return nil
}

// writeBackupFile writes atomically (temp file + rename) with private permissions.
func writeBackupFile(ctx context.Context, db *storage.DB, cfg *config.Config, path, pass, reason string) (*backup.Manifest, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".partial"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	m, err := backup.Write(ctx, db, f, backup.Options{AppVersion: version, MasterKey: cfg.MasterKey, Passphrase: pass, Reason: reason})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return nil, err
	}
	return m, os.Rename(tmp, path)
}

func restoreCommand(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	passFile := fs.String("passphrase-file", "", "file with the backup passphrase")
	ask := fs.Bool("ask-passphrase", false, "ask for the backup passphrase")
	yes := fs.Bool("yes", false, "replace the current data without asking")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: nexus restore [--ask-passphrase|--passphrase-file F] [--yes] FILE")
	}
	file := fs.Arg(0)
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if running, err := serviceRunning(); err == nil && running {
		return errors.New("stop the Nexus service before restoring")
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	m, _, err := backup.ReadManifest(f, st.Size())
	if err != nil {
		return err
	}
	fmt.Printf("Backup from %s (Nexus %s, schema %s, reason %q)\n", m.CreatedAt.Local().Format(time.RFC1123), m.AppVersion, m.SchemaVersion(), m.Reason)
	pass, err := readPassphrase(*passFile, *ask, false)
	if err != nil {
		return err
	}
	if !*yes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("restore replaces all current data; add --yes to confirm")
		}
		fmt.Fprint(os.Stderr, "This replaces ALL current Nexus data (a safety backup is made first). Type RESTORE to continue: ")
		var answer string
		fmt.Scanln(&answer)
		if answer != "RESTORE" {
			return errors.New("cancelled")
		}
	}
	ctx := context.Background()
	log := cliLogger(cfg)
	db, done, err := openDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer done()
	if applied, err := db.Applied(ctx); err != nil {
		return err
	} else if len(applied) > 0 {
		dir := cfg.BackupDir
		if dir == "" {
			dir = filepath.Dir(file)
		}
		safety := filepath.Join(dir, "nexus-before-restore-"+time.Now().Format("20060102-150405")+backup.Extension)
		if _, err := writeBackupFile(ctx, db, cfg, safety, "", "before-restore"); err != nil {
			return fmt.Errorf("safety backup failed, nothing changed: %w", err)
		}
		fmt.Println("Safety backup of the current data:", safety)
		if _, err := db.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
			return err
		}
	}
	res, err := backup.Restore(ctx, db, f, st.Size(), backup.RestoreOptions{MasterKey: cfg.MasterKey, Passphrase: pass, Log: log})
	if err != nil {
		return fmt.Errorf("restore failed: %w (the safety backup can be restored the same way)", err)
	}
	fmt.Printf("Restored %d tables, %d rows.\n", res.Tables, res.Rows)
	if res.CredentialsResealed > 0 {
		fmt.Printf("%d stored credentials re-encrypted with this installation's master key.\n", res.CredentialsResealed)
	}
	for _, w := range res.Warnings {
		fmt.Println("warning:", w)
	}
	return nil
}

// backupBeforeMigrate writes a backup when the schema is about to change.
func backupBeforeMigrate(ctx context.Context, cfg *config.Config, db *storage.DB, log *slog.Logger) error {
	if cfg.BackupDir == "" {
		return nil
	}
	applied, err := db.Applied(ctx)
	if err != nil || len(applied) == 0 {
		return err
	}
	pending, err := db.Pending(ctx)
	if err != nil || len(pending) == 0 {
		return err
	}
	path := filepath.Join(cfg.BackupDir, fmt.Sprintf("nexus-pre-upgrade-%s%s", time.Now().Format("20060102-150405"), backup.Extension))
	if _, err := writeBackupFile(ctx, db, cfg, path, "", "pre-upgrade"); err != nil {
		return fmt.Errorf("backup before schema upgrade failed (nothing was changed): %w", err)
	}
	log.Info("backup written before schema upgrade", "file", path, "pending", pending)
	pruneBackups(cfg.BackupDir, "nexus-pre-upgrade-", 5, log)
	return nil
}

// autoBackups writes a daily backup and keeps the last keep files.
func autoBackups(ctx context.Context, cfg *config.Config, db *storage.DB, log *slog.Logger, keep int) {
	if cfg.BackupDir == "" {
		return
	}
	last := func() time.Time {
		files, _ := filepath.Glob(filepath.Join(cfg.BackupDir, "nexus-daily-*"+backup.Extension))
		var t time.Time
		for _, f := range files {
			if st, err := os.Stat(f); err == nil && st.ModTime().After(t) {
				t = st.ModTime()
			}
		}
		return t
	}
	check := time.NewTicker(time.Hour)
	defer check.Stop()
	for {
		if time.Since(last()) > 24*time.Hour {
			path := filepath.Join(cfg.BackupDir, "nexus-daily-"+time.Now().Format("20060102-150405")+backup.Extension)
			if _, err := writeBackupFile(ctx, db, cfg, path, "", "daily"); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Error("daily backup failed", "err", err)
			} else {
				log.Info("daily backup written", "file", path)
				pruneBackups(cfg.BackupDir, "nexus-daily-", keep, log)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-check.C:
		}
	}
}

func pruneBackups(dir, prefix string, keep int, log *slog.Logger) {
	files, _ := filepath.Glob(filepath.Join(dir, prefix+"*"+backup.Extension))
	sort.Strings(files) // timestamped names sort chronologically
	for len(files) > keep {
		if err := os.Remove(files[0]); err != nil {
			log.Warn("prune backup", "file", files[0], "err", err)
		}
		files = files[1:]
	}
}
