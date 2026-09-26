package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/backup"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/config"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/diag"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

var startedAt = time.Now()

// redactor knows this installation's secret values in all encodings they
// might appear in, on top of pattern-based redaction.
func redactor(cfg *config.Config) *diag.Redactor {
	if cfg == nil {
		cfg = &config.Config{}
	}
	known := []string{cfg.PGPassword, cfg.AdminPass, cfg.AnthropicAPIKey}
	if len(cfg.MasterKey) > 0 {
		known = append(known, base64.StdEncoding.EncodeToString(cfg.MasterKey), base64.RawStdEncoding.EncodeToString(cfg.MasterKey),
			base64.URLEncoding.EncodeToString(cfg.MasterKey), base64.RawURLEncoding.EncodeToString(cfg.MasterKey), hex.EncodeToString(cfg.MasterKey))
	}
	if v := os.Getenv("NEXUS_MASTER_KEY"); v != "" {
		known = append(known, v)
	}
	return diag.NewRedactor(known...)
}

func nexusEnv() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "NEXUS_") || k == "ANTHROPIC_API_KEY" {
			out[k] = v
		}
	}
	return out
}

func newDiagnostics(cfg *config.Config, db *storage.DB, creds *credentials.Store) *diag.Runner {
	r := &diag.Runner{DB: db, Version: version, StartedAt: startedAt, ListenAddr: cfg.ListenAddr, WebDir: cfg.WebDir,
		DataDir: cfg.PGData, LogFile: cfg.LogFile, BackupDir: cfg.BackupDir, Embedded: cfg.Embedded(),
		Env: nexusEnv, Redactor: redactor(cfg)}
	if creds != nil {
		r.CredentialCheck = creds.Verify
	}
	return r
}

func backupFunc(cfg *config.Config, db *storage.DB) func(context.Context, io.Writer, string) error {
	return func(ctx context.Context, w io.Writer, pass string) error {
		_, err := backup.Write(ctx, db, w, backup.Options{AppVersion: version, MasterKey: cfg.MasterKey, Passphrase: pass, Reason: "web"})
		return err
	}
}

// diagnosticsCommand prints health checks and writes a bundle; it works while
// the web interface is down.
func diagnosticsCommand(args []string) error {
	fs := flag.NewFlagSet("diagnostics", flag.ContinueOnError)
	out := fs.String("out", "", "bundle file (default: nexus-diagnostics-<time>.zip in the current directory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, done, err := openDatabase(ctx, cfg, cliLogger(cfg), true)
	if err != nil {
		// Still produce a bundle with logs and configuration.
		fmt.Fprintln(os.Stderr, "database unavailable:", redactor(cfg).Redact(err.Error()))
		return offlineBundle(cfg, *out, err)
	}
	defer done()
	sealer, err := credentials.NewSealer(cfg.MasterKey)
	if err != nil {
		return err
	}
	r := newDiagnostics(cfg, db, credentials.NewStore(db, sealer))
	for _, c := range r.Run(ctx) {
		fmt.Printf("%-8s %-22s %s\n", strings.ToUpper(c.Status), c.Component, c.Detail)
		if c.Hint != "" && c.Status != diag.OK {
			fmt.Printf("         %-22s hint: %s\n", "", c.Hint)
		}
	}
	path := bundlePath(*out)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := r.Bundle(ctx, f); err != nil {
		f.Close()
		return err
	}
	fmt.Println("Diagnostic bundle (secrets redacted):", path)
	return f.Close()
}

func bundlePath(out string) string {
	if out != "" {
		return out
	}
	return filepath.Join(".", "nexus-diagnostics-"+time.Now().Format("20060102-150405")+".zip")
}

func offlineBundle(cfg *config.Config, out string, cause error) error {
	path := bundlePath(out)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := diag.OfflineBundle(f, version, cause, cfg.LogFile, nexusEnv(), redactor(cfg)); err != nil {
		return err
	}
	fmt.Println("Diagnostic bundle (database unavailable, secrets redacted):", path)
	return errors.New("the database is not reachable; see the bundle for details")
}
