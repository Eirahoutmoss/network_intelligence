package api

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
)

func (s *Server) runDiagnostics(w http.ResponseWriter, r *http.Request) {
	if s.Diagnostics == nil {
		writeError(w, http.StatusNotImplemented, "diagnostics not available")
		return
	}
	checks := s.Diagnostics.Run(r.Context())
	status := "ok"
	for _, c := range checks {
		if c.Status == "failed" {
			status = "failed"
			break
		}
		if c.Status == "warning" {
			status = "warning"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "checks": checks, "version": Version, "checked_at": time.Now().UTC()})
}

func (s *Server) diagnosticsBundle(w http.ResponseWriter, r *http.Request) {
	if s.Diagnostics == nil {
		writeError(w, http.StatusNotImplemented, "diagnostics not available")
		return
	}
	var buf bytes.Buffer
	if err := s.Diagnostics.Bundle(r.Context(), &buf); err != nil {
		s.fail(w, r, err)
		return
	}
	auth.Audit(r.Context(), s.DB, "diagnostics.export", "", nil)
	name := fmt.Sprintf("nexus-diagnostics-%s.zip", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	if s.Backup == nil {
		writeError(w, http.StatusNotImplemented, "backup not available")
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Passphrase != "" && len(req.Passphrase) < 12 {
		writeError(w, http.StatusBadRequest, "backup passphrase must be at least 12 characters")
		return
	}
	var buf bytes.Buffer
	if err := s.Backup(r.Context(), &buf, req.Passphrase); err != nil {
		s.fail(w, r, err)
		return
	}
	auth.Audit(r.Context(), s.DB, "backup.export", "", map[string]any{"includes_key": req.Passphrase != "", "bytes": buf.Len()})
	name := fmt.Sprintf("nexus-%s.nxbackup", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}
