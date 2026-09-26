// Package api exposes the HTTP API and serves the web UI.
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/cli"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/discovery"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/explorer"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/locations"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/metrics"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/settings"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// Version is set at build time.
var Version = "dev"

// Server wires services to HTTP handlers.
type Server struct {
	DB        *storage.DB
	Auth      *auth.Service
	Creds     *credentials.Store
	Store     *inventory.Store
	Engine    *discovery.Engine
	Explorer  *explorer.Explorer
	Locations *locations.Service
	CLI       *cli.Service
	Settings  *settings.Service
	Metrics   *metrics.Registry
	Log       *slog.Logger
	WebDir    string
	Simulator bool
	LLM       bool
}

// Router builds the HTTP handler.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(s.recoverer, s.logRequests, securityHeaders)

	r.Get("/api/health", s.health)
	r.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		s.Metrics.Write(w)
	})
	r.Route("/api", func(r chi.Router) {
		r.Use(limitBody, csrfGuard)
		r.Post("/auth/login", s.login)
		r.Post("/auth/logout", s.logout)

		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Get("/auth/me", s.me)
			r.Post("/auth/password", s.changePassword)
			r.Get("/info", s.info)

			// read-only (viewer)
			r.Get("/dashboard", s.dashboard)
			r.Get("/devices", s.listDevices)
			r.Get("/devices/{id}", s.getDevice)
			r.Get("/devices/{id}/interfaces", s.deviceInterfaces)
			r.Get("/devices/{id}/neighbors", s.deviceNeighbors)
			r.Get("/devices/{id}/endpoints", s.deviceEndpoints)
			r.Get("/devices/{id}/tables/{table}", s.deviceTable)
			r.Get("/devices/{id}/events", s.deviceEvents)
			r.Get("/interfaces/{id}/metrics", s.interfaceMetrics)
			r.Get("/topology", s.topology)
			r.Get("/connections", s.connections)
			r.Post("/explore", s.explore)
			r.Post("/explore/query", s.exploreQuery)
			r.Get("/locations", s.listLocations)
			r.Get("/racks", s.listRacks)
			r.Get("/patch-panels", s.listPatchPanels)
			r.Get("/jacks", s.listJacks)
			r.Get("/events", s.listEvents)
			r.Get("/alerts", s.listAlerts)
			r.Get("/subnets", s.listSubnets)
			r.Get("/vlans", s.listVLANs)
			r.Get("/discovery/runs", s.listRuns)
			r.Get("/discovery/runs/{id}", s.getRun)
			r.Get("/discovery/runs/{id}/stream", s.streamRun)
			r.Get("/discovery/defaults", s.discoveryDefaults)
			r.Get("/reports/inventory.csv", s.inventoryCSV)
			r.Get("/reports/summary", s.reportSummary)

			// operator
			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleOperator))
				r.Get("/credentials", s.listCredentials)
				r.Post("/devices", s.addDevice)
				r.Post("/discovery/refresh", s.refresh)
				r.Post("/discovery/runs/{id}/cancel", s.cancelRun)
				r.Put("/devices/{id}/context", s.setContext)
				r.Put("/devices/{id}/access", s.setAccess)
				r.Post("/devices/assign-location", s.assignLocation)
				r.Post("/locations", s.createLocation)
				r.Put("/locations/{id}", s.updateLocation)
				r.Delete("/locations/{id}", s.deleteLocation)
				r.Post("/locations/import-syslocation", s.importSysLocation)
				r.Post("/racks", s.createRack)
				r.Delete("/racks/{id}", s.deleteRack)
				r.Post("/patch-panels", s.createPatchPanel)
				r.Delete("/patch-panels/{id}", s.deletePatchPanel)
				r.Post("/jacks", s.createJack)
				r.Put("/jacks/{id}", s.updateJack)
				r.Delete("/jacks/{id}", s.deleteJack)
				r.Put("/topology/layout", s.saveLayout)
				r.Delete("/topology/layout", s.resetLayout)
				r.Post("/manual-links", s.createManualLink)
				r.Delete("/manual-links/{id}", s.deleteManualLink)
				r.Post("/alerts/{id}/ack", s.ackAlert)
				r.Get("/devices/{id}/cli", s.cliSocket)
			})
			// admin
			r.Group(func(r chi.Router) {
				r.Use(requireRole(auth.RoleAdmin))
				r.Post("/credentials", s.createCredential)
				r.Delete("/credentials/{id}", s.deleteCredential)
				r.Delete("/devices/{id}", s.deleteDevice)
				r.Delete("/devices/{id}/ssh-host-key", s.resetHostKey)
				r.Get("/users", s.listUsers)
				r.Post("/users", s.createUser)
				r.Put("/users/{id}", s.updateUser)
				r.Delete("/users/{id}", s.deleteUser)
				r.Get("/audit", s.listAudit)
				r.Get("/cli-sessions", s.listCLISessions)
				r.Get("/cli-sessions/{id}/transcript", s.cliTranscript)
				r.Post("/cli-sessions/{id}/terminate", s.terminateCLI)
				r.Get("/settings", s.getSettings)
				r.Put("/settings", s.putSettings)
			})
		})
		r.NotFound(func(w http.ResponseWriter, r *http.Request) { writeError(w, http.StatusNotFound, "not found") })
	})
	if s.WebDir != "" {
		r.NotFound(s.spa)
	}
	return r
}

// ---- middleware

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack is needed for WebSocket upgrades.
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	w.status = http.StatusSwitchingProtocols
	return h.Hijack()
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if !strings.HasPrefix(r.URL.Path, "/api") && r.URL.Path != "/metrics" {
			return
		}
		lvl := slog.LevelDebug
		if sw.status >= 500 {
			lvl = slog.LevelError
		} else if strings.HasPrefix(r.URL.Path, "/api") && r.Method != http.MethodGet {
			lvl = slog.LevelInfo
		}
		s.Log.Log(r.Context(), lvl, "http", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(), "bytes", sw.bytes)
		s.Metrics.Inc("nexus_http_requests_total", strconv.Itoa(sw.status/100)+"xx")
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic", "err", rec, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		next.ServeHTTP(w, r)
	})
}

// csrfGuard requires a custom header on state-changing requests. Browsers
// cannot send it cross-origin without a CORS preflight, which we never allow.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if r.Header.Get("X-Requested-With") != "nexus" && !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				writeError(w, http.StatusForbidden, "missing X-Requested-With header")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := s.Auth.Authenticate(r.Context(), auth.TokenFrom(r))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), u)))
	})
}

func requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !auth.UserFrom(r.Context()).Can(role) {
				writeError(w, http.StatusForbidden, "requires "+role+" role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	s.Log.Error("request failed", "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

func idParam(r *http.Request, name string) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, name), 10, 64)
}

func queryInt(r *http.Request, name string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(name)); err == nil {
		return v
	}
	return def
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	start := time.Now()
	dbOK := s.DB.Ping(ctx) == nil
	status, code := "ok", http.StatusOK
	if !dbOK {
		status, code = "degraded", http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"status": status, "database": dbOK, "db_latency_ms": time.Since(start).Milliseconds(), "version": Version})
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": Version, "simulator": s.Simulator, "llm": s.LLM})
}

// spa serves the built frontend with index.html fallback for client routes.
func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	clean := filepath.Clean("/" + r.URL.Path)
	p := filepath.Join(s.WebDir, clean)
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		if strings.HasPrefix(clean, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeFile(w, r, p)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, filepath.Join(s.WebDir, "index.html"))
}
