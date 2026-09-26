package api

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
)

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	token, u, err := s.Auth.Login(r.Context(), strings.TrimSpace(req.Username), req.Password, clientIP(r))
	if err != nil {
		s.Metrics.Inc("nexus_login_failures_total", "")
		auth.Audit(r.Context(), s.DB, "login.failed", req.Username, map[string]any{"ip": clientIP(r)})
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.Auth.SetCookie(w, token)
	auth.Audit(auth.WithUser(r.Context(), u), s.DB, "login", u.Username, map[string]any{"ip": clientIP(r)})
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

// isLoopback reports whether the request comes from this computer.
func isLoopback(r *http.Request) bool {
	ip := net.ParseIP(clientIP(r))
	return ip != nil && ip.IsLoopback()
}

func (s *Server) setupRequired(r *http.Request) bool {
	if !s.FirstRunSetup {
		return false
	}
	n, err := s.Auth.UserCount(r.Context())
	return err == nil && n == 0
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	req := s.setupRequired(r)
	writeJSON(w, http.StatusOK, map[string]any{"required": req, "allowed": req && isLoopback(r)})
}

// setup creates the first administrator. It is only available while no
// account exists and only from the local machine, so nobody on the network
// can claim a fresh installation.
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if !s.setupRequired(r) {
		writeError(w, http.StatusConflict, "setup has already been completed; sign in instead")
		return
	}
	if !isLoopback(r) {
		writeError(w, http.StatusForbidden, "the first administrator can only be created on the Nexus computer itself (http://localhost)")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.Auth.CreateFirstAdmin(r.Context(), req.Username, req.Password); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, auth.ErrSetupDone) {
			code = http.StatusConflict
		}
		writeError(w, code, err.Error())
		return
	}
	token, u, err := s.Auth.Login(r.Context(), strings.TrimSpace(req.Username), req.Password, clientIP(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Auth.SetCookie(w, token)
	auth.Audit(auth.WithUser(r.Context(), u), s.DB, "setup.admin_created", u.Username, map[string]any{"ip": clientIP(r)})
	s.Log.Info("first administrator created", "username", u.Username)
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if t := auth.TokenFrom(r); t != "" {
		s.Auth.Logout(r.Context(), t)
	}
	s.Auth.ClearCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"user": auth.UserFrom(r.Context())})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u := auth.UserFrom(r.Context())
	if _, _, err := s.Auth.Login(r.Context(), u.Username, req.Current, clientIP(r)); err != nil {
		writeError(w, http.StatusBadRequest, "current password is incorrect")
		return
	}
	if err := s.Auth.SetPassword(r.Context(), u.ID, req.New); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auth.Audit(r.Context(), s.DB, "password.changed", u.Username, nil)
	s.Auth.ClearCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Auth.Users(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.Auth.CreateUser(r.Context(), req.Username, req.Password, req.Role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auth.Audit(r.Context(), s.DB, "user.created", req.Username, map[string]any{"role": req.Role})
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req struct {
		Role     string `json:"role"`
		Disabled bool   `json:"disabled"`
		Password string `json:"password,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Auth.UpdateUser(r.Context(), id, req.Role, req.Disabled); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Password != "" {
		if err := s.Auth.SetPassword(r.Context(), id, req.Password); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	auth.Audit(r.Context(), s.DB, "user.updated", "user#"+chiID(r), map[string]any{"role": req.Role, "disabled": req.Disabled, "password_reset": req.Password != ""})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if id == auth.UserFrom(r.Context()).ID {
		writeError(w, http.StatusBadRequest, "you cannot delete yourself")
		return
	}
	if err := s.Auth.DeleteUser(r.Context(), id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auth.Audit(r.Context(), s.DB, "user.deleted", "user#"+chiID(r), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(r.Context(), `SELECT id, ts, COALESCE(username,''), action, COALESCE(target,''), detail FROM audit_log ORDER BY ts DESC LIMIT $1`, queryInt(r, "limit", 300))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type entry struct {
		ID       int64          `json:"id"`
		TS       any            `json:"ts"`
		Username string         `json:"username"`
		Action   string         `json:"action"`
		Target   string         `json:"target"`
		Detail   map[string]any `json:"detail"`
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[entry])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
