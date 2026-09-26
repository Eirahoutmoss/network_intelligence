package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/discovery"
)

type runRow struct {
	ID         int64            `json:"id"`
	SeedIP     string           `json:"seed_ip"`
	MaxDepth   int              `json:"max_depth"`
	Scope      []string         `json:"scope"`
	Options    json.RawMessage  `json:"options"`
	Status     string           `json:"status"`
	Steps      []discovery.Step `json:"steps"`
	Summary    map[string]any   `json:"summary"`
	Error      *string          `json:"error"`
	CreatedBy  *string          `json:"created_by"`
	CreatedAt  time.Time        `json:"created_at"`
	StartedAt  *time.Time       `json:"started_at"`
	FinishedAt *time.Time       `json:"finished_at"`
}

const runCols = `r.id, host(r.seed_ip), r.max_depth, r.scope::text[], r.options, r.status, r.steps, r.summary, r.error, u.username, r.created_at, r.started_at, r.finished_at`

func scanRun(row interface{ Scan(...any) error }, withSteps bool) (runRow, error) {
	var x runRow
	var steps []byte
	err := row.Scan(&x.ID, &x.SeedIP, &x.MaxDepth, &x.Scope, &x.Options, &x.Status, &steps, &x.Summary, &x.Error, &x.CreatedBy, &x.CreatedAt, &x.StartedAt, &x.FinishedAt)
	if err == nil && withSteps {
		_ = json.Unmarshal(steps, &x.Steps)
	}
	if x.Steps == nil {
		x.Steps = []discovery.Step{}
	}
	return x, err
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(r.Context(), `SELECT `+runCols+` FROM discovery_runs r LEFT JOIN users u ON u.id=r.created_by ORDER BY r.id DESC LIMIT $1`, queryInt(r, "limit", 50))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []runRow{}
	for rows.Next() {
		x, err := scanRun(rows, false)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, x)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	x, err := scanRun(s.DB.QueryRow(r.Context(), `SELECT `+runCols+` FROM discovery_runs r LEFT JOIN users u ON u.id=r.created_by WHERE r.id=$1`, id), true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, x)
}

// streamRun sends live progress as Server-Sent Events. The first event is a
// full snapshot; later events carry individual steps and status changes.
func (s *Server) streamRun(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ch, unsub := s.Engine.Hub.Subscribe(id)
	defer unsub()
	x, err := scanRun(s.DB.QueryRow(r.Context(), `SELECT `+runCols+` FROM discovery_runs r LEFT JOIN users u ON u.id=r.created_by WHERE r.id=$1`, id), true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	send := func(event string, v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		flusher.Flush()
	}
	send("snapshot", x)
	if x.Status != "queued" && x.Status != "running" {
		return
	}
	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keep.C:
			fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()
		case m, ok := <-ch:
			if !ok {
				return
			}
			send("update", m)
			if m.Status != "" && m.Status != "running" {
				return
			}
		}
	}
}

func (s *Server) discoveryDefaults(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	opt := discovery.DefaultOptions(ip)
	st := s.Settings.Get(r.Context())
	opt.MaxDepth, opt.MaxDevices, opt.ActiveFingerprint = st.DefaultDepth, st.MaxDevices, st.ActiveFingerprinting
	if len(st.DefaultScope) > 0 {
		opt.Scope = st.DefaultScope
	}
	writeJSON(w, http.StatusOK, opt)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	id, err := s.Engine.SubmitRefresh(r.Context(), auth.UserFrom(r.Context()).ID)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	auth.Audit(r.Context(), s.DB, "discovery.refresh", "", map[string]any{"run_id": id})
	writeJSON(w, http.StatusAccepted, map[string]int64{"run_id": id})
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.Engine.Cancel(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	auth.Audit(r.Context(), s.DB, "discovery.cancelled", fmt.Sprintf("run#%d", id), nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
