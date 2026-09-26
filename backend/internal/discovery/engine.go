// Package discovery orchestrates network discovery runs: seed collection,
// controlled recursion to neighbors, identity resolution, fingerprinting,
// classification and topology updates.
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/events"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/fingerprint"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/inventory"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/metrics"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/model"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// Options control the extent of a discovery run. Defaults are conservative.
type Options struct {
	// MaxDepth is how many LLDP/CDP hops to follow from the seed (0 = seed only).
	MaxDepth int `json:"max_depth"`
	// Scope limits recursion and probing to these CIDRs. Empty → seed /16 (IPv4).
	Scope []string `json:"scope"`
	// MaxDevices caps the number of SNMP devices contacted in one run.
	MaxDevices int `json:"max_devices"`
	// ActiveFingerprint enables NetBIOS/SMB/HTTP/port probes of endpoints in scope.
	ActiveFingerprint bool `json:"active_fingerprint"`
	// TryAllCredentials tries every saved SNMP credential on neighbors.
	TryAllCredentials bool `json:"try_all_credentials"`
	// Concurrency is the number of devices collected in parallel.
	Concurrency int `json:"concurrency"`
	// Fingerprint probe spacing in milliseconds (rate limit).
	ProbeSpacingMS int `json:"probe_spacing_ms"`
	// Targets, when set, is a refresh of known devices: each is collected
	// once and no recursion happens.
	Targets []string `json:"targets,omitempty"`
	// SSHCredentialID is assigned to discovered devices that have none (for the CLI).
	SSHCredentialID int64 `json:"ssh_credential_id,omitempty"`
}

func (o *Options) defaults(seed string) {
	if o.MaxDepth < 0 {
		o.MaxDepth = 0
	}
	if o.MaxDepth > 10 {
		o.MaxDepth = 10
	}
	if o.MaxDevices <= 0 {
		o.MaxDevices = 64
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.Concurrency > 16 {
		o.Concurrency = 16
	}
	if o.ProbeSpacingMS <= 0 {
		o.ProbeSpacingMS = 20
	}
	if len(o.Scope) == 0 {
		if ip := net.ParseIP(seed).To4(); ip != nil {
			o.Scope = []string{fmt.Sprintf("%d.%d.0.0/16", ip[0], ip[1])}
		}
	}
}

// DefaultOptions returns the defaults for a seed (shown to the user before starting).
func DefaultOptions(seed string) Options {
	o := Options{MaxDepth: 3, TryAllCredentials: true}
	o.defaults(seed)
	return o
}

// Engine runs discovery jobs.
type Engine struct {
	DB        *storage.DB
	Store     *inventory.Store
	Creds     *credentials.Store
	Collector *Collector
	Prober    fingerprint.Prober
	Hub       *Hub
	Log       *slog.Logger
	Metrics   *metrics.Registry

	queue   chan int64
	mu      sync.Mutex
	cancels map[int64]context.CancelFunc
	// DefaultSSHCredential is assigned to discovered devices without one (0 = none).
	DefaultSSHCredential int64
	// ResolveLock serializes network-wide derivation with pollers.
	ResolveLock sync.Mutex
}

// Start launches the job worker. Runs are processed one at a time; devices
// within a run are collected concurrently.
func (e *Engine) Start(ctx context.Context) {
	e.queue = make(chan int64, 100)
	e.cancels = map[int64]context.CancelFunc{}
	// Recover runs interrupted by a restart.
	if _, err := e.DB.Exec(ctx, `UPDATE discovery_runs SET status='failed', error='interrupted by restart', finished_at=now() WHERE status='running'`); err != nil {
		e.Log.Warn("recover runs", "err", err)
	}
	rows, err := e.DB.Query(ctx, `SELECT id FROM discovery_runs WHERE status='queued' ORDER BY id`)
	if err == nil {
		ids, _ := pgx.CollectRows(rows, pgx.RowTo[int64])
		for _, id := range ids {
			e.queue <- id
		}
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case id := <-e.queue:
				e.execute(ctx, id)
			}
		}
	}()
}

// Submit queues a run.
func (e *Engine) Submit(ctx context.Context, seed string, credID int64, opt Options, userID int64) (int64, error) {
	if net.ParseIP(seed) == nil {
		return 0, errors.New("invalid IP address")
	}
	opt.defaults(seed)
	var scope []string
	for _, s := range opt.Scope {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			return 0, fmt.Errorf("invalid scope %q", s)
		}
		scope = append(scope, n.String())
	}
	opt.Scope = scope
	if !inScope(seed, scope) {
		opt.Scope = append(opt.Scope, seed+"/32")
	}
	var uid any
	if userID != 0 {
		uid = userID
	}
	var id int64
	err := e.DB.QueryRow(ctx, `INSERT INTO discovery_runs(seed_ip, credential_id, max_depth, scope, options, status, created_by)
		VALUES ($1,$2,$3,$4,$5,'queued',$6) RETURNING id`, seed, nzID(credID), opt.MaxDepth, opt.Scope, opt, uid).Scan(&id)
	if err != nil {
		return 0, err
	}
	select {
	case e.queue <- id:
	default:
		return id, errors.New("discovery queue is full, try again later")
	}
	return id, nil
}

// Cancel stops a running or queued run.
func (e *Engine) Cancel(ctx context.Context, id int64) error {
	e.mu.Lock()
	cancel := e.cancels[id]
	e.mu.Unlock()
	if cancel != nil {
		cancel()
		return nil
	}
	_, err := e.DB.Exec(ctx, `UPDATE discovery_runs SET status='cancelled', finished_at=now() WHERE id=$1 AND status='queued'`, id)
	return err
}

func inScope(ip string, scope []string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, s := range scope {
		if _, n, err := net.ParseCIDR(s); err == nil && n.Contains(p) {
			return true
		}
	}
	return false
}

type target struct {
	ip     string
	depth  int
	via    string
	credID int64
	from   string
}

type runState struct {
	id       int64
	opt      Options
	mu       sync.Mutex
	steps    []Step
	lastSave time.Time
}

func (e *Engine) emit(ctx context.Context, rs *runState, s Step) {
	if s.At.IsZero() {
		s.At = time.Now()
	}
	rs.mu.Lock()
	// replace an existing running step with the same key/device
	replaced := false
	for i := len(rs.steps) - 1; i >= 0 && i >= len(rs.steps)-30; i-- {
		if rs.steps[i].Key == s.Key && rs.steps[i].Device == s.Device && rs.steps[i].Status == "running" {
			rs.steps[i] = s
			replaced = true
			break
		}
	}
	if !replaced {
		rs.steps = append(rs.steps, s)
	}
	save := time.Since(rs.lastSave) > 500*time.Millisecond || s.Status != "running"
	var snapshot []Step
	if save {
		snapshot = append(snapshot, rs.steps...)
		rs.lastSave = time.Now()
	}
	rs.mu.Unlock()
	if e.Hub != nil {
		e.Hub.Publish(Message{RunID: rs.id, Step: &s})
	}
	if save {
		if _, err := e.DB.Exec(ctx, `UPDATE discovery_runs SET steps=$2 WHERE id=$1`, rs.id, snapshot); err != nil {
			e.Log.Warn("save steps", "err", err)
		}
	}
}

func (e *Engine) execute(parent context.Context, id int64) {
	ctx, cancel := context.WithCancel(parent)
	e.mu.Lock()
	e.cancels[id] = cancel
	e.mu.Unlock()
	defer func() {
		cancel()
		e.mu.Lock()
		delete(e.cancels, id)
		e.mu.Unlock()
	}()
	var seed string
	var credID *int64
	var optRaw []byte
	var status string
	err := e.DB.QueryRow(ctx, `SELECT host(seed_ip), credential_id, options, status FROM discovery_runs WHERE id=$1`, id).Scan(&seed, &credID, &optRaw, &status)
	if err != nil || status != "queued" {
		return
	}
	rs := &runState{id: id}
	_ = json.Unmarshal(optRaw, &rs.opt)
	rs.opt.defaults(seed)
	start := time.Now()
	_, _ = e.DB.Exec(ctx, `UPDATE discovery_runs SET status='running', started_at=now() WHERE id=$1`, id)
	if e.Hub != nil {
		e.Hub.Publish(Message{RunID: id, Status: "running"})
	}
	log := e.Log.With("run", id, "seed", seed)
	log.Info("discovery started", "options", rs.opt)

	summary, runErr := e.run(ctx, rs, seed, credID, log)
	finalStatus := "completed"
	errText := ""
	switch {
	case errors.Is(ctx.Err(), context.Canceled) && parent.Err() == nil:
		finalStatus = "cancelled"
	case runErr != nil:
		finalStatus = "failed"
		errText = runErr.Error()
	}
	summary["duration_ms"] = time.Since(start).Milliseconds()
	bg := context.Background()
	rs.mu.Lock()
	steps := append([]Step(nil), rs.steps...)
	rs.mu.Unlock()
	_, _ = e.DB.Exec(bg, `UPDATE discovery_runs SET status=$2, error=$3, summary=$4, steps=$5, finished_at=now() WHERE id=$1`,
		id, finalStatus, nz(errText), summary, steps)
	kind, sev := events.DiscoveryCompleted, events.Info
	msg := fmt.Sprintf("Discovery from %s %s: %v devices, %v endpoints", seed, finalStatus, summary["devices"], summary["endpoints"])
	if finalStatus == "failed" {
		kind, sev = events.DiscoveryFailed, events.Warning
		msg = fmt.Sprintf("Discovery from %s failed: %s", seed, errText)
	}
	events.Record(bg, e.DB, 0, kind, sev, msg, map[string]any{"run_id": id})
	if e.Metrics != nil {
		e.Metrics.Observe("nexus_discovery_duration_seconds", time.Since(start).Seconds())
		e.Metrics.Inc("nexus_discovery_runs_total", finalStatus)
	}
	if e.Hub != nil {
		e.Hub.Publish(Message{RunID: id, Status: finalStatus, Summary: summary})
	}
	log.Info("discovery finished", "status", finalStatus, "summary", summary, "err", errText)
}

func nzID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func nz(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (e *Engine) run(ctx context.Context, rs *runState, seed string, credID *int64, log *slog.Logger) (map[string]any, error) {
	summary := map[string]any{"devices": 0, "endpoints": 0}
	var runCred int64
	if credID != nil {
		runCred = *credID
	}
	allCreds, err := e.snmpCredentials(ctx, runCred)
	if err != nil {
		return summary, err
	}
	if len(allCreds) == 0 {
		return summary, errors.New("no SNMP credential available")
	}
	e.emit(ctx, rs, Step{Key: "scope", Label: "Discovery scope", Status: "done",
		Detail: fmt.Sprintf("%s · up to %d hops · max %d devices", strings.Join(rs.opt.Scope, ", "), rs.opt.MaxDepth, rs.opt.MaxDevices)})

	var (
		mu        sync.Mutex
		visited   = map[string]bool{}
		devices   = map[int64]bool{}
		contacted int
		seedErr   error
		wg        sync.WaitGroup
	)
	sem := make(chan struct{}, rs.opt.Concurrency)
	var visit func(t target)
	visit = func(t target) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		if ctx.Err() != nil {
			return
		}
		creds := []int64{t.credID}
		if t.via != "seed" && t.via != "refresh" && rs.opt.TryAllCredentials {
			creds = allCreds
		}
		var snap *model.Snapshot
		var usedCred int64
		var lastErr error
		for i, cid := range creds {
			cred, err := e.Creds.SNMP(ctx, cid)
			if err != nil {
				lastErr = err
				continue
			}
			progress := func(s Step) {
				// Only the first attempt reports connection chatter.
				if i > 0 && s.Status == "failed" {
					return
				}
				e.emit(ctx, rs, s)
			}
			start := time.Now()
			var used credentials.SNMP
			snap, used, lastErr = e.Collector.CollectWithCredential(ctx, t.ip, cred, true, progress)
			if lastErr == nil && cred.Autodetect && !used.Autodetect {
				// remember the protocols that worked so polling uses them directly
				if err := e.Creds.UpdateSNMP(ctx, cid, used); err != nil {
					log.Warn("update detected SNMP settings", "err", err)
				}
			}
			if e.Metrics != nil {
				e.Metrics.Observe("nexus_collect_duration_seconds", time.Since(start).Seconds())
			}
			if lastErr == nil {
				usedCred = cid
				break
			}
			if errors.Is(lastErr, ErrUnreachable) {
				break // do not hammer unreachable hosts with every credential
			}
		}
		if lastErr != nil {
			if e.Metrics != nil {
				label := "error"
				if errors.Is(lastErr, ErrAuthFailed) {
					label = "auth"
				} else if errors.Is(lastErr, ErrUnreachable) {
					label = "timeout"
				}
				e.Metrics.Inc("nexus_snmp_errors_total", label)
			}
			if t.via == "seed" || len(rs.opt.Targets) == 1 {
				mu.Lock()
				seedErr = lastErr
				mu.Unlock()
			}
			e.emit(ctx, rs, Step{Key: "device", Label: "Could not collect " + t.ip, Status: "failed", Detail: lastErr.Error(), Device: t.ip})
			return
		}
		devID, created, err := e.Store.IngestSnapshot(ctx, snap, inventory.IngestOptions{MgmtIP: t.ip, CredentialID: usedCred, Via: t.via, Full: true})
		if err != nil {
			log.Error("ingest", "ip", t.ip, "err", err)
			e.emit(ctx, rs, Step{Key: "device", Label: "Saving " + t.ip, Status: "failed", Detail: err.Error(), Device: t.ip})
			return
		}
		if sshID := firstID(rs.opt.SSHCredentialID, e.DefaultSSHCredential); sshID != 0 {
			_, _ = e.DB.Exec(ctx, `UPDATE devices SET ssh_credential_id=$2 WHERE id=$1 AND ssh_credential_id IS NULL`, devID, sshID)
		}
		label := "Device identity updated"
		if created {
			label = "Device identity created"
		}
		e.emit(ctx, rs, Step{Key: "identity", Label: label, Status: "done", Detail: firstNonEmpty(snap.System.Name, t.ip), Device: t.ip})
		mu.Lock()
		devices[devID] = true
		mu.Unlock()

		if t.depth >= rs.opt.MaxDepth {
			return
		}
		for _, n := range snap.Neighbors {
			if n.MgmtIP == "" || !looksLikeNetworkDevice(n) {
				continue
			}
			mu.Lock()
			seen := visited[n.MgmtIP]
			if !seen {
				visited[n.MgmtIP] = true
			}
			over := contacted >= rs.opt.MaxDevices
			if !seen && !over && inScope(n.MgmtIP, rs.opt.Scope) {
				contacted++
			}
			mu.Unlock()
			if seen {
				continue
			}
			name := firstNonEmpty(n.SysName, n.MgmtIP)
			switch {
			case !inScope(n.MgmtIP, rs.opt.Scope):
				e.emit(ctx, rs, Step{Key: "neighbor", Label: "Skipped " + name, Status: "skipped", Detail: n.MgmtIP + " is outside the discovery scope", Device: t.ip})
			case over:
				e.emit(ctx, rs, Step{Key: "neighbor", Label: "Skipped " + name, Status: "skipped", Detail: "device limit reached", Device: t.ip})
			default:
				e.emit(ctx, rs, Step{Key: "neighbor", Label: "Following neighbor " + name, Status: "done", Detail: fmt.Sprintf("%s via %s (hop %d)", n.MgmtIP, strings.ToUpper(n.Protocol), t.depth+1), Device: t.ip})
				wg.Add(1)
				go visit(target{ip: n.MgmtIP, depth: t.depth + 1, via: n.Protocol, credID: usedCred, from: t.ip})
			}
		}
	}
	if len(rs.opt.Targets) > 0 {
		for _, ip := range rs.opt.Targets {
			if visited[ip] {
				continue
			}
			visited[ip] = true
			contacted++
			wg.Add(1)
			go visit(target{ip: ip, depth: rs.opt.MaxDepth, via: "refresh", credID: e.credentialFor(ctx, ip, allCreds[0])})
		}
	} else {
		visited[seed] = true
		contacted = 1
		wg.Add(1)
		go visit(target{ip: seed, depth: 0, via: "seed", credID: allCreds[0]})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return summary, ctx.Err()
	}
	summary["devices"] = len(devices)
	if len(devices) == 0 {
		if seedErr != nil {
			return summary, seedErr
		}
		return summary, errors.New("no device could be collected")
	}

	// Network-wide derivation.
	e.ResolveLock.Lock()
	defer e.ResolveLock.Unlock()
	e.emit(ctx, rs, Step{Key: "resolve", Label: "Resolving device identities", Status: "running"})
	st, err := e.Store.ResolveNetwork(ctx)
	if err != nil {
		e.emit(ctx, rs, Step{Key: "resolve", Label: "Resolving device identities", Status: "failed", Detail: err.Error()})
		return summary, err
	}
	e.emit(ctx, rs, Step{Key: "resolve", Label: "Device identities resolved", Status: "done",
		Detail: fmt.Sprintf("%d endpoints (%d new), %d port attachments, %d duplicates merged", st.Endpoints, st.NewEndpoints, st.Attachments, st.Merges)})
	summary["endpoints"] = st.Endpoints
	summary["new_endpoints"] = st.NewEndpoints
	summary["attachments"] = st.Attachments
	summary["merges"] = st.Merges
	summary["moves"] = st.Moves

	if e.Prober != nil {
		label := "Identifying endpoints (DNS)"
		if rs.opt.ActiveFingerprint {
			label = "Fingerprinting endpoints"
		}
		e.emit(ctx, rs, Step{Key: "fingerprint", Label: label, Status: "running"})
		n, err := e.fingerprint(ctx, rs.opt)
		if err != nil {
			e.emit(ctx, rs, Step{Key: "fingerprint", Label: label, Status: "warning", Detail: err.Error()})
		} else {
			e.emit(ctx, rs, Step{Key: "fingerprint", Label: label, Status: "done", Detail: fmt.Sprintf("%d endpoints examined", n)})
		}
	}
	e.emit(ctx, rs, Step{Key: "classify", Label: "Classifying devices", Status: "running"})
	if _, err := e.Store.ClassifyAll(ctx); err != nil {
		e.emit(ctx, rs, Step{Key: "classify", Label: "Classifying devices", Status: "failed", Detail: err.Error()})
		return summary, err
	}
	counts := e.typeCounts(ctx)
	e.emit(ctx, rs, Step{Key: "classify", Label: "Devices classified", Status: "done", Detail: counts})
	edges, err := e.Store.RebuildTopology(ctx)
	if err != nil {
		e.emit(ctx, rs, Step{Key: "topology", Label: "Updating topology", Status: "failed", Detail: err.Error()})
		return summary, err
	}
	summary["edges"] = edges
	e.emit(ctx, rs, Step{Key: "topology", Label: "Topology updated", Status: "done", Detail: fmt.Sprintf("%d links", edges)})
	e.emit(ctx, rs, Step{Key: "polling", Label: "Monitoring enabled", Status: "done", Detail: fmt.Sprintf("%d devices will be polled periodically", len(devices))})
	return summary, nil
}

func (e *Engine) typeCounts(ctx context.Context) string {
	rows, err := e.DB.Query(ctx, `SELECT device_type, count(*) FROM devices GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		return ""
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var t string
		var n int
		if rows.Scan(&t, &n) == nil {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ReplaceAll(t, "_", " ")))
		}
	}
	return strings.Join(parts, ", ")
}

func (e *Engine) snmpCredentials(ctx context.Context, first int64) ([]int64, error) {
	rows, err := e.DB.Query(ctx, `SELECT id FROM credentials WHERE kind='snmp' ORDER BY id=$1 DESC, id DESC`, first)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// looksLikeNetworkDevice decides whether a neighbor is worth an SNMP attempt:
// switches/routers/firewalls/APs yes; phones and hosts no.
func looksLikeNetworkDevice(n model.Neighbor) bool {
	caps := map[string]bool{}
	for _, c := range n.Capabilities {
		caps[c] = true
	}
	if caps["phone"] || caps["station"] {
		return false
	}
	if caps["bridge"] || caps["router"] || caps["wlan-ap"] {
		return true
	}
	return n.Protocol == "cdp" || len(n.Capabilities) == 0
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// fingerprint probes unmanaged devices with an IP inside the scope.
func (e *Engine) fingerprint(ctx context.Context, opt Options) (int, error) {
	rows, err := e.DB.Query(ctx, `SELECT d.id, (SELECT host(ip) FROM device_addresses a WHERE a.device_id=d.id ORDER BY last_seen DESC LIMIT 1)
		FROM devices d WHERE NOT d.managed`)
	if err != nil {
		return 0, err
	}
	type cand struct {
		id int64
		ip *string
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (cand, error) {
		var c cand
		err := r.Scan(&c.id, &c.ip)
		return c, err
	})
	if err != nil {
		return 0, err
	}
	var ids []int64
	var ips []string
	for _, c := range all {
		if c.ip != nil && inScope(*c.ip, opt.Scope) {
			ids = append(ids, c.id)
			ips = append(ips, *c.ip)
		}
	}
	obs := fingerprint.ProbeAll(ctx, e.Prober, ips, fingerprint.Options{Active: opt.ActiveFingerprint, Timeout: 2 * time.Second},
		8, time.Duration(opt.ProbeSpacingMS)*time.Millisecond)
	b := &pgx.Batch{}
	for i, o := range obs {
		if o.IP == "" {
			continue
		}
		sort.Ints(o.OpenPorts)
		b.Queue(`UPDATE devices SET fingerprint=$2, fingerprinted_at=now() WHERE id=$1`, ids[i], o)
		if o.Hostname != "" {
			b.Queue(`INSERT INTO device_hostnames(device_id,name,source) VALUES ($1,$2,$3) ON CONFLICT (device_id,name,source) DO UPDATE SET last_seen=now()`,
				ids[i], fingerprint.ShortName(o.Hostname), firstNonEmpty(o.HostnameSource, "dns"))
		}
		if o.NetBIOSName != "" {
			b.Queue(`INSERT INTO device_hostnames(device_id,name,source) VALUES ($1,$2,'netbios') ON CONFLICT (device_id,name,source) DO UPDATE SET last_seen=now()`,
				ids[i], strings.ToLower(o.NetBIOSName))
		}
	}
	if err := e.DB.SendBatch(ctx, b).Close(); err != nil {
		return 0, err
	}
	return len(ips), nil
}

// credentialFor returns the credential a device was last collected with.
func (e *Engine) credentialFor(ctx context.Context, ip string, def int64) int64 {
	var id *int64
	_ = e.DB.QueryRow(ctx, `SELECT snmp_credential_id FROM devices WHERE host(mgmt_ip)=$1 AND managed LIMIT 1`, ip).Scan(&id)
	if id != nil {
		return *id
	}
	return def
}

// SubmitRefresh queues a re-collection of every managed device (no recursion).
func (e *Engine) SubmitRefresh(ctx context.Context, userID int64) (int64, error) {
	rows, err := e.DB.Query(ctx, `SELECT host(mgmt_ip) FROM devices WHERE managed AND mgmt_ip IS NOT NULL ORDER BY id`)
	if err != nil {
		return 0, err
	}
	ips, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	if len(ips) == 0 {
		return 0, errors.New("no managed devices to refresh")
	}
	var busy bool
	_ = e.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_runs WHERE status IN ('queued','running'))`).Scan(&busy)
	if busy {
		return 0, errors.New("a discovery is already in progress")
	}
	var scope []string
	for _, ip := range ips {
		scope = append(scope, ip+"/32")
	}
	return e.Submit(ctx, ips[0], 0, Options{Targets: ips, Scope: scope, MaxDepth: 0, MaxDevices: len(ips) + 1}, userID)
}

func firstID(ids ...int64) int64 {
	for _, id := range ids {
		if id != 0 {
			return id
		}
	}
	return 0
}
