// Package cli bridges a browser terminal (WebSocket) to a device's SSH or
// Telnet console. The browser never talks to the device and never receives
// credentials: the backend decrypts them, connects, and relays bytes.
// Every session is recorded in cli_sessions (metadata + capped transcript).
package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/auth"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// Service opens CLI sessions.
type Service struct {
	DB          *storage.DB
	Creds       *credentials.Store
	Log         *slog.Logger
	IdleTimeout time.Duration
	MaxDuration time.Duration
	// TelnetAllowed is the global switch; devices must also opt in.
	TelnetAllowed func(ctx context.Context) bool
	// Dial allows tests / simulator to redirect connections.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	active sync.Map // session id → cancel
}

const maxTranscript = 1 << 20

// Target describes where to connect.
type Target struct {
	DeviceID int64
	Host     string
	Protocol string // ssh|telnet
	Login    credentials.Login
	HostKey  string // stored SHA256 fingerprint (TOFU)
}

// Resolve loads the connection target for a device.
func (s *Service) Resolve(ctx context.Context, deviceID int64, protocol string) (Target, error) {
	t := Target{DeviceID: deviceID, Protocol: protocol}
	var ip *string
	var sshCred, telnetCred *int64
	var telnetEnabled bool
	var hostKey *string
	err := s.DB.QueryRow(ctx, `SELECT COALESCE(host(mgmt_ip), (SELECT host(ip) FROM device_addresses WHERE device_id=d.id ORDER BY source='snmp' DESC LIMIT 1)),
		ssh_credential_id, telnet_credential_id, telnet_enabled, ssh_host_key FROM devices d WHERE id=$1`, deviceID).
		Scan(&ip, &sshCred, &telnetCred, &telnetEnabled, &hostKey)
	if err != nil {
		return t, errors.New("device not found")
	}
	if ip == nil {
		return t, errors.New("device has no known IP address")
	}
	t.Host = *ip
	switch protocol {
	case "ssh":
		if sshCred == nil {
			return t, errors.New("no SSH credential is assigned to this device")
		}
		t.Login, err = s.Creds.Login(ctx, *sshCred, credentials.KindSSH)
		if hostKey != nil {
			t.HostKey = *hostKey
		}
	case "telnet":
		if s.TelnetAllowed == nil || !s.TelnetAllowed(ctx) {
			return t, errors.New("Telnet is disabled in Settings (it sends passwords in clear text)")
		}
		if !telnetEnabled {
			return t, errors.New("Telnet is not enabled for this device")
		}
		if telnetCred != nil {
			t.Login, err = s.Creds.Login(ctx, *telnetCred, credentials.KindTelnet)
		}
		if t.Login.Port == 0 {
			t.Login.Port = 23
		}
	default:
		return t, fmt.Errorf("unsupported protocol %q", protocol)
	}
	return t, err
}

// control messages from the browser
type clientMsg struct {
	Type string `json:"type"` // input|resize|ping
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

type serverMsg struct {
	Type    string `json:"type"` // output|status|error|closed
	Data    string `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

// remote is an established console.
type remote interface {
	io.ReadWriter
	Resize(cols, rows int) error
	Close() error
}

// Serve runs a session on an upgraded WebSocket until either side closes.
func (s *Service) Serve(ctx context.Context, ws *websocket.Conn, user *auth.User, t Target, clientAddr string, cols, rows int) {
	defer ws.Close()
	var wmu sync.Mutex
	send := func(m serverMsg) error {
		wmu.Lock()
		defer wmu.Unlock()
		_ = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return ws.WriteJSON(m)
	}
	var sessID int64
	err := s.DB.QueryRow(ctx, `INSERT INTO cli_sessions(user_id, username, device_id, protocol, remote_addr, client_addr) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		user.ID, user.Username, t.DeviceID, t.Protocol, net.JoinHostPort(t.Host, strconv.Itoa(t.Login.Port)), clientAddr).Scan(&sessID)
	if err != nil {
		_ = send(serverMsg{Type: "error", Message: "could not start session"})
		return
	}
	log := s.Log.With("cli_session", sessID, "device", t.DeviceID, "user", user.Username, "protocol", t.Protocol)
	log.Info("cli session starting")
	_ = send(serverMsg{Type: "status", Message: fmt.Sprintf("Connecting to %s via %s…", t.Host, t.Protocol)})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.active.Store(sessID, cancel)
	defer s.active.Delete(sessID)

	var transcript safeBuffer
	var bytesIn, bytesOut atomic.Int64
	reason := "closed"
	defer func() {
		_, _ = s.DB.Exec(context.Background(), `UPDATE cli_sessions SET ended_at=now(), end_reason=$2, bytes_in=$3, bytes_out=$4, transcript=$5 WHERE id=$1`,
			sessID, reason, bytesIn.Load(), bytesOut.Load(), transcript.Bytes())
		log.Info("cli session ended", "reason", reason, "bytes_in", bytesIn.Load(), "bytes_out", bytesOut.Load())
	}()

	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 32
	}
	var r remote
	switch t.Protocol {
	case "ssh":
		r, err = s.dialSSH(ctx, t, cols, rows)
	case "telnet":
		r, err = s.dialTelnet(ctx, t)
	}
	if err != nil {
		reason = "connect failed: " + err.Error()
		_ = send(serverMsg{Type: "error", Message: err.Error()})
		return
	}
	defer r.Close()
	_ = send(serverMsg{Type: "status", Message: "connected"})

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	done := make(chan string, 3)

	// device → browser
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				bytesOut.Add(int64(n))
				transcript.Write(buf[:n])
				if send(serverMsg{Type: "output", Data: base64.StdEncoding.EncodeToString(buf[:n])}) != nil {
					done <- "browser write failed"
					return
				}
			}
			if err != nil {
				done <- "device closed the connection"
				return
			}
		}
	}()
	// browser → device
	go func() {
		ws.SetReadLimit(64 * 1024)
		for {
			var m clientMsg
			if err := ws.ReadJSON(&m); err != nil {
				done <- "browser disconnected"
				return
			}
			lastActivity.Store(time.Now().UnixNano())
			switch m.Type {
			case "input":
				bytesIn.Add(int64(len(m.Data)))
				if _, err := r.Write([]byte(m.Data)); err != nil {
					done <- "device write failed"
					return
				}
			case "resize":
				if m.Cols > 0 && m.Rows > 0 && m.Cols < 1000 && m.Rows < 500 {
					_ = r.Resize(m.Cols, m.Rows)
				}
			}
		}
	}()
	// timeouts
	idle := s.IdleTimeout
	if idle <= 0 {
		idle = 15 * time.Minute
	}
	maxDur := s.MaxDuration
	if maxDur <= 0 {
		maxDur = 4 * time.Hour
	}
	deadline := time.NewTimer(maxDur)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case reason = <-done:
			_ = send(serverMsg{Type: "closed", Message: reason})
			return
		case <-ctx.Done():
			reason = "terminated"
			_ = send(serverMsg{Type: "closed", Message: "session terminated"})
			return
		case <-deadline.C:
			reason = "maximum session duration reached"
			_ = send(serverMsg{Type: "closed", Message: reason})
			return
		case <-tick.C:
			if time.Since(time.Unix(0, lastActivity.Load())) > idle {
				reason = "idle timeout"
				_ = send(serverMsg{Type: "closed", Message: "closed after " + idle.String() + " of inactivity"})
				return
			}
		}
	}
}

// Terminate stops an active session (admin action).
func (s *Service) Terminate(id int64) bool {
	if c, ok := s.active.Load(id); ok {
		c.(context.CancelFunc)()
		return true
	}
	return false
}

type safeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *safeBuffer) Write(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := maxTranscript - len(b.buf); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		b.buf = append(b.buf, p...)
	}
}

func (b *safeBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf...)
}

func (s *Service) dial(ctx context.Context, addr string) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, "tcp", addr)
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

// ---- SSH

type sshRemote struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
}

func (r *sshRemote) Read(p []byte) (int, error)  { return r.stdout.Read(p) }
func (r *sshRemote) Write(p []byte) (int, error) { return r.stdin.Write(p) }
func (r *sshRemote) Resize(c, h int) error       { return r.session.WindowChange(h, c) }
func (r *sshRemote) Close() error {
	r.session.Close()
	return r.client.Close()
}

// Fingerprint returns the OpenSSH-style SHA256 fingerprint of a host key.
func Fingerprint(k ssh.PublicKey) string {
	h := sha256.Sum256(k.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

// ErrHostKeyMismatch signals a possible man-in-the-middle.
var ErrHostKeyMismatch = errors.New("SSH host key changed since the first connection — possible man-in-the-middle. An admin must reset the stored key on the device page")

func (s *Service) dialSSH(ctx context.Context, t Target, cols, rows int) (remote, error) {
	var methods []ssh.AuthMethod
	if t.Login.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(t.Login.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if t.Login.Password != "" {
		pw := t.Login.Password
		methods = append(methods, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			ans := make([]string, len(qs))
			for i := range qs {
				ans[i] = pw
			}
			return ans, nil
		}))
	}
	var seenKey string
	cfg := &ssh.ClientConfig{
		User:    t.Login.Username,
		Auth:    methods,
		Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := Fingerprint(key)
			if t.HostKey != "" && t.HostKey != fp {
				return ErrHostKeyMismatch
			}
			seenKey = fp
			return nil
		},
	}
	// Network gear often only speaks older algorithms; allow them (still encrypted).
	supported := ssh.SupportedAlgorithms()
	insecure := ssh.InsecureAlgorithms()
	cfg.KeyExchanges = append(supported.KeyExchanges, insecure.KeyExchanges...)
	cfg.Ciphers = append(supported.Ciphers, insecure.Ciphers...)
	cfg.MACs = append(supported.MACs, insecure.MACs...)
	cfg.HostKeyAlgorithms = append(supported.HostKeys, insecure.HostKeys...)

	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Login.Port))
	conn, err := s.dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		if errors.Is(err, ErrHostKeyMismatch) {
			return nil, ErrHostKeyMismatch
		}
		return nil, fmt.Errorf("SSH login failed: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	if t.HostKey == "" && seenKey != "" {
		_, _ = s.DB.Exec(ctx, `UPDATE devices SET ssh_host_key=$2 WHERE id=$1 AND ssh_host_key IS NULL`, t.DeviceID, seenKey)
	}
	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, err
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := sess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, err
	}
	sess.Stderr = io.Discard
	if err := sess.Shell(); err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	return &sshRemote{client: client, session: sess, stdin: stdin, stdout: stdout}, nil
}

// MarshalControl is exported for tests.
func MarshalControl(t string, data string) []byte {
	b, _ := json.Marshal(clientMsg{Type: t, Data: data})
	return b
}
