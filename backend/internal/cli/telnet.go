package cli

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Telnet protocol bytes.
const (
	iac     = 255
	dont    = 254
	do      = 253
	wont    = 252
	will    = 251
	sb      = 250
	se      = 240
	optEcho = 1
	optSGA  = 3
)

type telnetRemote struct {
	conn    net.Conn
	mu      sync.Mutex
	pending []byte
	login   *autoLogin
}

// autoLogin answers the first username/password prompts with the stored credential.
type autoLogin struct {
	user, pass string
	stage      int
	window     []byte
}

func (s *Service) dialTelnet(ctx context.Context, t Target) (remote, error) {
	conn, err := s.dial(ctx, net.JoinHostPort(t.Host, strconv.Itoa(t.Login.Port)))
	if err != nil {
		return nil, err
	}
	r := &telnetRemote{conn: conn}
	if t.Login.Username != "" {
		r.login = &autoLogin{user: t.Login.Username, pass: t.Login.Password}
	}
	return r, nil
}

func (r *telnetRemote) Write(p []byte) (int, error) {
	// escape IAC in user data
	return r.conn.Write(bytes.ReplaceAll(p, []byte{iac}, []byte{iac, iac}))
}

func (r *telnetRemote) Resize(int, int) error { return nil }
func (r *telnetRemote) Close() error          { return r.conn.Close() }

// Read strips and answers option negotiation, returning only display data.
func (r *telnetRemote) Read(p []byte) (int, error) {
	for {
		buf := make([]byte, len(p))
		n, err := r.conn.Read(buf)
		if n > 0 {
			out, replies := parseTelnet(append(r.pending, buf[:n]...), &r.pending)
			if len(replies) > 0 {
				_, _ = r.conn.Write(replies)
			}
			if r.login != nil && len(out) > 0 {
				r.login.observe(out, r.conn)
				if r.login.stage >= 2 {
					r.login = nil
				}
			}
			if len(out) > 0 {
				return copy(p, out), nil
			}
		}
		if err != nil {
			return 0, err
		}
	}
}

func (a *autoLogin) observe(out []byte, conn net.Conn) {
	a.window = append(a.window, out...)
	if len(a.window) > 256 {
		a.window = a.window[len(a.window)-256:]
	}
	l := strings.ToLower(string(a.window))
	switch {
	case a.stage == 0 && (strings.HasSuffix(strings.TrimSpace(l), "username:") || strings.HasSuffix(strings.TrimSpace(l), "login:")):
		time.Sleep(50 * time.Millisecond)
		_, _ = conn.Write([]byte(a.user + "\r\n"))
		a.stage, a.window = 1, nil
	case a.stage <= 1 && strings.HasSuffix(strings.TrimSpace(l), "password:"):
		time.Sleep(50 * time.Millisecond)
		_, _ = conn.Write([]byte(a.pass + "\r\n"))
		a.stage, a.window = 2, nil
	}
}

// parseTelnet separates data from IAC commands. Incomplete trailing commands
// are kept in *pending. We agree to the server echoing and suppressing
// go-ahead, and refuse everything else.
func parseTelnet(in []byte, pending *[]byte) (data, replies []byte) {
	*pending = nil
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c != iac {
			data = append(data, c)
			continue
		}
		if i+1 >= len(in) {
			*pending = append([]byte(nil), in[i:]...)
			return
		}
		cmd := in[i+1]
		switch cmd {
		case iac:
			data = append(data, iac)
			i++
		case do, dont, will, wont:
			if i+2 >= len(in) {
				*pending = append([]byte(nil), in[i:]...)
				return
			}
			opt := in[i+2]
			switch cmd {
			case will:
				if opt == optEcho || opt == optSGA {
					replies = append(replies, iac, do, opt)
				} else {
					replies = append(replies, iac, dont, opt)
				}
			case do:
				if opt == optSGA {
					replies = append(replies, iac, will, opt)
				} else {
					replies = append(replies, iac, wont, opt)
				}
			}
			i += 2
		case sb:
			end := bytes.Index(in[i:], []byte{iac, se})
			if end < 0 {
				*pending = append([]byte(nil), in[i:]...)
				return
			}
			i += end + 1
		default:
			i++
		}
	}
	return
}
