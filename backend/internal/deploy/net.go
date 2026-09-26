package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PortFree reports whether port can be bound on host ("" = all interfaces).
func PortFree(host string, port int) bool {
	l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	l.Close()
	if host == "127.0.0.1" {
		// A program bound to 0.0.0.0 on the same port would still shadow us on
		// some systems; check the wildcard too.
		if l2, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(port))); err == nil {
			l2.Close()
		} else {
			return false
		}
	}
	return true
}

// ChoosePort returns preferred when free, otherwise the first free
// alternative. current is the port an existing installation already uses; it
// is considered free because our own service may be holding it.
func ChoosePort(host string, preferred, current int) (int, bool) {
	try := append([]int{preferred}, Alternatives...)
	for _, p := range try {
		if p <= 0 || p > 65535 {
			continue
		}
		if p == current || PortFree(host, p) {
			return p, p == preferred
		}
	}
	// Let the OS pick.
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, false
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, false
}

// Health is the /api/health response.
type Health struct {
	Status   string `json:"status"`
	Database bool   `json:"database"`
	Version  string `json:"version"`
}

// WaitHealthy polls the health endpoint and the web interface until both
// answer or the timeout expires. progress is called with a short status.
func WaitHealthy(ctx context.Context, port int, timeout time.Duration, progress func(string)) (*Health, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 5 * time.Second}
	var last error
	lastNote := time.Time{}
	for {
		h, err := checkOnce(ctx, client, base)
		if err == nil {
			return h, nil
		}
		last = err
		if progress != nil && time.Since(lastNote) > 15*time.Second {
			progress(err.Error())
			lastNote = time.Now()
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("not healthy after %s: %w", timeout, last)
		case <-time.After(time.Second):
		}
	}
}

func checkOnce(ctx context.Context, c *http.Client, base string) (*Health, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/health", nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("web service not answering yet")
	}
	var h Health
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&h)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("unexpected health response")
	}
	if resp.StatusCode != http.StatusOK || !h.Database {
		return &h, fmt.Errorf("database not ready (%s)", h.Status)
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	resp, err = c.Do(req)
	if err != nil {
		return &h, fmt.Errorf("web interface not answering")
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(strings.ToLower(string(b)), "<html") {
		return &h, fmt.Errorf("web interface returned %d", resp.StatusCode)
	}
	return &h, nil
}
