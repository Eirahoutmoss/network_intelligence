package lab

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
)

// Running is a started lab: management IP → UDP address of its agent.
type Running struct {
	Lab   *Lab
	Addrs map[string]string
}

// Start launches one SNMP agent per managed device on host (e.g. "127.0.0.1"),
// using ephemeral ports. Agents stop when ctx is cancelled.
func (l *Lab) Start(ctx context.Context, host string, log *slog.Logger) (*Running, error) {
	r := &Running{Lab: l, Addrs: map[string]string{}}
	for ip, mibs := range l.Build() {
		a := &snmp.Agent{MIB: mibs.Main, Contexts: mibs.Contexts, Community: l.Community, Log: log,
			V3Users: map[string]snmp.V3User{l.V3User: {AuthProtocol: "SHA", AuthPassword: l.V3Pass}}}
		if err := a.Listen(fmt.Sprintf("%s:0", host)); err != nil {
			return nil, fmt.Errorf("lab agent for %s: %w", ip, err)
		}
		r.Addrs[ip] = a.Addr().String()
		go a.Serve(ctx)
	}
	return r, nil
}
