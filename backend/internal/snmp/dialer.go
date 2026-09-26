package snmp

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
)

// Dialer opens SNMP clients. Discovery depends on this interface so that
// simulated networks can be addressed by their "real" IPs.
type Dialer interface {
	Dial(ctx context.Context, host string, cred credentials.SNMP) (Client, error)
}

// NetDialer dials real UDP targets. When Map is set, listed hosts are
// redirected (simulator) and, if Strict, unlisted hosts fail immediately.
type NetDialer struct {
	Opt    Options
	Map    map[string]string
	Strict bool
}

func (d NetDialer) Dial(ctx context.Context, host string, cred credentials.SNMP) (Client, error) {
	if d.Map != nil {
		if addr, ok := d.Map[host]; ok {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			cred.Port, _ = strconv.Atoi(p)
			return Dial(ctx, h, cred, d.Opt)
		}
		if d.Strict {
			return nil, fmt.Errorf("%w: %s is not part of the simulated network", ErrTimeout, host)
		}
	}
	return Dial(ctx, host, cred, d.Opt)
}
