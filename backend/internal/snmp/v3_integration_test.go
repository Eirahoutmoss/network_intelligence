package snmp

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
)

// TestSNMPv3AgainstNetSNMP runs against a real net-snmp agent when
// NEXUS_TEST_SNMPD=host:port is set. The agent must have users:
//
//	createUser prometheus SHA "testpass123"             (authNoPriv)
//	createUser privuser  SHA "testpass123" AES "privpass123" (authPriv)
func TestSNMPv3AgainstNetSNMP(t *testing.T) {
	addr := os.Getenv("NEXUS_TEST_SNMPD")
	if addr == "" {
		t.Skip("NEXUS_TEST_SNMPD not set")
	}
	host, portS, _ := strings.Cut(addr, ":")
	port, _ := strconv.Atoi(portS)
	ctx := context.Background()
	opt := Options{Timeout: 2 * time.Second}

	get := func(c credentials.SNMP) (string, error) {
		cl, err := Dial(ctx, host, c, opt)
		if err != nil {
			return "", err
		}
		defer cl.Close()
		p, ok, err := GetOne(ctx, cl, "1.3.6.1.2.1.1.5.0")
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("sysName missing")
		}
		return p.String(), nil
	}

	// The default "simple" path: username + password → v3 authNoPriv SHA.
	name, err := get(credentials.SNMP{Username: "prometheus", AuthPassword: "testpass123", Port: port})
	if err != nil || name == "" {
		t.Fatalf("authNoPriv SHA: %q %v", name, err)
	}
	if _, err := get(credentials.SNMP{Username: "privuser", AuthPassword: "testpass123", PrivPassword: "privpass123", Port: port}); err != nil {
		t.Fatalf("authPriv AES: %v", err)
	}
	_, err = get(credentials.SNMP{Username: "prometheus", AuthPassword: "wrongpass99", Port: port})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password should be ErrAuth, got %v", err)
	}
	_, err = get(credentials.SNMP{Username: "nobody", AuthPassword: "wrongpass99", Port: port})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("unknown user should be ErrAuth, got %v", err)
	}
	// Walk the interface table over v3.
	cl, _ := Dial(ctx, host, credentials.SNMP{Username: "prometheus", AuthPassword: "testpass123", Port: port}, opt)
	defer cl.Close()
	ifs, err := cl.Walk(ctx, "1.3.6.1.2.1.2.2.1.2")
	if err != nil || len(ifs) == 0 {
		t.Fatalf("v3 walk: %d %v", len(ifs), err)
	}
}
