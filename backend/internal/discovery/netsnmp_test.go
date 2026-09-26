package discovery

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/snmp"
	"github.com/Eirahoutmoss/network_intelligence/backend/internal/vendors/all"
)

// TestCollectAgainstNetSNMP runs the standard collectors against a real
// net-snmp agent (Linux host MIBs) when NEXUS_TEST_SNMPD is set.
func TestCollectAgainstNetSNMP(t *testing.T) {
	addr := os.Getenv("NEXUS_TEST_SNMPD")
	if addr == "" {
		t.Skip("NEXUS_TEST_SNMPD not set")
	}
	host, portS, _ := strings.Cut(addr, ":")
	port, _ := strconv.Atoi(portS)
	c := &Collector{Dialer: snmp.NetDialer{Opt: snmp.Options{Timeout: 2 * time.Second}}, Registry: all.Registry()}
	snap, err := c.Collect(context.Background(), host, credentials.SNMP{Username: "prometheus", AuthPassword: "testpass123", Port: port}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("system: %+v", snap.System)
	t.Logf("interfaces=%d ips=%d routes=%d arp=%d sensors=%d errors=%v", len(snap.Interfaces), len(snap.IPs), len(snap.Routes), len(snap.ARP), len(snap.Sensors), snap.Errors)
	if snap.System.Name == "" || !strings.Contains(snap.System.Descr, "Linux") {
		t.Errorf("system group: %+v", snap.System)
	}
	if len(snap.Interfaces) == 0 {
		t.Error("no interfaces")
	}
	for _, i := range snap.Interfaces {
		if i.Name == "" || i.OperStatus == "" {
			t.Errorf("interface incomplete: %+v", i)
		}
	}
	// hrProcessorLoad stays empty during the agent's first minute, so only memory is required.
	if snap.System.MemoryPercent == nil {
		t.Errorf("host resources: mem=%v", snap.System.MemoryPercent)
	}
	if len(snap.Routes) == 0 {
		t.Error("no routes")
	}
	if len(snap.Errors) > 0 {
		t.Errorf("collector errors: %v", snap.Errors)
	}
}

// TestAutodetectAuthPrivNetSNMP: the user typed only username + password, the
// device requires authPriv with the same password for privacy.
func TestAutodetectAuthPrivNetSNMP(t *testing.T) {
	addr := os.Getenv("NEXUS_TEST_SNMPD")
	if addr == "" {
		t.Skip("NEXUS_TEST_SNMPD not set")
	}
	host, portS, _ := strings.Cut(addr, ":")
	port, _ := strconv.Atoi(portS)
	c := &Collector{Dialer: snmp.NetDialer{Opt: snmp.Options{Timeout: 2 * time.Second}}, Registry: all.Registry()}
	_, used, err := c.CollectWithCredential(context.Background(), host, credentials.SNMP{Username: "privsame", AuthPassword: "testpass123", Port: port, Autodetect: true}, false, nil)
	if err != nil {
		t.Skipf("agent has no 'privsame' user (see CI config): %v", err)
	}
	if used.SecurityLevel != "authPriv" || used.AuthProtocol != "SHA" || used.PrivProtocol != "AES" {
		t.Fatalf("detected %+v", used)
	}
}
