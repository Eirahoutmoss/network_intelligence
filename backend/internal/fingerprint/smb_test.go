package fingerprint

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseNBStat(t *testing.T) {
	b := make([]byte, 57)
	b[56] = 2
	e1 := append([]byte("LAB-PC-07      "), 0x00, 0x04, 0x00)
	e2 := append([]byte("LAB            "), 0x00, 0x84, 0x00)
	b = append(append(b, e1...), e2...)
	n, g := parseNBStat(b)
	if n != "LAB-PC-07" || g != "LAB" {
		t.Fatalf("%q %q", n, g)
	}
}

func TestSPNEGOEncoding(t *testing.T) {
	tok := spnegoInit(ntlmNegotiate())
	if tok[0] != 0x60 || !strings.Contains(string(tok), "NTLMSSP") {
		t.Fatalf("bad token % x", tok)
	}
}

// TestSMBAgainstSamba runs when NEXUS_TEST_SMB=host:port points to a Samba
// server (SMB1 enabled) — the only available real SMB implementation in CI.
func TestSMBAgainstSamba(t *testing.T) {
	addr := os.Getenv("NEXUS_TEST_SMB")
	if addr == "" {
		t.Skip("NEXUS_TEST_SMB not set")
	}
	info := SMBProbe(context.Background(), addr, 3*time.Second)
	t.Logf("%+v", info)
	if info.Dialect == "" {
		t.Fatal("no dialect negotiated")
	}
	if !strings.Contains(strings.ToLower(info.LanMan), "samba") && info.NetBIOSName == "" {
		t.Fatalf("expected Samba identification or NetBIOS name: %+v", info)
	}
}
