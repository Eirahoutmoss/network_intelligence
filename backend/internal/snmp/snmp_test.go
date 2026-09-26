package snmp

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/credentials"
)

const rec = `1.3.6.1.2.1.1.1.0|4|Huawei Versatile Routing Platform Software
1.3.6.1.2.1.1.2.0|6|1.3.6.1.4.1.2011.2.23.419
1.3.6.1.2.1.1.3.0|67|123456
1.3.6.1.2.1.1.5.0|4|SW-CORE-01
1.3.6.1.2.1.2.2.1.2.1|4|GigabitEthernet0/0/1
1.3.6.1.2.1.2.2.1.2.2|4|GigabitEthernet0/0/2
1.3.6.1.2.1.2.2.1.2.10|4|Vlanif10
1.3.6.1.2.1.2.2.1.6.1|4x|00e0fc123456
1.3.6.1.2.1.31.1.1.1.6.1|70|18446744073709551000
1.3.6.1.2.1.4.20.1.1.10.0.0.1|64|10.0.0.1
`

func TestSnmprecAndWalk(t *testing.T) {
	m, err := ParseSnmprec(strings.NewReader(rec))
	if err != nil {
		t.Fatal(err)
	}
	c := MIBClient{M: m}
	ctx := context.Background()
	pdus, err := c.Walk(ctx, "1.3.6.1.2.1.2.2.1.2")
	if err != nil {
		t.Fatal(err)
	}
	if len(pdus) != 3 || pdus[2].OID != "1.3.6.1.2.1.2.2.1.2.10" {
		t.Fatalf("walk order wrong: %+v", pdus)
	}
	p, ok, _ := GetOne(ctx, c, "1.3.6.1.2.1.2.2.1.6.1")
	if !ok || p.MAC() != "00:e0:fc:12:34:56" {
		t.Fatalf("mac: %v %q", ok, p.MAC())
	}
	p, _, _ = GetOne(ctx, c, "1.3.6.1.2.1.31.1.1.1.6.1")
	if p.Uint() != 18446744073709551000 {
		t.Fatalf("counter64 %d", p.Uint())
	}
	rows, order, err := Table(ctx, c, "1.3.6.1.2.1.2.2.1", 2, 6)
	if err != nil || len(order) != 3 || rows["1"][6].MAC() == "" {
		t.Fatalf("table: %v %v %v", rows, order, err)
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"AA-BB-CC-DD-EE-FF": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":    "aa:bb:cc:dd:ee:ff",
		"aabbccddeeff":      "aa:bb:cc:dd:ee:ff",
		"00:00:00:00:00:00": "",
		"zz":                "",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("%s → %q want %q", in, got, want)
		}
	}
}

func TestIndexToString(t *testing.T) {
	s, rest := IndexToString([]int{3, 'a', 'b', 'c', 7}, false)
	if s != "abc" || len(rest) != 1 || rest[0] != 7 {
		t.Fatalf("%q %v", s, rest)
	}
}

// TestAgentRoundTrip exercises the real gosnmp client against the simulator
// agent over UDP, including GETBULK walks.
func TestAgentRoundTrip(t *testing.T) {
	m, _ := ParseSnmprec(strings.NewReader(rec))
	for i := 1; i <= 200; i++ {
		m.Int("1.3.6.1.2.1.2.2.1.1."+strconv.Itoa(i+100), int64(i))
	}
	a := &Agent{MIB: m, Community: "public"}
	if err := a.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	port := a.Addr().(interface{ String() string }).String()
	_, portStr, _ := strings.Cut(port, ":")
	cred := credentials.SNMP{Community: "public", Port: mustAtoi(portStr)}
	c, err := Dial(ctx, "127.0.0.1", cred, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	res, err := c.Get(ctx, "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.9.0")
	if err != nil {
		t.Fatal(err)
	}
	if res[0].String() != "SW-CORE-01" || res[1].String() != "1.3.6.1.4.1.2011.2.23.419" || res[2].Uint() != 123456 || res[3].Exists() {
		t.Fatalf("get: %+v", res)
	}
	walk, err := c.Walk(ctx, "1.3.6.1.2.1.2.2.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(walk) != 200 {
		t.Fatalf("bulk walk got %d", len(walk))
	}
	ip, err := c.Walk(ctx, "1.3.6.1.2.1.4.20.1.1")
	if err != nil || len(ip) != 1 || ip[0].IP() != "10.0.0.1" {
		t.Fatalf("ip walk %+v %v", ip, err)
	}
	c64, _ := c.Get(ctx, "1.3.6.1.2.1.31.1.1.1.6.1")
	if c64[0].Uint() != 18446744073709551000 {
		t.Fatalf("c64 %v", c64[0])
	}

	// wrong community → timeout classified
	bad, _ := Dial(ctx, "127.0.0.1", credentials.SNMP{Community: "wrong", Port: cred.Port}, Options{Timeout: 200 * time.Millisecond})
	_, err = bad.Get(ctx, "1.3.6.1.2.1.1.5.0")
	if err == nil || !strings.Contains(err.Error(), "no SNMP response") {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func TestAgentV3(t *testing.T) {
	m, _ := ParseSnmprec(strings.NewReader(rec))
	a := &Agent{MIB: m, V3Users: map[string]V3User{"prometheus": {AuthProtocol: "SHA", AuthPassword: "testpass123"}}}
	if err := a.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Serve(ctx)
	_, portStr, _ := strings.Cut(a.Addr().String(), ":")
	port := mustAtoi(portStr)
	get := func(user, pass string) (string, error) {
		c, err := Dial(ctx, "127.0.0.1", credentials.SNMP{Username: user, AuthPassword: pass, Port: port}, Options{Timeout: 500 * time.Millisecond})
		if err != nil {
			return "", err
		}
		defer c.Close()
		p, _, err := GetOne(ctx, c, "1.3.6.1.2.1.1.5.0")
		return p.String(), err
	}
	name, err := get("prometheus", "testpass123")
	if err != nil || name != "SW-CORE-01" {
		t.Fatalf("v3 get: %q %v", name, err)
	}
	c, _ := Dial(ctx, "127.0.0.1", credentials.SNMP{Username: "prometheus", AuthPassword: "testpass123", Port: port}, Options{Timeout: time.Second})
	w, err := c.Walk(ctx, "1.3.6.1.2.1.2.2.1.2")
	if err != nil || len(w) != 3 {
		t.Fatalf("v3 walk: %d %v", len(w), err)
	}
	if _, err := get("prometheus", "wrongpass99"); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong pass: %v", err)
	}
	if _, err := get("nobody", "testpass123"); !errors.Is(err, ErrAuth) {
		t.Fatalf("unknown user: %v", err)
	}
}
