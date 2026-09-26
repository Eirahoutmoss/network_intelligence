package diag

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	cases := []struct{ in, mustNot string }{
		{`NEXUS_MASTER_KEY=q83vEjRWeJq83vEjRWeJq83vEjRWeJq83vEjRWeJ12=`, "q83vEj"},
		{`NEXUS_PG_PASSWORD="s3cr3t value"`, "s3cr3t"},
		{`{"auth_password":"hunter2hunter2","username":"prometheus"}`, "hunter2"},
		{`{"community": "c0mmunity-string"}`, "c0mmunity"},
		{`level=WARN msg=x password=pa55word-xyz ip=10.0.0.1`, "pa55word"},
		{`time=x snmp_password=nexus-demo-pass`, "nexus-demo-pass"},
		{`postgres://nexus:Sup3rS3cret@127.0.0.1:54329/nexus`, "Sup3rS3cret"},
		{"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----", "abc"},
		{`Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def`, "eyJhbGci"},
		{`Cookie: nexus_session=abcdef0123456789`, "abcdef0123"},
		{`{"priv_password":"x\"y-escaped-secret"}`, "escaped-secret"},
		{`ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxx`, "sk-ant"},
		{`token_hash: 9f86d081884c7d659a2feaa0c55ad015`, "9f86d0818"},
	}
	for _, c := range cases {
		out := Redact(c.in)
		if strings.Contains(out, c.mustNot) {
			t.Errorf("%q -> %q still contains %q", c.in, out, c.mustNot)
		}
	}
	keep := []string{
		`NEXUS_MASTER_KEY_FILE=C:\ProgramData\Nexus\secrets\master.key`,
		`telnet_allowed=false`,
		`{"security_level":"authNoPriv","version":"3"}`,
		`device=SW-CORE-01 ip=10.20.99.1 port=161`,
		`"password_set": true`,
	}
	for _, k := range keep {
		if out := Redact(k); out != k {
			t.Errorf("harmless text changed: %q -> %q", k, out)
		}
	}
	r := NewRedactor("literal-master-key-value")
	if out := r.Redact("x literal-master-key-value y"); strings.Contains(out, "literal-master") {
		t.Error(out)
	}
}
