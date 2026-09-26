package credentials

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func key(t *testing.T) []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealRoundTrip(t *testing.T) {
	s, err := NewSealer(key(t))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte(`{"auth_password":"s3cr3t-pass"}`)
	sealed, err := s.Seal(secret, aad(1, KindSNMP))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("s3cr3t")) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := s.Open(sealed, aad(1, KindSNMP))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("got %q", got)
	}
}

func TestSealBindsAAD(t *testing.T) {
	s, _ := NewSealer(key(t))
	sealed, _ := s.Seal([]byte("x"), aad(1, KindSNMP))
	if _, err := s.Open(sealed, aad(2, KindSNMP)); err == nil {
		t.Fatal("expected failure with different row id")
	}
	if _, err := s.Open(sealed, aad(1, KindSSH)); err == nil {
		t.Fatal("expected failure with different kind")
	}
}

func TestWrongKeyFails(t *testing.T) {
	a, _ := NewSealer(key(t))
	b, _ := NewSealer(key(t))
	sealed, _ := a.Seal([]byte("x"), nil)
	if _, err := b.Open(sealed, nil); err == nil {
		t.Fatal("expected failure with wrong key")
	}
}

func TestNonceUnique(t *testing.T) {
	s, _ := NewSealer(key(t))
	a, _ := s.Seal([]byte("same"), nil)
	b, _ := s.Seal([]byte("same"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext must differ")
	}
}

func TestSNMPNormalize(t *testing.T) {
	c := SNMP{Username: "prometheus", AuthPassword: "longenough"}
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	if c.Version != "3" || c.SecurityLevel != "authNoPriv" || c.AuthProtocol != "SHA" || c.Port != 161 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	c2 := SNMP{Community: "public"}
	if err := c2.Normalize(); err != nil || c2.Version != "2c" {
		t.Fatalf("v2c default: %+v %v", c2, err)
	}
	c3 := SNMP{Username: "u", AuthPassword: "short"}
	if err := c3.Normalize(); err == nil {
		t.Fatal("expected short password error")
	}
	c4 := SNMP{Username: "u", AuthPassword: "longenough", PrivPassword: "privpass1"}
	if err := c4.Normalize(); err != nil || c4.SecurityLevel != "authPriv" || c4.PrivProtocol != "AES" {
		t.Fatalf("authPriv default: %+v %v", c4, err)
	}
	if _, ok := c4.Summary()["auth_password"]; ok {
		t.Fatal("summary leaked secret")
	}
}
