// Package credentials stores device access secrets encrypted at rest.
//
// Secrets are sealed with AES-256-GCM using a master key supplied through the
// environment (NEXUS_MASTER_KEY). The ciphertext layout is:
//
//	version(1) | nonce(12) | ciphertext+tag
//
// The credential row id and kind are bound as additional authenticated data so
// a ciphertext cannot be swapped between rows.
package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const sealVersion = 1

// Sealer encrypts and decrypts secrets.
type Sealer struct {
	aead cipher.AEAD
}

func NewSealer(masterKey []byte) (*Sealer, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+s.aead.Overhead())
	out = append(out, sealVersion)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plaintext, aad), nil
}

func (s *Sealer) Open(sealed, aad []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(sealed) < 1+ns+s.aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	if sealed[0] != sealVersion {
		return nil, fmt.Errorf("unsupported ciphertext version %d", sealed[0])
	}
	pt, err := s.aead.Open(nil, sealed[1:1+ns], sealed[1+ns:], aad)
	if err != nil {
		return nil, errors.New("decrypt credential: authentication failed (wrong master key?)")
	}
	return pt, nil
}

// KeyFingerprint identifies a master key without revealing it
// (first 8 bytes of SHA-256 over a domain-separated input, hex).
func KeyFingerprint(masterKey []byte) string {
	h := sha256.Sum256(append([]byte("nexus-master-key-fingerprint:"), masterKey...))
	return hex.EncodeToString(h[:8])
}
