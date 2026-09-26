package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// Kinds of credentials.
const (
	KindSNMP   = "snmp"
	KindSSH    = "ssh"
	KindTelnet = "telnet"
)

// SNMP holds everything needed to talk SNMP to a device. The zero value of the
// advanced fields means "choose a sensible default".
type SNMP struct {
	Version       string `json:"version"`                  // "2c" or "3" ("" → auto from fields)
	Community     string `json:"community,omitempty"`      // v2c
	Username      string `json:"username,omitempty"`       // v3
	SecurityLevel string `json:"security_level,omitempty"` // noAuthNoPriv|authNoPriv|authPriv
	AuthProtocol  string `json:"auth_protocol,omitempty"`  // MD5|SHA|SHA224|SHA256|SHA384|SHA512
	AuthPassword  string `json:"auth_password,omitempty"`  //
	PrivProtocol  string `json:"priv_protocol,omitempty"`  // DES|AES|AES192|AES256|AES192C|AES256C
	PrivPassword  string `json:"priv_password,omitempty"`  //
	ContextName   string `json:"context_name,omitempty"`   //
	Port          int    `json:"port,omitempty"`           // default 161
	// Autodetect lets discovery try other auth/privacy protocols when the
	// defaults are rejected (the user only gave a username and password).
	Autodetect bool `json:"autodetect,omitempty"`
}

// Normalize fills defaults following the "simple by default" principle:
// username+password → SNMPv3 authNoPriv SHA; community → v2c.
func (s *SNMP) Normalize() error {
	if s.Port == 0 {
		s.Port = 161
	}
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("invalid SNMP port")
	}
	if s.Version == "" {
		if s.Username != "" {
			s.Version = "3"
		} else {
			s.Version = "2c"
		}
	}
	switch s.Version {
	case "1", "2c":
		if s.Community == "" {
			return errors.New("SNMP community is required for v1/v2c")
		}
	case "3":
		if s.Username == "" {
			return errors.New("SNMPv3 username is required")
		}
		if s.SecurityLevel == "" {
			switch {
			case s.PrivPassword != "":
				s.SecurityLevel = "authPriv"
			case s.AuthPassword != "":
				s.SecurityLevel = "authNoPriv"
			default:
				s.SecurityLevel = "noAuthNoPriv"
			}
		}
		if s.SecurityLevel != "noAuthNoPriv" {
			if s.AuthProtocol == "" {
				s.AuthProtocol = "SHA"
			}
			if len(s.AuthPassword) < 8 {
				return errors.New("SNMPv3 auth password must be at least 8 characters")
			}
		}
		if s.SecurityLevel == "authPriv" {
			if s.PrivProtocol == "" {
				s.PrivProtocol = "AES"
			}
			if len(s.PrivPassword) < 8 {
				return errors.New("SNMPv3 privacy password must be at least 8 characters")
			}
		}
	default:
		return fmt.Errorf("unsupported SNMP version %q", s.Version)
	}
	return nil
}

// Summary returns non-secret information safe to show in the UI.
func (s SNMP) Summary() map[string]any {
	m := map[string]any{"version": s.Version, "port": s.Port}
	if s.Version == "3" {
		m["username"] = s.Username
		m["security_level"] = s.SecurityLevel
		if s.AuthProtocol != "" {
			m["auth_protocol"] = s.AuthProtocol
		}
		if s.PrivProtocol != "" {
			m["priv_protocol"] = s.PrivProtocol
		}
		if s.ContextName != "" {
			m["context_name"] = s.ContextName
		}
	}
	return m
}

// Login is an SSH/Telnet credential.
type Login struct {
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"` // PEM, SSH only
	Port       int    `json:"port,omitempty"`
}

func (l Login) Summary() map[string]any {
	return map[string]any{"username": l.Username, "port": l.Port, "has_key": l.PrivateKey != ""}
}

// Record is a stored credential without its secret.
type Record struct {
	ID        int64          `json:"id"`
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`
	Summary   map[string]any `json:"summary"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// Store persists sealed credentials.
type Store struct {
	db     *storage.DB
	sealer *Sealer
}

func NewStore(db *storage.DB, sealer *Sealer) *Store { return &Store{db: db, sealer: sealer} }

func aad(id int64, kind string) []byte {
	return []byte("cred:" + strconv.FormatInt(id, 10) + ":" + kind)
}

func (s *Store) create(ctx context.Context, q storage.DBTX, name, kind string, summary map[string]any, secret any) (int64, error) {
	plain, err := json.Marshal(secret)
	if err != nil {
		return 0, err
	}
	var id int64
	// Reserve the id first so it can be bound into the AAD.
	if err := q.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('credentials','id'))`).Scan(&id); err != nil {
		return 0, err
	}
	sealed, err := s.sealer.Seal(plain, aad(id, kind))
	if err != nil {
		return 0, err
	}
	_, err = q.Exec(ctx, `INSERT INTO credentials(id,name,kind,summary,secret) VALUES ($1,$2,$3,$4,$5)`,
		id, name, kind, summary, sealed)
	return id, err
}

func (s *Store) CreateSNMP(ctx context.Context, q storage.DBTX, name string, c SNMP) (int64, error) {
	if err := c.Normalize(); err != nil {
		return 0, err
	}
	return s.create(ctx, q, name, KindSNMP, c.Summary(), c)
}

// UpdateSNMP re-seals an SNMP credential (e.g. after protocol auto-detection).
func (s *Store) UpdateSNMP(ctx context.Context, id int64, c SNMP) error {
	if err := c.Normalize(); err != nil {
		return err
	}
	plain, err := json.Marshal(c)
	if err != nil {
		return err
	}
	sealed, err := s.sealer.Seal(plain, aad(id, KindSNMP))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `UPDATE credentials SET secret=$2, summary=$3, updated_at=now() WHERE id=$1 AND kind='snmp'`, id, sealed, c.Summary())
	return err
}

func (s *Store) CreateLogin(ctx context.Context, q storage.DBTX, name, kind string, l Login) (int64, error) {
	if kind != KindSSH && kind != KindTelnet {
		return 0, errors.New("login credential kind must be ssh or telnet")
	}
	if l.Username == "" {
		return 0, errors.New("username is required")
	}
	if l.Password == "" && l.PrivateKey == "" {
		return 0, errors.New("password or private key is required")
	}
	if kind == KindTelnet && l.PrivateKey != "" {
		return 0, errors.New("telnet does not support private keys")
	}
	if l.Port == 0 {
		if kind == KindSSH {
			l.Port = 22
		} else {
			l.Port = 23
		}
	}
	return s.create(ctx, q, name, kind, l.Summary(), l)
}

func (s *Store) open(ctx context.Context, id int64, wantKind string, out any) error {
	var kind string
	var sealed []byte
	err := s.db.QueryRow(ctx, `SELECT kind, secret FROM credentials WHERE id=$1`, id).Scan(&kind, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("credential %d not found", id)
	}
	if err != nil {
		return err
	}
	if kind != wantKind {
		return fmt.Errorf("credential %d is %s, not %s", id, kind, wantKind)
	}
	plain, err := s.sealer.Open(sealed, aad(id, kind))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, out)
}

// SNMP decrypts an SNMP credential. For internal use only — never return the
// result from an API handler.
func (s *Store) SNMP(ctx context.Context, id int64) (SNMP, error) {
	var c SNMP
	err := s.open(ctx, id, KindSNMP, &c)
	return c, err
}

// Login decrypts an SSH/Telnet credential. Internal use only.
func (s *Store) Login(ctx context.Context, id int64, kind string) (Login, error) {
	var l Login
	err := s.open(ctx, id, kind, &l)
	return l, err
}

func (s *Store) List(ctx context.Context) ([]Record, error) {
	rows, err := s.db.Query(ctx, `SELECT id,name,kind,summary,created_at,updated_at FROM credentials ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Record, error) {
		var rec Record
		err := r.Scan(&rec.ID, &rec.Name, &rec.Kind, &rec.Summary, &rec.CreatedAt, &rec.UpdatedAt)
		return rec, err
	})
}

func (s *Store) Delete(ctx context.Context, id int64) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM credentials WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("credential %d not found", id)
	}
	return nil
}

// DefaultName builds a readable credential name.
func DefaultName(kind, user, ip string) string {
	parts := []string{strings.ToUpper(kind)}
	if user != "" {
		parts = append(parts, user)
	}
	if ip != "" {
		parts = append(parts, "@"+ip)
	}
	return strings.Join(parts, " ")
}
