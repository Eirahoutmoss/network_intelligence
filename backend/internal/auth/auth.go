// Package auth implements users, sessions and role-based authorization.
//
// Roles: viewer (read-only), operator (discovery, context editing, CLI),
// admin (users, credentials, settings).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
	CookieName   = "nexus_session"
)

var roleRank = map[string]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { return roleRank[r] > 0 }

// User is an authenticated principal.
type User struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

// Can reports whether the user has at least role r.
func (u *User) Can(r string) bool { return u != nil && !u.Disabled && roleRank[u.Role] >= roleRank[r] }

// Service manages users and sessions.
type Service struct {
	DB     *storage.DB
	TTL    time.Duration
	Secure bool
	Log    *slog.Logger

	limiter sync.Map // ip → *attempts
}

type attempts struct {
	mu    sync.Mutex
	count int
	reset time.Time
}

var ErrInvalidLogin = errors.New("invalid username or password")

var (
	dummyOnce sync.Once
	dummyHash []byte
)

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Bootstrap creates the first admin if no users exist. When no password is
// configured a random one is generated and logged once.
func (s *Service) Bootstrap(ctx context.Context, username, password string) error {
	var n int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	generated := false
	if password == "" {
		password = randomToken(12)
		generated = true
	}
	if _, err := s.CreateUser(ctx, username, password, RoleAdmin); err != nil {
		return err
	}
	if generated {
		s.Log.Warn("created initial admin user with a generated password — change it after first login",
			"username", username, "password", password)
	} else {
		s.Log.Info("created initial admin user", "username", username)
	}
	return nil
}

func validatePassword(p string) error {
	if len(p) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

func (s *Service) CreateUser(ctx context.Context, username, password, role string) (int64, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return 0, errors.New("username is required")
	}
	if !ValidRole(role) {
		return 0, fmt.Errorf("invalid role %q", role)
	}
	if err := validatePassword(password); err != nil {
		return 0, err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.DB.QueryRow(ctx, `INSERT INTO users(username,password_hash,role) VALUES ($1,$2,$3) RETURNING id`, username, string(h), role).Scan(&id)
	if err != nil && strings.Contains(err.Error(), "duplicate") {
		return 0, errors.New("username already exists")
	}
	return id, err
}

func (s *Service) SetPassword(ctx context.Context, id int64, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := s.DB.Exec(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, id, string(h)); err != nil {
		return err
	}
	// invalidate other sessions
	_, err = s.DB.Exec(ctx, `DELETE FROM auth_sessions WHERE user_id=$1`, id)
	return err
}

func (s *Service) UpdateUser(ctx context.Context, id int64, role string, disabled bool) error {
	if !ValidRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	// never lock out the last active admin
	if role != RoleAdmin || disabled {
		var admins int
		if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin' AND NOT disabled AND id<>$1`, id).Scan(&admins); err != nil {
			return err
		}
		if admins == 0 {
			return errors.New("at least one active admin is required")
		}
	}
	if _, err := s.DB.Exec(ctx, `UPDATE users SET role=$2, disabled=$3 WHERE id=$1`, id, role, disabled); err != nil {
		return err
	}
	if disabled {
		_, err := s.DB.Exec(ctx, `DELETE FROM auth_sessions WHERE user_id=$1`, id)
		return err
	}
	return nil
}

func (s *Service) DeleteUser(ctx context.Context, id int64) error {
	var admins int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin' AND NOT disabled AND id<>$1`, id).Scan(&admins); err != nil {
		return err
	}
	if admins == 0 {
		return errors.New("at least one active admin is required")
	}
	_, err := s.DB.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}

func (s *Service) Users(ctx context.Context) ([]User, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, username, role, disabled, created_at, last_login_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) {
		var u User
		err := r.Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &u.CreatedAt, &u.LastLoginAt)
		return u, err
	})
}

// allow implements a per-client login attempt limit (10 per 5 minutes).
func (s *Service) allow(client string) bool {
	v, _ := s.limiter.LoadOrStore(client, &attempts{})
	a := v.(*attempts)
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Now().After(a.reset) {
		a.count, a.reset = 0, time.Now().Add(5*time.Minute)
	}
	a.count++
	return a.count <= 10
}

// Login verifies credentials and returns a new session token.
func (s *Service) Login(ctx context.Context, username, password, client string) (string, *User, error) {
	if !s.allow(client) {
		return "", nil, errors.New("too many login attempts, try again in a few minutes")
	}
	var u User
	var hash string
	err := s.DB.QueryRow(ctx, `SELECT id, username, role, disabled, password_hash, created_at FROM users WHERE username=$1`, username).
		Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &hash, &u.CreatedAt)
	if err != nil {
		// equalize timing
		dummyOnce.Do(func() { dummyHash, _ = bcrypt.GenerateFromPassword([]byte(randomToken(8)), bcrypt.DefaultCost) })
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return "", nil, ErrInvalidLogin
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || u.Disabled {
		return "", nil, ErrInvalidLogin
	}
	token := randomToken(32)
	ttl := s.TTL
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO auth_sessions(token_hash,user_id,expires_at) VALUES ($1,$2,$3)`, hashToken(token), u.ID, time.Now().Add(ttl)); err != nil {
		return "", nil, err
	}
	_, _ = s.DB.Exec(ctx, `UPDATE users SET last_login_at=now() WHERE id=$1`, u.ID)
	_, _ = s.DB.Exec(ctx, `DELETE FROM auth_sessions WHERE expires_at < now()`)
	return token, &u, nil
}

func (s *Service) Logout(ctx context.Context, token string) {
	_, _ = s.DB.Exec(ctx, `DELETE FROM auth_sessions WHERE token_hash=$1`, hashToken(token))
}

// Authenticate resolves a session token (sliding expiration).
func (s *Service) Authenticate(ctx context.Context, token string) (*User, error) {
	if token == "" {
		return nil, errors.New("no session")
	}
	var u User
	err := s.DB.QueryRow(ctx, `UPDATE auth_sessions s SET last_seen=now(), expires_at=GREATEST(s.expires_at, now() + $2::interval)
		FROM users u WHERE s.token_hash=$1 AND s.expires_at > now() AND u.id=s.user_id AND NOT u.disabled
		RETURNING u.id, u.username, u.role, u.disabled, u.created_at`, hashToken(token), fmt.Sprintf("%d seconds", int(s.TTL.Seconds()/4))).
		Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &u.CreatedAt)
	if err != nil {
		return nil, errors.New("session expired")
	}
	return &u, nil
}

// TokenFrom extracts the session token from cookie or bearer header.
func TokenFrom(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie(CookieName); err == nil {
		return c.Value
	}
	return ""
}

// SetCookie writes the session cookie.
func (s *Service) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.Secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.TTL.Seconds())})
}

func (s *Service) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

type ctxKey struct{}

// WithUser stores the user in the context.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// UserFrom returns the authenticated user or nil.
func UserFrom(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKey{}).(*User)
	return u
}

// Audit records a security-relevant action.
func Audit(ctx context.Context, db storage.DBTX, action, target string, detail map[string]any) {
	u := UserFrom(ctx)
	var uid any
	name := ""
	if u != nil {
		uid, name = u.ID, u.Username
	}
	if detail == nil {
		detail = map[string]any{}
	}
	_, _ = db.Exec(ctx, `INSERT INTO audit_log(user_id, username, action, target, detail) VALUES ($1,$2,$3,$4,$5)`, uid, name, action, target, detail)
}
