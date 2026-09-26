// Package settings stores runtime-editable options.
package settings

import (
	"context"
	"encoding/json"

	"github.com/Eirahoutmoss/network_intelligence/backend/internal/storage"
)

// Settings are admin-editable options.
type Settings struct {
	TelnetAllowed        bool     `json:"telnet_allowed"`
	DefaultDepth         int      `json:"default_depth"`
	DefaultScope         []string `json:"default_scope"`
	ActiveFingerprinting bool     `json:"active_fingerprinting"`
	MaxDevices           int      `json:"max_devices"`
}

func Defaults() Settings {
	return Settings{DefaultDepth: 3, MaxDevices: 64, DefaultScope: []string{}}
}

type Service struct{ DB *storage.DB }

func (s *Service) Get(ctx context.Context) Settings {
	st := Defaults()
	var raw []byte
	if err := s.DB.QueryRow(ctx, `SELECT value FROM settings WHERE key='app'`).Scan(&raw); err == nil {
		_ = json.Unmarshal(raw, &st)
	}
	if st.DefaultScope == nil {
		st.DefaultScope = []string{}
	}
	return st
}

func (s *Service) Put(ctx context.Context, st Settings) error {
	if st.DefaultDepth < 0 {
		st.DefaultDepth = 0
	}
	if st.DefaultDepth > 10 {
		st.DefaultDepth = 10
	}
	if st.MaxDevices <= 0 {
		st.MaxDevices = 64
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('app', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, st)
	return err
}
