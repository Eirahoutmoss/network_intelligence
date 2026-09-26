// Package config loads runtime configuration from the environment.
//
// Secrets (database password, master key, admin bootstrap password) are only
// ever read from the environment or from files referenced by *_FILE variables,
// never from source code.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr   string
	DatabaseURL  string
	MasterKey    []byte // 32 bytes, AES-256
	WebDir       string // built frontend (optional)
	LogLevel     string
	LogFormat    string // json|text
	AdminUser    string
	AdminPass    string // only used to bootstrap the first admin
	SessionTTL   time.Duration
	CookieSecure bool

	PollInterval     time.Duration
	RediscoverEvery  time.Duration
	MetricsRetention time.Duration
	DiscoveryWorkers int
	SNMPTimeout      time.Duration
	SNMPRetries      int

	CLIIdleTimeout time.Duration
	CLIMaxDuration time.Duration

	// Simulator starts an in-process SNMP lab (for demos and tests).
	SimulatorListen string // e.g. "127.0.1.1-8:16100"; empty = off

	// Optional LLM query interpreter. The LLM only turns questions into
	// structured filters; answers always come from the database.
	AnthropicAPIKey string
	LLMModel        string
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// secret reads KEY or the file named by KEY_FILE.
func secret(key string) (string, error) {
	if f := os.Getenv(key + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("read %s_FILE: %w", key, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv(key), nil
}

func duration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func integer(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// ParseMasterKey accepts 32 raw bytes encoded as base64 (std or url) or hex.
func ParseMasterKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("NEXUS_MASTER_KEY is required (32 bytes, base64 or hex). Generate one with: openssl rand -base64 32")
	}
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	}
	for _, d := range decoders {
		if b, err := d(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("NEXUS_MASTER_KEY must decode to exactly 32 bytes (base64 or hex)")
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:      getenv("NEXUS_LISTEN", ":8080"),
		DatabaseURL:     getenv("NEXUS_DATABASE_URL", ""),
		WebDir:          getenv("NEXUS_WEB_DIR", ""),
		LogLevel:        getenv("NEXUS_LOG_LEVEL", "info"),
		LogFormat:       getenv("NEXUS_LOG_FORMAT", "json"),
		AdminUser:       getenv("NEXUS_ADMIN_USER", "admin"),
		SimulatorListen: getenv("NEXUS_SIMULATOR", ""),
		LLMModel:        getenv("NEXUS_LLM_MODEL", "claude-opus-5"),
		CookieSecure:    getenv("NEXUS_COOKIE_SECURE", "false") == "true",
	}
	var err error
	if c.DatabaseURL == "" {
		if c.DatabaseURL, err = secret("NEXUS_DATABASE_URL"); err != nil {
			return nil, err
		}
	}
	if c.DatabaseURL == "" {
		return nil, errors.New("NEXUS_DATABASE_URL is required")
	}
	mk, err := secret("NEXUS_MASTER_KEY")
	if err != nil {
		return nil, err
	}
	if c.MasterKey, err = ParseMasterKey(mk); err != nil {
		return nil, err
	}
	if c.AdminPass, err = secret("NEXUS_ADMIN_PASSWORD"); err != nil {
		return nil, err
	}
	if c.AnthropicAPIKey, err = secret("ANTHROPIC_API_KEY"); err != nil {
		return nil, err
	}
	if c.SessionTTL, err = duration("NEXUS_SESSION_TTL", 12*time.Hour); err != nil {
		return nil, err
	}
	if c.PollInterval, err = duration("NEXUS_POLL_INTERVAL", 5*time.Minute); err != nil {
		return nil, err
	}
	if c.RediscoverEvery, err = duration("NEXUS_REDISCOVER_INTERVAL", 6*time.Hour); err != nil {
		return nil, err
	}
	if c.MetricsRetention, err = duration("NEXUS_METRICS_RETENTION", 7*24*time.Hour); err != nil {
		return nil, err
	}
	if c.SNMPTimeout, err = duration("NEXUS_SNMP_TIMEOUT", 3*time.Second); err != nil {
		return nil, err
	}
	if c.CLIIdleTimeout, err = duration("NEXUS_CLI_IDLE_TIMEOUT", 15*time.Minute); err != nil {
		return nil, err
	}
	if c.CLIMaxDuration, err = duration("NEXUS_CLI_MAX_DURATION", 4*time.Hour); err != nil {
		return nil, err
	}
	if c.SNMPRetries, err = integer("NEXUS_SNMP_RETRIES", 1); err != nil {
		return nil, err
	}
	if c.DiscoveryWorkers, err = integer("NEXUS_DISCOVERY_WORKERS", 4); err != nil {
		return nil, err
	}
	return c, nil
}
