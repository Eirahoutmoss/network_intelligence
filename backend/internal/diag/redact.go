// Package diag runs health checks and builds diagnostic bundles. Everything
// that leaves the machine through a bundle passes through Redact.
package diag

import (
	"regexp"
	"strings"
)

// secretKey matches names of fields/variables that hold secrets.
const secretKey = `(?i)[a-z0-9_.-]*(?:pass(?:word|wd|phrase)?|pwd|secret|token|community|priv(?:ate)?_?key|auth_?key|master_?key|api_?key|cookie|authorization|session|credential|sealed)[a-z0-9_.-]*`

var (
	pemBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`)
	// "key": "value" (JSON)
	jsonPair = regexp.MustCompile(`("` + secretKey + `"\s*:\s*)("(?:[^"\\]|\\.)*"|[^,}\s]+)`)
	// key=value / key: value (env files, logfmt, text logs); value up to whitespace or quote-delimited
	kvPair = regexp.MustCompile(`(\b` + secretKey + `\s*[=:]\s*)("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&"']+)`)
	// scheme://user:password@host
	urlCreds = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+:)([^@\s]+)(@)`)
	bearer   = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
)

// Redactor removes secrets from text. Known secret values (for example the
// master key and database password of this installation) are replaced
// wherever they appear, in addition to pattern-based redaction.
type Redactor struct {
	known []string
}

// NewRedactor returns a redactor that also removes the given literal values.
func NewRedactor(known ...string) *Redactor {
	r := &Redactor{}
	for _, k := range known {
		if len(k) >= 6 {
			r.known = append(r.known, k)
		}
	}
	return r
}

// Redact returns s with secrets replaced by [REDACTED].
func (r *Redactor) Redact(s string) string {
	for _, k := range r.known {
		s = strings.ReplaceAll(s, k, "[REDACTED]")
	}
	return Redact(s)
}

// Redact applies pattern-based redaction.
func Redact(s string) string {
	s = pemBlock.ReplaceAllString(s, "[REDACTED PEM BLOCK]")
	s = urlCreds.ReplaceAllString(s, "${1}[REDACTED]${3}")
	s = bearer.ReplaceAllString(s, "$1 [REDACTED]")
	s = jsonPair.ReplaceAllStringFunc(s, func(m string) string {
		sub := jsonPair.FindStringSubmatch(m)
		if isHarmless(sub[2]) {
			return m
		}
		return sub[1] + `"[REDACTED]"`
	})
	s = kvPair.ReplaceAllStringFunc(s, func(m string) string {
		sub := kvPair.FindStringSubmatch(m)
		if isHarmless(sub[2]) || isPathSetting(sub[1]) {
			return m
		}
		return sub[1] + "[REDACTED]"
	})
	return s
}

// isPathSetting keeps *_FILE / *_DIR settings, which name a location, not a secret.
func isPathSetting(key string) bool {
	k := strings.ToUpper(strings.TrimRight(key, " =:"))
	return strings.HasSuffix(k, "_FILE") || strings.HasSuffix(k, "_DIR")
}

// isHarmless keeps booleans, numbers, nulls, empty values and file paths
// readable (e.g. NEXUS_MASTER_KEY_FILE=C:\...\master.key).
func isHarmless(v string) bool {
	u := strings.Trim(v, `"'`)
	switch strings.ToLower(u) {
	case "", "true", "false", "null", "none", "[redacted]":
		return true
	}
	if strings.Trim(u, "0123456789.") == "" {
		return true
	}
	return false
}
