package deploy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// Severity of an install log entry.
const (
	Info  = "info"
	Warn  = "warning"
	Error = "error"
)

// Entry is one structured install log record.
type Entry struct {
	Time      time.Time `json:"time"`
	Phase     string    `json:"phase"`
	Component string    `json:"component"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Hint      string    `json:"hint,omitempty"`
}

// Log writes JSON lines to a file and human-readable progress lines to Out
// (the installer window). Never pass secrets to it.
type Log struct {
	Out   io.Writer
	ASCII bool // plain markers instead of ✓ / ! / ✗
	// DialogFont uses √ and × which every Windows UI font contains (the
	// installer window's font has no ✓/✗ glyphs).
	DialogFont bool

	mu   sync.Mutex
	file *os.File
}

// OpenLog appends to path (created with its directory).
func OpenLog(path string, out io.Writer) (*Log, error) {
	l := &Log{Out: out}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		l.file = f
	}
	return l, nil
}

// Close closes the log file.
func (l *Log) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

func (l *Log) marker(sev string) string {
	if l.ASCII {
		switch sev {
		case Warn:
			return "[!!]"
		case Error:
			return "[XX]"
		}
		return "[OK]"
	}
	switch sev {
	case Warn:
		return "!"
	case Error:
		if l.DialogFont {
			return "×"
		}
		return "✗"
	}
	if l.DialogFont {
		return "√"
	}
	return "✓"
}

// Record writes an entry.
func (l *Log) Record(phase, component, sev, msg, hint string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{Time: time.Now().UTC(), Phase: phase, Component: component, Severity: sev, Message: msg, Hint: hint}
	if l.file != nil {
		b, _ := json.Marshal(e)
		l.file.Write(append(b, '\n'))
	}
	if l.Out != nil {
		line := fmt.Sprintf("  %s %s", l.marker(sev), component)
		if msg != "" {
			line += ": " + msg
		}
		fmt.Fprintln(l.Out, line)
		if hint != "" && sev != Info {
			fmt.Fprintln(l.Out, "      "+hint)
		}
	}
}

// UTF16Writer converts UTF-8 text to UTF-16LE with a leading BOM. NSIS's
// nsExec decodes child output as the ANSI code page unless it starts with a
// UTF-16LE byte order mark, so this keeps ✓ and non-ASCII names intact.
type UTF16Writer struct {
	W       io.Writer
	started bool
}

func (u *UTF16Writer) Write(p []byte) (int, error) {
	var out []byte
	if !u.started {
		out = append(out, 0xFF, 0xFE)
		u.started = true
	}
	for _, r := range string(p) {
		if r == '\n' {
			out = append(out, '\r', 0) // CRLF for the Windows list control
		}
		for _, c := range utf16.Encode([]rune{r}) {
			out = append(out, byte(c), byte(c>>8))
		}
	}
	if _, err := u.W.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Heading prints a section title to the installer window.
func (l *Log) Heading(s string) {
	if l != nil && l.Out != nil {
		fmt.Fprintln(l.Out, s)
	}
}

// Step records a finished step.
func (l *Log) Step(phase, component, msg string) { l.Record(phase, component, Info, msg, "") }

// Warn records a warning with a remediation hint.
func (l *Log) Warn(phase, component, msg, hint string) { l.Record(phase, component, Warn, msg, hint) }

// Fail records an error with a remediation hint and returns it as an error.
func (l *Log) Fail(phase, component, msg, hint string) error {
	l.Record(phase, component, Error, msg, hint)
	if hint != "" {
		return fmt.Errorf("%s: %s (%s)", component, msg, strings.TrimSuffix(hint, "."))
	}
	return fmt.Errorf("%s: %s", component, msg)
}
