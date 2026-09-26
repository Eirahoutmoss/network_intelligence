package logfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs", "nexus.log")
	w, err := Open(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 39) + "\n"
	for i := 0; i < 20; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	for _, f := range []string{p, p + ".1", p + ".2"} {
		st, err := os.Stat(f)
		if err != nil || st.Size() > 100 {
			t.Errorf("%s: %v %v", f, st, err)
		}
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Error("kept too many files")
	}
}
