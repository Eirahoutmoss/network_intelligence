// Package logfile is a size-rotated log file writer.
package logfile

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Writer appends to Path and rotates it to Path.1 … Path.Keep when it grows
// beyond MaxBytes.
type Writer struct {
	Path     string
	MaxBytes int64
	Keep     int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// Open creates the directory and opens the file for appending.
func Open(path string, maxBytes int64, keep int) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	w := &Writer{Path: path, MaxBytes: maxBytes, Keep: keep}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, st.Size()
	return nil
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.MaxBytes > 0 && w.size+int64(len(p)) > w.MaxBytes && w.size > 0 {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *Writer) rotate() error {
	w.f.Close()
	for i := w.Keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", w.Path, i), fmt.Sprintf("%s.%d", w.Path, i+1))
	}
	if w.Keep > 0 {
		_ = os.Rename(w.Path, w.Path+".1")
	} else {
		_ = os.Remove(w.Path)
	}
	return w.open()
}

// Close closes the file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
