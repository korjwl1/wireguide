// Package logrotate provides a small size-based rotating file writer. It
// exists so the root helper can own its log file instead of leaving launchd to
// append to it forever.
package logrotate

import (
	"fmt"
	"os"
	"sync"
)

// Writer is an io.WriteCloser that appends to Path and rotates by size:
// Path -> Path.1 -> ... -> Path.<MaxFiles>; the oldest is dropped. Rotation
// happens in-process so no external signal is needed.
type Writer struct {
	path     string
	maxBytes int64
	maxFiles int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// Open opens (creating if needed, mode 0644, O_APPEND) the log at path. If an
// existing file is already larger than maxBytes it is rotated immediately so
// an oversized existing log is retired at once.
func Open(path string, maxBytes int64, maxFiles int) (*Writer, error) {
	if maxBytes <= 0 || maxFiles < 1 {
		return nil, fmt.Errorf("logrotate: invalid limits (%d bytes, %d files)", maxBytes, maxFiles)
	}
	w := &Writer{path: path, maxBytes: maxBytes, maxFiles: maxFiles}
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxBytes {
		if err := w.rotateFiles(); err != nil {
			return nil, err
		}
	}
	if err := w.openLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) openLocked() error {
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f, w.size = f, fi.Size()
	return nil
}

// rotateFiles shifts the numbered files up and moves the live file to .1.
// The live file handle must already be closed.
func (w *Writer) rotateFiles() error {
	_ = os.Remove(fmt.Sprintf("%s.%d", w.path, w.maxFiles))
	for i := w.maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, fmt.Sprintf("%s.%d", w.path, i+1)); err != nil {
				return err
			}
		}
	}
	if _, err := os.Stat(w.path); err == nil {
		return os.Rename(w.path, w.path+".1")
	}
	return nil
}

// Write implements io.Writer.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		if err := w.openLocked(); err != nil {
			return 0, err
		}
	}
	if w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		_ = w.f.Close()
		w.f = nil
		if err := w.rotateFiles(); err != nil {
			// Keep logging rather than losing lines; try to reopen.
			_ = w.openLocked()
		} else if err := w.openLocked(); err != nil {
			return 0, err
		}
		if w.f == nil {
			return 0, fmt.Errorf("logrotate: cannot reopen %s", w.path)
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// Close closes the live file.
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
