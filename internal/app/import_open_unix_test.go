//go:build !windows

package app

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestImportRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe.conf")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readImportFile(path, 1024); err == nil {
		t.Fatal("FIFO was accepted as a config")
	}
}
