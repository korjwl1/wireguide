package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProfileLockWaitIsBounded(t *testing.T) {
	dir := t.TempDir()
	store := NewTunnelStore(dir)
	cfg := testConfig()
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, ".imports.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := flockExclusive(int(f.Fd())); err != nil {
		t.Fatal(err)
	}
	defer flockUnlock(int(f.Fd()))
	start := time.Now()
	if err := store.UpdateMeta(cfg.Name, func(*TunnelMeta) {}); !errors.Is(err, ErrStoreBusy) {
		t.Fatalf("contended store returned %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("storage lock trapped a profile operation beyond its deadline")
	}
}
