package gui

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestTunnelSnapshotDetectsEditsAndMetadata(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "vpn.conf")
	if err := os.WriteFile(conf, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := tunnelFilesSnapshot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte("after!"), 0600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(conf, later, later); err != nil {
		t.Fatal(err)
	}
	after, err := tunnelFilesSnapshot(dir)
	if err != nil || slices.Equal(before, after) {
		t.Fatalf("same-name config edit missed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vpn.meta.json"), []byte(`{"notes":"changed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	meta, err := tunnelFilesSnapshot(dir)
	if err != nil || slices.Equal(after, meta) {
		t.Fatalf("metadata change missed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".wireguide-test.tmp"), []byte("writing"), 0600); err != nil {
		t.Fatal(err)
	}
	temp, err := tunnelFilesSnapshot(dir)
	if err != nil || !slices.Equal(meta, temp) {
		t.Fatalf("temporary file triggered a refresh: %v", err)
	}
}
