package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritableDirectoryProbePreservesExistingFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".wireguide-write-test")
	if err := os.WriteFile(path, []byte("existing user data"), 0600); err != nil {
		t.Fatal(err)
	}
	if !canWriteDir(dir) {
		t.Fatal("writable directory rejected")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing user data" {
		t.Fatalf("writability probe modified an existing file: %q, %v", data, err)
	}
}
