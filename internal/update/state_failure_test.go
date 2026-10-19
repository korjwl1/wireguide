package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateUpdateRollsBackMemoryOnPersistenceFailure(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Dismiss("v1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "update.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "update.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.Dismiss("v2"); err == nil {
		t.Fatal("expected write failure")
	}
	if store.IsDismissed("v2") || !store.IsDismissed("v1") {
		t.Fatal("failed publication changed memory")
	}
}
