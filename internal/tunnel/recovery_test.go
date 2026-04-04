package tunnel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadActiveState(t *testing.T) {
	dir := t.TempDir()
	state := &ActiveTunnelState{
		TunnelName:    "test-vpn",
		InterfaceName: "utun5",
		FullTunnel:    true,
	}

	if err := SaveActiveState(dir, state); err != nil {
		t.Fatalf("SaveActiveState failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(filepath.Join(dir, activeTunnelFile)); err != nil {
		t.Fatalf("state file should exist: %v", err)
	}

	loaded := LoadActiveState(dir)
	if loaded == nil {
		t.Fatal("LoadActiveState returned nil")
	}
	if loaded.TunnelName != "test-vpn" {
		t.Errorf("tunnel name mismatch: %s", loaded.TunnelName)
	}
	if loaded.InterfaceName != "utun5" {
		t.Errorf("interface name mismatch: %s", loaded.InterfaceName)
	}
	if !loaded.FullTunnel {
		t.Error("full tunnel should be true")
	}
}

func TestClearActiveState(t *testing.T) {
	dir := t.TempDir()
	state := &ActiveTunnelState{TunnelName: "test"}
	SaveActiveState(dir, state)

	if err := ClearActiveState(dir); err != nil {
		t.Fatalf("ClearActiveState failed: %v", err)
	}

	if LoadActiveState(dir) != nil {
		t.Error("state should be nil after clear")
	}
}

func TestLoadActiveStateNoFile(t *testing.T) {
	dir := t.TempDir()
	if LoadActiveState(dir) != nil {
		t.Error("should return nil when no state file")
	}
}

func TestRecoverFromCrashNoState(t *testing.T) {
	dir := t.TempDir()
	name := RecoverFromCrash(dir)
	if name != "" {
		t.Errorf("expected empty, got %s", name)
	}
}

func TestRecoverFromCrashWithState(t *testing.T) {
	dir := t.TempDir()
	SaveActiveState(dir, &ActiveTunnelState{
		TunnelName:    "crashed-vpn",
		InterfaceName: "utun99",
	})

	name := RecoverFromCrash(dir)
	if name != "crashed-vpn" {
		t.Errorf("expected 'crashed-vpn', got %s", name)
	}

	// State should be cleared after recovery
	if LoadActiveState(dir) != nil {
		t.Error("state should be cleared after recovery")
	}
}
