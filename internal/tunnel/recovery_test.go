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

	// Verify file exists in tunnel-states directory
	stateFile := filepath.Join(dir, tunnelStatesDir, stateFileName("test-vpn"))
	if _, err := os.Stat(stateFile); err != nil {
		t.Fatalf("state file should exist: %v", err)
	}

	loaded := LoadActiveState(dir)
	if len(loaded) == 0 {
		t.Fatal("LoadActiveState returned empty")
	}
	if loaded[0].TunnelName != "test-vpn" {
		t.Errorf("tunnel name mismatch: %s", loaded[0].TunnelName)
	}
	if loaded[0].InterfaceName != "utun5" {
		t.Errorf("interface name mismatch: %s", loaded[0].InterfaceName)
	}
	if !loaded[0].FullTunnel {
		t.Error("full tunnel should be true")
	}
}

func TestSaveAndLoadMultipleStates(t *testing.T) {
	dir := t.TempDir()

	state1 := &ActiveTunnelState{TunnelName: "vpn1", InterfaceName: "utun1"}
	state2 := &ActiveTunnelState{TunnelName: "vpn2", InterfaceName: "utun2"}

	if err := SaveActiveState(dir, state1); err != nil {
		t.Fatalf("SaveActiveState vpn1 failed: %v", err)
	}
	if err := SaveActiveState(dir, state2); err != nil {
		t.Fatalf("SaveActiveState vpn2 failed: %v", err)
	}

	loaded := LoadActiveState(dir)
	if len(loaded) != 2 {
		t.Fatalf("expected 2 states, got %d", len(loaded))
	}

	names := map[string]bool{}
	for _, s := range loaded {
		names[s.TunnelName] = true
	}
	if !names["vpn1"] || !names["vpn2"] {
		t.Errorf("expected vpn1 and vpn2 in loaded states, got %v", names)
	}
}

func TestClearActiveState(t *testing.T) {
	dir := t.TempDir()
	state := &ActiveTunnelState{TunnelName: "test"}
	SaveActiveState(dir, state)

	if err := ClearActiveState(dir, "test"); err != nil {
		t.Fatalf("ClearActiveState failed: %v", err)
	}

	if len(LoadActiveState(dir)) != 0 {
		t.Error("state should be empty after clear")
	}
}

func TestClearActiveState_Specific(t *testing.T) {
	dir := t.TempDir()

	SaveActiveState(dir, &ActiveTunnelState{TunnelName: "vpn1"})
	SaveActiveState(dir, &ActiveTunnelState{TunnelName: "vpn2"})

	if err := ClearActiveState(dir, "vpn1"); err != nil {
		t.Fatalf("ClearActiveState vpn1 failed: %v", err)
	}

	loaded := LoadActiveState(dir)
	if len(loaded) != 1 {
		t.Fatalf("expected 1 state remaining, got %d", len(loaded))
	}
	if loaded[0].TunnelName != "vpn2" {
		t.Errorf("expected vpn2 to remain, got %s", loaded[0].TunnelName)
	}
}

func TestLoadActiveStateNoFile(t *testing.T) {
	dir := t.TempDir()
	if len(LoadActiveState(dir)) != 0 {
		t.Error("should return empty when no state file")
	}
}

func TestLoadActiveState_LegacyMigration(t *testing.T) {
	dir := t.TempDir()
	// Write a legacy single-file state.
	legacyData := `{"tunnel_name":"legacy-vpn","interface_name":"utun5","full_tunnel":true}`
	if err := os.WriteFile(filepath.Join(dir, activeTunnelFile), []byte(legacyData), 0600); err != nil {
		t.Fatalf("write legacy file failed: %v", err)
	}

	loaded := LoadActiveState(dir)
	if len(loaded) != 1 {
		t.Fatalf("expected 1 state from legacy, got %d", len(loaded))
	}
	if loaded[0].TunnelName != "legacy-vpn" {
		t.Errorf("expected legacy-vpn, got %s", loaded[0].TunnelName)
	}
}

func TestRecoverFromCrashNoState(t *testing.T) {
	dir := t.TempDir()
	names := RecoverFromCrash(dir)
	if len(names) != 0 {
		t.Errorf("expected empty, got %v", names)
	}
}

func TestRecoverFromCrashWithState(t *testing.T) {
	dir := t.TempDir()
	SaveActiveState(dir, &ActiveTunnelState{
		TunnelName:    "crashed-vpn",
		InterfaceName: "utun99",
	})

	names := RecoverFromCrash(dir)
	if len(names) != 1 || names[0] != "crashed-vpn" {
		t.Errorf("expected ['crashed-vpn'], got %v", names)
	}

	// State should be cleared after recovery
	if len(LoadActiveState(dir)) != 0 {
		t.Error("state should be cleared after recovery")
	}
}

func TestRecoverFromCrashMultiple(t *testing.T) {
	dir := t.TempDir()
	SaveActiveState(dir, &ActiveTunnelState{TunnelName: "vpn1", InterfaceName: "utun1"})
	SaveActiveState(dir, &ActiveTunnelState{TunnelName: "vpn2", InterfaceName: "utun2"})

	names := RecoverFromCrash(dir)
	if len(names) != 2 {
		t.Fatalf("expected 2 recovered tunnels, got %d: %v", len(names), names)
	}

	if len(LoadActiveState(dir)) != 0 {
		t.Error("all state should be cleared after recovery")
	}
}

func TestClearAllActiveStates(t *testing.T) {
	dir := t.TempDir()
	SaveActiveState(dir, &ActiveTunnelState{TunnelName: "vpn1"})
	SaveActiveState(dir, &ActiveTunnelState{TunnelName: "vpn2"})

	if err := ClearAllActiveStates(dir); err != nil {
		t.Fatalf("ClearAllActiveStates failed: %v", err)
	}

	if len(LoadActiveState(dir)) != 0 {
		t.Error("all states should be cleared")
	}
}
