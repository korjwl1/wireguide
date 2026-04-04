package tunnel

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
)

// ActiveTunnelState is persisted to disk while a tunnel is active.
// On startup, if this file exists, a previous crash is detected.
type ActiveTunnelState struct {
	TunnelName    string   `json:"tunnel_name"`
	InterfaceName string   `json:"interface_name"`
	DNSServers    []string `json:"dns_servers_original"`
	FullTunnel    bool     `json:"full_tunnel"`
}

const activeTunnelFile = "active-tunnel.json"

// SaveActiveState writes the active tunnel state to disk.
func SaveActiveState(dataDir string, state *ActiveTunnelState) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dataDir, activeTunnelFile), data, 0600)
}

// ClearActiveState removes the active tunnel state file (called on clean disconnect).
func ClearActiveState(dataDir string) error {
	path := filepath.Join(dataDir, activeTunnelFile)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// LoadActiveState reads the active tunnel state. Returns nil if no state file exists.
func LoadActiveState(dataDir string) *ActiveTunnelState {
	path := filepath.Join(dataDir, activeTunnelFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var state ActiveTunnelState
	if err := json.Unmarshal(data, &state); err != nil {
		slog.Warn("corrupt active tunnel state file, removing", "error", err)
		os.Remove(path)
		return nil
	}
	return &state
}

// RecoverFromCrash checks for orphaned tunnel state and cleans up.
// Returns the name of the cleaned-up tunnel, or empty string if none.
func RecoverFromCrash(dataDir string) string {
	state := LoadActiveState(dataDir)
	if state == nil {
		return ""
	}
	slog.Warn("detected orphaned tunnel from previous crash",
		"tunnel", state.TunnelName,
		"interface", state.InterfaceName)

	// The TUN device is already gone (process died), but routes/DNS may be stale.
	// Cleanup is best-effort via the network manager.
	ClearActiveState(dataDir)
	return state.TunnelName
}
