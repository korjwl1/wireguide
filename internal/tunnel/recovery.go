package tunnel

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/network"
)

// ActiveTunnelState is persisted to disk while a tunnel is active.
// On startup, if this file exists, a previous crash is detected.
type ActiveTunnelState struct {
	TunnelName    string   `json:"tunnel_name"`
	InterfaceName string   `json:"interface_name"`
	DNSServers    []string `json:"dns_servers_original"`
	FullTunnel    bool     `json:"full_tunnel"`
	Table         string   `json:"table,omitempty"`
	FwMark        string   `json:"fwmark,omitempty"`
	// PreModDNS stores the original DNS settings per network service
	// captured BEFORE any modification. Used for precise crash recovery
	// instead of the blunt ResetDNSToSystemDefault which loses custom
	// user preferences.
	PreModDNS map[string][]string `json:"pre_mod_dns,omitempty"`
}

// Legacy single-tunnel state file (kept for backward-compatible migration).
const activeTunnelFile = "active-tunnel.json"

// tunnelStatesDir is the directory that stores per-tunnel state files.
const tunnelStatesDir = "tunnel-states"

// stateFileName returns the per-tunnel state file name inside tunnelStatesDir.
func stateFileName(tunnelName string) string {
	// Sanitize the tunnel name so it's safe as a file name.
	safe := strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(tunnelName)
	return safe + ".json"
}

// SaveActiveState writes the active tunnel state to disk in a per-tunnel file.
func SaveActiveState(dataDir string, state *ActiveTunnelState) error {
	dir := filepath.Join(dataDir, tunnelStatesDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, stateFileName(state.TunnelName)), data, 0600)
}

// ClearActiveState removes the state file for a specific tunnel.
func ClearActiveState(dataDir string, tunnelName string) error {
	path := filepath.Join(dataDir, tunnelStatesDir, stateFileName(tunnelName))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ClearAllActiveStates removes all per-tunnel state files.
func ClearAllActiveStates(dataDir string) error {
	dir := filepath.Join(dataDir, tunnelStatesDir)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// LoadActiveState reads all active tunnel states from the tunnel-states
// directory. Falls back to the legacy single-file format for migration.
func LoadActiveState(dataDir string) []*ActiveTunnelState {
	// Try per-tunnel directory first.
	dir := filepath.Join(dataDir, tunnelStatesDir)
	entries, err := os.ReadDir(dir)
	if err == nil && len(entries) > 0 {
		var states []*ActiveTunnelState
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			var st ActiveTunnelState
			if err := json.Unmarshal(data, &st); err != nil {
				slog.Warn("corrupt tunnel state file, removing", "file", e.Name(), "error", err)
				os.Remove(filepath.Join(dir, e.Name()))
				continue
			}
			states = append(states, &st)
		}
		if len(states) > 0 {
			return states
		}
	}

	// Fallback: legacy single-file format.
	legacyPath := filepath.Join(dataDir, activeTunnelFile)
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		return nil
	}
	var st ActiveTunnelState
	if err := json.Unmarshal(data, &st); err != nil {
		slog.Warn("corrupt legacy active tunnel state file, removing", "error", err)
		os.Remove(legacyPath)
		return nil
	}
	return []*ActiveTunnelState{&st}
}

// RecoverFromCrash checks for orphaned tunnel state and cleans up.
// Returns the names of the cleaned-up tunnels, or nil if none.
//
// After a crash the TUN device is already gone (the process that owned it
// died), but routes, DNS overrides, and firewall rules may still reference
// the dead interface. We run a best-effort cleanup via the platform network
// manager to avoid leaving the user stuck on the tunnel's DNS servers or
// with unreachable bypass routes.
func RecoverFromCrash(dataDir string) []string {
	states := LoadActiveState(dataDir)
	if len(states) == 0 {
		return nil
	}

	mgr := network.NewPlatformManager()
	var recovered []string

	for _, state := range states {
		slog.Warn("detected orphaned tunnel from previous crash",
			"tunnel", state.TunnelName,
			"interface", state.InterfaceName)

		// Restore routing state (table/fwmark) from persisted values so that
		// cleanup uses the correct table instead of hardcoded defaults.
		if rs, ok := mgr.(network.RoutingStateRestorer); ok {
			rs.RestoreRoutingState(state.Table, state.FwMark)
		}

		// DNS: if we have pre-modification DNS state, restore it precisely.
		// Otherwise fall back to the blunt ResetDNSToSystemDefault which
		// clears everything to DHCP defaults (loses custom user preferences).
		if len(state.PreModDNS) > 0 {
			if restorer, ok := mgr.(network.DNSStateRestorer); ok {
				if err := restorer.RestoreDNSFromSnapshot(state.PreModDNS); err != nil {
					slog.Warn("crash recovery: precise DNS restore failed, falling back to reset", "error", err)
					_ = mgr.ResetDNSToSystemDefault()
				} else {
					slog.Info("crash recovery: DNS restored from pre-modification snapshot")
				}
			} else {
				_ = mgr.ResetDNSToSystemDefault()
			}
		} else {
			if err := mgr.ResetDNSToSystemDefault(); err != nil {
				slog.Warn("crash recovery: DNS reset failed", "error", err)
			}
		}

		// Routes: Cleanup knows how to walk the route table to find stale entries
		// pointing at the recorded interface name.
		if state.InterfaceName != "" {
			if err := mgr.RemoveRoutes(state.InterfaceName, nil, state.FullTunnel); err != nil {
				slog.Warn("crash recovery: route removal failed", "error", err)
			}
			if err := mgr.Cleanup(state.InterfaceName); err != nil {
				slog.Warn("crash recovery: network cleanup failed", "error", err)
			}
		}

		recovered = append(recovered, state.TunnelName)
	}

	// Firewall: clean up any leftover PF/nftables/netsh rules from the
	// crashed tunnel's kill switch or DNS protection.
	fwMgr := firewall.NewPlatformFirewall()
	if err := fwMgr.Cleanup(); err != nil {
		slog.Warn("crash recovery: firewall cleanup failed", "error", err)
	}

	// Clear all state files (both per-tunnel and legacy).
	ClearAllActiveStates(dataDir)
	os.Remove(filepath.Join(dataDir, activeTunnelFile)) // legacy cleanup

	return recovered
}
