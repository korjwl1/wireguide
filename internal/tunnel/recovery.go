package tunnel

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"

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
//
// After a crash the TUN device is already gone (the process that owned it
// died), but routes, DNS overrides, and firewall rules may still reference
// the dead interface. We run a best-effort cleanup via the platform network
// manager to avoid leaving the user stuck on the tunnel's DNS servers or
// with unreachable bypass routes.
//
// Important: RestoreDNS relies on the in-memory "savedDNS" snapshot from
// SetDNS, which a fresh process doesn't have. We therefore call the
// state-free ResetDNSToSystemDefault() instead, which clears overrides
// back to DHCP-provided values for every network service. Users lose any
// custom DNS preferences on the crash recovery path — an acceptable
// trade-off vs. being stuck on a dead tunnel's DNS.
func RecoverFromCrash(dataDir string) string {
	state := LoadActiveState(dataDir)
	if state == nil {
		return ""
	}
	slog.Warn("detected orphaned tunnel from previous crash",
		"tunnel", state.TunnelName,
		"interface", state.InterfaceName)

	mgr := network.NewPlatformManager()

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
	// pointing at the recorded interface name, so this works even on a fresh
	// process. This also handles policy rules and routing tables on Linux.
	if state.InterfaceName != "" {
		if err := mgr.RemoveRoutes(state.InterfaceName, nil, state.FullTunnel); err != nil {
			slog.Warn("crash recovery: route removal failed", "error", err)
		}
		if err := mgr.Cleanup(state.InterfaceName); err != nil {
			slog.Warn("crash recovery: network cleanup failed", "error", err)
		}
	}

	// Firewall: clean up any leftover PF/nftables/netsh rules from the
	// crashed tunnel's kill switch or DNS protection.
	fwMgr := firewall.NewPlatformFirewall()
	if err := fwMgr.Cleanup(); err != nil {
		slog.Warn("crash recovery: firewall cleanup failed", "error", err)
	}

	ClearActiveState(dataDir)
	return state.TunnelName
}
