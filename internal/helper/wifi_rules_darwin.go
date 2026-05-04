//go:build darwin

package helper

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/korjwl1/wireguide/internal/storage"
)

// deriveUserAppSupport returns the user's macOS Application Support
// directory for WireGuide given the uid passed to the helper at
// launch (`--uid` from the LaunchDaemon plist). The helper itself
// runs as root, so we can't read os.UserHomeDir() — that returns
// /var/root. Looking the user up by uid recovers their actual home.
func deriveUserAppSupport(uid int) (string, error) {
	if uid < 0 {
		return "", fmt.Errorf("invalid uid %d", uid)
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", fmt.Errorf("user.LookupId %d: %w", uid, err)
	}
	return filepath.Join(u.HomeDir, "Library", "Application Support", "wireguide"), nil
}

// loadUserSettings reads the user's settings.json directly. Reading
// fresh on every SSID transition (instead of caching + IPC sync from
// the GUI) means rule edits made in Settings take effect on the next
// network change without any explicit push, and there's no "in-memory
// state diverged from disk" failure mode.
func (h *Helper) loadUserSettings() (*storage.Settings, error) {
	if h.userAppSupport == "" {
		return nil, fmt.Errorf("user app-support dir not derived")
	}
	path := filepath.Join(h.userAppSupport, "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return storage.DefaultSettings(), nil
		}
		return nil, err
	}
	s := storage.DefaultSettings()
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	return s, nil
}

// handleSSIDChange evaluates the user's wifi rules against newSSID
// and triggers the matching connect/disconnect actions. This runs
// entirely inside the helper, so the rules keep firing whether or
// not a GUI is alive.
//
// Auto-management semantics:
//
//   - A trusted SSID disconnects every active tunnel and clears the
//     auto-managed map.
//   - A matched SSID auto-connects that tunnel and records it in the
//     auto-managed map. Tunnels in the map that no longer match the
//     current SSID get auto-disconnected.
//   - A no-rule SSID disconnects only auto-managed tunnels —
//     manually-connected tunnels are never touched.
//
// The map lives only in memory; on helper restart the user starts
// fresh, which is the intuitive "I rebooted, anything still up was
// connected by me" behavior.
func (h *Helper) handleSSIDChange(oldSSID, newSSID string) {
	if newSSID == "" {
		// Wi-Fi off (or unknown). Network change detection will
		// handle reconnect on the new interface; we don't want to
		// thrash tunnels here.
		return
	}
	settings, err := h.loadUserSettings()
	if err != nil {
		slog.Debug("wifi rule eval: cannot load settings", "error", err)
		return
	}
	rules := &settings.WifiRules
	if !rules.Enabled {
		return
	}
	action, tunnelName := rules.Action(newSSID)

	// Snapshot the auto-managed map under the lock, then operate
	// without holding it (manager calls can take seconds on slow
	// reconnects).
	h.wifiMu.Lock()
	autoSnapshot := make(map[string]string, len(h.autoConnectedBy))
	for k, v := range h.autoConnectedBy {
		autoSnapshot[k] = v
	}
	h.wifiMu.Unlock()

	switch action {
	case "disconnect":
		slog.Info("wifi rule: trusted SSID, disconnecting all", "ssid", newSSID)
		_ = h.manager.Disconnect()
		h.wifiMu.Lock()
		h.autoConnectedBy = make(map[string]string)
		h.wifiMu.Unlock()

	case "connect":
		// Disconnect every other auto-managed tunnel — switching
		// SSID means the previous auto-connect zone is gone.
		for name := range autoSnapshot {
			if name == tunnelName {
				continue
			}
			slog.Info("wifi rule: leaving SSID, disconnecting auto-managed",
				"tunnel", name, "old_ssid", autoSnapshot[name], "new_ssid", newSSID)
			_ = h.manager.DisconnectTunnel(name)
			h.wifiMu.Lock()
			delete(h.autoConnectedBy, name)
			h.wifiMu.Unlock()
		}
		// Connect the matched tunnel if it isn't already up.
		alreadyUp := false
		for _, n := range h.manager.ActiveTunnels() {
			if n == tunnelName {
				alreadyUp = true
				break
			}
		}
		if alreadyUp {
			h.wifiMu.Lock()
			h.autoConnectedBy[tunnelName] = newSSID
			h.wifiMu.Unlock()
			return
		}
		if h.userTunnelStore == nil {
			slog.Warn("wifi rule: tunnel store unavailable, cannot connect",
				"tunnel", tunnelName)
			return
		}
		cfg, err := h.userTunnelStore.Load(tunnelName)
		if err != nil {
			slog.Warn("wifi rule: cannot load tunnel config",
				"tunnel", tunnelName, "error", err)
			return
		}
		slog.Info("wifi rule: matched SSID, connecting",
			"ssid", newSSID, "tunnel", tunnelName)
		h.connectMu.Lock()
		err = h.manager.Connect(cfg)
		h.connectMu.Unlock()
		if err != nil {
			slog.Warn("wifi rule connect failed", "tunnel", tunnelName, "error", err)
			return
		}
		// Cache the cfg in activeCfgs so reconnect monitor and
		// recovery treat it the same as a GUI-initiated connect.
		h.mu.Lock()
		h.activeCfgs[cfg.Name] = cfg
		h.mu.Unlock()
		h.wifiMu.Lock()
		h.autoConnectedBy[tunnelName] = newSSID
		h.wifiMu.Unlock()

	case "none":
		// New SSID has no rule. Tear down only auto-managed tunnels.
		for name := range autoSnapshot {
			slog.Info("wifi rule: SSID no longer in auto-connect list, disconnecting",
				"tunnel", name, "previous_ssid", autoSnapshot[name], "new_ssid", newSSID)
			_ = h.manager.DisconnectTunnel(name)
			h.wifiMu.Lock()
			delete(h.autoConnectedBy, name)
			h.wifiMu.Unlock()
		}
	}
}
