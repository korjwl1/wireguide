package app

import (
	"log/slog"
	"os"

	"github.com/korjwl1/wireguide/internal/autostart"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

// guiLogLevelSetter is set by internal/gui at startup so the app package
// (which is Wails-bound) can update the GUI process's own log level at
// runtime without importing internal/gui (which would create an import
// cycle). SetLogLevel below calls this in addition to forwarding the
// level to the helper.
var guiLogLevelSetter func(string)

// SetGUILogLevelSetter is called once from internal/gui.Run to register
// the GUI-side log level mutator. Safe to call before NewTunnelService.
func SetGUILogLevelSetter(f func(string)) {
	guiLogLevelSetter = f
}

// --- Settings (all local, no IPC) ---

func (s *TunnelService) GetSettings() (*storage.Settings, error) {
	return s.settingsStore.Load()
}

// SaveSettings persists the settings file AND applies any side effects:
// currently, pushing the new log level to both the GUI's slog handler and
// the helper's slog handler. Without those side effects a user lowering the
// level to Debug wouldn't see any new records — the saved file would match
// the UI but the running process would still be at Info.
func (s *TunnelService) SaveSettings(settings *storage.Settings) error {
	// Read the previous state first so we only (un)install the autostart
	// entry when the user actually toggles it. This avoids rewriting the
	// LaunchAgent plist / desktop file on every unrelated setting change.
	prev, _ := s.settingsStore.Load()

	if err := s.settingsStore.Save(settings); err != nil {
		return err
	}

	if prev == nil || prev.AutoStart != settings.AutoStart {
		if settings.AutoStart {
			exe, err := os.Executable()
			if err != nil {
				slog.Warn("autostart: cannot resolve exe path", "error", err)
			} else if err := autostart.InstallAutostart(exe); err != nil {
				slog.Warn("autostart: install failed", "error", err)
			}
		} else {
			if err := autostart.RemoveAutostart(); err != nil && !os.IsNotExist(err) {
				slog.Warn("autostart: remove failed", "error", err)
			}
		}
	}
	if settings.LogLevel != "" {
		if guiLogLevelSetter != nil {
			guiLogLevelSetter(settings.LogLevel)
		}
		// Best-effort: the helper may be unreachable during shutdown, and
		// the level change is not critical to Save succeeding.
		_ = s.call(ipc.MethodSetLogLevel, ipc.SetLogLevelRequest{Level: settings.LogLevel}, nil)
	}
	return nil
}

// SetLogLevel updates both the GUI's and the helper's slog level
// immediately. Exposed as a Wails method so the Settings view can call
// it without waiting for a full SaveSettings round trip.
func (s *TunnelService) SetLogLevel(level string) error {
	if guiLogLevelSetter != nil {
		guiLogLevelSetter(level)
	}
	return s.call(ipc.MethodSetLogLevel, ipc.SetLogLevelRequest{Level: level}, nil)
}

// --- Firewall toggles (go through helper) ---

// SetKillSwitch asks the helper to enable or disable the firewall kill switch.
func (s *TunnelService) SetKillSwitch(enabled bool) error {
	return s.call(ipc.MethodSetKillSwitch, ipc.KillSwitchRequest{Enabled: enabled}, nil)
}

// SetDNSProtection asks the helper to lock DNS to the active tunnel's servers.
// When enabling, we look up the active tunnel's DNS list from local storage
// and pass it along (the helper never touches user-space storage).
func (s *TunnelService) SetDNSProtection(enabled bool) error {
	var dnsServers []string
	if enabled {
		var active ipc.StringResponse
		_ = s.call(ipc.MethodActiveName, nil, &active)
		if active.Value != "" {
			if cfg, err := s.tunnelStore.Load(active.Value); err == nil {
				dnsServers = cfg.Interface.DNS
			}
		}
	}
	return s.call(ipc.MethodSetDNSProtection, ipc.DNSProtectionRequest{
		Enabled:    enabled,
		DNSServers: dnsServers,
	}, nil)
}
