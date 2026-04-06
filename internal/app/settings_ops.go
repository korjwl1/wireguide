package app

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync/atomic"

	"github.com/korjwl1/wireguide/internal/autostart"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/update"
)

// guiLogLevelSetter is set by internal/gui at startup so the app package
// (which is Wails-bound) can update the GUI process's own log level at
// runtime without importing internal/gui (which would create an import
// cycle). SetLogLevel below calls this in addition to forwarding the
// level to the helper. Uses atomic.Value for safe concurrent access.
var guiLogLevelSetter atomic.Value // stores func(string)

// SetGUILogLevelSetter is called once from internal/gui.Run to register
// the GUI-side log level mutator. Safe to call before NewTunnelService.
func SetGUILogLevelSetter(f func(string)) {
	guiLogLevelSetter.Store(f)
}

func getGUILogLevelSetter() func(string) {
	if v := guiLogLevelSetter.Load(); v != nil {
		return v.(func(string))
	}
	return nil
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
				return fmt.Errorf("autostart: cannot resolve exe path: %w", err)
			}
			if err := autostart.InstallAutostart(exe); err != nil {
				return fmt.Errorf("autostart: install failed: %w", err)
			}
		} else {
			if err := autostart.RemoveAutostart(); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("autostart: remove failed: %w", err)
			}
		}
	}
	if settings.LogLevel != "" {
		if fn := getGUILogLevelSetter(); fn != nil {
			fn(settings.LogLevel)
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
	if fn := getGUILogLevelSetter(); fn != nil {
		fn(level)
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
		if err := s.call(ipc.MethodActiveName, nil, &active); err != nil {
			return fmt.Errorf("cannot verify tunnel state: %w", err)
		}
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

// --- Auto-update ---

// GetVersion returns the current app version string.
func (s *TunnelService) GetVersion() string {
	return update.CurrentVersion()
}

// CheckForUpdate queries GitHub for a newer release.
func (s *TunnelService) CheckForUpdate() (*update.UpdateInfo, error) {
	return update.CheckForUpdate()
}

// RunUpdate performs the update. If installed via Homebrew, runs brew upgrade.
// Otherwise downloads and installs directly from GitHub Releases.
func (s *TunnelService) RunUpdate(info *update.UpdateInfo) error {
	if info == nil || !info.Available {
		return fmt.Errorf("no update available")
	}

	if runtime.GOOS == "darwin" && update.IsBrewInstall() {
		slog.Info("update: running brew upgrade --cask wireguide")
		cmd := exec.Command("brew", "upgrade", "--cask", "wireguide")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("brew upgrade failed: %w (%s)", err, string(out))
		}
		// postflight in the cask handles killall + relaunch
		return nil
	}

	// Direct download path (non-brew installs)
	path, err := update.DownloadUpdate(info)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	return update.Install(path, info)
}
