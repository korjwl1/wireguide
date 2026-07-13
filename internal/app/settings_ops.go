package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/korjwl1/wireguide/internal/autostart"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/update"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// KnownSSIDs is the response shape for GetKnownSSIDs. The frontend uses
// it to render a picker so users can tap saved networks instead of
// retyping SSIDs they've already joined.
type KnownSSIDs struct {
	Current string   `json:"current"` // currently-connected SSID (empty if not on Wi-Fi)
	Known   []string `json:"known"`   // saved/preferred networks reported by the OS
}

// GetKnownSSIDs returns the currently-connected SSID (if any) plus the
// system's saved wireless networks. Both are best-effort — empty values
// are normal on a Mac that's only ever been on Ethernet.
func (s *TunnelService) GetKnownSSIDs() KnownSSIDs {
	return KnownSSIDs{
		Current: wifi.CurrentSSID(),
		Known:   wifi.KnownSSIDs(),
	}
}

// GetCurrentSubnets returns the network CIDRs of the physical interfaces
// the machine is currently on (Wi-Fi or Ethernet). The Automation editor
// offers these as suggestions for subnet conditions so the user can
// target the network they're on without knowing its CIDR.
func (s *TunnelService) GetCurrentSubnets() []string {
	return wifi.PhysicalSubnets()
}

// CurrentNetwork is the fingerprint of the network the machine is on now,
// for the Automation editor's "use current network" button.
type CurrentNetwork struct {
	GatewayMAC string `json:"gateway_mac"` // "" when unavailable (e.g. Windows, no gateway)
	Label      string `json:"label"`       // human hint, e.g. "192.168.0.0/24"
}

// GetCurrentNetwork returns the current default-gateway MAC fingerprint
// plus a readable label (the current subnet) so the editor can capture
// "this network" precisely without the user typing a MAC. GatewayMAC is
// empty when it can't be determined.
func (s *TunnelService) GetCurrentNetwork() CurrentNetwork {
	label := ""
	if subs := wifi.PhysicalSubnets(); len(subs) > 0 {
		label = subs[0]
	}
	return CurrentNetwork{
		GatewayMAC: wifi.GatewayMAC(),
		Label:      label,
	}
}

// RecordCurrentNetwork remembers the network the machine is on right now
// in the known-networks registry (keyed by gateway MAC) and returns the
// full registry, newest first. Called by the Automation editor on open
// and by the GUI as it roams, so the "this network" condition can offer a
// pick-list of networks the user has visited — including ones they aren't
// currently on. No-op (returns the existing list) when no gateway MAC is
// available.
func (s *TunnelService) RecordCurrentNetwork() ([]storage.KnownNetwork, error) {
	cur := s.GetCurrentNetwork()
	settings, err := s.settingsStore.Load()
	if err != nil {
		return nil, err
	}
	if cur.GatewayMAC != "" {
		if settings.RecordKnownNetwork(cur.GatewayMAC, cur.Label, time.Now().Unix()) {
			if err := s.settingsStore.Save(settings); err != nil {
				return nil, err
			}
		}
	}
	nets := append([]storage.KnownNetwork(nil), settings.KnownNetworks...)
	// Newest first (simple insertion sort — the list is tiny).
	for i := 1; i < len(nets); i++ {
		for j := i; j > 0 && nets[j].LastSeenUnix > nets[j-1].LastSeenUnix; j-- {
			nets[j], nets[j-1] = nets[j-1], nets[j]
		}
	}
	return nets, nil
}

// CheckSSIDPermission reports whether the process can read the current SSID.
// Used by the frontend to prompt the user for Location Services access before
// Wi-Fi auto-connect rules can fire.
func (s *TunnelService) CheckSSIDPermission() wifi.SSIDPermissionStatus {
	return wifi.CheckSSIDPermission()
}

// OpenLocationSettings opens System Settings to the Location Services page so
// the user can grant SSID access without navigating there manually.
func (s *TunnelService) OpenLocationSettings() {
	if runtime.GOOS == "darwin" {
		exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices").Start() //nolint:errcheck
	}
}

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
	settings, err := s.settingsStore.Load()
	if err != nil {
		return nil, err
	}
	// Always hand the frontend a populated Automation model so the rule
	// editor can read/edit it directly — EnsureAutomation lazily migrates
	// the legacy WifiRules the first time (in memory; persisted only when
	// the user saves). Without this the UI would see a null automation for
	// legacy users and couldn't show their migrated rules.
	if settings != nil {
		settings.EnsureAutomation()
	}
	return settings, nil
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

	// Auto-update toggle OFF→ON: nudge the scheduler so the user doesn't
	// have to wait up to 24 h for the next regular tick. The force flag
	// on Kick bypasses the focusRecheckThreshold gate (we *want* to
	// re-check immediately after the user opts back in, regardless of
	// when the last check ran). OFF→OFF, ON→ON, and ON→OFF all skip.
	prevEnabled := prev == nil || prev.AutoUpdateCheckEnabled()
	if !prevEnabled && settings.AutoUpdateCheckEnabled() && s.updateScheduler != nil {
		s.updateScheduler.Kick(true)
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

// SetPinInterface enables or disables -ifscope bypass route pinning.
func (s *TunnelService) SetPinInterface(enabled bool) error {
	return s.call(ipc.MethodSetPinInterface, ipc.SetPinInterfaceRequest{Enabled: enabled}, nil)
}

// SetHealthCheck enables or disables the tunnel health check monitor.
func (s *TunnelService) SetHealthCheck(enabled bool) error {
	return s.call(ipc.MethodSetHealthCheck, ipc.SetHealthCheckRequest{Enabled: enabled}, nil)
}

// OpenURL opens a URL in the default browser. Only HTTPS URLs on
// github.com are allowed to prevent misuse from a compromised frontend.
func (s *TunnelService) OpenURL(url string) error {
	if !strings.HasPrefix(url, "https://github.com/") {
		return fmt.Errorf("URL not allowed: %s", url)
	}
	if s.app != nil {
		return s.app.Browser.OpenURL(url)
	}
	return fmt.Errorf("app not initialized")
}

// GetVersion returns the current app version string.
func (s *TunnelService) GetVersion() string {
	return update.CurrentVersion()
}

// CheckForUpdate is the legacy synchronous check kept for backward
// compatibility with the (now-removed) onMount call. New code should call
// ManualCheckForUpdate, which routes through the scheduler so the result
// is also persisted (ETag, last-checked timestamp) and the in-app banner
// can update without a separate round-trip.
func (s *TunnelService) CheckForUpdate() (*update.UpdateInfo, error) {
	if s.updateScheduler != nil {
		res, err := s.updateScheduler.CheckNow()
		if err != nil {
			return nil, err
		}
		if res == nil || res.Info == nil {
			return &update.UpdateInfo{Available: false, CurrentVer: update.CurrentVersion()}, nil
		}
		return res.Info, nil
	}
	return update.CheckForUpdate()
}

// UpdateState is the frontend-facing snapshot of persisted check state.
// Exposed so Settings → About can render the "Last checked …" line and
// the first-check placeholder correctly.
//
// IsDevBuild + AutoEnabled together let the UI distinguish three
// "not-yet-checked" cases that look identical to a naive `last_check==0`
// gate:
//
//	dev build  → scheduler is intentionally inert, show "Never checked"
//	auto off   → user disabled the scheduler, show "Never checked"
//	auto on    → first tick is 30–120 s away, show "scheduled" hint
//
// CurrentVersion is duplicated here (also in GetVersion()) so the About
// tab doesn't need two round-trips to render.
type UpdateState struct {
	CurrentVersion    string   `json:"current_version"`
	LastCheckUnix     int64    `json:"last_check_unix"`
	LastSeenVersion   string   `json:"last_seen_version"`
	DismissedVersions []string `json:"dismissed_versions"`
	IsDevBuild        bool     `json:"is_dev_build"`
	AutoEnabled       bool     `json:"auto_enabled"`
}

// GetUpdateState returns persisted state for the About tab UI.
func (s *TunnelService) GetUpdateState() UpdateState {
	out := UpdateState{
		CurrentVersion: update.CurrentVersion(),
		IsDevBuild:     update.IsDevBuild(),
		AutoEnabled:    true,
	}
	if s.settingsStore != nil {
		if cfg, _ := s.settingsStore.Load(); cfg != nil {
			out.AutoEnabled = cfg.AutoUpdateCheckEnabled()
		}
	}
	if s.updateStore != nil {
		st := s.updateStore.Get()
		out.LastCheckUnix = st.LastCheckUnix
		out.LastSeenVersion = st.LastSeenVersion
		out.DismissedVersions = st.DismissedVersions
	}
	return out
}

// DismissUpdate persists a version dismissal so the in-app banner stays
// hidden across restarts until a newer version arrives.
func (s *TunnelService) DismissUpdate(version string) error {
	if s.updateStore == nil {
		return nil
	}
	return s.updateStore.Dismiss(version)
}

// RunUpdate performs the update end-to-end:
//
//   - Homebrew installs → `brew update && brew upgrade --cask wireguide`,
//     letting the cask's postflight handle the killall + relaunch. This
//     is the "one-click" expectation users have, not "copy this command
//     into your terminal".
//   - Non-brew installs → open the GitHub Releases page in the browser.
//     Auto-replacing an un-notarised `.app` bundle needs sudo and races
//     with Gatekeeper quarantining of the new binary; redirecting the
//     user to the download page is the honest path for an indie macOS
//     app without an Apple Developer account.
func (s *TunnelService) RunUpdate(info *update.UpdateInfo) error {
	if info == nil || !info.Available {
		return fmt.Errorf("no update available")
	}

	if runtime.GOOS == "darwin" && update.IsBrewInstall() {
		brewBin := update.BrewPath()

		// `brew update` is pure-network (git fetch on tap repos); 90 s is
		// generous even on a slow link. If it hangs past that, the GitHub
		// API or the user's DNS is wedged — we'd rather surface that to
		// the user via a clear timeout than spin forever with "Updating…".
		updCtx, updCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer updCancel()
		slog.Info("update: running brew update", "brew", brewBin)
		if out, err := exec.CommandContext(updCtx, brewBin, "update").CombinedOutput(); err != nil {
			slog.Warn("brew update failed, continuing with upgrade", "error", err, "output", string(out))
		}

		// `brew upgrade --cask wireguide` runs the cask postflight which
		// killalls and relaunches us. The postflight typically completes
		// in 10–20 s; 5 min is a defensive ceiling for slow disks or
		// signature-check work — if we hit it, brew is genuinely stuck.
		//
		// Note: the cask postflight kills *this* process, which is the
		// parent of brew's exec. Go's exec.CommandContext attaches the
		// child's Wait, but a SIGKILL on the parent terminates the wait
		// before brew completes — the new wireguide binary that brew
		// installs will be launched fresh, so this RunUpdate's return
		// value never gets surfaced anywhere in practice.
		upCtx, upCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer upCancel()
		slog.Info("update: running brew upgrade --cask wireguide")
		cmd := exec.CommandContext(upCtx, brewBin, "upgrade", "--cask", "wireguide")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("brew upgrade failed: %w (%s)", err, string(out))
		}
		return nil
	}

	slog.Info("update: opening GitHub Releases page (non-brew install)")
	if s.app != nil {
		return s.app.Browser.OpenURL("https://github.com/korjwl1/wireguide/releases/latest")
	}
	return exec.Command("open", "https://github.com/korjwl1/wireguide/releases/latest").Run()
}
