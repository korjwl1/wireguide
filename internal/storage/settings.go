package storage

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/korjwl1/wireguide/internal/wifi"
)

// Settings holds application-wide settings.
type Settings struct {
	Language      string `json:"language"`        // "auto", "en", "ko", "ja"
	Theme         string `json:"theme"`           // "dark", "light", "system"
	TrayIconStyle string `json:"tray_icon_style"` // "color" (MVP: color only)
	AutoStart     bool   `json:"auto_start"`      // launch GUI on OS login
	KillSwitch    bool   `json:"kill_switch"`
	DNSProtection bool   `json:"dns_protection"`
	HealthCheck   bool   `json:"health_check"`  // periodic handshake age monitoring
	PinInterface  bool   `json:"pin_interface"` // pin bypass routes to upstream interface (-ifscope)
	LogLevel      string `json:"log_level"`     // "debug", "info", "warn", "error"
	CompactList   bool   `json:"compact_list"`  // dense tunnel list: hide endpoint line, shorter rows

	// ListSort controls tunnel-list ordering: "name_asc" (default),
	// "name_desc". ListActiveOnTop floats connected tunnels above the
	// sort. Both are pure view state managed from the list header.
	ListSort        string `json:"list_sort"`
	ListActiveOnTop bool   `json:"list_active_on_top"`
	// ListPaneWidth is the draggable width (px) of the tunnel-list
	// column. 0 falls back to the default.
	ListPaneWidth int `json:"list_pane_width,omitempty"`

	// AutoUpdateCheck controls the periodic update scheduler. *bool so we
	// can distinguish "user never touched this" from "user explicitly
	// turned it off" — defaults to true on first load. A user who installs
	// via brew might prefer to disable in-app checks and let brew handle
	// it instead; an offline / corporate-network user might disable to
	// silence the failed-check log noise.
	AutoUpdateCheck *bool `json:"auto_update_check,omitempty"`

	// WifiRules holds the LEGACY SSID-based auto-connect / auto-disconnect
	// policy. Retained for migration; superseded by Automation. Once
	// Automation is populated it is the source of truth and WifiRules is
	// no longer consulted by the rule engine.
	WifiRules wifi.Rules `json:"wifi_rules"`

	// Automation is the per-tunnel condition→action rule model (issue
	// #12). A nil pointer means "not yet migrated from WifiRules";
	// EnsureAutomation() populates it once from the legacy rules. A
	// non-nil (possibly empty) value means the user is on the new model.
	Automation *wifi.Automation `json:"automation,omitempty"`
}

// EnsureAutomation lazily migrates the legacy WifiRules into the
// Automation model the first time it's needed, so existing users keep
// their auto-connect/disconnect behaviour after the model change. It's a
// no-op once Automation is non-nil (the user is already on the new
// model), so it never overwrites edited rules. Callers that want the
// migration persisted must Save afterwards; the rule engine can call it
// on each load without persisting (it's deterministic and cheap).
func (s *Settings) EnsureAutomation() {
	if s.Automation != nil {
		return
	}
	s.Automation = wifi.MigrateFromLegacy(&s.WifiRules)
}

// RenameTunnelRules moves a tunnel's Automation (and legacy WifiRules)
// entries from oldName to newName. Automation rules are keyed by tunnel
// name, so a rename that doesn't carry them over silently orphans the
// rules — and, worse, they'd re-attach if a new tunnel later reused the
// old name (issue #12). Call inside a SettingsStore.Update.
func (s *Settings) RenameTunnelRules(oldName, newName string) {
	if oldName == newName {
		return
	}
	if s.Automation != nil && s.Automation.PerTunnel != nil {
		if r, ok := s.Automation.PerTunnel[oldName]; ok {
			s.Automation.PerTunnel[newName] = r
			delete(s.Automation.PerTunnel, oldName)
		}
	}
	if s.WifiRules.PerTunnel != nil {
		if r, ok := s.WifiRules.PerTunnel[oldName]; ok {
			s.WifiRules.PerTunnel[newName] = r
			delete(s.WifiRules.PerTunnel, oldName)
		}
	}
}

// DeleteTunnelRules drops a tunnel's Automation (and legacy WifiRules)
// entries so a deleted tunnel leaves no stale rules behind that could
// unexpectedly attach to a same-named tunnel created later (issue #12).
func (s *Settings) DeleteTunnelRules(name string) {
	if s.Automation != nil {
		delete(s.Automation.PerTunnel, name)
	}
	if s.WifiRules.PerTunnel != nil {
		delete(s.WifiRules.PerTunnel, name)
	}
}

// DefaultSettings returns settings with sensible defaults.
func DefaultSettings() *Settings {
	on := true
	return &Settings{
		Language:        "auto",
		Theme:           "system", // follows OS dark/light mode
		TrayIconStyle:   "color",
		KillSwitch:      false,
		DNSProtection:   false,
		HealthCheck:     false,
		PinInterface:    false, // off by default — enable for dual-network setups
		LogLevel:        "info",
		AutoUpdateCheck: &on,
		ListSort:        "name_asc",
		ListActiveOnTop: true,
		ListPaneWidth:   240,
		WifiRules: wifi.Rules{
			// Initialize the map so JSON serialization round-trips
			// produce {} rather than null for an empty mapping.
			PerTunnel: make(map[string]wifi.TunnelSSIDs),
		},
	}
}

// AutoUpdateCheckEnabled returns the effective value, treating nil
// (unset in legacy settings.json) as true. Callers should use this
// rather than dereferencing the pointer directly.
func (s *Settings) AutoUpdateCheckEnabled() bool {
	if s == nil || s.AutoUpdateCheck == nil {
		return true
	}
	return *s.AutoUpdateCheck
}

// SettingsStore manages the app settings JSON file.
type SettingsStore struct {
	mu   sync.Mutex
	path string
}

// NewSettingsStore creates a store for the given config directory.
func NewSettingsStore(configDir string) *SettingsStore {
	return &SettingsStore{
		path: filepath.Join(configDir, "config.json"),
	}
}

// Load reads settings from disk. Returns defaults if file doesn't exist.
func (s *SettingsStore) Load() (*Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

// loadLocked is Load without the mutex, for callers (Update) that already
// hold s.mu. Writes are atomic renames, so a concurrent writer never
// exposes a torn file to a reader — no file lock is needed just to read.
func (s *SettingsStore) loadLocked() (*Settings, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultSettings(), nil
		}
		return nil, err
	}

	settings := DefaultSettings()
	if err := json.Unmarshal(data, settings); err != nil {
		// Corrupt settings file (truncated write, manual edit, etc.) should
		// not prevent the application from starting. Log the error, back up
		// the corrupt file for debugging, and return default settings.
		slog.Warn("settings file is corrupt, falling back to defaults",
			"path", s.path, "error", err)
		// If the .corrupt rename fails (e.g. Windows file-in-use, ENOSPC),
		// the next Load would hit the same corrupt file and warn again
		// forever. Try to remove the corrupt source as a last resort so
		// the next Save can write a fresh file. Errors here are also
		// best-effort — the in-memory defaults still work for this
		// session.
		corruptPath := s.path + ".corrupt"
		if renameErr := os.Rename(s.path, corruptPath); renameErr != nil {
			slog.Warn("could not back up corrupt settings; attempting direct removal",
				"rename_error", renameErr)
			if rmErr := os.Remove(s.path); rmErr != nil {
				slog.Warn("could not remove corrupt settings either; will keep retrying on each Load",
					"remove_error", rmErr)
			}
		}
		return DefaultSettings(), nil
	}
	return settings, nil
}

// Update runs a read-modify-write of the settings file that is atomic
// ACROSS PROCESSES: it holds an exclusive file lock across the whole
// load → mutate → save, so a `wireguide ctl` edit and a GUI edit can't
// clobber each other (e.g. a CLI automation edit reverting a GUI
// kill-switch change). Field-level mutators (the CLI, tunnel rename/
// delete) should use this rather than Load-then-Save. mutate sees the
// freshest on-disk state.
func (s *SettingsStore) Update(mutate func(*Settings) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	lf, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := flockExclusive(int(lf.Fd())); err != nil {
		return err
	}
	defer flockUnlock(int(lf.Fd())) //nolint:errcheck
	settings, err := s.loadLocked()
	if err != nil {
		return err
	}
	if err := mutate(settings); err != nil {
		return err
	}
	return s.saveLocked(settings)
}

// Save writes settings to disk atomically. It takes the same
// cross-process file lock as Update so a whole-object GUI write can't
// interleave with an in-progress CLI Update at the file level.
func (s *SettingsStore) Save(settings *Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	if lf, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0600); err == nil {
		defer lf.Close()
		if flockExclusive(int(lf.Fd())) == nil {
			defer flockUnlock(int(lf.Fd())) //nolint:errcheck
		}
	}
	return s.saveLocked(settings)
}

// saveLocked is Save's body without the mutex/flock, for callers (Update)
// that already hold both.
func (s *SettingsStore) saveLocked(settings *Settings) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	// Ensure the config directory exists before writing (matches history's
	// saveLocked). Without this, os.CreateTemp fails when EnsureDirs hasn't
	// run or the directory was removed out from under us.
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(s.path), ".wireguide-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := atomicRenameDurable(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
