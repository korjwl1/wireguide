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

	// WifiRules holds the SSID-based auto-connect / auto-disconnect
	// policy. Disabled by default; the frontend Settings panel toggles
	// it and per-SSID mappings. Evaluated by the GUI on each SSID
	// change broadcast from the helper.
	WifiRules wifi.Rules `json:"wifi_rules"`
}

// DefaultSettings returns settings with sensible defaults.
func DefaultSettings() *Settings {
	return &Settings{
		Language:      "auto",
		Theme:         "system", // follows OS dark/light mode
		TrayIconStyle: "color",
		KillSwitch:    false,
		DNSProtection: false,
		HealthCheck:   false,
		PinInterface:  false, // off by default — enable for dual-network setups
		LogLevel:      "info",
		WifiRules: wifi.Rules{
			// Initialize the map so JSON serialization round-trips
			// produce {} rather than null for an empty mapping.
			PerTunnel: make(map[string]wifi.TunnelSSIDs),
		},
	}
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
		_ = os.Rename(s.path, s.path+".corrupt")
		return DefaultSettings(), nil
	}
	return settings, nil
}

// Save writes settings to disk atomically.
func (s *SettingsStore) Save(settings *Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
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
	if err := atomicRename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
