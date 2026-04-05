package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Settings holds application-wide settings.
type Settings struct {
	Language       string `json:"language"`        // "auto", "en", "ko", "ja"
	Theme          string `json:"theme"`           // "dark", "light", "system"
	TrayIconStyle  string `json:"tray_icon_style"` // "color" (MVP: color only)
	AutoReconnect  bool   `json:"auto_reconnect"`
	KillSwitch     bool   `json:"kill_switch"`
	DNSProtection  bool   `json:"dns_protection"`
	LogLevel       string `json:"log_level"`       // "debug", "info", "warn", "error"
}

// DefaultSettings returns settings with sensible defaults.
func DefaultSettings() *Settings {
	return &Settings{
		Language:      "auto",
		Theme:         "system", // follows OS dark/light mode
		TrayIconStyle: "color",
		AutoReconnect: true,
		KillSwitch:    false,
		DNSProtection: false,
		LogLevel:      "info",
	}
}

// SettingsStore manages the app settings JSON file.
type SettingsStore struct {
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
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultSettings(), nil
		}
		return nil, err
	}

	settings := DefaultSettings()
	if err := json.Unmarshal(data, settings); err != nil {
		return nil, err
	}
	return settings, nil
}

// Save writes settings to disk atomically.
func (s *SettingsStore) Save(settings *Settings) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
