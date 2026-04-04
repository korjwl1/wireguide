// Package app provides Wails bindings bridging Go backend and Svelte frontend.
package app

import (
	"fmt"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// TunnelService exposes tunnel operations to the frontend via Wails bindings.
type TunnelService struct {
	tunnelStore   *storage.TunnelStore
	settingsStore *storage.SettingsStore
	manager       *tunnel.Manager
}

// NewTunnelService creates a new TunnelService.
func NewTunnelService(tunnelStore *storage.TunnelStore, settingsStore *storage.SettingsStore, manager *tunnel.Manager) *TunnelService {
	return &TunnelService{
		tunnelStore:   tunnelStore,
		settingsStore: settingsStore,
		manager:       manager,
	}
}

// TunnelInfo is a summary of a tunnel for the UI list.
type TunnelInfo struct {
	Name        string `json:"name"`
	IsConnected bool   `json:"is_connected"`
	Endpoint    string `json:"endpoint"`
	HasScripts  bool   `json:"has_scripts"`
}

// ListTunnels returns all saved tunnels with their connection status.
func (s *TunnelService) ListTunnels() ([]TunnelInfo, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}

	activeTunnel := s.manager.ActiveTunnel()
	var tunnels []TunnelInfo

	for _, name := range names {
		cfg, err := s.tunnelStore.Load(name)
		if err != nil {
			continue
		}
		endpoint := ""
		if len(cfg.Peers) > 0 {
			endpoint = cfg.Peers[0].Endpoint
		}
		tunnels = append(tunnels, TunnelInfo{
			Name:        name,
			IsConnected: name == activeTunnel,
			Endpoint:    endpoint,
			HasScripts:  cfg.HasScripts(),
		})
	}
	return tunnels, nil
}

// GetTunnelDetail returns full config details for a tunnel.
func (s *TunnelService) GetTunnelDetail(name string) (*config.WireGuardConfig, error) {
	return s.tunnelStore.Load(name)
}

// Connect connects to the named tunnel.
func (s *TunnelService) Connect(name string, scriptsAllowed bool) error {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return fmt.Errorf("loading tunnel %s: %w", name, err)
	}
	return s.manager.Connect(cfg, scriptsAllowed)
}

// Disconnect disconnects the active tunnel.
func (s *TunnelService) Disconnect() error {
	return s.manager.Disconnect()
}

// GetStatus returns the current connection status.
func (s *TunnelService) GetStatus() *tunnel.ConnectionStatus {
	return s.manager.Status()
}

// DeleteTunnel removes a tunnel. Cannot delete a connected tunnel.
func (s *TunnelService) DeleteTunnel(name string) error {
	if s.manager.ActiveTunnel() == name {
		return fmt.Errorf("cannot delete connected tunnel %q — disconnect first", name)
	}
	return s.tunnelStore.Delete(name)
}

// ImportConfig imports a .conf from text content.
func (s *TunnelService) ImportConfig(name, content string) (*TunnelInfo, error) {
	cfg, err := s.tunnelStore.ImportFromContent(name, content)
	if err != nil {
		return nil, err
	}
	endpoint := ""
	if len(cfg.Peers) > 0 {
		endpoint = cfg.Peers[0].Endpoint
	}
	return &TunnelInfo{
		Name:       cfg.Name,
		Endpoint:   endpoint,
		HasScripts: cfg.HasScripts(),
	}, nil
}

// ValidateConfig validates .conf content without saving.
func (s *TunnelService) ValidateConfig(content string) ([]string, error) {
	cfg, err := config.Parse(content)
	if err != nil {
		return []string{err.Error()}, nil
	}
	result := config.Validate(cfg)
	if result.IsValid() {
		return nil, nil
	}
	return result.ErrorMessages(), nil
}

// GetConfigText returns the raw .conf text for editing.
func (s *TunnelService) GetConfigText(name string) (string, error) {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return "", err
	}
	return config.Serialize(cfg), nil
}

// UpdateConfig updates a tunnel's config from text. Cannot update connected tunnel.
func (s *TunnelService) UpdateConfig(name, content string) error {
	if s.manager.ActiveTunnel() == name {
		return fmt.Errorf("cannot edit connected tunnel %q — disconnect first", name)
	}
	cfg, err := config.Parse(content)
	if err != nil {
		return err
	}
	result := config.Validate(cfg)
	if !result.IsValid() {
		return fmt.Errorf("validation failed: %s", result.ErrorMessages()[0])
	}
	cfg.Name = name
	return s.tunnelStore.Save(cfg)
}

// ExportConfig returns the .conf text for export/download.
func (s *TunnelService) ExportConfig(name string) (string, error) {
	return s.GetConfigText(name)
}

// GetSettings returns the current app settings.
func (s *TunnelService) GetSettings() (*storage.Settings, error) {
	return s.settingsStore.Load()
}

// SaveSettings saves app settings.
func (s *TunnelService) SaveSettings(settings *storage.Settings) error {
	return s.settingsStore.Save(settings)
}

// TunnelExists checks if a tunnel name already exists.
func (s *TunnelService) TunnelExists(name string) bool {
	return s.tunnelStore.Exists(name)
}
