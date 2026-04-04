// Package app provides Wails bindings bridging Svelte frontend and Go backend directly.
package app

import (
	"fmt"
	"strings"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// TunnelService exposes tunnel operations to Svelte frontend via Wails bindings.
type TunnelService struct {
	tunnelStore   *storage.TunnelStore
	settingsStore *storage.SettingsStore
	manager       *tunnel.Manager
	firewall      firewall.FirewallManager
}

// NewTunnelService creates a service with direct access to manager and storage.
func NewTunnelService(ts *storage.TunnelStore, ss *storage.SettingsStore, mgr *tunnel.Manager, fw firewall.FirewallManager) *TunnelService {
	return &TunnelService{
		tunnelStore:   ts,
		settingsStore: ss,
		manager:       mgr,
		firewall:      fw,
	}
}

// --- Types for frontend ---

type TunnelInfo struct {
	Name        string `json:"name"`
	IsConnected bool   `json:"is_connected"`
	Endpoint    string `json:"endpoint"`
	HasScripts  bool   `json:"has_scripts"`
}

type ConnectionStatus struct {
	State         string `json:"state"`
	TunnelName    string `json:"tunnel_name"`
	InterfaceName string `json:"interface_name"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	LastHandshake string `json:"last_handshake"`
	Duration      string `json:"duration"`
	Endpoint      string `json:"endpoint"`
}

// --- Tunnel operations ---

func (s *TunnelService) ListTunnels() ([]TunnelInfo, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}
	activeName := s.manager.ActiveTunnel()
	var result []TunnelInfo
	for _, name := range names {
		cfg, err := s.tunnelStore.Load(name)
		if err != nil {
			continue
		}
		endpoint := ""
		if len(cfg.Peers) > 0 {
			endpoint = cfg.Peers[0].Endpoint
		}
		result = append(result, TunnelInfo{
			Name:        name,
			IsConnected: name == activeName,
			Endpoint:    endpoint,
			HasScripts:  cfg.HasScripts(),
		})
	}
	return result, nil
}

func (s *TunnelService) Connect(name string, scriptsAllowed bool) error {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return fmt.Errorf("loading tunnel %s: %w", name, err)
	}
	return s.manager.Connect(cfg, scriptsAllowed)
}

func (s *TunnelService) Disconnect() error {
	return s.manager.Disconnect()
}

func (s *TunnelService) GetStatus() *ConnectionStatus {
	status := s.manager.Status()
	return &ConnectionStatus{
		State:         string(status.State),
		TunnelName:    status.TunnelName,
		InterfaceName: status.InterfaceName,
		RxBytes:       status.RxBytes,
		TxBytes:       status.TxBytes,
		LastHandshake: status.HandshakeAge,
		Duration:      status.Duration,
		Endpoint:      status.Endpoint,
	}
}

func (s *TunnelService) GetTunnelDetail(name string) (*config.WireGuardConfig, error) {
	return s.tunnelStore.Load(name)
}

func (s *TunnelService) DeleteTunnel(name string) error {
	if s.manager.ActiveTunnel() == name {
		return fmt.Errorf("cannot delete connected tunnel %q — disconnect first", name)
	}
	return s.tunnelStore.Delete(name)
}

// --- Config management ---

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

func (s *TunnelService) GetConfigText(name string) (string, error) {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return "", err
	}
	return config.Serialize(cfg), nil
}

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
		return fmt.Errorf("validation failed: %s", strings.Join(result.ErrorMessages(), "; "))
	}
	cfg.Name = name
	return s.tunnelStore.Save(cfg)
}

func (s *TunnelService) ExportConfig(name string) (string, error) {
	return s.GetConfigText(name)
}

func (s *TunnelService) TunnelExists(name string) bool {
	return s.tunnelStore.Exists(name)
}

// --- Settings ---

func (s *TunnelService) GetSettings() (*storage.Settings, error) {
	return s.settingsStore.Load()
}

func (s *TunnelService) SaveSettings(settings *storage.Settings) error {
	return s.settingsStore.Save(settings)
}

// --- Firewall ---

func (s *TunnelService) SetKillSwitch(enabled bool) error {
	if enabled {
		status := s.manager.Status()
		if status.State != tunnel.StateConnected {
			return fmt.Errorf("cannot enable kill switch: no active tunnel")
		}
		return s.firewall.EnableKillSwitch(status.InterfaceName, status.Endpoint)
	}
	return s.firewall.DisableKillSwitch()
}

func (s *TunnelService) SetDNSProtection(enabled bool) error {
	if enabled {
		status := s.manager.Status()
		if status.State != tunnel.StateConnected {
			return fmt.Errorf("cannot enable DNS protection: no active tunnel")
		}
		cfg, err := s.tunnelStore.Load(s.manager.ActiveTunnel())
		if err != nil {
			return err
		}
		return s.firewall.EnableDNSProtection(status.InterfaceName, cfg.Interface.DNS)
	}
	return s.firewall.DisableDNSProtection()
}
