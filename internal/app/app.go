// Package app provides Wails bindings bridging Svelte frontend to the
// IPC helper client and local storage.
package app

import (
	"fmt"
	"strings"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

// TunnelService is the Wails-bound service.
// Storage (tunnel files, settings) stays in the GUI process.
// Tunnel operations go through the helper via IPC.
type TunnelService struct {
	tunnelStore   *storage.TunnelStore
	settingsStore *storage.SettingsStore
	client        *ipc.Client
}

// NewTunnelService creates a service.
func NewTunnelService(ts *storage.TunnelStore, ss *storage.SettingsStore, client *ipc.Client) *TunnelService {
	return &TunnelService{
		tunnelStore:   ts,
		settingsStore: ss,
		client:        client,
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

// --- Tunnel operations (storage is local, tunnel ops go through helper) ---

func (s *TunnelService) ListTunnels() ([]TunnelInfo, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}

	// Ask helper for currently active tunnel
	var active ipc.StringResponse
	_ = s.client.Call(ipc.MethodActiveName, nil, &active)

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
			IsConnected: name == active.Value,
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
	return s.client.Call(ipc.MethodConnect, ipc.ConnectRequest{
		Config:         cfg,
		ScriptsAllowed: scriptsAllowed,
	}, nil)
}

func (s *TunnelService) Disconnect() error {
	return s.client.Call(ipc.MethodDisconnect, nil, nil)
}

func (s *TunnelService) GetStatus() (*ConnectionStatus, error) {
	var dto ipc.ConnectionStatusDTO
	if err := s.client.Call(ipc.MethodStatus, nil, &dto); err != nil {
		return &ConnectionStatus{State: "error"}, nil
	}
	return &ConnectionStatus{
		State:         dto.State,
		TunnelName:    dto.TunnelName,
		InterfaceName: dto.InterfaceName,
		RxBytes:       dto.RxBytes,
		TxBytes:       dto.TxBytes,
		LastHandshake: dto.LastHandshake,
		Duration:      dto.Duration,
		Endpoint:      dto.Endpoint,
	}, nil
}

func (s *TunnelService) GetTunnelDetail(name string) (*config.WireGuardConfig, error) {
	return s.tunnelStore.Load(name)
}

func (s *TunnelService) DeleteTunnel(name string) error {
	var active ipc.StringResponse
	_ = s.client.Call(ipc.MethodActiveName, nil, &active)
	if active.Value == name {
		return fmt.Errorf("cannot delete connected tunnel %q — disconnect first", name)
	}
	return s.tunnelStore.Delete(name)
}

// --- Config management (all local) ---

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
	var active ipc.StringResponse
	_ = s.client.Call(ipc.MethodActiveName, nil, &active)
	if active.Value == name {
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

// --- Settings (all local) ---

func (s *TunnelService) GetSettings() (*storage.Settings, error) {
	return s.settingsStore.Load()
}

func (s *TunnelService) SaveSettings(settings *storage.Settings) error {
	return s.settingsStore.Save(settings)
}

// --- Firewall (goes through helper) ---

func (s *TunnelService) SetKillSwitch(enabled bool) error {
	return s.client.Call(ipc.MethodSetKillSwitch, ipc.KillSwitchRequest{Enabled: enabled}, nil)
}

func (s *TunnelService) SetDNSProtection(enabled bool) error {
	// Frontend passes empty DNS list; helper uses active tunnel's DNS
	// We need to fetch the active tunnel's DNS servers from local storage
	dnsServers := []string{}
	if enabled {
		var active ipc.StringResponse
		_ = s.client.Call(ipc.MethodActiveName, nil, &active)
		if active.Value != "" {
			if cfg, err := s.tunnelStore.Load(active.Value); err == nil {
				dnsServers = cfg.Interface.DNS
			}
		}
	}
	return s.client.Call(ipc.MethodSetDNSProtection, ipc.DNSProtectionRequest{
		Enabled:    enabled,
		DNSServers: dnsServers,
	}, nil)
}
