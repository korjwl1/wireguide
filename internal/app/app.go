// Package app provides Wails bindings bridging Svelte frontend and daemon via gRPC.
package app

import (
	"context"
	"fmt"

	"github.com/korjwl1/wireguide/internal/ipc"
	pb "github.com/korjwl1/wireguide/internal/ipc/proto"
)

// TunnelService exposes daemon operations to the Svelte frontend via Wails bindings.
type TunnelService struct {
	client *ipc.Client
}

// NewTunnelService creates a service connected to the daemon.
func NewTunnelService(client *ipc.Client) *TunnelService {
	return &TunnelService{client: client}
}

type TunnelInfo struct {
	Name        string `json:"name"`
	IsConnected bool   `json:"is_connected"`
	Endpoint    string `json:"endpoint"`
	HasScripts  bool   `json:"has_scripts"`
}

type ConnectionStatus struct {
	State            string `json:"state"`
	TunnelName       string `json:"tunnel_name"`
	RxBytes          int64  `json:"rx_bytes"`
	TxBytes          int64  `json:"tx_bytes"`
	LastHandshake    string `json:"last_handshake"`
	Duration         string `json:"duration"`
	Endpoint         string `json:"endpoint"`
	ErrorMessage     string `json:"error_message"`
}

func (s *TunnelService) ListTunnels() ([]TunnelInfo, error) {
	tunnels, err := s.client.ListTunnels(context.Background())
	if err != nil {
		return nil, err
	}
	var result []TunnelInfo
	for _, t := range tunnels {
		result = append(result, TunnelInfo{
			Name:        t.Name,
			IsConnected: t.IsConnected,
			Endpoint:    t.Endpoint,
			HasScripts:  t.HasScripts,
		})
	}
	return result, nil
}

func (s *TunnelService) GetTunnelDetail(name string) (*pb.TunnelDetail, error) {
	return s.client.GetTunnelDetail(context.Background(), name)
}

func (s *TunnelService) Connect(name string, scriptsAllowed bool) error {
	return s.client.Connect(context.Background(), name, scriptsAllowed)
}

func (s *TunnelService) Disconnect() error {
	return s.client.Disconnect(context.Background())
}

func (s *TunnelService) GetStatus() (*ConnectionStatus, error) {
	tunnels, err := s.client.ListTunnels(context.Background())
	if err != nil {
		return &ConnectionStatus{State: "error", ErrorMessage: err.Error()}, nil
	}
	for _, t := range tunnels {
		if t.IsConnected {
			return &ConnectionStatus{State: "connected", TunnelName: t.Name, Endpoint: t.Endpoint}, nil
		}
	}
	return &ConnectionStatus{State: "disconnected"}, nil
}

func (s *TunnelService) DeleteTunnel(name string) error {
	return s.client.DeleteTunnel(context.Background(), name)
}

func (s *TunnelService) ImportConfig(name, content string) (*TunnelInfo, error) {
	t, err := s.client.ImportConfig(context.Background(), name, content)
	if err != nil {
		return nil, err
	}
	return &TunnelInfo{Name: t.Name, Endpoint: t.Endpoint, HasScripts: t.HasScripts}, nil
}

func (s *TunnelService) ValidateConfig(content string) ([]string, error) {
	return s.client.ValidateConfig(context.Background(), content)
}

func (s *TunnelService) GetConfigText(name string) (string, error) {
	return s.client.GetConfigText(context.Background(), name)
}

func (s *TunnelService) UpdateConfig(name, content string) error {
	return s.client.UpdateConfig(context.Background(), name, content)
}

func (s *TunnelService) ExportConfig(name string) (string, error) {
	return s.client.ExportConfig(context.Background(), name)
}

func (s *TunnelService) TunnelExists(name string) (bool, error) {
	return s.client.TunnelExists(context.Background(), name)
}

func (s *TunnelService) IsDaemonRunning() bool {
	_, err := s.client.Ping(context.Background())
	return err == nil
}

func (s *TunnelService) DaemonError() string {
	_, err := s.client.Ping(context.Background())
	if err != nil {
		return fmt.Sprintf("Cannot connect to WireGuide daemon: %v", err)
	}
	return ""
}
