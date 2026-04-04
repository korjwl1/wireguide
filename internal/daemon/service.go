package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/firewall"
	pb "github.com/korjwl1/wireguide/internal/ipc/proto"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// Service implements the gRPC WireGuideService.
type Service struct {
	pb.UnimplementedWireGuideServiceServer
	tunnelStore   *storage.TunnelStore
	settingsStore *storage.SettingsStore
	manager       *tunnel.Manager
	firewall      firewall.FirewallManager
}

// NewService creates a new gRPC service.
func NewService(ts *storage.TunnelStore, ss *storage.SettingsStore, mgr *tunnel.Manager) *Service {
	return &Service{
		tunnelStore:   ts,
		settingsStore: ss,
		manager:       mgr,
		firewall:      firewall.NewPlatformFirewall(),
	}
}

func (s *Service) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{Version: "0.2.0", Status: "running"}, nil
}

func (s *Service) Connect(ctx context.Context, req *pb.ConnectRequest) (*pb.ConnectResponse, error) {
	cfg, err := s.tunnelStore.Load(req.TunnelName)
	if err != nil {
		return nil, fmt.Errorf("loading tunnel %s: %w", req.TunnelName, err)
	}
	if err := s.manager.Connect(cfg, req.ScriptsAllowed); err != nil {
		return nil, err
	}
	return &pb.ConnectResponse{}, nil
}

func (s *Service) Disconnect(ctx context.Context, req *pb.DisconnectRequest) (*pb.DisconnectResponse, error) {
	if err := s.manager.Disconnect(); err != nil {
		return nil, err
	}
	return &pb.DisconnectResponse{}, nil
}

func (s *Service) ListTunnels(ctx context.Context, req *pb.ListTunnelsRequest) (*pb.ListTunnelsResponse, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}
	activeName := s.manager.ActiveTunnel()
	var tunnels []*pb.TunnelInfo
	for _, name := range names {
		cfg, err := s.tunnelStore.Load(name)
		if err != nil {
			continue
		}
		endpoint := ""
		if len(cfg.Peers) > 0 {
			endpoint = cfg.Peers[0].Endpoint
		}
		tunnels = append(tunnels, &pb.TunnelInfo{
			Name:        name,
			IsConnected: name == activeName,
			Endpoint:    endpoint,
			HasScripts:  cfg.HasScripts(),
		})
	}
	return &pb.ListTunnelsResponse{Tunnels: tunnels}, nil
}

func (s *Service) GetTunnelDetail(ctx context.Context, req *pb.GetTunnelDetailRequest) (*pb.TunnelDetail, error) {
	cfg, err := s.tunnelStore.Load(req.Name)
	if err != nil {
		return nil, err
	}
	return configToDetail(cfg), nil
}

func (s *Service) StreamStatus(req *pb.StreamStatusRequest, stream pb.WireGuideService_StreamStatusServer) error {
	for {
		status := s.manager.Status()
		pbStatus := &pb.ConnectionStatus{
			State:         string(status.State),
			TunnelName:    status.TunnelName,
			InterfaceName: status.InterfaceName,
			RxBytes:       status.RxBytes,
			TxBytes:       status.TxBytes,
			LastHandshake: status.HandshakeAge,
			Duration:      status.Duration,
			Endpoint:      status.Endpoint,
		}
		if err := stream.Send(pbStatus); err != nil {
			return err
		}
		time.Sleep(1 * time.Second)
	}
}

func (s *Service) ImportConfig(ctx context.Context, req *pb.ImportConfigRequest) (*pb.ImportConfigResponse, error) {
	cfg, err := s.tunnelStore.ImportFromContent(req.Name, req.Content)
	if err != nil {
		return nil, err
	}
	endpoint := ""
	if len(cfg.Peers) > 0 {
		endpoint = cfg.Peers[0].Endpoint
	}
	return &pb.ImportConfigResponse{
		Tunnel: &pb.TunnelInfo{
			Name:       cfg.Name,
			Endpoint:   endpoint,
			HasScripts: cfg.HasScripts(),
		},
	}, nil
}

func (s *Service) ValidateConfig(ctx context.Context, req *pb.ValidateConfigRequest) (*pb.ValidateConfigResponse, error) {
	cfg, err := config.Parse(req.Content)
	if err != nil {
		return &pb.ValidateConfigResponse{Errors: []string{err.Error()}}, nil
	}
	result := config.Validate(cfg)
	if result.IsValid() {
		return &pb.ValidateConfigResponse{}, nil
	}
	return &pb.ValidateConfigResponse{Errors: result.ErrorMessages()}, nil
}

func (s *Service) GetConfigText(ctx context.Context, req *pb.GetConfigTextRequest) (*pb.GetConfigTextResponse, error) {
	cfg, err := s.tunnelStore.Load(req.Name)
	if err != nil {
		return nil, err
	}
	return &pb.GetConfigTextResponse{Content: config.Serialize(cfg)}, nil
}

func (s *Service) UpdateConfig(ctx context.Context, req *pb.UpdateConfigRequest) (*pb.UpdateConfigResponse, error) {
	if s.manager.ActiveTunnel() == req.Name {
		return nil, fmt.Errorf("cannot edit connected tunnel %q", req.Name)
	}
	cfg, err := config.Parse(req.Content)
	if err != nil {
		return nil, err
	}
	result := config.Validate(cfg)
	if !result.IsValid() {
		return nil, fmt.Errorf("validation: %s", strings.Join(result.ErrorMessages(), "; "))
	}
	cfg.Name = req.Name
	if err := s.tunnelStore.Save(cfg); err != nil {
		return nil, err
	}
	return &pb.UpdateConfigResponse{}, nil
}

func (s *Service) DeleteTunnel(ctx context.Context, req *pb.DeleteTunnelRequest) (*pb.DeleteTunnelResponse, error) {
	if s.manager.ActiveTunnel() == req.Name {
		return nil, fmt.Errorf("cannot delete connected tunnel %q", req.Name)
	}
	if err := s.tunnelStore.Delete(req.Name); err != nil {
		return nil, err
	}
	return &pb.DeleteTunnelResponse{}, nil
}

func (s *Service) ExportConfig(ctx context.Context, req *pb.ExportConfigRequest) (*pb.ExportConfigResponse, error) {
	cfg, err := s.tunnelStore.Load(req.Name)
	if err != nil {
		return nil, err
	}
	return &pb.ExportConfigResponse{Content: config.Serialize(cfg)}, nil
}

func (s *Service) TunnelExists(ctx context.Context, req *pb.TunnelExistsRequest) (*pb.TunnelExistsResponse, error) {
	return &pb.TunnelExistsResponse{Exists: s.tunnelStore.Exists(req.Name)}, nil
}

func (s *Service) GetSettings(ctx context.Context, req *pb.GetSettingsRequest) (*pb.Settings, error) {
	settings, err := s.settingsStore.Load()
	if err != nil {
		return nil, err
	}
	return &pb.Settings{
		Language:      settings.Language,
		Theme:         settings.Theme,
		TrayIconStyle: settings.TrayIconStyle,
		AutoReconnect: settings.AutoReconnect,
		KillSwitch:    settings.KillSwitch,
		DnsProtection: settings.DNSProtection,
		LogLevel:      settings.LogLevel,
	}, nil
}

func (s *Service) SaveSettings(ctx context.Context, pbSettings *pb.Settings) (*pb.SaveSettingsResponse, error) {
	settings := &storage.Settings{
		Language:      pbSettings.Language,
		Theme:         pbSettings.Theme,
		TrayIconStyle: pbSettings.TrayIconStyle,
		AutoReconnect: pbSettings.AutoReconnect,
		KillSwitch:    pbSettings.KillSwitch,
		DNSProtection: pbSettings.DnsProtection,
		LogLevel:      pbSettings.LogLevel,
	}
	if err := s.settingsStore.Save(settings); err != nil {
		return nil, err
	}
	return &pb.SaveSettingsResponse{}, nil
}

func (s *Service) SetKillSwitch(ctx context.Context, req *pb.SetKillSwitchRequest) (*pb.SetKillSwitchResponse, error) {
	slog.Info("kill switch", "enabled", req.Enabled)
	if req.Enabled {
		status := s.manager.Status()
		if status.State != tunnel.StateConnected {
			return nil, fmt.Errorf("cannot enable kill switch: no active tunnel")
		}
		if err := s.firewall.EnableKillSwitch(status.InterfaceName, status.Endpoint); err != nil {
			return nil, fmt.Errorf("enabling kill switch: %w", err)
		}
	} else {
		if err := s.firewall.DisableKillSwitch(); err != nil {
			return nil, fmt.Errorf("disabling kill switch: %w", err)
		}
	}
	return &pb.SetKillSwitchResponse{}, nil
}

func (s *Service) SetDNSProtection(ctx context.Context, req *pb.SetDNSProtectionRequest) (*pb.SetDNSProtectionResponse, error) {
	slog.Info("DNS protection", "enabled", req.Enabled)
	if req.Enabled {
		status := s.manager.Status()
		if status.State != tunnel.StateConnected {
			return nil, fmt.Errorf("cannot enable DNS protection: no active tunnel")
		}
		// Get DNS servers from active tunnel config
		activeName := s.manager.ActiveTunnel()
		cfg, err := s.tunnelStore.Load(activeName)
		if err != nil {
			return nil, err
		}
		if err := s.firewall.EnableDNSProtection(status.InterfaceName, cfg.Interface.DNS); err != nil {
			return nil, fmt.Errorf("enabling DNS protection: %w", err)
		}
	} else {
		if err := s.firewall.DisableDNSProtection(); err != nil {
			return nil, fmt.Errorf("disabling DNS protection: %w", err)
		}
	}
	return &pb.SetDNSProtectionResponse{}, nil
}

func configToDetail(cfg *config.WireGuardConfig) *pb.TunnelDetail {
	detail := &pb.TunnelDetail{
		Name: cfg.Name,
		InterfaceConfig: &pb.InterfaceConfig{
			Address:    cfg.Interface.Address,
			Dns:        cfg.Interface.DNS,
			Mtu:        int32(cfg.Interface.MTU),
			ListenPort: int32(cfg.Interface.ListenPort),
			PreUp:      cfg.Interface.PreUp,
			PostUp:     cfg.Interface.PostUp,
			PreDown:    cfg.Interface.PreDown,
			PostDown:   cfg.Interface.PostDown,
		},
	}
	for _, p := range cfg.Peers {
		detail.Peers = append(detail.Peers, &pb.PeerConfig{
			PublicKey:            p.PublicKey,
			Endpoint:             p.Endpoint,
			AllowedIps:           p.AllowedIPs,
			PersistentKeepalive:  int32(p.PersistentKeepalive),
			HasPresharedKey:      p.PresharedKey != "",
		})
	}
	return detail
}
