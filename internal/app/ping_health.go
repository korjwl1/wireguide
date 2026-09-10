package app

import (
	"fmt"

	"github.com/korjwl1/wireguide/internal/healthcheck"
	"github.com/korjwl1/wireguide/internal/storage"
)

func (s *TunnelService) GetTunnelPingHealth(name string) (healthcheck.Config, error) {
	_, meta, err := s.tunnelStore.LoadWithMeta(name)
	if err != nil {
		return healthcheck.Config{}, err
	}
	if meta == nil || meta.PingHealth == nil {
		return healthcheck.DefaultConfig(), nil
	}
	return meta.PingHealth.Normalize()
}

// SaveTunnelPingHealth updates only this tunnel's metadata. It cannot overwrite
// another tunnel's settings, automation rules, notes or WireGuard configuration.
func (s *TunnelService) SaveTunnelPingHealth(name string, settings healthcheck.Config) error {
	settings, err := settings.Normalize()
	if err != nil {
		return err
	}
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return err
	}
	var allowed []string
	for _, peer := range cfg.Peers {
		allowed = append(allowed, peer.AllowedIPs...)
	}
	if settings.Enabled {
		for _, target := range settings.Targets {
			if !healthcheck.Covered(target, allowed) {
				return fmt.Errorf("ping target %s is outside this tunnel's AllowedIPs", target)
			}
		}
	}
	return s.tunnelStore.UpdateMeta(name, func(meta *storage.TunnelMeta) { meta.PingHealth = &settings })
}
