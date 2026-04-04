package tunnel

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/korjwl1/wireguide/internal/config"
)

// Engine wraps wireguard-go device and TUN.
type Engine struct {
	tunDevice tun.Device
	wgDevice  *device.Device
	ifaceName string
}

// NewEngine creates a WireGuard tunnel with a TUN device and starts the WG protocol.
func NewEngine(cfg *config.WireGuardConfig) (*Engine, error) {
	// Create TUN device
	tunDev, err := tun.CreateTUN("utun", cfg.Interface.MTU)
	if err != nil {
		return nil, fmt.Errorf("creating TUN device: %w", err)
	}

	ifaceName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("getting TUN name: %w", err)
	}

	slog.Info("TUN device created", "interface", ifaceName)

	// Create WireGuard device
	logger := device.NewLogger(device.LogLevelSilent, "")
	wgDev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	engine := &Engine{
		tunDevice: tunDev,
		wgDevice:  wgDev,
		ifaceName: ifaceName,
	}

	// Apply WireGuard configuration
	if err := engine.applyConfig(cfg); err != nil {
		engine.Close()
		return nil, fmt.Errorf("applying config: %w", err)
	}

	// Bring up the WireGuard device
	if err := wgDev.Up(); err != nil {
		engine.Close()
		return nil, fmt.Errorf("bringing up device: %w", err)
	}

	slog.Info("WireGuard device up", "interface", ifaceName)
	return engine, nil
}

// InterfaceName returns the OS interface name (e.g., "utun3").
func (e *Engine) InterfaceName() string {
	return e.ifaceName
}

// Close stops the WireGuard device and closes the TUN.
func (e *Engine) Close() {
	if e.wgDevice != nil {
		e.wgDevice.Close()
	}
	// TUN is closed by device.Close()
}

func (e *Engine) applyConfig(cfg *config.WireGuardConfig) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("creating wgctrl client: %w", err)
	}
	defer client.Close()

	privKey, err := wgtypes.ParseKey(cfg.Interface.PrivateKey)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}

	var peers []wgtypes.PeerConfig
	for _, p := range cfg.Peers {
		peerCfg, err := buildPeerConfig(p)
		if err != nil {
			return fmt.Errorf("building peer config: %w", err)
		}
		peers = append(peers, peerCfg)
	}

	listenPort := cfg.Interface.ListenPort

	wgCfg := wgtypes.Config{
		PrivateKey:   &privKey,
		Peers:        peers,
		ReplacePeers: true,
	}
	if listenPort > 0 {
		wgCfg.ListenPort = &listenPort
	}

	if err := client.ConfigureDevice(e.ifaceName, wgCfg); err != nil {
		return fmt.Errorf("configuring device %s: %w", e.ifaceName, err)
	}

	return nil
}

func buildPeerConfig(p config.PeerConfig) (wgtypes.PeerConfig, error) {
	pubKey, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("parsing public key: %w", err)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		ReplaceAllowedIPs: true,
	}

	if p.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(p.PresharedKey)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("parsing preshared key: %w", err)
		}
		peerCfg.PresharedKey = &psk
	}

	if p.Endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("resolving endpoint %s: %w", p.Endpoint, err)
		}
		peerCfg.Endpoint = addr
	}

	for _, cidr := range p.AllowedIPs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("parsing allowed IP %s: %w", cidr, err)
		}
		peerCfg.AllowedIPs = append(peerCfg.AllowedIPs, net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		})
	}

	if p.PersistentKeepalive > 0 {
		ka := time.Duration(p.PersistentKeepalive) * time.Second
		peerCfg.PersistentKeepaliveInterval = &ka
	}

	return peerCfg, nil
}
