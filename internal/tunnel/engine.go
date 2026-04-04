package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/korjwl1/wireguide/internal/config"
)

// Engine wraps wireguard-go device and TUN.
type Engine struct {
	tunDevice    tun.Device
	wgDevice     *device.Device
	uapiListener net.Listener
	ifaceName    string
}

// NewEngine creates a WireGuard tunnel with a TUN device and starts the WG protocol.
func NewEngine(cfg *config.WireGuardConfig) (*Engine, error) {
	mtu := cfg.Interface.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	tunDev, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, fmt.Errorf("creating TUN device: %w", err)
	}

	ifaceName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("getting TUN name: %w", err)
	}

	slog.Info("TUN device created", "interface", ifaceName)

	logger := device.NewLogger(device.LogLevelSilent, "")
	wgDev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	engine := &Engine{
		tunDevice: tunDev,
		wgDevice:  wgDev,
		ifaceName: ifaceName,
	}

	// Apply config using IpcSet (in-process, no UAPI socket needed)
	if err := wgDev.IpcSet(buildIpcConfig(cfg)); err != nil {
		engine.Close()
		return nil, fmt.Errorf("applying config: %w", err)
	}
	slog.Info("WireGuard config applied", "interface", ifaceName)

	if err := wgDev.Up(); err != nil {
		engine.Close()
		return nil, fmt.Errorf("bringing up device: %w", err)
	}

	// Start UAPI listener for status queries
	uapi, err := createUAPIListener(ifaceName)
	if err != nil {
		slog.Warn("UAPI listener failed, status queries may not work", "error", err)
	} else {
		engine.uapiListener = uapi
		go func() {
			for {
				c, err := uapi.Accept()
				if err != nil {
					return
				}
				go wgDev.IpcHandle(c)
			}
		}()
	}

	slog.Info("WireGuard device up", "interface", ifaceName)
	return engine, nil
}

func (e *Engine) InterfaceName() string { return e.ifaceName }

func (e *Engine) Close() {
	if e.uapiListener != nil {
		e.uapiListener.Close()
	}
	if e.wgDevice != nil {
		e.wgDevice.Close()
	}
}

// buildIpcConfig creates the WireGuard IPC config string.
// Protocol: https://www.wireguard.com/xplatform/#configuration-protocol
func buildIpcConfig(cfg *config.WireGuardConfig) string {
	var b strings.Builder

	b.WriteString("private_key=" + keyToHex(cfg.Interface.PrivateKey) + "\n")
	if cfg.Interface.ListenPort > 0 {
		b.WriteString(fmt.Sprintf("listen_port=%d\n", cfg.Interface.ListenPort))
	}
	b.WriteString("replace_peers=true\n")

	for _, peer := range cfg.Peers {
		b.WriteString("public_key=" + keyToHex(peer.PublicKey) + "\n")
		if peer.PresharedKey != "" {
			b.WriteString("preshared_key=" + keyToHex(peer.PresharedKey) + "\n")
		}
		if peer.Endpoint != "" {
			if addr, err := net.ResolveUDPAddr("udp", peer.Endpoint); err == nil {
				b.WriteString("endpoint=" + addr.String() + "\n")
			}
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, cidr := range peer.AllowedIPs {
			b.WriteString("allowed_ip=" + cidr + "\n")
		}
		if peer.PersistentKeepalive > 0 {
			b.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
		}
	}

	return b.String()
}

// keyToHex converts a base64 WireGuard key to hex (IPC protocol uses hex).
func keyToHex(b64Key string) string {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}
