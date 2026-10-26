//go:build windows

package tunnel

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/wireguardnt"
)

// kernelEngine owns a wireguard.dll adapter. The driver keeps the UDP socket
// and protocol state in kernel mode; Go only creates/configures the adapter
// and reads counters.
type kernelEngine struct {
	mu        sync.Mutex
	adapter   *wireguardnt.Adapter
	ifaceName string
}

var kernelLoggerOnce sync.Once

// newKernelEngine creates and configures a WireGuardNT adapter. It does not
// bring the adapter up; Engine.Start does that after the connect phases have
// installed firewall rules.
func newKernelEngine(cfg, resolved *config.WireGuardConfig, resolvedEndpointIPs, resolvedEndpoints []string) (*Engine, error) {
	api, err := wireguardnt.Default()
	if err != nil {
		return nil, fmt.Errorf("loading WireGuardNT library: %w", err)
	}
	driverVersion, versionErr := api.RunningDriverVersion()

	name := platformTUNName(runtime.GOOS, cfg.Name)
	guid := kernelAdapterGUID(cfg.Name)
	adapter, err := api.CreateAdapter(name, "WireGuard", &guid)
	if err != nil {
		return nil, fmt.Errorf("creating WireGuardNT adapter %q: %w", name, err)
	}

	installKernelLogger(api)
	if err := adapter.SetLogging(true); err != nil {
		slog.Debug("enabling WireGuardNT adapter logging failed", "interface", name, "error", err)
	}

	kernelCfg, err := kernelConfiguration(resolved)
	if err != nil {
		adapter.Close()
		return nil, err
	}
	if err := adapter.SetConfiguration(kernelCfg); err != nil {
		adapter.Close()
		return nil, fmt.Errorf("applying WireGuardNT configuration: %w", err)
	}

	if versionErr != nil {
		slog.Debug("WireGuardNT driver not loaded before adapter creation", "error", versionErr)
	} else {
		slog.Info("WireGuardNT driver loaded", "version", driverVersion)
	}
	slog.Info("WireGuardNT kernel adapter created", "interface", name)

	return &Engine{
		kernel:              &kernelEngine{adapter: adapter, ifaceName: name},
		ifaceName:           name,
		resolvedEndpointIPs: resolvedEndpointIPs,
		resolvedEndpoints:   resolvedEndpoints,
	}, nil
}

// kernelAdapterGUID derives a stable GUID from the tunnel name. NLA stores
// the Public/Private network profile against this GUID, so a random GUID
// would reset the user's firewall profile on every reconnect.
func kernelAdapterGUID(tunnelName string) wireguardnt.GUID {
	sum := sha256.Sum256([]byte("WireGuide WireGuardNT adapter\x00" + tunnelName))
	sum[6] = (sum[6] & 0x0f) | 0x50 // RFC 4122 version 5
	sum[8] = (sum[8] & 0x3f) | 0x80 // RFC 4122 variant
	return wireguardnt.GUID{
		Data1: binary.BigEndian.Uint32(sum[0:4]),
		Data2: binary.BigEndian.Uint16(sum[4:6]),
		Data3: binary.BigEndian.Uint16(sum[6:8]),
		Data4: [8]byte(sum[8:16]),
	}
}

func kernelConfiguration(cfg *config.WireGuardConfig) (*wireguardnt.Configuration, error) {
	privateKey, err := decodeKernelKey(cfg.Interface.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("interface private key: %w", err)
	}
	out := &wireguardnt.Configuration{PrivateKey: privateKey}
	if cfg.Interface.ListenPort > 0 {
		if cfg.Interface.ListenPort > 65535 {
			return nil, fmt.Errorf("listen port %d is out of range", cfg.Interface.ListenPort)
		}
		out.ListenPort = uint16(cfg.Interface.ListenPort)
	}

	for i, peerCfg := range cfg.Peers {
		publicKey, err := decodeKernelKey(peerCfg.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer[%d] public key: %w", i, err)
		}
		peer := wireguardnt.Peer{PublicKey: publicKey}
		if peerCfg.PresharedKey != "" {
			presharedKey, err := decodeKernelKey(peerCfg.PresharedKey)
			if err != nil {
				return nil, fmt.Errorf("peer[%d] preshared key: %w", i, err)
			}
			peer.PresharedKey = presharedKey
			peer.HasPresharedKey = true
		}
		if peerCfg.Endpoint != "" {
			endpoint, err := netip.ParseAddrPort(peerCfg.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("peer[%d] endpoint %q: %w", i, peerCfg.Endpoint, err)
			}
			peer.Endpoint = endpoint
		}
		if peerCfg.PersistentKeepalive > 0 {
			if peerCfg.PersistentKeepalive > 65535 {
				return nil, fmt.Errorf("peer[%d] persistent keepalive %d is out of range", i, peerCfg.PersistentKeepalive)
			}
			peer.PersistentKeepalive = uint16(peerCfg.PersistentKeepalive)
		}
		for _, cidr := range peerCfg.AllowedIPs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("peer[%d] allowed IP %q: %w", i, cidr, err)
			}
			peer.AllowedIPs = append(peer.AllowedIPs, prefix.Masked())
		}
		out.Peers = append(out.Peers, peer)
	}
	return out, nil
}

func decodeKernelKey(value string) ([32]byte, error) {
	var key [32]byte
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return key, fmt.Errorf("invalid base64: %w", err)
	}
	if len(raw) != len(key) {
		return key, fmt.Errorf("key must be %d bytes, got %d", len(key), len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

func installKernelLogger(api *wireguardnt.API) {
	kernelLoggerOnce.Do(func() {
		callback := windows.NewCallback(func(level uint32, _ uint64, message *uint16) uintptr {
			text := windows.UTF16PtrToString(message)
			switch level {
			case 2:
				slog.Error("[wgnt] " + text)
			case 1:
				slog.Warn("[wgnt] " + text)
			default:
				slog.Debug("[wgnt] " + text)
			}
			return 0
		})
		api.SetLogger(callback)
	})
}

func (e *kernelEngine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.adapter == nil {
		return errors.New("kernel WireGuard adapter is closed")
	}
	return e.adapter.SetUp(true)
}

func (e *kernelEngine) Close() error {
	e.mu.Lock()
	adapter := e.adapter
	e.adapter = nil
	e.mu.Unlock()
	if adapter == nil {
		return nil
	}
	_ = adapter.SetUp(false)
	adapter.Close()
	return nil
}

func (e *kernelEngine) Status(tunnelName string, connectedAt time.Time) (*ConnectionStatus, error) {
	// Hold the lock across the driver calls so Close cannot invalidate the
	// adapter handle between Snapshot and Up.
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.adapter == nil {
		return nil, errors.New("kernel WireGuard adapter is closed")
	}
	snapshot, err := e.adapter.Snapshot()
	if err != nil {
		return nil, err
	}
	up, err := e.adapter.Up()
	if err != nil {
		return nil, err
	}
	if !up {
		return nil, errors.New("kernel WireGuard adapter is down")
	}

	status := &ConnectionStatus{
		State:         StateConnected,
		TunnelName:    tunnelName,
		InterfaceName: e.ifaceName,
		ConnectedAt:   connectedAt,
		Duration:      domain.FormatDuration(time.Since(connectedAt)),
	}
	for _, peer := range snapshot.Peers {
		status.RxBytes += int64(peer.RxBytes)
		status.TxBytes += int64(peer.TxBytes)
		if !peer.LastHandshake.IsZero() && (status.LastHandshakeTime.IsZero() || peer.LastHandshake.After(status.LastHandshakeTime)) {
			status.LastHandshakeTime = peer.LastHandshake
		}
		if peer.Endpoint.IsValid() && status.Endpoint == "" {
			status.Endpoint = peer.Endpoint.String()
		}
	}
	if !status.LastHandshakeTime.IsZero() {
		status.LastHandshake = domain.FormatDuration(time.Since(status.LastHandshakeTime))
	}
	return status, nil
}

func (e *kernelEngine) CurrentEndpointIPs() ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.adapter == nil {
		return nil, errors.New("kernel WireGuard adapter is closed")
	}
	snapshot, err := e.adapter.Snapshot()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(snapshot.Peers))
	endpoints := make([]string, 0, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		if !peer.Endpoint.IsValid() {
			continue
		}
		host := peer.Endpoint.Addr().Unmap().String()
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		endpoints = append(endpoints, host)
	}
	return endpoints, nil
}
