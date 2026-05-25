package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

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
	closeOnce    sync.Once

	// bind is the wireguard-go conn.Bind we passed to device.NewDevice.
	// Held so the socket-pinning path (Windows: IP_UNICAST_IF; see
	// internal/tunnel/socketbind_windows.go) can downcast it to
	// conn.BindSocketToInterface and pin the WG UDP socket to the
	// physical underlay's ifIndex after engine.Start has opened the
	// sockets. The cast may yield nil on platforms whose default bind
	// doesn't implement that interface — every call site checks.
	bind conn.Bind

	// SocketPinV4/V6 record the ifIndex pinSocketToPhysical succeeded
	// against at connect time. Read by the manager to seed the socket-
	// bind monitor's "previous" baseline so the first poll only fires
	// a re-pin if the underlay has actually moved since connect.
	SocketPinV4 uint32
	SocketPinV6 uint32

	// resolvedEndpointIPs caches the IP address each peer endpoint was
	// resolved to during NewEngine. The network adapter uses these when
	// installing bypass routes, instead of doing a second round of DNS
	// lookups AFTER the tunnel routes have been installed (which would
	// create a chicken-and-egg loop — the DNS query itself would try to
	// route through the tunnel that hasn't finished coming up yet).
	resolvedEndpointIPs []string

	// resolvedEndpoints caches the full ip:port pairs for each peer
	// endpoint. Used by the firewall to add port-specific allow rules.
	resolvedEndpoints []string
}

// NewEngine creates a WireGuard tunnel with a TUN device and starts the WG protocol.
//
// The MTU passed in here is the initial value the TUN device is created with.
// It can be overridden later by the platform network manager's SetMTU.
func NewEngine(cfg *config.WireGuardConfig) (*Engine, error) {
	// Validate keys up front — otherwise we'd write `private_key=\n` to the
	// UAPI config and wireguard-go would reject or misbehave with an empty
	// key, producing a confusing downstream failure.
	if err := validateWireGuardKey(cfg.Interface.PrivateKey); err != nil {
		return nil, fmt.Errorf("invalid interface private key: %w", err)
	}
	for i, peer := range cfg.Peers {
		if err := validateWireGuardKey(peer.PublicKey); err != nil {
			return nil, fmt.Errorf("invalid peer[%d] public key: %w", i, err)
		}
		if peer.PresharedKey != "" {
			if err := validateWireGuardKey(peer.PresharedKey); err != nil {
				return nil, fmt.Errorf("invalid peer[%d] preshared key: %w", i, err)
			}
		}
	}

	// Resolve peer endpoints eagerly. This has two purposes:
	//  1. Give wireguard-go a literal IP (its UAPI rejects hostnames).
	//  2. Record the resolved IPs so the network adapter can install bypass
	//     routes without re-running DNS after it has installed split routes
	//     — which would loop the DNS query through the tunnel.
	// Resolution failures here are FATAL to Connect, matching wg-quick's
	// behaviour (it won't bring up a tunnel whose peer is unreachable).
	resolvedCfg := *cfg
	resolvedCfg.Peers = make([]config.PeerConfig, len(cfg.Peers))
	var resolvedEndpointIPs []string
	var resolvedEndpoints []string // ip:port pairs for firewall rules
	for i, p := range cfg.Peers {
		resolvedCfg.Peers[i] = p
		if p.Endpoint == "" {
			continue
		}
		host, port, err := net.SplitHostPort(p.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("peer[%d] endpoint %q: %w", i, p.Endpoint, err)
		}
		dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 10*time.Second)
		ips, err := net.DefaultResolver.LookupHost(dnsCtx, host)
		dnsCancel()
		if err != nil {
			return nil, fmt.Errorf("peer[%d] resolve %q: %w", i, host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("peer[%d] resolve %q: no addresses found", i, host)
		}
		// Use the first resolved IP for the WG config. wireguard-go will
		// roam to a different source if the peer's handshake arrives from
		// somewhere else, so this is a reasonable starting point.
		resolved := net.JoinHostPort(ips[0], port)
		resolvedCfg.Peers[i].Endpoint = resolved
		resolvedEndpointIPs = append(resolvedEndpointIPs, ips[0])
		resolvedEndpoints = append(resolvedEndpoints, net.JoinHostPort(ips[0], port))
	}

	mtu := cfg.Interface.MTU
	if mtu <= 0 {
		mtu = 1420 // conservative default; platform SetMTU may override
	}

	// Platform-specific TUN device name:
	//  - macOS: "utun" — wireguard-go allocates utun0, utun1, etc.
	//  - Linux: "wg" — wireguard-go creates wg0, wg1, etc. ("utun" is invalid on Linux)
	//  - Windows: "WireGuide" — Windows expects a proper adapter name, not "utun"
	tunName := "utun"
	switch runtime.GOOS {
	case "linux":
		tunName = "wg"
	case "windows":
		tunName = "WireGuide"
		// Best-effort: close any leftover adapter from a previous helper
		// crash before CreateTUN attempts to allocate the same name.
		// No-op on non-Windows.
		cleanupStaleWintunAdapter(tunName)
	}

	tunDev, err := tun.CreateTUN(tunName, mtu)
	if err != nil {
		// Surface a more actionable message for the common Windows
		// failure mode: a previous helper crash left a Wintun adapter
		// in the kernel that we couldn't clean up (cleanupStaleWintunAdapter
		// is best-effort and silently no-ops when wintun.dll isn't
		// loadable from our path).
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("creating TUN device %q: %w (hint: a stale WireGuide adapter may still be installed — open Device Manager → Network adapters and remove any 'WireGuide' entries, then try again)", tunName, err)
		}
		return nil, fmt.Errorf("creating TUN device: %w", err)
	}

	ifaceName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("getting TUN name: %w", err)
	}

	slog.Info("TUN device created", "interface", ifaceName)

	// Use a verbose logger routed to slog so handshake failures / peer
	// rejections / MTU issues aren't invisible. Previously this was
	// LogLevelSilent which made debugging impossible.
	logger := newWireguardSlogLogger(ifaceName)
	bind := conn.NewDefaultBind()
	wgDev := device.NewDevice(tunDev, bind, logger)

	engine := &Engine{
		tunDevice:           tunDev,
		wgDevice:            wgDev,
		bind:                bind,
		ifaceName:           ifaceName,
		resolvedEndpointIPs: resolvedEndpointIPs,
		resolvedEndpoints:   resolvedEndpoints,
	}

	// Apply config using IpcSet (in-process, no UAPI socket needed)
	ipcCfg, err := buildIpcConfig(&resolvedCfg)
	if err != nil {
		engine.Close()
		return nil, fmt.Errorf("building WG config: %w", err)
	}
	if err := wgDev.IpcSet(ipcCfg); err != nil {
		engine.Close()
		return nil, fmt.Errorf("applying WG config: %w", err)
	}
	slog.Info("WireGuard config applied", "interface", ifaceName)

	// IMPORTANT: we do NOT call wgDev.Up() here. The handshake-start
	// must happen AFTER the connect_phases caller has installed
	// platform-level firewall rules (Windows: WFP endpoint-loop
	// protection BLOCK at ALE_AUTH_CONNECT_V4) so the very first
	// handshake packet is already subject to those filters. Otherwise
	// the kernel's ALE flow cache can record a PERMIT for the first
	// sendto and subsequent packets bypass our newly-installed BLOCK.
	// Callers MUST call engine.Start() after the firewall hooks ran.

	// Start UAPI listener for status queries.
	//
	// On Windows this listener almost always fails to bind: wireguard-go's
	// pipe target is \\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>,
	// which requires the BUILTIN\Administrators group SID as the pipe's
	// owner. Our helper runs as an elevated user (UAC-spawned), NOT as
	// LocalSystem or as the Administrators group itself, so the kernel
	// rejects the bind with "This security ID may not be assigned as the
	// owner of this object." Status queries route through the in-process
	// Engine.IpcGet path instead — the pipe is only used by external
	// tools like the `wg` CLI, which we don't ship.
	//
	// Logging the failure at WARN every connect produces alarming noise
	// for a state that's expected and not user-actionable. Downgrade to
	// DEBUG on Windows; keep WARN on other platforms where this listener
	// failing IS unexpected.
	uapi, err := createUAPIListener(ifaceName)
	if err != nil {
		if runtime.GOOS == "windows" {
			slog.Debug("UAPI listener unavailable on Windows elevated helper (status served by in-process IpcGet)", "error", err)
		} else {
			slog.Warn("UAPI listener failed, status queries may not work", "error", err)
		}
	} else {
		engine.uapiListener = uapi
		go func() {
			for {
				c, err := uapi.Accept()
				if err != nil {
					return
				}
				go func() {
					defer func() {
						if r := recover(); r != nil {
							slog.Warn("UAPI IpcHandle panic (recovered)", "panic", r)
						}
					}()
					wgDev.IpcHandle(c)
				}()
			}
		}()
	}

	slog.Info("WireGuard device created (not yet up)", "interface", ifaceName)
	return engine, nil
}

// Start transitions the WireGuard device into the running state by
// calling wgDev.Up(). Split from NewEngine so the connect_phases caller
// can install platform firewall rules BEFORE the first handshake fires
// — see the ALE_AUTH_CONNECT_V4 flow-cache rationale in NewEngine.
//
// Safe to call multiple times (wgDev.Up itself is idempotent when the
// device is already up); on subsequent calls it returns the device's
// stored last error if Up failed previously. Callers should treat any
// non-nil error here as a fatal connect failure.
//
// A nil wgDevice is treated as a successful no-op: that case only
// arises in tests where the engine is constructed without a real
// wireguard-go device (the manager-level tests in manager_test.go
// build fakeEngine instances that exercise lifecycle ordering without
// touching the protocol layer). Production callers always go through
// NewEngine which produces a non-nil device.
func (e *Engine) Start() error {
	if e == nil {
		return fmt.Errorf("engine.Start: nil engine")
	}
	if e.wgDevice == nil {
		return nil
	}
	if err := e.wgDevice.Up(); err != nil {
		return fmt.Errorf("bringing up device: %w", err)
	}
	slog.Info("WireGuard device up", "interface", e.ifaceName)
	return nil
}

// InterfaceName returns the kernel interface name (utunN on macOS).
func (e *Engine) InterfaceName() string { return e.ifaceName }

// ResolvedEndpointIPs returns the IP addresses each peer endpoint was
// resolved to at Connect time. Used by the network adapter for installing
// bypass routes without re-running DNS through the tunnel.
func (e *Engine) ResolvedEndpointIPs() []string {
	result := make([]string, len(e.resolvedEndpointIPs))
	copy(result, e.resolvedEndpointIPs)
	return result
}

// ResolvedEndpoints returns the full ip:port pairs for each resolved peer
// endpoint. Used by the firewall to add port-specific allow rules.
func (e *Engine) ResolvedEndpoints() []string {
	result := make([]string, len(e.resolvedEndpoints))
	copy(result, e.resolvedEndpoints)
	return result
}

// Close tears down the UAPI listener and the wireguard-go device (which in
// turn closes the TUN). Safe for concurrent and repeated calls.
func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		if e.uapiListener != nil {
			e.uapiListener.Close()
		}
		if e.wgDevice != nil {
			e.wgDevice.Close()
		}
	})
}

// IpcGet returns the wireguard-go device's UAPI state as a multi-line
// string (see https://www.wireguard.com/xplatform/#configuration-protocol).
// This is an in-process call straight into wgDevice — it does NOT require
// the UAPI named-pipe / socket to be reachable, which on Windows fails
// because wireguard-go's pipe target (\\.\pipe\ProtectedPrefix\Administrators\…)
// rejects any owner SID other than the Administrators group, and our
// helper runs as an elevated user (not as LocalSystem). Callers that
// need peer stats and don't want to depend on the pipe should use this
// instead of going through wgctrl.
func (e *Engine) IpcGet() (string, error) {
	if e.wgDevice == nil {
		return "", fmt.Errorf("engine wgDevice is nil")
	}
	return e.wgDevice.IpcGet()
}

// buildIpcConfig creates the WireGuard IPC config string.
// Protocol: https://www.wireguard.com/xplatform/#configuration-protocol
//
// Assumes keys have been validated and peer endpoints have been resolved
// to literal IPs by NewEngine.
func buildIpcConfig(cfg *config.WireGuardConfig) (string, error) {
	var b strings.Builder

	pk, err := keyToHex(cfg.Interface.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	b.WriteString("private_key=" + pk + "\n")
	if cfg.Interface.ListenPort > 0 {
		b.WriteString(fmt.Sprintf("listen_port=%d\n", cfg.Interface.ListenPort))
	}
	// FwMark is intentionally NOT set here in the UAPI config. The platform
	// network manager sets it via `wg set <iface> fwmark <value>` AFTER
	// engine creation, which avoids a brief mismatch window on Linux
	// full-tunnel where the platform installs fwmark-aware routing rules.
	b.WriteString("replace_peers=true\n")

	for i, peer := range cfg.Peers {
		pk, err := keyToHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer[%d] public key: %w", i, err)
		}
		b.WriteString("public_key=" + pk + "\n")
		if peer.PresharedKey != "" {
			psk, err := keyToHex(peer.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("peer[%d] preshared key: %w", i, err)
			}
			b.WriteString("preshared_key=" + psk + "\n")
		}
		if peer.Endpoint != "" {
			// Endpoint has already been resolved to a literal IP by NewEngine.
			// We still run ResolveUDPAddr as a format sanity check.
			addr, err := net.ResolveUDPAddr("udp", peer.Endpoint)
			if err != nil {
				return "", fmt.Errorf("peer[%d] endpoint %q: %w", i, peer.Endpoint, err)
			}
			b.WriteString("endpoint=" + addr.String() + "\n")
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, cidr := range peer.AllowedIPs {
			b.WriteString("allowed_ip=" + cidr + "\n")
		}
		if peer.PersistentKeepalive > 0 {
			b.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
		}
	}

	return b.String(), nil
}

// validateWireGuardKey ensures a string is a base64-encoded 32-byte WG key.
func validateWireGuardKey(b64Key string) error {
	if b64Key == "" {
		return fmt.Errorf("empty key")
	}
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return nil
}

// keyToHex converts a base64 WireGuard key to hex (UAPI uses hex).
// Caller must have validated the key first.
func keyToHex(b64Key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}


// newWireguardSlogLogger builds a wireguard-go logger that routes Errorf to
// our structured log stream at Warn level, and Verbosef at Debug level.
// Verbosef is called by wireguard-go on per-packet events (key rotations,
// idle detection, keepalive ticks) AND on the handshake state machine
// (handshake initiation send, response receipt, retries) — the latter is
// the only window into why a tunnel fails to come up when the peer is
// silent. Routing to Debug keeps the firehose suppressed in the default
// INFO configuration, so users only pay the per-packet cost when they
// explicitly turn the helper to DEBUG in Settings to diagnose a connect
// problem. Errorf stays at Warn because that surfaces peer rejections,
// bad packet formats, and rekey failures that the user always needs to see.
func newWireguardSlogLogger(ifaceName string) *device.Logger {
	prefix := "[wg:" + ifaceName + "] "
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			slog.Debug(prefix + fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			slog.Warn(prefix + fmt.Sprintf(format, args...))
		},
	}
}
