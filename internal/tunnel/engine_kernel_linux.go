//go:build linux

package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/korjwl1/wireguide/internal/config"
)

// kernelIPTimeout bounds every ip(8) invocation. A stuck rtnetlink reply
// must not block the helper's connect/disconnect path indefinitely.
const kernelIPTimeout = 30 * time.Second

// kernelEngine owns a Linux kernel WireGuard netdev. The module carries the
// protocol and the UDP socket; Go only creates the netdev, applies its
// configuration through wgctrl, and reads counters.
type kernelEngine struct {
	mu     sync.Mutex
	iface  string
	closed bool
}

// newKernelEngine creates and configures a kernel WireGuard interface. The
// netdev starts administratively down; the generic connect phases bring it
// up (BringUp), and Engine.Start re-asserts that state. Unlike Windows,
// Linux has no endpoint loop-protection layer that must precede the first
// handshake, so the ordering constraint that shapes the userspace engine
// does not apply here.
func newKernelEngine(cfg, resolved *config.WireGuardConfig, resolvedEndpointIPs, resolvedEndpoints []string) (*Engine, error) {
	name := platformTUNName(runtime.GOOS, cfg.Name)
	removeStaleKernelInterface(name)
	if _, err := runIP("link", "add", "dev", name, "type", "wireguard"); err != nil {
		return nil, kernelInterfaceError(name, err)
	}

	wgCfg, err := kernelWgtypesConfig(resolved)
	if err != nil {
		_ = deleteKernelInterface(name)
		return nil, err
	}
	client, err := wgctrl.New()
	if err != nil {
		_ = deleteKernelInterface(name)
		return nil, fmt.Errorf("opening wgctrl client: %w", err)
	}
	defer client.Close()
	if err := client.ConfigureDevice(name, wgCfg); err != nil {
		_ = deleteKernelInterface(name)
		return nil, fmt.Errorf("applying WireGuard configuration to %q: %w", name, err)
	}

	slog.Info("WireGuard kernel interface created", "interface", name)
	return &Engine{
		kernel:              &kernelEngine{iface: name},
		ifaceName:           name,
		resolvedEndpointIPs: resolvedEndpointIPs,
		resolvedEndpoints:   resolvedEndpoints,
	}, nil
}

// kernelWgtypesConfig translates the imported profile into the wgctrl
// configuration. Keys and endpoints were validated and resolved by
// NewEngineWithBackend; this function only rejects shapes wgctrl cannot
// represent.
func kernelWgtypesConfig(cfg *config.WireGuardConfig) (wgtypes.Config, error) {
	privateKey, err := wgtypes.ParseKey(cfg.Interface.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("interface private key: %w", err)
	}
	out := wgtypes.Config{
		PrivateKey:   &privateKey,
		ReplacePeers: true,
	}
	if cfg.Interface.ListenPort > 0 {
		if cfg.Interface.ListenPort > 65535 {
			return wgtypes.Config{}, fmt.Errorf("listen port %d is out of range", cfg.Interface.ListenPort)
		}
		port := cfg.Interface.ListenPort
		out.ListenPort = &port
	}

	for i, peerCfg := range cfg.Peers {
		publicKey, err := wgtypes.ParseKey(peerCfg.PublicKey)
		if err != nil {
			return wgtypes.Config{}, fmt.Errorf("peer[%d] public key: %w", i, err)
		}
		peer := wgtypes.PeerConfig{
			PublicKey:         publicKey,
			ReplaceAllowedIPs: true,
		}
		if peerCfg.PresharedKey != "" {
			presharedKey, err := wgtypes.ParseKey(peerCfg.PresharedKey)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("peer[%d] preshared key: %w", i, err)
			}
			peer.PresharedKey = &presharedKey
		}
		if peerCfg.Endpoint != "" {
			// Endpoint is already a literal ip:port; ResolveUDPAddr only
			// converts it to the net.UDPAddr shape wgctrl expects.
			endpoint, err := net.ResolveUDPAddr("udp", peerCfg.Endpoint)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("peer[%d] endpoint %q: %w", i, peerCfg.Endpoint, err)
			}
			peer.Endpoint = endpoint
		}
		if peerCfg.PersistentKeepalive > 0 {
			if peerCfg.PersistentKeepalive > 65535 {
				return wgtypes.Config{}, fmt.Errorf("peer[%d] persistent keepalive %d is out of range", i, peerCfg.PersistentKeepalive)
			}
			keepalive := time.Duration(peerCfg.PersistentKeepalive) * time.Second
			peer.PersistentKeepaliveInterval = &keepalive
		}
		for _, cidr := range peerCfg.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("peer[%d] allowed IP %q: %w", i, cidr, err)
			}
			peer.AllowedIPs = append(peer.AllowedIPs, *ipnet)
		}
		out.Peers = append(out.Peers, peer)
	}
	return out, nil
}

// runIP executes ip(8) with a bounded timeout. The existing Linux network
// manager uses the same tool for every other interface mutation, so the
// kernel data plane stays consistent with how addresses, MTU and routes
// are applied afterwards.
func runIP(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), kernelIPTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("ip %s: timed out after %s", strings.Join(args, " "), kernelIPTimeout)
		}
		return out, fmt.Errorf("ip %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func kernelInterfaceError(name string, err error) error {
	msg := err.Error()
	hint := ""
	switch {
	case strings.Contains(msg, "executable file not found"):
		hint = " (install iproute2)"
	case strings.Contains(msg, "Operation not supported"),
		strings.Contains(msg, "Protocol not supported"),
		strings.Contains(msg, "Unknown device type"):
		hint = " (the WireGuard kernel module is unavailable; run 'modprobe wireguard' or install the WireGuard module package for your kernel)"
	}
	return fmt.Errorf("creating WireGuard kernel interface %q: %w%s", name, err, hint)
}

// ipLinkInfo is the subset of `ip -j -d link show` needed to identify a
// link's kind without parsing human-readable output.
type ipLinkInfo struct {
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

// isWireGuardInterface reports whether name exists and is a wireguard-type
// netdev. The JSON form is deliberate: searching the detailed text listing
// for "wireguard" would also match an alias or description on an unrelated
// interface, and that interface must never be deleted as a stale tunnel.
func isWireGuardInterface(name string) bool {
	out, err := runIP("-j", "-d", "link", "show", "dev", name)
	if err != nil {
		return false
	}
	var links []ipLinkInfo
	if err := json.Unmarshal(out, &links); err != nil {
		return false
	}
	return len(links) == 1 && links[0].LinkInfo.Kind == "wireguard"
}

// removeStaleKernelInterface deletes an interface left behind by a previous
// helper crash. A kernel netdev outlives its creator (unlike a userspace
// TUN), and the deterministic name would make the next connect fail with
// EEXIST. Only a wireguard-type link is removed: a same-named interface
// owned by anything else must surface as a real error instead of being
// silently destroyed.
func removeStaleKernelInterface(name string) {
	if !isWireGuardInterface(name) {
		return
	}
	if err := deleteKernelInterface(name); err != nil {
		slog.Warn("removing stale WireGuard kernel interface failed", "interface", name, "error", err)
	}
}

// deleteKernelInterface removes the netdev. Callers decide whether a
// failure is fatal: connect rollback gives up quietly, while Close logs it
// because the interface may already have disappeared.
func deleteKernelInterface(name string) error {
	_, err := runIP("link", "delete", "dev", name)
	return err
}

// Start re-asserts the interface's up state. BringUp already brought it up
// on the normal connect path; the second call keeps Engine.Start meaningful
// for callers that construct an engine without the generic phases.
func (e *kernelEngine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("kernel WireGuard interface is closed")
	}
	if _, err := runIP("link", "set", "dev", e.iface, "up"); err != nil {
		return fmt.Errorf("bringing up kernel interface %q: %w", e.iface, err)
	}
	return nil
}

func (e *kernelEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	if err := deleteKernelInterface(e.iface); err != nil {
		slog.Debug("deleting WireGuard kernel interface failed", "interface", e.iface, "error", err)
	}
	return nil
}

func (e *kernelEngine) Status(tunnelName string, connectedAt time.Time) (*ConnectionStatus, error) {
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return nil, errors.New("kernel WireGuard interface is closed")
	}
	return GetStatus(e.iface, tunnelName, connectedAt)
}

func (e *kernelEngine) CurrentEndpointIPs() ([]string, error) {
	e.mu.Lock()
	closed := e.closed
	iface := e.iface
	e.mu.Unlock()
	if closed {
		return nil, errors.New("kernel WireGuard interface is closed")
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("opening wgctrl client: %w", err)
	}
	defer client.Close()
	dev, err := client.Device(iface)
	if err != nil {
		return nil, fmt.Errorf("querying device %s: %w", iface, err)
	}

	seen := make(map[string]struct{}, len(dev.Peers))
	endpoints := make([]string, 0, len(dev.Peers))
	for _, peer := range dev.Peers {
		if peer.Endpoint == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(peer.Endpoint.IP)
		if !ok {
			continue
		}
		host := addr.Unmap().String()
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		endpoints = append(endpoints, host)
	}
	return endpoints, nil
}
