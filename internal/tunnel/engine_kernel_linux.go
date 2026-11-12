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

type kernelEngine struct {
	mu     sync.Mutex
	iface  string
	link   *kernelLinkHandle
	closed bool
}

func newKernelEngine(cfg, resolved *config.WireGuardConfig, resolvedEndpointIPs, resolvedEndpoints []string) (*Engine, error) {
	return newKernelEngineWithDataDir(cfg, resolved, resolvedEndpointIPs, resolvedEndpoints, "")
}

// newKernelEngineWithDataDir creates the link through rtnetlink with a random
// requested ifindex. With a dataDir, a durable intent is written before
// RTM_NEWLINK so a crash at any point before the first ActiveTunnelState
// save is recoverable without touching foreign devices.
func newKernelEngineWithDataDir(cfg, resolved *config.WireGuardConfig, resolvedEndpointIPs, resolvedEndpoints []string, dataDir string) (*Engine, error) {
	name := platformTUNName(runtime.GOOS, cfg.Name)
	backend, err := kernelLinkBackendFactory()
	if err != nil {
		return nil, kernelInterfaceError(name, err)
	}
	link, err := createKernelLink(kernelLinkRequest{
		backend: backend,
		dataDir: dataDir,
		tunnel:  cfg.Name,
		name:    name,
		prepare: func() error { return prepareKernelInterface(name, cfg.Name) },
		configure: func() error {
			wgCfg, err := kernelWgtypesConfig(resolved)
			if err != nil {
				return err
			}
			client, err := wgctrl.New()
			if err != nil {
				return fmt.Errorf("opening wgctrl client: %w", err)
			}
			defer client.Close()
			if err := client.ConfigureDevice(name, wgCfg); err != nil {
				return fmt.Errorf("applying WireGuard configuration to %q: %w", name, err)
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}

	slog.Info("WireGuard kernel interface created", "interface", name, "ifindex", link.kernelLinkIndex())
	return &Engine{
		kernel:              &kernelEngine{iface: name, link: link},
		ifaceName:           name,
		resolvedEndpointIPs: resolvedEndpointIPs,
		resolvedEndpoints:   resolvedEndpoints,
	}, nil
}

func (e *kernelEngine) kernelLinkIndex() int32 { return e.link.kernelLinkIndex() }

func (e *kernelEngine) commitKernelLinkIntent() error { return e.link.commitKernelLinkIntent() }

func (e *kernelEngine) releaseKernelLink() error { return e.link.releaseKernelLink() }

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

// ipLinkInfo is the subset of `ip -j -d link show` needed to identify a
// link's kind and owner without parsing human-readable output.
type ipLinkInfo struct {
	IfName   string `json:"ifname"`
	IfAlias  string `json:"ifalias"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

// kernelInterfaceState looks up the link named name. exists=false means the
// interface is absent; a failed query returns an error, which callers must
// not mistake for absence.
func kernelInterfaceState(name string) (ipLinkInfo, bool, error) {
	out, err := runIP("-j", "-d", "link", "show")
	if err != nil {
		return ipLinkInfo{}, false, err
	}
	var links []ipLinkInfo
	if err := json.Unmarshal(out, &links); err != nil {
		return ipLinkInfo{}, false, fmt.Errorf("parsing ip link output: %w", err)
	}
	for _, link := range links {
		if link.IfName == name {
			return link, true, nil
		}
	}
	return ipLinkInfo{}, false, nil
}

// prepareKernelInterface makes name available to this connection.
//
// A kernel netdev outlives the process that created it: after a helper crash
// the deterministic name makes the next `ip link add` fail with EEXIST. Only
// a leftover interface carrying this helper's ownership marker is deleted; a
// same-named link owned by anything else is reported as a conflict and left
// untouched.
func prepareKernelInterface(name, tunnel string) error {
	info, exists, err := kernelInterfaceState(name)
	if err != nil {
		return fmt.Errorf("inspecting interface %q: %w", name, err)
	}
	if !exists {
		return nil
	}
	if info.LinkInfo.Kind != "wireguard" {
		return fmt.Errorf("%w: %q is a %q link, not a WireGuard interface",
			errKernelInterfaceConflict, name, info.LinkInfo.Kind)
	}
	want := kernelOwnershipAliasPrefix + tunnel
	if info.IfAlias != want {
		if info.IfAlias == "" {
			// Interfaces created before ownership markers existed carry no
			// alias, so they can never be recognised as ours. Name the manual
			// command instead of leaving the user with a connect that fails
			// forever.
			return fmt.Errorf("%w: %q has no WireGuide ownership marker; if it is a leftover from an older WireGuide version, remove it with `ip link delete dev %s`",
				errKernelInterfaceConflict, name, name)
		}
		return fmt.Errorf("%w: %q is not owned by WireGuide (alias %q)",
			errKernelInterfaceConflict, name, info.IfAlias)
	}
	return fmt.Errorf("%w: %q has a matching profile marker, but may still be active; recover or remove the interface explicitly before reconnecting", errKernelInterfaceConflict, name)
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
	if err := e.link.releaseKernelLink(); err != nil {
		slog.Warn("deleting WireGuard kernel interface failed", "interface", e.iface, "error", err)
		return err
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
