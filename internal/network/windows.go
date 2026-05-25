//go:build windows

package network

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/korjwl1/wireguide/internal/sysexec"
)

// decodeOEM converts a byte slice produced by a Windows console child
// (netsh, route, etc.) from the system OEM codepage to UTF-8. Without
// this, Korean Windows error messages — printed by netsh as CP949 —
// surface in slog output as the U+FFFD replacement character garbage
// ("���"). Returns the input unchanged if the conversion fails.
func decodeOEM(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const cpOEMCP = 1
	wlen, err := windows.MultiByteToWideChar(cpOEMCP, 0, &b[0], int32(len(b)), nil, 0)
	if err != nil || wlen <= 0 {
		return string(b)
	}
	wbuf := make([]uint16, wlen)
	_, err = windows.MultiByteToWideChar(cpOEMCP, 0, &b[0], int32(len(b)), &wbuf[0], wlen)
	if err != nil {
		return string(b)
	}
	return windows.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(&wbuf[0]))[:wlen:wlen])
}

// cmdTimeout bounds every external command (netsh/route/PowerShell).
// PowerShell cold-start can legitimately take 1-2s; 30s leaves headroom
// for slow netsh operations on contested interfaces.
const cmdTimeout = 30 * time.Second

// WindowsManager implements NetworkManager for Windows using netsh/winipcfg.
type WindowsManager struct {
	origDNS         []string
	origDNSIface    string   // interface name where origDNS was saved from
	bypassEndpoints []string // endpoint IPs we added bypass routes for
	origGateway     string   // original IPv4 default gateway for cleanup
	origGatewayV6   string   // original IPv6 default gateway for cleanup
	origIfIdx6      string   // original IPv6 interface index for bypass route cleanup
	splitRoutes     []string // split-tunnel routes we added (CIDR strings)

	// bypassPhys{LuidV4,LuidV6,IfIdxV4} capture the underlay adapter
	// addFullTunnelRoutes installed bypass /32 host routes against. We
	// need them to delete the SAME rows via DeleteIpForwardEntry2 — the
	// delete path is a 4-tuple match (LUID, dest, prefix, nexthop), so
	// "best-effort sweep by route delete <ip>" can no longer pick up
	// rows whose LUID we never knew. Captured once, cleared by
	// RemoveRoutes / Cleanup.
	bypassPhysLuidV4  uint64
	bypassPhysLuidV6  uint64
	bypassPhysIfIdxV4 uint32
}

func NewPlatformManager() NetworkManager {
	return &WindowsManager{}
}

func (m *WindowsManager) AssignAddress(ifaceName string, addresses []string) error {
	for i, addr := range addresses {
		ip, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return fmt.Errorf("invalid address %q: %w", addr, err)
		}
		// netsh expects separate IP and subnet mask, not CIDR notation.
		mask := net.IP(ipNet.Mask).String()
		if i == 0 {
			// First address: use 'set' to transition from DHCP to static
			if err := runWin("netsh", "interface", "ip", "set", "address",
				ifaceName, "static", ip.String(), mask); err != nil {
				return fmt.Errorf("assigning address %s: %w", addr, err)
			}
		} else {
			// Additional addresses: use 'add'
			if err := runWin("netsh", "interface", "ip", "add", "address",
				ifaceName, ip.String(), mask); err != nil {
				return fmt.Errorf("assigning address %s: %w", addr, err)
			}
		}
	}
	return nil
}

func (m *WindowsManager) SetMTU(ifaceName string, mtu int) error {
	if mtu <= 0 {
		// Auto-detect: try to get upstream MTU and subtract 80
		if upMTU := getUpstreamMTU(); upMTU > 0 {
			mtu = upMTU - 80
		}
		if mtu <= 0 {
			mtu = 1420
		}
		if mtu < 1280 {
			mtu = 1280
		}
	}
	// Set MTU for both IPv4 AND IPv6 — the official WireGuard Windows client
	// does this for both address families. Without IPv6 MTU, tunnels carrying
	// IPv6 traffic (::/0 in AllowedIPs) get the default 1500 MTU, causing
	// fragmentation or packet drops.
	// H17: Use store=active so the MTU setting applies immediately and does not
	// persist across reboots (the tunnel is transient).
	mtuStr := fmt.Sprintf("mtu=%d", mtu)
	if err := runWin("netsh", "interface", "ipv4", "set", "subinterface", ifaceName,
		mtuStr, "store=active"); err != nil {
		return err
	}
	// IPv6 MTU — non-fatal if the interface has no IPv6 address configured.
	if err := runWin("netsh", "interface", "ipv6", "set", "subinterface", ifaceName,
		mtuStr, "store=active"); err != nil {
		slog.Warn("failed to set IPv6 MTU (interface may not have IPv6)", "error", err)
	}
	return nil
}

func (m *WindowsManager) BringUp(ifaceName string) error {
	// On Windows, the interface is usually already up after TUN creation.
	// Enable weak-host send/receive on the tunnel interface so that reply
	// packets whose source IP is the tunnel address are accepted on whatever
	// physical interface they arrive on (Windows IPv4 strong-host model
	// would otherwise drop them in multi-homed setups). Mirrors what the
	// official WireGuard-Windows client does via WFP, but using netsh keeps
	// us self-contained for the netsh-based code path. Best-effort.
	//
	// KNOWN LIMITATION (enterprise): Active Directory Group Policy can
	// enforce strong-host behaviour at the registry level (HKLM\SYSTEM\
	// CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}\). On
	// such managed machines our weakhostreceive=enabled is reverted by
	// the next gpupdate. There is no programmatic workaround — the user
	// must ask their IT admin to exempt the WireGuide adapter (or accept
	// that multi-homed reply packets may be dropped). See README for the
	// full operator note.
	tryRunWin("set weakhostsend ipv4", "netsh", "interface", "ipv4", "set", "interface", ifaceName, "weakhostsend=enabled", "weakhostreceive=enabled", "store=active")
	tryRunWin("set weakhostsend ipv6", "netsh", "interface", "ipv6", "set", "interface", ifaceName, "weakhostsend=enabled", "weakhostreceive=enabled", "store=active")
	return nil
}

func (m *WindowsManager) AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpoints []string, tableCfg string, fwmarkCfg string) error {
	if strings.EqualFold(tableCfg, "off") {
		slog.Info("Table=off: skipping route installation", "interface", ifaceName)
		return nil
	}
	if fullTunnel {
		return m.addFullTunnelRoutes(ifaceName, endpoints)
	}
	// M14: Track split-tunnel routes so Cleanup can remove them.
	for _, cidr := range allowedIPs {
		if strings.Contains(cidr, ":") {
			if err := runWin("netsh", "interface", "ipv6", "add", "route", cidr, ifaceName, "nexthop=::"); err != nil {
				return fmt.Errorf("adding route %s: %w", cidr, err)
			}
		} else {
			if err := runWin("netsh", "interface", "ip", "add", "route", cidr, ifaceName, "nexthop=0.0.0.0"); err != nil {
				return fmt.Errorf("adding route %s: %w", cidr, err)
			}
		}
		m.splitRoutes = append(m.splitRoutes, cidr)
	}
	return nil
}

func (m *WindowsManager) addFullTunnelRoutes(ifaceName string, endpoints []string) error {
	// PREFLIGHT — fail FAST on the conditions that would otherwise produce
	// the routing-loop class of bug (issue #14 / "6 GB upload spike"):
	//
	//   - No IPv4 default route detected. Without one we cannot install the
	//     /32 bypass that keeps WireGuard's own UDP traffic off the tunnel.
	//     Continuing to install /1 split routes would silently trap the
	//     encrypted handshake inside the tunnel and recurse at line rate.
	//
	//   - No IPv4 endpoints to bypass. A full-tunnel config with zero
	//     resolved IPv4 endpoints is either malformed or pure-IPv6; the
	//     latter is handled by the IPv6 branch below. For IPv4 we refuse
	//     rather than silently leave a hole.
	//
	// Errors here propagate to connectPhases which runs `rollback` — the
	// caller never sees a partially-installed split route. No netsh-warn-
	// and-continue fallback path: the user-visible failure mode of "Connect
	// returned an error" is strictly better than "Connect succeeded and
	// your upload meter spins to 6 GB".
	// Underlay detection with bounded retry. The user-facing failure
	// mode we're guarding against is "Connect right after wake from
	// sleep / fresh boot fails because Windows hasn't installed the
	// default route yet" — typical lag is 0.5–3 s on Wi-Fi handoff,
	// up to 10 s on slow DHCP / cellular tether. 5 s is the sweet
	// spot: covers most legitimate slow-start scenarios while
	// bounding the fail-fast window to something the user perceives
	// as a normal connect delay.
	//
	// Captures: IPv4/IPv6 default-route gateway, the underlay LUID
	// (what CreateIpForwardEntry2 wants for the bypass /32), the
	// underlay ifIndex, and the IPv6 ifIndex (used for netsh-style
	// legacy paths in Cleanup). Excludes our own wintun adapter so a
	// second-connect re-detect doesn't loop on the just-up tunnel.
	var (
		origGw      string
		origGw6     string
		origIfIdx6  string
		physLuidV4  uint64
		physIfIdxV4 uint32
		physLuidV6  uint64
	)
	const underlayPollInterval = 250 * time.Millisecond
	const underlayPollBudget = 5 * time.Second
	pollDeadline := time.Now().Add(underlayPollBudget)
	for {
		origGw = getWindowsDefaultGateway()
		origGw6 = getWindowsDefaultIPv6Gateway()
		origIfIdx6 = getWindowsDefaultIPv6InterfaceIndex()
		physLuidV4, physIfIdxV4, _ = DefaultRouteV4LuidAndIndex([]string{ifaceName})
		physLuidV6, _, _ = DefaultRouteV6LuidAndIndex([]string{ifaceName})
		// We have what we need as soon as the IPv4 underlay is present;
		// IPv6 is optional and best-effort. Most VPN configs are v4-only
		// peers, so v6 underlay missing must not block.
		if origGw != "" && physLuidV4 != 0 {
			break
		}
		if time.Now().After(pollDeadline) {
			break
		}
		time.Sleep(underlayPollInterval)
	}

	// Classify endpoints by family so we can demand a usable underlay only
	// for the families we actually need to bypass.
	var v4Endpoints, v6Endpoints []net.IP
	for _, ipStr := range endpoints {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4Endpoints = append(v4Endpoints, ip.To4())
		} else {
			v6Endpoints = append(v6Endpoints, ip)
		}
	}

	if len(v4Endpoints) > 0 && (origGw == "" || physLuidV4 == 0) {
		return fmt.Errorf("full-tunnel: cannot detect a usable IPv4 default gateway "+
			"(gw=%q, physLuid=%d). Refusing to install split routes — without an "+
			"endpoint bypass the encrypted WireGuard traffic would loop through the "+
			"tunnel and saturate the link",
			origGw, physLuidV4)
	}
	if len(v6Endpoints) > 0 && (origGw6 == "" || physLuidV6 == 0) {
		return fmt.Errorf("full-tunnel: cannot detect a usable IPv6 default gateway "+
			"(gw=%q, physLuid=%d). IPv6 peer endpoint cannot be bypassed safely",
			origGw6, physLuidV6)
	}

	// Resolve the tunnel adapter's LUID once — we'll use it for both the
	// (later) /1 split routes and any IPv6 bypass tracking.
	tunnelLuid, _ := convertInterfaceAliasToLuid(ifaceName)
	if tunnelLuid == 0 {
		return fmt.Errorf("full-tunnel: cannot resolve tunnel adapter LUID for %q", ifaceName)
	}

	gwIPv4 := net.ParseIP(origGw)

	// PHASE 1+2: bypass host routes for every IPv4 + IPv6 peer endpoint.
	// We install every row first, then batch-verify against ONE
	// snapshot of the route table per family. The naive per-route
	// VerifyIpForwardRoute would issue N GetIpForwardTable2 calls
	// for N peers — wasteful on multi-peer site-to-site configs and
	// on machines with hundreds of unrelated routes. One snapshot
	// per family is enough because Add and Verify both run while
	// addFullTunnelRoutes holds the only writer; the table can only
	// be larger at Verify time than at Add time.
	gwIPv6 := net.ParseIP(origGw6)
	wantKeys := make([]routeKey, 0, len(v4Endpoints)+len(v6Endpoints))
	for _, ip := range v4Endpoints {
		err := AddIpForwardRoute(physLuidV4, physIfIdxV4, ip, 32, gwIPv4, 1)
		if err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
			return fmt.Errorf("installing IPv4 endpoint bypass %s via %s: %w", ip, origGw, err)
		}
		wantKeys = append(wantKeys, routeKey{ifaceLuid: physLuidV4, dest: ip, prefixLen: 32})
	}
	for _, ip := range v6Endpoints {
		err := AddIpForwardRoute(physLuidV6, 0, ip, 128, gwIPv6, 1)
		if err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
			return fmt.Errorf("installing IPv6 endpoint bypass %s via %s: %w", ip, origGw6, err)
		}
		wantKeys = append(wantKeys, routeKey{ifaceLuid: physLuidV6, dest: ip, prefixLen: 128})
	}
	if missing := VerifyIpForwardRoutes(wantKeys); len(missing) > 0 {
		return fmt.Errorf("installing endpoint bypass: %d route(s) reported success but not visible in table (first missing: %s/%d via LUID %d)",
			len(missing), missing[0].dest, missing[0].prefixLen, missing[0].ifaceLuid)
	}

	// Persist the bypass list so disconnect can target the same rows.
	m.bypassEndpoints = endpoints
	m.bypassPhysLuidV4 = physLuidV4
	m.bypassPhysLuidV6 = physLuidV6
	m.bypassPhysIfIdxV4 = physIfIdxV4
	m.origGateway = origGw
	m.origGatewayV6 = origGw6
	m.origIfIdx6 = origIfIdx6

	// PHASE 3: IPv4 /1 split-route trick (0.0.0.0/1 + 128.0.0.0/1).
	// More specific than the user's existing 0.0.0.0/0 default route, so
	// it takes precedence WITHOUT replacing it — disconnect's row delete
	// automatically restores the underlay's default-route precedence.
	// metric=0 keeps the kernel-computed effective metric purely driven
	// by the tunnel adapter's interface metric (set to 1 by SetDNS).
	if err := AddIpForwardRoute(tunnelLuid, 0, net.IPv4(0, 0, 0, 0), 1, nil, 0); err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
		return fmt.Errorf("adding 0.0.0.0/1: %w", err)
	}
	if err := AddIpForwardRoute(tunnelLuid, 0, net.IPv4(128, 0, 0, 0), 1, nil, 0); err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
		return fmt.Errorf("adding 128.0.0.0/1: %w", err)
	}

	// PHASE 4: IPv6 /1 split routes — best-effort. A box with no IPv6
	// connectivity at all will still pass v4 traffic correctly even if
	// these fail (no kernel-side loop risk because the only IPv6 routes
	// installed are the ones we tried and failed to add).
	v6Unspec := net.IPv6unspecified
	if err := AddIpForwardRoute(tunnelLuid, 0, v6Unspec, 1, nil, 0); err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
		slog.Warn("IPv6 ::/1 split route add failed", "error", err)
	}
	v68000 := net.ParseIP("8000::")
	if err := AddIpForwardRoute(tunnelLuid, 0, v68000, 1, nil, 0); err != nil && !errors.Is(err, ErrRouteAlreadyExists) {
		slog.Warn("IPv6 8000::/1 split route add failed", "error", err)
	}

	return nil
}

func (m *WindowsManager) RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error {
	if fullTunnel {
		// Use iphlpapi for the routes we installed via iphlpapi. Each
		// Delete* call is ~microseconds, so we don't need parallelTry's
		// goroutine fan-out anymore — the wall-clock cost of all six
		// deletes is dominated by the kernel's nsi serialisation, not
		// console startup.
		tunnelLuid, _ := convertInterfaceAliasToLuid(ifaceName)
		tryDeleteRoute := func(luid uint64, dest net.IP, prefix uint8, nextHop net.IP, name string) {
			if luid == 0 {
				return
			}
			if err := DeleteIpForwardRoute(luid, 0, dest, prefix, nextHop); err != nil && !errors.Is(err, ErrRouteNotFound) {
				slog.Debug("RemoveRoutes: "+name+" delete failed", "error", err)
			}
		}
		// /1 split routes on the tunnel adapter.
		tryDeleteRoute(tunnelLuid, net.IPv4(0, 0, 0, 0), 1, nil, "0.0.0.0/1")
		tryDeleteRoute(tunnelLuid, net.IPv4(128, 0, 0, 0), 1, nil, "128.0.0.0/1")
		tryDeleteRoute(tunnelLuid, net.IPv6unspecified, 1, nil, "::/1")
		if v6 := net.ParseIP("8000::"); v6 != nil {
			tryDeleteRoute(tunnelLuid, v6, 1, nil, "8000::/1")
		}

		// IPv4 endpoint bypass /32 routes on the physical adapter.
		gwV4 := net.ParseIP(m.origGateway)
		for _, ipStr := range m.bypassEndpoints {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				tryDeleteRoute(m.bypassPhysLuidV4, v4, 32, gwV4, "bypass v4 "+ipStr)
				continue
			}
			gwV6 := net.ParseIP(m.origGatewayV6)
			tryDeleteRoute(m.bypassPhysLuidV6, ip, 128, gwV6, "bypass v6 "+ipStr)
		}

		m.bypassEndpoints = nil
		m.origGateway = ""
		m.origGatewayV6 = ""
		m.origIfIdx6 = ""
		m.bypassPhysLuidV4 = 0
		m.bypassPhysLuidV6 = 0
		m.bypassPhysIfIdxV4 = 0
		return nil
	}
	thunks := make([]func(), 0, len(allowedIPs))
	for _, cidr := range allowedIPs {
		cidr := cidr
		thunks = append(thunks, func() {
			tryRunWin("delete split route", "netsh", "interface", "ip", "delete", "route", cidr, ifaceName)
		})
	}
	parallelTry(thunks...)
	m.splitRoutes = nil
	return nil
}

func (m *WindowsManager) SetDNS(ifaceName string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	// Save original DNS from the PHYSICAL interface (the one with the default
	// route), not the VPN interface. The VPN interface has no DNS configured yet,
	// so saving from it would give us empty/DHCP, making RestoreDNS a no-op.
	// We also record which interface the DNS was saved from so RestoreDNS can
	// write it back to the correct interface.
	physIface := getWindowsPhysicalInterfaceName()
	if physIface != "" {
		m.origDNS = getCurrentWinDNS(physIface)
		m.origDNSIface = physIface
	}
	if len(m.origDNS) == 0 {
		m.origDNSIface = ifaceName
		m.origDNS = getCurrentWinDNS(ifaceName)
	}

	// Set primary DNS
	if err := runWin("netsh", "interface", "ip", "set", "dns", ifaceName, "static", servers[0]); err != nil {
		return err
	}
	// Add additional DNS servers
	for i := 1; i < len(servers); i++ {
		if err := runWin("netsh", "interface", "ip", "add", "dns", ifaceName, servers[i], fmt.Sprintf("index=%d", i+1)); err != nil {
			slog.Warn("SetDNS: adding secondary DNS failed", "server", servers[i], "error", err)
		}
	}

	// Set the VPN interface metric to 1 so Windows prefers its DNS over
	// other interfaces, preventing DNS leaks through the physical adapter.
	tryRunWin("set IPv4 iface metric", "netsh", "interface", "ip", "set", "interface", ifaceName, "metric=1")
	tryRunWin("set IPv6 iface metric", "netsh", "interface", "ipv6", "set", "interface", ifaceName, "metric=1")

	return nil
}

// ResetDNSToSystemDefault resets DNS to DHCP for any WireGuard-style
// interfaces that still exist. Used by crash recovery when we have no
// in-memory origDNS snapshot.
func (m *WindowsManager) ResetDNSToSystemDefault() error {
	// Enumerate interfaces and reset any that look like ours.
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "wg") || strings.HasPrefix(iface.Name, "WireGuard") {
			// Best-effort: if the interface still exists, set DNS back to DHCP.
			if resetErr := runWin("netsh", "interface", "ip", "set", "dns", iface.Name, "dhcp"); resetErr != nil {
				slog.Warn("crash recovery: failed to reset DNS to DHCP",
					"interface", iface.Name, "error", resetErr)
			}
		}
	}
	return nil
}

// PreCloseAdapterCleanup deprioritizes the VPN adapter and clears its
// DNS BEFORE the caller destroys the underlying TUN device. The wintun
// adapter typically lingers for 1-2 seconds after WintunCloseAdapter
// returns; during that window Windows still sees a metric-1 adapter
// with DNS=<configured>, and faithfully forwards DNS queries through
// it — to a tunnel that doesn't exist anymore. The fix: bump the
// metric so Ethernet wins routing/DNS preference, and clear the DNS
// so even a lingering metric-1 adapter has nothing to answer with.
//
// All three netsh calls are independent and fire in parallel; total
// wall-clock is one cold-start (~200 ms). The DNS clear is the one
// that tends to be slowest because Windows triggers DNS Client
// notifications on the change — accepting that one-time cost beats
// the alternative of "fast disconnect but DNS is wedged for 5
// seconds afterwards".
func (m *WindowsManager) PreCloseAdapterCleanup(ifaceName string) {
	parallelTry(
		func() {
			tryRunWin("bump VPN iface metric v4", "netsh", "interface", "ip", "set", "interface", ifaceName, "metric=35")
		},
		func() {
			tryRunWin("bump VPN iface metric v6", "netsh", "interface", "ipv6", "set", "interface", ifaceName, "metric=35")
		},
		func() {
			tryRunWin("clear VPN iface DNS", "netsh", "interface", "ip", "set", "dns", ifaceName, "dhcp")
		},
	)
}

// RestoreDNS on Windows is now intentionally minimal — it only resets
// the VPN adapter's own DNS to DHCP (cheap; usually a no-op because the
// adapter is already gone by the time disconnect calls us). It does NOT
// rewrite the physical interface's DNS even though we snapshot it in
// SetDNS, because SetDNS never modified the physical interface in the
// first place: it sets the VPN adapter's DNS and bumps the VPN adapter
// metric to 1, leaving the physical adapter's DNS exactly as DHCP left
// it. Writing the snapshot back was a 12-second no-op (Windows'
// `netsh interface ip set dns` triggers DNS Client service notifications
// + cache flush regardless of whether the value actually changed) that
// dominated the disconnect path.
//
// If a future change does start modifying the physical adapter's DNS,
// resurrect the snapshot-write here, but route it through
// SetInterfaceDnsSettings (iphlpapi) rather than netsh — that API
// completes in milliseconds.
func (m *WindowsManager) RestoreDNS(ifaceName string) error {
	tryRunWin("reset VPN iface DNS to DHCP", "netsh", "interface", "ip", "set", "dns", ifaceName, "dhcp")
	m.origDNSIface = ""
	m.origDNS = nil
	return nil
}

func (m *WindowsManager) Cleanup(ifaceName string) error {
	if err := m.RestoreDNS(ifaceName); err != nil {
		slog.Warn("Cleanup: RestoreDNS failed", "iface", ifaceName, "error", err)
	}
	// Defensive route cleanup. RemoveRoutes(fullTunnel=true) is the
	// primary path; Cleanup runs as a belt-and-suspenders sweep for
	// the case where Cleanup was reached without a prior RemoveRoutes
	// (e.g. partial connect rollback). All deletes are best-effort —
	// errRouteNotFound is the expected state when the row was already
	// reaped by RemoveRoutes.
	tunnelLuid, _ := convertInterfaceAliasToLuid(ifaceName)
	tryDelete := func(luid uint64, dest net.IP, prefix uint8, nextHop net.IP, name string) {
		if luid == 0 || dest == nil {
			return
		}
		if err := DeleteIpForwardRoute(luid, 0, dest, prefix, nextHop); err != nil && !errors.Is(err, ErrRouteNotFound) {
			slog.Debug("Cleanup: "+name+" delete failed", "error", err)
		}
	}
	if tunnelLuid != 0 {
		tryDelete(tunnelLuid, net.IPv4(0, 0, 0, 0), 1, nil, "0.0.0.0/1")
		tryDelete(tunnelLuid, net.IPv4(128, 0, 0, 0), 1, nil, "128.0.0.0/1")
		tryDelete(tunnelLuid, net.IPv4(0, 0, 0, 0), 0, nil, "0.0.0.0/0")
		tryDelete(tunnelLuid, net.IPv6unspecified, 1, nil, "::/1")
		if v6 := net.ParseIP("8000::"); v6 != nil {
			tryDelete(tunnelLuid, v6, 1, nil, "8000::/1")
		}
		tryDelete(tunnelLuid, net.IPv6unspecified, 0, nil, "::/0")
		for _, cidr := range m.splitRoutes {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			tryDelete(tunnelLuid, ipNet.IP, uint8(ones), nil, "split "+cidr)
		}
	}
	gwV4 := net.ParseIP(m.origGateway)
	gwV6 := net.ParseIP(m.origGatewayV6)
	for _, ipStr := range m.bypassEndpoints {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			tryDelete(m.bypassPhysLuidV4, v4, 32, gwV4, "bypass v4 "+ipStr)
			continue
		}
		tryDelete(m.bypassPhysLuidV6, ip, 128, gwV6, "bypass v6 "+ipStr)
	}

	// Flush the DNS resolver cache so any responses that came back via
	// the tunnel before disconnect (now invalid because the tunnel's
	// gone) are evicted. ipconfig /flushdns is just DnsFlushResolverCache
	// under the hood but takes <50 ms — cheap insurance against the
	// "VPN off → first DNS lookup returns a tunnel-era stale answer"
	// class of bug.
	tryRunWin("flush DNS cache", "ipconfig", "/flushdns")

	m.bypassEndpoints = nil
	m.origGatewayV6 = ""
	m.origIfIdx6 = ""
	m.bypassPhysLuidV4 = 0
	m.bypassPhysLuidV6 = 0
	m.bypassPhysIfIdxV4 = 0
	m.splitRoutes = nil
	return nil
}

func getUpstreamMTU() int {
	// Locate the default-route interface, then read its MTU directly via
	// iphlpapi — no PowerShell cold start (saves ~1s per Connect).
	def := getDefaultRoute(afInet)
	if def == nil {
		return 0
	}
	if mtu := findInterfaceMTU(def.InterfaceIndex); mtu > 0 {
		return int(mtu)
	}
	return 0
}

func runWin(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	sysexec.Hide(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("%s %s: timed out after %s (%s)", name, strings.Join(args, " "), cmdTimeout, strings.TrimSpace(decodeOEM(out)))
		}
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(decodeOEM(out)))
	}
	return nil
}

// runWinOut runs a Windows command with a bounded context and returns combined
// output. Used for parse-output queries (netsh/route/PowerShell) so they
// can't hang the helper indefinitely.
func runWinOut(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	sysexec.Hide(cmd)
	return cmd.CombinedOutput()
}

// tryRunWin runs a Windows command best-effort and logs failures at debug.
// Use for cleanup operations where the target may legitimately not exist
// (e.g. deleting a route that was never installed).
func tryRunWin(why, name string, args ...string) {
	if err := runWin(name, args...); err != nil {
		slog.Debug("best-effort "+why+" failed", "cmd", name, "args", args, "error", err)
	}
}

// parallelTry runs each thunk in its own goroutine and waits for all to
// finish. Used to fan out independent netsh / route invocations during
// disconnect — every cold-start of netsh costs ~200-500ms on Windows
// because the network configuration service has to load, and a typical
// full-tunnel teardown serially fires 10+ such commands. Running them
// concurrently turns the wall-clock cost from "sum" into "max", which
// is what makes the "disconnect takes 4-5 seconds" feeling go away.
//
// Caller-passed work must be independent — if a follow-up command needs
// the previous one's side effect (e.g. `netsh interface ip set dns
// static …` then `add dns …` for secondaries), keep those in a single
// thunk so they stay sequential inside the goroutine.
func parallelTry(thunks ...func()) {
	if len(thunks) == 0 {
		return
	}
	var wg sync.WaitGroup
	wg.Add(len(thunks))
	for _, t := range thunks {
		t := t
		go func() {
			defer wg.Done()
			t()
		}()
	}
	wg.Wait()
}

// getWindowsDefaultGateway returns the current IPv4 default gateway,
// preferring the iphlpapi syscall (locale-independent + microsecond-fast).
// Falls back to `route print` parsing, then PowerShell, so an unusual
// kernel state still resolves.
func getWindowsDefaultGateway() string {
	if def := getDefaultRoute(afInet); def != nil && def.NextHop != nil {
		return def.NextHop.String()
	}
	if gw := getDefaultGatewayFromRoutePrint(); gw != "" {
		return gw
	}
	return getDefaultGatewayFromPowerShell()
}

func getDefaultGatewayFromRoutePrint() string {
	out, err := runWinOut("route", "print", "0.0.0.0")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		// Look for "0.0.0.0  0.0.0.0  <gateway>  <interface>  <metric>"
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := fields[2]
			if net.ParseIP(gw) != nil && gw != "0.0.0.0" {
				return gw
			}
		}
	}
	return ""
}

func getDefaultGatewayFromPowerShell() string {
	out, err := runWinOut("powershell", "-NoProfile", "-Command",
		`(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop`)
	if err != nil {
		return ""
	}
	gw := strings.TrimSpace(string(out))
	if net.ParseIP(gw) != nil && gw != "0.0.0.0" {
		return gw
	}
	return ""
}

// getCurrentWinDNS retrieves the current DNS servers for the given interface.
// Direct iphlpapi syscall — locale-independent and ~1000× faster than the
// previous PowerShell path. netsh fallback retained in case the adapter is
// in a transitional state and GetAdaptersAddresses misses it.
func getCurrentWinDNS(ifaceName string) []string {
	if servers := getDNSServersForInterface(ifaceName); len(servers) > 0 {
		return servers
	}
	return getDNSViaNetsh(ifaceName)
}

// getWindowsDefaultIPv6InterfaceIndex returns the interface index of the
// physical adapter used for the IPv6 default route. Direct syscall — no
// PowerShell fork (saves ~1s per Connect).
func getWindowsDefaultIPv6InterfaceIndex() string {
	def := getDefaultRoute(afInet6)
	if def == nil || def.InterfaceIndex == 0 {
		return ""
	}
	return strconvU32(def.InterfaceIndex)
}

// getWindowsDefaultIPv6Gateway returns the current IPv6 default gateway.
// Direct syscall.
func getWindowsDefaultIPv6Gateway() string {
	def := getDefaultRoute(afInet6)
	if def == nil || def.NextHop == nil || def.NextHop.IsUnspecified() {
		return ""
	}
	return def.NextHop.String()
}

// getWindowsPhysicalInterfaceName returns the FriendlyName of the
// interface holding the IPv4 default route. Used to identify which
// adapter's DNS to save/restore.
func getWindowsPhysicalInterfaceName() string {
	def := getDefaultRoute(afInet)
	if def == nil || def.InterfaceIndex == 0 {
		return ""
	}
	return getInterfaceNameByIndex(def.InterfaceIndex)
}

func getDNSViaNetsh(ifaceName string) []string {
	out, _ := runWinOut("netsh", "interface", "ip", "show", "dns", ifaceName)
	var servers []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Try to find IP addresses on each line, regardless of locale.
		for _, field := range strings.Fields(line) {
			if net.ParseIP(field) != nil {
				servers = append(servers, field)
			}
		}
	}
	return servers
}
