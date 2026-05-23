//go:build windows

package network

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/sysexec"
)

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
	// Detect current default gateways before adding our routes.
	origGw := getWindowsDefaultGateway()
	origGw6 := getWindowsDefaultIPv6Gateway()
	// Detect the physical IPv6 interface index for netsh route commands.
	origIfIdx6 := getWindowsDefaultIPv6InterfaceIndex()

	// M10+C8: Add endpoint bypass routes via the original gateway. Handle
	// both IPv4 and IPv6 endpoints with correct Windows route syntax.
	for _, ipStr := range endpoints {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			// C8: Windows route command uses "mask" keyword, not CIDR notation.
			if origGw != "" {
				if err := runWin("route", "add", ipStr, "mask", "255.255.255.255", origGw, "metric", "1"); err != nil {
					slog.Warn("endpoint bypass route add failed", "ip", ipStr, "gw", origGw, "error", err)
				}
			}
		} else {
			// M10: IPv6 endpoint bypass route. netsh syntax requires
			// interface index (not gateway IP) as the second positional arg,
			// then nexthop= for the gateway.
			if origGw6 != "" && origIfIdx6 != "" {
				if err := runWin("netsh", "interface", "ipv6", "add", "route",
					ipStr+"/128", origIfIdx6, "nexthop="+origGw6, "metric=1"); err != nil {
					slog.Warn("IPv6 endpoint bypass route add failed", "ip", ipStr, "gw", origGw6, "error", err)
				}
			}
		}
	}
	m.bypassEndpoints = endpoints
	m.origGateway = origGw
	m.origGatewayV6 = origGw6
	m.origIfIdx6 = origIfIdx6

	// IPv4: Use the /1 split-route trick (0.0.0.0/1 + 128.0.0.0/1) instead
	// of a single 0.0.0.0/0. The /1 routes are more specific than the existing
	// default route, so they take precedence WITHOUT replacing it. This means:
	// - On disconnect, the original default route automatically resumes
	// - On crash, the system is NOT left without a default route
	// - No metric competition with existing default routes
	// This is the same approach used by wg-quick on macOS/Linux and documented
	// in wireguard-windows/docs/netquirk.md as the recommended user approach.
	if err := runWin("netsh", "interface", "ip", "add", "route", "0.0.0.0/1", ifaceName, "nexthop=0.0.0.0", "metric=0"); err != nil {
		return fmt.Errorf("adding 0.0.0.0/1: %w", err)
	}
	if err := runWin("netsh", "interface", "ip", "add", "route", "128.0.0.0/1", ifaceName, "nexthop=0.0.0.0", "metric=0"); err != nil {
		return fmt.Errorf("adding 128.0.0.0/1: %w", err)
	}
	// IPv6: Same /1 split-route trick (non-fatal if IPv6 is unavailable)
	tryRunWin("IPv6 ::/1 split route add", "netsh", "interface", "ipv6", "add", "route", "::/1", "interface="+ifaceName, "nexthop=::", "metric=0")
	tryRunWin("IPv6 8000::/1 split route add", "netsh", "interface", "ipv6", "add", "route", "8000::/1", "interface="+ifaceName, "nexthop=::", "metric=0")

	return nil
}

func (m *WindowsManager) RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error {
	if fullTunnel {
		// Remove /1 split routes (matching what addFullTunnelRoutes installed).
		tryRunWin("delete 0.0.0.0/1", "netsh", "interface", "ip", "delete", "route", "0.0.0.0/1", ifaceName)
		tryRunWin("delete 128.0.0.0/1", "netsh", "interface", "ip", "delete", "route", "128.0.0.0/1", ifaceName)
		tryRunWin("delete ::/1", "netsh", "interface", "ipv6", "delete", "route", "::/1", ifaceName)
		tryRunWin("delete 8000::/1", "netsh", "interface", "ipv6", "delete", "route", "8000::/1", ifaceName)
		// Remove endpoint bypass routes
		for _, ipStr := range m.bypassEndpoints {
			if ipStr == "" {
				continue
			}
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				// C8: No CIDR notation for Windows route delete.
				tryRunWin("delete bypass route", "route", "delete", ipStr)
			} else {
				// IPv6 bypass was added via the physical interface index.
				if m.origIfIdx6 != "" {
					tryRunWin("delete IPv6 bypass route", "netsh", "interface", "ipv6", "delete", "route", ipStr+"/128", m.origIfIdx6)
				}
			}
		}
		m.bypassEndpoints = nil
		m.origGateway = ""
		m.origGatewayV6 = ""
		m.origIfIdx6 = ""
		return nil
	}
	for _, cidr := range allowedIPs {
		tryRunWin("delete split route", "netsh", "interface", "ip", "delete", "route", cidr, ifaceName)
	}
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

func (m *WindowsManager) RestoreDNS(ifaceName string) error {
	// Reset the VPN interface DNS back to DHCP (cleanup).
	tryRunWin("reset VPN iface DNS to DHCP", "netsh", "interface", "ip", "set", "dns", ifaceName, "dhcp")

	// Restore original DNS to the PHYSICAL interface it was saved from.
	// If origDNSIface is empty, the DNS was likely never overridden.
	restoreIface := m.origDNSIface
	if restoreIface == "" || len(m.origDNS) == 0 {
		return nil
	}
	if err := runWin("netsh", "interface", "ip", "set", "dns", restoreIface, "static", m.origDNS[0]); err != nil {
		return err
	}
	for i := 1; i < len(m.origDNS); i++ {
		if err := runWin("netsh", "interface", "ip", "add", "dns", restoreIface, m.origDNS[i], fmt.Sprintf("index=%d", i+1)); err != nil {
			slog.Warn("RestoreDNS: adding secondary DNS failed", "server", m.origDNS[i], "error", err)
		}
	}
	m.origDNSIface = ""
	return nil
}

func (m *WindowsManager) Cleanup(ifaceName string) error {
	if err := m.RestoreDNS(ifaceName); err != nil {
		slog.Warn("Cleanup: RestoreDNS failed", "iface", ifaceName, "error", err)
	}
	// Clean up /1 split routes (defensive — also try /0 in case of legacy state)
	tryRunWin("cleanup 0.0.0.0/1", "netsh", "interface", "ip", "delete", "route", "0.0.0.0/1", ifaceName)
	tryRunWin("cleanup 128.0.0.0/1", "netsh", "interface", "ip", "delete", "route", "128.0.0.0/1", ifaceName)
	tryRunWin("cleanup 0.0.0.0/0", "netsh", "interface", "ip", "delete", "route", "0.0.0.0/0", ifaceName)
	tryRunWin("cleanup ::/1", "netsh", "interface", "ipv6", "delete", "route", "::/1", ifaceName)
	tryRunWin("cleanup 8000::/1", "netsh", "interface", "ipv6", "delete", "route", "8000::/1", ifaceName)
	tryRunWin("cleanup ::/0", "netsh", "interface", "ipv6", "delete", "route", "::/0", ifaceName)
	// Clean up endpoint bypass routes
	for _, ipStr := range m.bypassEndpoints {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			tryRunWin("cleanup bypass route", "route", "delete", ipStr)
		} else {
			if m.origIfIdx6 != "" {
				tryRunWin("cleanup IPv6 bypass route", "netsh", "interface", "ipv6", "delete", "route", ipStr+"/128", m.origIfIdx6)
			}
		}
	}
	m.bypassEndpoints = nil
	m.origGatewayV6 = ""
	m.origIfIdx6 = ""
	// M14: Clean up split-tunnel routes.
	for _, cidr := range m.splitRoutes {
		tryRunWin("cleanup split route", "netsh", "interface", "ip", "delete", "route", cidr, ifaceName)
	}
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
			return fmt.Errorf("%s %s: timed out after %s (%s)", name, strings.Join(args, " "), cmdTimeout, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
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
