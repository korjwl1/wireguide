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

	"github.com/korjwl1/wireguide/internal/sysexec"
	"golang.org/x/sys/windows"
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
