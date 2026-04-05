//go:build darwin

package network

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
)

// DarwinManager implements NetworkManager for macOS, modeled after wg-quick's
// darwin.bash script (github.com/WireGuard/wireguard-tools/src/wg-quick/darwin.bash).
type DarwinManager struct {
	// DNS state — saved per service (matches wg-quick collect_new_service_dns).
	// wg-quick sets DNS on EVERY network service, not just the primary one,
	// because macOS can switch primary between Wi-Fi and Ethernet mid-session.
	savedDNS         map[string][]string // service name → original DNS list
	savedSearch      map[string][]string // service name → original search domains
	dnsActive        bool

	// Endpoint bypass route state — tracked for cleanup.
	bypassEndpoints []string // IPs we added host routes for
}

func NewPlatformManager() NetworkManager {
	return &DarwinManager{
		savedDNS:    make(map[string][]string),
		savedSearch: make(map[string][]string),
	}
}

// AssignAddress uses wg-quick's form: `ifconfig <if> inet <ip/cidr> <ip> alias`.
// For IPv6: `ifconfig <if> inet6 <ip/cidr> alias` (no netmask).
func (m *DarwinManager) AssignAddress(ifaceName string, addresses []string) error {
	for _, addr := range addresses {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			return fmt.Errorf("invalid address %q: %w", addr, err)
		}
		if ip.To4() != nil {
			// IPv4: ifconfig <if> inet <cidr> <ip> alias
			if err := run("ifconfig", ifaceName, "inet", addr, ip.String(), "alias"); err != nil {
				return fmt.Errorf("assigning address %s: %w", addr, err)
			}
		} else {
			// IPv6: ifconfig <if> inet6 <cidr> alias
			if err := run("ifconfig", ifaceName, "inet6", addr, "alias"); err != nil {
				return fmt.Errorf("assigning address %s: %w", addr, err)
			}
		}
	}
	return nil
}

// SetMTU uses dynamic detection (wg-quick algorithm): default interface MTU
// minus 80 bytes (40 IPv6 + 8 UDP + 32 WireGuard header overhead).
// Falls back to 1420 if detection fails.
func (m *DarwinManager) SetMTU(ifaceName string, mtu int) error {
	if mtu <= 0 {
		// Auto-detect from default interface
		defaultIf := getDefaultInterface()
		upstreamMTU := 1500
		if defaultIf != "" {
			if v := getInterfaceMTU(defaultIf); v > 0 {
				upstreamMTU = v
			}
		}
		mtu = upstreamMTU - 80
		if mtu < 1280 { // IPv6 minimum
			mtu = 1280
		}
	}
	return run("ifconfig", ifaceName, "mtu", fmt.Sprintf("%d", mtu))
}

func (m *DarwinManager) BringUp(ifaceName string) error {
	return run("ifconfig", ifaceName, "up")
}

// AddRoutes installs routes for AllowedIPs. For /0 (full tunnel) it uses
// the split-route trick + endpoint bypass. Routes are added longest-prefix
// first to avoid transient conflicts (wg-quick's sort -nr -k 2 -t /).
func (m *DarwinManager) AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpoint string) error {
	// Sort by prefix length descending (longest first)
	sorted := sortAllowedIPs(allowedIPs)

	hasV4Default := false
	hasV6Default := false
	for _, cidr := range sorted {
		isV6 := strings.Contains(cidr, ":")
		if cidr == "0.0.0.0/0" {
			hasV4Default = true
			continue
		}
		if cidr == "::/0" {
			hasV6Default = true
			continue
		}
		// Non-default route: skip if already pointing at this interface (idempotent)
		family := "-inet"
		if isV6 {
			family = "-inet6"
		}
		if existing, _ := runOut("route", "-n", "get", family, cidr); routeUsesInterface(existing, ifaceName) {
			continue
		}
		if err := run("route", "-q", "-n", "add", family, cidr, "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding route %s: %w", cidr, err)
		}
	}

	// Install default routes using the split trick
	if hasV4Default {
		if err := run("route", "-q", "-n", "add", "-inet", "0.0.0.0/1", "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding 0.0.0.0/1: %w", err)
		}
		if err := run("route", "-q", "-n", "add", "-inet", "128.0.0.0/1", "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding 128.0.0.0/1: %w", err)
		}
	}
	if hasV6Default {
		_ = run("route", "-q", "-n", "add", "-inet6", "::/1", "-interface", ifaceName)
		_ = run("route", "-q", "-n", "add", "-inet6", "8000::/1", "-interface", ifaceName)
	}

	// Add endpoint bypass route if we have a default route
	if (hasV4Default || hasV6Default) && endpoint != "" {
		if err := m.addEndpointBypass(endpoint); err != nil {
			slog.Warn("endpoint bypass route failed", "error", err)
		}
	}

	return nil
}

// addEndpointBypass adds a host route for the WG endpoint via the original
// default gateway. Without this, encrypted WG packets would be routed through
// the tunnel itself (infinite loop).
func (m *DarwinManager) addEndpointBypass(endpoint string) error {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return err
	}
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("resolve %s: %w", host, err)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		isV6 := ip.To4() == nil

		gw, err := getDefaultGatewayFor(isV6)
		if err != nil {
			// No default gateway — use blackhole to prevent routing loop (wg-quick fallback)
			loopback := "127.0.0.1"
			family := "-inet"
			if isV6 {
				loopback = "::1"
				family = "-inet6"
			}
			_ = run("route", "-q", "-n", "add", family, ipStr, loopback, "-blackhole")
			m.bypassEndpoints = append(m.bypassEndpoints, ipStr)
			continue
		}

		family := "-inet"
		if isV6 {
			family = "-inet6"
		}
		// Try -add first, fall back to -change if exists
		if err := run("route", "-q", "-n", "add", family, ipStr, "-gateway", gw); err != nil {
			if err2 := run("route", "-q", "-n", "change", family, ipStr, "-gateway", gw); err2 != nil {
				return fmt.Errorf("bypass route %s via %s: add=%v, change=%v", ipStr, gw, err, err2)
			}
		}
		m.bypassEndpoints = append(m.bypassEndpoints, ipStr)
	}
	return nil
}

// RemoveRoutes cleans up. wg-quick approach: walk netstat and remove ALL
// routes pointing at this interface, then remove endpoint bypass routes.
// This is more robust than tracking what we added.
func (m *DarwinManager) RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error {
	// Remove all routes via this interface (both IPv4 and IPv6)
	m.deleteInterfaceRoutes(ifaceName, "inet")
	m.deleteInterfaceRoutes(ifaceName, "inet6")

	// Remove endpoint bypass routes
	for _, ip := range m.bypassEndpoints {
		family := "-inet"
		if strings.Contains(ip, ":") {
			family = "-inet6"
		}
		_ = run("route", "-q", "-n", "delete", family, ip)
	}
	m.bypassEndpoints = nil
	return nil
}

// deleteInterfaceRoutes walks netstat for the given family and deletes
// every route whose interface (Netif column) matches ifaceName.
// Also handles the wg-quick IPv6 edge case where Netif=lo0 but Gateway=utunN.
func (m *DarwinManager) deleteInterfaceRoutes(ifaceName, family string) {
	out, err := runOut("netstat", "-nr", "-f", family)
	if err != nil {
		return
	}
	// Parse header to find Destination / Gateway / Netif column positions.
	netifIdx, destIdx, gwIdx := -1, 0, 1
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if netifIdx < 0 {
			// Look for header row
			for i, f := range fields {
				switch f {
				case "Destination":
					destIdx = i
				case "Gateway":
					gwIdx = i
				case "Netif":
					netifIdx = i
				}
			}
			continue
		}
		if len(fields) <= netifIdx {
			continue
		}
		dest := fields[destIdx]
		gw := fields[gwIdx]
		netif := fields[netifIdx]

		// Match: Netif is our interface, OR (IPv6 only) Netif is lo* and Gateway is our interface
		match := netif == ifaceName
		if !match && family == "inet6" && strings.HasPrefix(netif, "lo") && gw == ifaceName {
			match = true
		}
		if !match {
			continue
		}

		if dest == "default" {
			dest = "0.0.0.0/0"
			if family == "inet6" {
				dest = "::/0"
			}
		}
		famFlag := "-inet"
		if family == "inet6" {
			famFlag = "-inet6"
		}
		_ = run("route", "-q", "-n", "delete", famFlag, dest)
	}
}

// routeUsesInterface checks `route get` output for an exact match on the
// interface field. Prevents false matches between utun3 / utun33.
func routeUsesInterface(routeOutput []byte, ifaceName string) bool {
	for _, line := range strings.Split(string(routeOutput), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
			return name == ifaceName
		}
	}
	return false
}

// SetDNS sets DNS on ALL network services (matching wg-quick).
func (m *DarwinManager) SetDNS(ifaceName string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}

	services := getAllNetworkServices()
	if len(services) == 0 {
		return fmt.Errorf("no network services found")
	}

	// Save original DNS for each service before overriding
	for _, svc := range services {
		orig, _ := getCurrentDNS(svc)
		m.savedDNS[svc] = orig
		search, _ := getCurrentSearchDomains(svc)
		m.savedSearch[svc] = search
	}

	// Apply new DNS to all services
	for _, svc := range services {
		args := append([]string{"-setdnsservers", svc}, servers...)
		if err := run("networksetup", args...); err != nil {
			slog.Warn("failed to set DNS on service", "service", svc, "error", err)
		}
	}

	m.dnsActive = true
	return nil
}

// RestoreDNS restores original DNS for every service we touched.
func (m *DarwinManager) RestoreDNS(ifaceName string) error {
	if !m.dnsActive {
		return nil
	}
	for svc, orig := range m.savedDNS {
		if len(orig) == 0 {
			_ = run("networksetup", "-setdnsservers", svc, "Empty")
		} else {
			args := append([]string{"-setdnsservers", svc}, orig...)
			_ = run("networksetup", args...)
		}
	}
	for svc, search := range m.savedSearch {
		if len(search) == 0 {
			_ = run("networksetup", "-setsearchdomains", svc, "Empty")
		} else {
			args := append([]string{"-setsearchdomains", svc}, search...)
			_ = run("networksetup", args...)
		}
	}
	m.savedDNS = make(map[string][]string)
	m.savedSearch = make(map[string][]string)
	m.dnsActive = false
	return nil
}

func (m *DarwinManager) Cleanup(ifaceName string) error {
	_ = m.RestoreDNS(ifaceName)
	// Defensive: remove any remaining routes via this interface
	m.deleteInterfaceRoutes(ifaceName, "inet")
	m.deleteInterfaceRoutes(ifaceName, "inet6")
	for _, ip := range m.bypassEndpoints {
		family := "-inet"
		if strings.Contains(ip, ":") {
			family = "-inet6"
		}
		_ = run("route", "-q", "-n", "delete", family, ip)
	}
	m.bypassEndpoints = nil
	return nil
}

// --- helpers ---

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	// Force C locale so parsing English sentinels like "There aren't any DNS Servers"
	// works on non-English macOS systems. wg-quick uses `export LC_ALL=C` at script top.
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runOut runs a command with LC_ALL=C and returns combined output.
// Use for commands where we parse the output.
func runOut(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	return cmd.CombinedOutput()
}

// getDefaultGatewayFor returns the IPv4 or IPv6 default gateway, skipping
// link-local entries (link#N) per wg-quick's collect_gateways.
func getDefaultGatewayFor(ipv6 bool) (string, error) {
	family := "inet"
	if ipv6 {
		family = "inet6"
	}
	out, err := runOut("netstat", "-nr", "-f", family)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] != "default" {
			continue
		}
		gw := fields[1]
		// Skip link-local defaults (point-to-point with no gateway IP)
		if strings.HasPrefix(gw, "link#") {
			continue
		}
		return gw, nil
	}
	return "", fmt.Errorf("no default gateway for %s", family)
}

// getDefaultInterface returns the name of the default route's interface.
// macOS netstat -nr -f inet has columns: Destination Gateway Flags Netif Expire
// The default row may have 4 columns (no Expire). We use the LAST field.
func getDefaultInterface() string {
	out, err := runOut("netstat", "-nr", "-f", "inet")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[0] != "default" {
			continue
		}
		// Netif is typically index 3 (4th column) on the default row,
		// or 5 if Refs/Use columns are present. Use a heuristic: it's
		// the first field that looks like an interface name (utun, en, ...).
		for i := 3; i < len(fields); i++ {
			f := fields[i]
			// Interface names on macOS: en0, utun3, bridge0, awdl0, etc.
			if len(f) > 0 && (f[0] >= 'a' && f[0] <= 'z') && !strings.Contains(f, ":") && !strings.Contains(f, ".") {
				return f
			}
		}
	}
	return ""
}

// getInterfaceMTU reads the MTU from ifconfig output.
func getInterfaceMTU(ifaceName string) int {
	out, err := runOut("ifconfig", ifaceName)
	if err != nil {
		return 0
	}
	// Format includes "mtu 1500"
	idx := strings.Index(string(out), "mtu ")
	if idx < 0 {
		return 0
	}
	rest := string(out)[idx+4:]
	var mtu int
	fmt.Sscanf(rest, "%d", &mtu)
	return mtu
}

// getAllNetworkServices returns all network services, including disabled ones.
// wg-quick includes disabled services (strips the "*" prefix) so DNS is
// applied/restored uniformly regardless of current enabled state.
func getAllNetworkServices() []string {
	out, err := runOut("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil
	}
	var services []string
	firstLine := true
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if firstLine {
			// First non-empty line is the header ("An asterisk...")
			firstLine = false
			continue
		}
		// Strip leading "*" from disabled services (don't skip them)
		if strings.HasPrefix(line, "*") {
			line = strings.TrimSpace(line[1:])
		}
		if line != "" {
			services = append(services, line)
		}
	}
	return services
}

func getCurrentDNS(service string) ([]string, error) {
	out, err := runOut("networksetup", "-getdnsservers", service)
	if err != nil {
		return nil, err
	}
	output := strings.TrimSpace(string(out))
	if strings.Contains(output, "There aren't any DNS Servers") {
		return nil, nil
	}
	var servers []string
	for _, line := range strings.Split(output, "\n") {
		s := strings.TrimSpace(line)
		if s != "" {
			servers = append(servers, s)
		}
	}
	return servers, nil
}

func getCurrentSearchDomains(service string) ([]string, error) {
	out, err := runOut("networksetup", "-getsearchdomains", service)
	if err != nil {
		return nil, err
	}
	output := strings.TrimSpace(string(out))
	if strings.Contains(output, "There aren't any Search Domains") {
		return nil, nil
	}
	var domains []string
	for _, line := range strings.Split(output, "\n") {
		s := strings.TrimSpace(line)
		if s != "" {
			domains = append(domains, s)
		}
	}
	return domains, nil
}

// sortAllowedIPs sorts CIDRs by prefix length descending (longest first),
// matching wg-quick's `sort -nr -k 2 -t /`. Stable order for determinism.
func sortAllowedIPs(cidrs []string) []string {
	result := make([]string, len(cidrs))
	copy(result, cidrs)

	// Simple insertion sort (lists are small, stability guaranteed)
	for i := 1; i < len(result); i++ {
		cur := result[i]
		curPrefix := prefixLen(cur)
		j := i - 1
		for j >= 0 && prefixLen(result[j]) < curPrefix {
			result[j+1] = result[j]
			j--
		}
		result[j+1] = cur
	}
	return result
}

func prefixLen(cidr string) int {
	idx := strings.Index(cidr, "/")
	if idx < 0 {
		return 128
	}
	var n int
	fmt.Sscanf(cidr[idx+1:], "%d", &n)
	return n
}
