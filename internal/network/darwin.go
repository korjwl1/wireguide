//go:build darwin

package network

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
)

// DarwinManager implements NetworkManager for macOS.
type DarwinManager struct {
	origDNS     []string
	origService string
	// Endpoint bypass route state — tracked so we can remove it on disconnect.
	bypassEndpointIP string
	bypassGateway    string
}

func NewPlatformManager() NetworkManager {
	return &DarwinManager{}
}

func (m *DarwinManager) AssignAddress(ifaceName string, addresses []string) error {
	for i, addr := range addresses {
		ip, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return fmt.Errorf("invalid address %q: %w", addr, err)
		}
		if i == 0 {
			// Primary address
			if err := run("ifconfig", ifaceName, "inet", ip.String(), ip.String(), "netmask", netmaskString(ipNet.Mask)); err != nil {
				return fmt.Errorf("assigning address %s: %w", addr, err)
			}
		} else {
			// Alias address
			if err := run("ifconfig", ifaceName, "inet", ip.String(), "alias", "netmask", netmaskString(ipNet.Mask)); err != nil {
				return fmt.Errorf("assigning alias %s: %w", addr, err)
			}
		}
	}
	return nil
}

func (m *DarwinManager) SetMTU(ifaceName string, mtu int) error {
	if mtu <= 0 {
		mtu = 1420
	}
	return run("ifconfig", ifaceName, "mtu", fmt.Sprintf("%d", mtu))
}

func (m *DarwinManager) BringUp(ifaceName string) error {
	return run("ifconfig", ifaceName, "up")
}

func (m *DarwinManager) AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpoint string) error {
	if fullTunnel {
		return m.addFullTunnelRoutes(ifaceName, endpoint)
	}
	for _, cidr := range allowedIPs {
		if err := run("route", "-n", "add", "-net", cidr, "-interface", ifaceName); err != nil {
			return fmt.Errorf("adding route %s: %w", cidr, err)
		}
	}
	return nil
}

func (m *DarwinManager) addFullTunnelRoutes(ifaceName string, endpoint string) error {
	// Get default gateway for endpoint bypass route.
	// This MUST succeed — without the bypass, WireGuard handshake packets
	// would be routed through the tunnel itself (infinite loop), killing
	// all connectivity.
	gw, err := getDefaultGateway()
	if err != nil {
		return fmt.Errorf("getting default gateway: %w", err)
	}

	// Add bypass route for WireGuard endpoint via original gateway.
	// Critical for full tunnel: encrypted WG packets must reach the server
	// via the real network interface, not the tunnel.
	if endpoint != "" {
		host, _, _ := net.SplitHostPort(endpoint)
		if host != "" {
			ips, err := net.LookupHost(host)
			if err == nil && len(ips) > 0 {
				endpointIP := ips[0]
				// Try -add first; if route exists, use -change
				if err := run("route", "-n", "add", "-host", endpointIP, gw); err != nil {
					slog.Warn("endpoint bypass add failed, trying change", "error", err)
					if err2 := run("route", "-n", "change", "-host", endpointIP, gw); err2 != nil {
						return fmt.Errorf("endpoint bypass route failed: add=%v, change=%v", err, err2)
					}
				}
				// Remember for cleanup on disconnect
				m.bypassEndpointIP = endpointIP
				m.bypassGateway = gw
			}
		}
	}

	// Split route: 0.0.0.0/1 + 128.0.0.0/1 covers all IPv4 without
	// replacing the system default route.
	if err := run("route", "-n", "add", "-net", "0.0.0.0/1", "-interface", ifaceName); err != nil {
		return fmt.Errorf("adding 0.0.0.0/1 route: %w", err)
	}
	if err := run("route", "-n", "add", "-net", "128.0.0.0/1", "-interface", ifaceName); err != nil {
		return fmt.Errorf("adding 128.0.0.0/1 route: %w", err)
	}
	return nil
}

func (m *DarwinManager) RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error {
	if fullTunnel {
		_ = run("route", "-n", "delete", "-net", "0.0.0.0/1", "-interface", ifaceName)
		_ = run("route", "-n", "delete", "-net", "128.0.0.0/1", "-interface", ifaceName)
		// Remove endpoint bypass route so it doesn't leak across reconnects
		// or affect other apps.
		if m.bypassEndpointIP != "" {
			_ = run("route", "-n", "delete", "-host", m.bypassEndpointIP)
			m.bypassEndpointIP = ""
			m.bypassGateway = ""
		}
		return nil
	}
	for _, cidr := range allowedIPs {
		_ = run("route", "-n", "delete", "-net", cidr, "-interface", ifaceName)
	}
	return nil
}

func (m *DarwinManager) SetDNS(ifaceName string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}

	// Find the primary network service
	service, err := getPrimaryNetworkService()
	if err != nil {
		return err
	}
	m.origService = service

	// Save original DNS
	origDNS, _ := getCurrentDNS(service)
	m.origDNS = origDNS

	// Set new DNS
	args := append([]string{"-setdnsservers", service}, servers...)
	return run("networksetup", args...)
}

func (m *DarwinManager) RestoreDNS(ifaceName string) error {
	if m.origService == "" {
		return nil
	}
	if len(m.origDNS) == 0 {
		return run("networksetup", "-setdnsservers", m.origService, "Empty")
	}
	args := append([]string{"-setdnsservers", m.origService}, m.origDNS...)
	err := run("networksetup", args...)
	// Clear state after successful restore so a second Disconnect is a no-op
	if err == nil {
		m.origService = ""
		m.origDNS = nil
	}
	return err
}

func (m *DarwinManager) Cleanup(ifaceName string) error {
	// utun interfaces are removed when the TUN device is closed.
	// Clean up any residual state.
	_ = m.RestoreDNS(ifaceName)
	// Defensive: remove bypass route if somehow still set
	if m.bypassEndpointIP != "" {
		_ = run("route", "-n", "delete", "-host", m.bypassEndpointIP)
		m.bypassEndpointIP = ""
	}
	return nil
}

// --- helpers ---

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func getDefaultGateway() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "gateway:")), nil
		}
	}
	return "", fmt.Errorf("could not find default gateway")
}

func getPrimaryNetworkService() (string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		// Return first non-disabled service (usually Wi-Fi or Ethernet)
		return line, nil
	}
	return "", fmt.Errorf("no network service found")
}

func getCurrentDNS(service string) ([]string, error) {
	out, err := exec.Command("networksetup", "-getdnsservers", service).CombinedOutput()
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

func netmaskString(mask net.IPMask) string {
	ip := net.IP(mask)
	return ip.String()
}
