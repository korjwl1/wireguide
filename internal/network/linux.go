//go:build linux

package network

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// LinuxManager implements NetworkManager for Linux using netlink/ip commands.
type LinuxManager struct {
	origDNS []string
}

func NewPlatformManager() NetworkManager {
	return &LinuxManager{}
}

func (m *LinuxManager) AssignAddress(ifaceName string, addresses []string) error {
	for _, addr := range addresses {
		if err := runCmd("ip", "addr", "add", addr, "dev", ifaceName); err != nil {
			return fmt.Errorf("assigning address %s: %w", addr, err)
		}
	}
	return nil
}

func (m *LinuxManager) SetMTU(ifaceName string, mtu int) error {
	if mtu <= 0 {
		mtu = 1420
	}
	return runCmd("ip", "link", "set", "dev", ifaceName, "mtu", fmt.Sprintf("%d", mtu))
}

func (m *LinuxManager) BringUp(ifaceName string) error {
	return runCmd("ip", "link", "set", "dev", ifaceName, "up")
}

func (m *LinuxManager) AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpoint string) error {
	if fullTunnel {
		return m.addFullTunnelRoutes(ifaceName, endpoint)
	}
	for _, cidr := range allowedIPs {
		if err := runCmd("ip", "route", "add", cidr, "dev", ifaceName); err != nil {
			return fmt.Errorf("adding route %s: %w", cidr, err)
		}
	}
	return nil
}

func (m *LinuxManager) addFullTunnelRoutes(ifaceName string, endpoint string) error {
	// Use fwmark-based policy routing (similar to wg-quick)
	// 1. Set fwmark on WireGuard interface
	// 2. Add policy rule: packets NOT marked -> use WG table
	// 3. Add default route in WG table
	// 4. Add bypass route for endpoint

	// Add WG routing table
	if err := runCmd("ip", "route", "add", "default", "dev", ifaceName, "table", "51820"); err != nil {
		return fmt.Errorf("adding default route to table 51820: %w", err)
	}

	// Add policy rule: unmarked traffic uses WG table
	if err := runCmd("ip", "rule", "add", "not", "fwmark", "51820", "table", "51820"); err != nil {
		return fmt.Errorf("adding policy rule: %w", err)
	}

	// Suppress default route for local subnet traffic
	_ = runCmd("ip", "rule", "add", "table", "main", "suppress_prefixlength", "0")

	return nil
}

func (m *LinuxManager) RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error {
	if fullTunnel {
		_ = runCmd("ip", "route", "delete", "default", "dev", ifaceName, "table", "51820")
		_ = runCmd("ip", "rule", "delete", "not", "fwmark", "51820", "table", "51820")
		_ = runCmd("ip", "rule", "delete", "table", "main", "suppress_prefixlength", "0")
		return nil
	}
	for _, cidr := range allowedIPs {
		_ = runCmd("ip", "route", "delete", cidr, "dev", ifaceName)
	}
	return nil
}

func (m *LinuxManager) SetDNS(ifaceName string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	// Try systemd-resolved first
	args := []string{"dns", ifaceName}
	args = append(args, servers...)
	if err := runCmd("resolvectl", args...); err == nil {
		return nil
	}
	// Fallback: write to /etc/resolv.conf (save original first)
	origData, _ := exec.Command("cat", "/etc/resolv.conf").Output()
	m.origDNS = strings.Split(strings.TrimSpace(string(origData)), "\n")

	var lines []string
	for _, s := range servers {
		lines = append(lines, "nameserver "+s)
	}
	content := strings.Join(lines, "\n") + "\n"
	return exec.Command("sh", "-c", fmt.Sprintf("echo '%s' > /etc/resolv.conf", content)).Run()
}

func (m *LinuxManager) RestoreDNS(ifaceName string) error {
	if len(m.origDNS) == 0 {
		return nil
	}
	content := strings.Join(m.origDNS, "\n") + "\n"
	return exec.Command("sh", "-c", fmt.Sprintf("echo '%s' > /etc/resolv.conf", content)).Run()
}

func (m *LinuxManager) Cleanup(ifaceName string) error {
	_ = m.RestoreDNS(ifaceName)
	_ = runCmd("ip", "link", "delete", "dev", ifaceName)
	return nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// unused but satisfies import for net package
var _ = net.ParseCIDR
