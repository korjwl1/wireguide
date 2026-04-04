//go:build windows

package network

import (
	"fmt"
	"os/exec"
	"strings"
)

// WindowsManager implements NetworkManager for Windows using netsh/winipcfg.
type WindowsManager struct {
	origDNS []string
}

func NewPlatformManager() NetworkManager {
	return &WindowsManager{}
}

func (m *WindowsManager) AssignAddress(ifaceName string, addresses []string) error {
	for _, addr := range addresses {
		// netsh interface ip add address "ifaceName" addr
		if err := runWin("netsh", "interface", "ip", "add", "address", ifaceName, addr); err != nil {
			return fmt.Errorf("assigning address %s: %w", addr, err)
		}
	}
	return nil
}

func (m *WindowsManager) SetMTU(ifaceName string, mtu int) error {
	if mtu <= 0 {
		mtu = 1420
	}
	return runWin("netsh", "interface", "ipv4", "set", "subinterface", ifaceName,
		fmt.Sprintf("mtu=%d", mtu), "store=persistent")
}

func (m *WindowsManager) BringUp(ifaceName string) error {
	// On Windows, the interface is usually already up after TUN creation
	return nil
}

func (m *WindowsManager) AddRoutes(ifaceName string, allowedIPs []string, fullTunnel bool, endpoint string) error {
	if fullTunnel {
		return m.addFullTunnelRoutes(ifaceName, endpoint)
	}
	for _, cidr := range allowedIPs {
		if err := runWin("netsh", "interface", "ip", "add", "route", cidr, ifaceName); err != nil {
			return fmt.Errorf("adding route %s: %w", cidr, err)
		}
	}
	return nil
}

func (m *WindowsManager) addFullTunnelRoutes(ifaceName string, endpoint string) error {
	// Set low metric on WG interface to make it preferred for default route
	if err := runWin("netsh", "interface", "ip", "add", "route", "0.0.0.0/0", ifaceName,
		"metric=5"); err != nil {
		return fmt.Errorf("adding default route: %w", err)
	}
	return nil
}

func (m *WindowsManager) RemoveRoutes(ifaceName string, allowedIPs []string, fullTunnel bool) error {
	if fullTunnel {
		_ = runWin("netsh", "interface", "ip", "delete", "route", "0.0.0.0/0", ifaceName)
		return nil
	}
	for _, cidr := range allowedIPs {
		_ = runWin("netsh", "interface", "ip", "delete", "route", cidr, ifaceName)
	}
	return nil
}

func (m *WindowsManager) SetDNS(ifaceName string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	// Save original DNS
	m.origDNS = getCurrentWinDNS(ifaceName)

	// Set primary DNS
	if err := runWin("netsh", "interface", "ip", "set", "dns", ifaceName, "static", servers[0]); err != nil {
		return err
	}
	// Add additional DNS servers
	for i := 1; i < len(servers); i++ {
		_ = runWin("netsh", "interface", "ip", "add", "dns", ifaceName, servers[i], fmt.Sprintf("index=%d", i+1))
	}
	return nil
}

func (m *WindowsManager) RestoreDNS(ifaceName string) error {
	if len(m.origDNS) == 0 {
		return runWin("netsh", "interface", "ip", "set", "dns", ifaceName, "dhcp")
	}
	if err := runWin("netsh", "interface", "ip", "set", "dns", ifaceName, "static", m.origDNS[0]); err != nil {
		return err
	}
	for i := 1; i < len(m.origDNS); i++ {
		_ = runWin("netsh", "interface", "ip", "add", "dns", ifaceName, m.origDNS[i], fmt.Sprintf("index=%d", i+1))
	}
	return nil
}

func (m *WindowsManager) Cleanup(ifaceName string) error {
	_ = m.RestoreDNS(ifaceName)
	return nil
}

func runWin(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func getCurrentWinDNS(ifaceName string) []string {
	out, _ := exec.Command("netsh", "interface", "ip", "show", "dns", ifaceName).CombinedOutput()
	// Parse output - simplified
	var servers []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "DNS") && !strings.Contains(line, "Register") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				last := parts[len(parts)-1]
				if strings.Contains(last, ".") {
					servers = append(servers, last)
				}
			}
		}
	}
	return servers
}
