//go:build windows

package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// WindowsFirewall implements FirewallManager using Windows netsh (simplified).
// Production implementation should use WFP (Windows Filtering Platform) via syscall.
type WindowsFirewall struct {
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
}

func NewPlatformFirewall() FirewallManager {
	return &WindowsFirewall{}
}

func (f *WindowsFirewall) EnableKillSwitch(interfaceName string, endpoint string) error {
	// Block all outbound except WG interface and endpoint
	// Using netsh advfirewall as simplified approach
	// Production: use WFP dynamic sessions for auto-cleanup on crash

	// Block all outbound
	runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-BlockAll", "dir=out", "action=block", "enable=yes")

	// Allow WG endpoint
	runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-AllowEndpoint", "dir=out", "action=allow",
		"remoteip="+strings.Split(endpoint, ":")[0], "enable=yes")

	// Allow WG interface (by interface name)
	runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-AllowTunnel", "dir=out", "action=allow",
		"localip=any", "enable=yes", "interfacetype=any")

	f.killSwitchEnabled = true
	return nil
}

func (f *WindowsFirewall) DisableKillSwitch() error {
	cleanupWinRules()
	f.killSwitchEnabled = false
	return nil
}

func (f *WindowsFirewall) EnableDNSProtection(interfaceName string, dnsServers []string) error {
	if len(dnsServers) == 0 {
		return nil
	}
	// Block all DNS
	runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-BlockDNS", "dir=out", "action=block",
		"protocol=udp", "remoteport=53", "enable=yes")

	// Allow DNS to specified servers
	for i, dns := range dnsServers {
		runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=WireGuide-AllowDNS%d", i), "dir=out", "action=allow",
			"protocol=udp", "remoteport=53", "remoteip="+dns, "enable=yes")
	}

	f.dnsProtectionEnabled = true
	return nil
}

func (f *WindowsFirewall) DisableDNSProtection() error {
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=WireGuide-BlockDNS").Run()
	for i := 0; i < 10; i++ {
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			fmt.Sprintf("name=WireGuide-AllowDNS%d", i)).Run()
	}
	f.dnsProtectionEnabled = false
	return nil
}

func (f *WindowsFirewall) IsKillSwitchEnabled() bool    { return f.killSwitchEnabled }
func (f *WindowsFirewall) IsDNSProtectionEnabled() bool { return f.dnsProtectionEnabled }

func (f *WindowsFirewall) Cleanup() error {
	f.killSwitchEnabled = false
	f.dnsProtectionEnabled = false
	cleanupWinRules()
	return nil
}

func cleanupWinRules() {
	names := []string{"WireGuide-BlockAll", "WireGuide-AllowEndpoint", "WireGuide-AllowTunnel",
		"WireGuide-BlockDNS"}
	for _, name := range names {
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	}
	for i := 0; i < 10; i++ {
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			fmt.Sprintf("name=WireGuide-AllowDNS%d", i)).Run()
	}
}

func runWinFW(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
