//go:build darwin

package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

const pfAnchor = "com.wireguide"

// DarwinFirewall implements FirewallManager using macOS pf (packet filter).
type DarwinFirewall struct {
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
}

func NewPlatformFirewall() FirewallManager {
	return &DarwinFirewall{}
}

func (f *DarwinFirewall) EnableKillSwitch(interfaceName string, endpoint string) error {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("parsing endpoint: %w", err)
	}

	// Resolve endpoint to IP
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("resolving endpoint: %w", err)
	}
	endpointIP := ips[0]

	// pf rules:
	// 1. Allow loopback
	// 2. Allow traffic to WG endpoint (so encrypted packets can reach the server)
	// 3. Allow traffic on WG interface (tunnel traffic)
	// 4. Block everything else
	rules := fmt.Sprintf(`
anchor "%s" {
  # Allow loopback
  pass quick on lo0 all
  # Allow WireGuard endpoint
  pass out quick to %s
  # Allow WireGuard tunnel interface
  pass quick on %s all
  # Block all other traffic
  block drop out all
  block drop in all
}
`, pfAnchor, endpointIP, interfaceName)

	if err := loadPfRules(rules); err != nil {
		return fmt.Errorf("loading pf rules: %w", err)
	}

	// Enable pf if not already
	exec.Command("pfctl", "-e").Run()

	f.killSwitchEnabled = true
	return nil
}

func (f *DarwinFirewall) DisableKillSwitch() error {
	if err := flushPfAnchor(); err != nil {
		return err
	}
	f.killSwitchEnabled = false
	return nil
}

func (f *DarwinFirewall) EnableDNSProtection(interfaceName string, dnsServers []string) error {
	if len(dnsServers) == 0 {
		return nil
	}

	// Build rules allowing DNS only to specified servers via WG tunnel
	var dnsRules []string
	dnsRules = append(dnsRules, fmt.Sprintf(`anchor "%s/dns" {`, pfAnchor))
	for _, dns := range dnsServers {
		dnsRules = append(dnsRules,
			fmt.Sprintf("  pass out quick on %s proto {tcp, udp} to %s port 53", interfaceName, dns))
	}
	// Block all other DNS
	dnsRules = append(dnsRules, "  block drop out quick proto {tcp, udp} to any port 53")
	dnsRules = append(dnsRules, "}")

	rules := strings.Join(dnsRules, "\n") + "\n"
	if err := loadPfRules(rules); err != nil {
		return fmt.Errorf("loading DNS rules: %w", err)
	}

	f.dnsProtectionEnabled = true
	return nil
}

func (f *DarwinFirewall) DisableDNSProtection() error {
	// Flush DNS sub-anchor
	exec.Command("pfctl", "-a", pfAnchor+"/dns", "-F", "rules").Run()
	f.dnsProtectionEnabled = false
	return nil
}

func (f *DarwinFirewall) IsKillSwitchEnabled() bool    { return f.killSwitchEnabled }
func (f *DarwinFirewall) IsDNSProtectionEnabled() bool { return f.dnsProtectionEnabled }

func (f *DarwinFirewall) Cleanup() error {
	f.killSwitchEnabled = false
	f.dnsProtectionEnabled = false
	return flushPfAnchor()
}

func loadPfRules(rules string) error {
	cmd := exec.Command("pfctl", "-a", pfAnchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func flushPfAnchor() error {
	exec.Command("pfctl", "-a", pfAnchor, "-F", "rules").Run()
	exec.Command("pfctl", "-a", pfAnchor+"/dns", "-F", "rules").Run()
	return nil
}
