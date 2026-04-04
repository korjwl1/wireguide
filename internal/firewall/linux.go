//go:build linux

package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

const nftTable = "wireguide"

// LinuxFirewall implements FirewallManager using nftables.
type LinuxFirewall struct {
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
}

func NewPlatformFirewall() FirewallManager {
	return &LinuxFirewall{}
}

func (f *LinuxFirewall) EnableKillSwitch(interfaceName string, endpoint string) error {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("parsing endpoint: %w", err)
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("resolving endpoint: %w", err)
	}
	endpointIP := ips[0]

	// nftables ruleset
	rules := fmt.Sprintf(`
table inet %s {
  chain output {
    type filter hook output priority 0; policy drop;
    # Allow loopback
    oif lo accept
    # Allow WireGuard endpoint
    ip daddr %s accept
    # Allow WireGuard tunnel
    oif %s accept
    # Allow established connections
    ct state established,related accept
  }
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    iif %s accept
    ct state established,related accept
  }
}
`, nftTable, endpointIP, interfaceName, interfaceName)

	if err := nftApply(rules); err != nil {
		return err
	}
	f.killSwitchEnabled = true
	return nil
}

func (f *LinuxFirewall) DisableKillSwitch() error {
	nftFlush()
	f.killSwitchEnabled = false
	return nil
}

func (f *LinuxFirewall) EnableDNSProtection(interfaceName string, dnsServers []string) error {
	if len(dnsServers) == 0 {
		return nil
	}

	var dnsAllowed []string
	for _, dns := range dnsServers {
		dnsAllowed = append(dnsAllowed, fmt.Sprintf("ip daddr %s tcp dport 53 oif %s accept", dns, interfaceName))
		dnsAllowed = append(dnsAllowed, fmt.Sprintf("ip daddr %s udp dport 53 oif %s accept", dns, interfaceName))
	}

	rules := fmt.Sprintf(`
table inet %s_dns {
  chain dns_output {
    type filter hook output priority -1; policy accept;
    %s
    tcp dport 53 drop
    udp dport 53 drop
  }
}
`, nftTable, strings.Join(dnsAllowed, "\n    "))

	if err := nftApply(rules); err != nil {
		return err
	}
	f.dnsProtectionEnabled = true
	return nil
}

func (f *LinuxFirewall) DisableDNSProtection() error {
	exec.Command("nft", "delete", "table", "inet", nftTable+"_dns").Run()
	f.dnsProtectionEnabled = false
	return nil
}

func (f *LinuxFirewall) IsKillSwitchEnabled() bool    { return f.killSwitchEnabled }
func (f *LinuxFirewall) IsDNSProtectionEnabled() bool { return f.dnsProtectionEnabled }

func (f *LinuxFirewall) Cleanup() error {
	f.killSwitchEnabled = false
	f.dnsProtectionEnabled = false
	nftFlush()
	exec.Command("nft", "delete", "table", "inet", nftTable+"_dns").Run()
	return nil
}

func nftApply(rules string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func nftFlush() {
	exec.Command("nft", "delete", "table", "inet", nftTable).Run()
}
