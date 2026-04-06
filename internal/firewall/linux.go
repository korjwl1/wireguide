//go:build linux

package firewall

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// validIfaceName matches valid Linux interface names (alphanumeric, underscore, hyphen, max 15 chars).
var validIfaceName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

const nftTable = "wireguide"

// LinuxFirewall implements FirewallManager using nftables.
type LinuxFirewall struct {
	mu                   sync.Mutex
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
	fwmark               int
}

func NewPlatformFirewall() FirewallManager {
	return &LinuxFirewall{fwmark: 51820}
}

// SetFwMark configures the fwmark used by kill switch nftables rules.
// Call this before EnableKillSwitch when a custom fwmark is configured.
func (f *LinuxFirewall) SetFwMark(mark int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if mark > 0 {
		f.fwmark = mark
	}
}

func (f *LinuxFirewall) EnableKillSwitch(interfaceName string, ifaceAddresses []string, endpoints []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Validate interface name before interpolating into nft rules.
	if !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}

	// Build endpoint allow rules with port restrictions (H11)
	var endpointRules strings.Builder
	for _, ep := range endpoints {
		ip, port, _ := net.SplitHostPort(ep)
		if ip == "" {
			ip = ep // fallback: bare IP without port
		}
		if ip == "" {
			continue
		}
		// Validate that the endpoint is a real IP before interpolating into nft rules.
		if net.ParseIP(ip) == nil {
			slog.Warn("skipping invalid endpoint IP in nft rules", "endpoint", ep)
			continue
		}
		addrKw := "ip"
		if strings.Contains(ip, ":") {
			addrKw = "ip6"
		}
		if port != "" {
			fmt.Fprintf(&endpointRules, "    %s daddr %s udp dport %s accept\n", addrKw, ip, port)
		} else {
			fmt.Fprintf(&endpointRules, "    %s daddr %s accept\n", addrKw, ip)
		}
	}

	// Extract plain IP addresses from CIDR interface addresses for the
	// preraw anti-spoof chain (C3).
	var ifaceIPs []string
	for _, addr := range ifaceAddresses {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			// Try as plain IP
			ip = net.ParseIP(addr)
		}
		if ip != nil {
			ifaceIPs = append(ifaceIPs, ip.String())
		}
	}

	// Build the preraw chain: drops spoofed packets arriving on non-WG
	// interfaces destined for the WG address (C3).
	var prerawRules strings.Builder
	for _, ip := range ifaceIPs {
		addrKw := "ip"
		if strings.Contains(ip, ":") {
			addrKw = "ip6"
		}
		fmt.Fprintf(&prerawRules, "    iifname != \"%s\" %s daddr %s fib saddr type != local drop\n",
			interfaceName, addrKw, ip)
	}

	fwmarkHex := fmt.Sprintf("0x%08x", f.fwmark)

	// nftables ruleset including CONNMARK/ct-mark chains (C3)
	rules := fmt.Sprintf(`
table inet %s {
  chain output {
    type filter hook output priority 0; policy drop;
    # Allow loopback
    oif lo accept
    # Allow DHCP renewal (prevents lease expiry while kill switch is active)
    udp sport 68 udp dport 67 accept
    # Allow DHCPv6 (H11)
    udp sport 546 udp dport 547 accept
    # Allow WireGuard endpoints
%s    # Allow WireGuard tunnel
    oif %s accept
    # Allow established connections
    ct state established,related accept
  }
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    iif %s accept
    # Allow DHCP responses
    udp sport 67 udp dport 68 accept
    # Allow DHCPv6 responses (H11)
    udp sport 547 udp dport 546 accept
    ct state established,related accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    oifname %s accept
    iifname %s accept
  }
  chain preraw {
    type filter hook prerouting priority raw; policy accept;
%s  }
  chain premangle {
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto udp ct mark %s meta mark set ct mark
  }
  chain postmangle {
    type filter hook postrouting priority mangle; policy accept;
    meta l4proto udp meta mark %s ct mark set meta mark
  }
}
`, nftTable, endpointRules.String(), interfaceName, interfaceName,
		interfaceName, interfaceName,
		prerawRules.String(), fwmarkHex, fwmarkHex)

	if err := nftApply(rules); err != nil {
		return err
	}
	f.killSwitchEnabled = true
	return nil
}

func (f *LinuxFirewall) DisableKillSwitch() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := nftFlush(); err != nil {
		return err
	}
	f.killSwitchEnabled = false
	return nil
}

func (f *LinuxFirewall) EnableDNSProtection(interfaceName string, dnsServers []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(dnsServers) == 0 {
		return nil
	}

	// Validate interface name before interpolating into nft rules.
	if !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}

	// H12: Detect IPv4 vs IPv6 for each DNS server
	var dnsAllowed []string
	for _, dns := range dnsServers {
		if net.ParseIP(dns) == nil {
			slog.Warn("skipping invalid DNS IP in nft rules", "dns", dns)
			continue
		}
		addrKw := "ip"
		if strings.Contains(dns, ":") {
			addrKw = "ip6"
		}
		dnsAllowed = append(dnsAllowed,
			fmt.Sprintf("%s daddr %s tcp dport 53 oif %s accept", addrKw, dns, interfaceName))
		dnsAllowed = append(dnsAllowed,
			fmt.Sprintf("%s daddr %s udp dport 53 oif %s accept", addrKw, dns, interfaceName))
	}

	rules := fmt.Sprintf(`
table inet %s_dns {
  chain dns_output {
    type filter hook output priority -1; policy accept;
    # Allow DNS to loopback (systemd-resolved stub at 127.0.0.53, local
    # Pi-hole at 127.0.0.1, etc). Without this, systems using
    # systemd-resolved would have ALL DNS blocked.
    oif lo tcp dport 53 accept
    oif lo udp dport 53 accept
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
	f.mu.Lock()
	defer f.mu.Unlock()
	// LOW: Log errors from nft delete
	if out, err := exec.Command("nft", "delete", "table", "inet", nftTable+"_dns").CombinedOutput(); err != nil {
		slog.Warn("nft delete dns table failed", "error", err, "output", strings.TrimSpace(string(out)))
	}
	f.dnsProtectionEnabled = false
	return nil
}

func (f *LinuxFirewall) IsKillSwitchEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killSwitchEnabled
}

func (f *LinuxFirewall) IsDNSProtectionEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dnsProtectionEnabled
}

func (f *LinuxFirewall) Cleanup() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killSwitchEnabled = false
	f.dnsProtectionEnabled = false
	flushErr := nftFlush()
	// Also clean up DNS table.
	if out, err := exec.Command("nft", "delete", "table", "inet", nftTable+"_dns").CombinedOutput(); err != nil {
		slog.Warn("nft delete dns table failed during cleanup", "error", err, "output", strings.TrimSpace(string(out)))
	}
	return flushErr
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

// nftFlush deletes the main wireguide nftables table and returns any error.
func nftFlush() error {
	if out, err := exec.Command("nft", "delete", "table", "inet", nftTable).CombinedOutput(); err != nil {
		return fmt.Errorf("nft delete table: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
