//go:build linux

package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// nftCmdTimeout bounds every nftables command. Without it, a contended
// netlink socket (e.g. concurrent firewalld activity) could hang the helper.
const nftCmdTimeout = 30 * time.Second

// validIfaceName matches valid Linux interface names (alphanumeric, underscore, hyphen, max 15 chars).
var validIfaceName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

const nftTable = "wireguide"

// LinuxFirewall implements FirewallManager using nftables.
type LinuxFirewall struct {
	mu                   sync.Mutex
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
	fwmark               int
	killSwitchTunnels    map[string][]string
	killSwitchAddresses  map[string][]string
}

func NewPlatformFirewall() FirewallManager {
	return &LinuxFirewall{
		fwmark:              51820,
		killSwitchTunnels:   make(map[string][]string),
		killSwitchAddresses: make(map[string][]string),
	}
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
	if interfaceName != "" && !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}
	f.killSwitchTunnels = make(map[string][]string)
	f.killSwitchAddresses = make(map[string][]string)
	if interfaceName != "" {
		f.killSwitchTunnels[interfaceName] = append([]string(nil), endpoints...)
		f.killSwitchAddresses[interfaceName] = append([]string(nil), ifaceAddresses...)
	}
	if err := f.applyKillSwitchLocked(false); err != nil {
		return err
	}
	f.killSwitchEnabled = true
	return nil
}

func (f *LinuxFirewall) applyKillSwitchLocked(replace bool) error {
	var endpointRules, tunnelOutputRules, tunnelInputRules, forwardRules, prerawRules strings.Builder
	for interfaceName, endpoints := range f.killSwitchTunnels {
		for _, ep := range endpoints {
			ip, port, _ := net.SplitHostPort(ep)
			if ip == "" {
				ip = ep
			}
			if net.ParseIP(ip) == nil {
				slog.Warn("skipping invalid endpoint IP in nft rules", "endpoint", ep)
				continue
			}
			addrKw := "ip"
			if strings.Contains(ip, ":") {
				addrKw = "ip6"
			}
			if port != "" {
				p, err := strconv.Atoi(port)
				if err != nil || p < 1 || p > 65535 {
					slog.Warn("skipping endpoint with invalid port in nft rules", "endpoint", ep)
					continue
				}
				fmt.Fprintf(&endpointRules, "    %s daddr %s udp dport %d accept\n", addrKw, ip, p)
			} else {
				fmt.Fprintf(&endpointRules, "    %s daddr %s accept\n", addrKw, ip)
			}
		}
		fmt.Fprintf(&tunnelOutputRules, "    oifname \"%s\" accept\n", interfaceName)
		fmt.Fprintf(&tunnelInputRules, "    iifname \"%s\" accept\n", interfaceName)
		fmt.Fprintf(&forwardRules, "    oifname \"%s\" accept\n    iifname \"%s\" accept\n", interfaceName, interfaceName)

		for _, addr := range f.killSwitchAddresses[interfaceName] {
			ip, _, err := net.ParseCIDR(addr)
			if err != nil {
				ip = net.ParseIP(addr)
			}
			if ip == nil {
				continue
			}
			addrKw := "ip"
			if ip.To4() == nil {
				addrKw = "ip6"
			}
			fmt.Fprintf(&prerawRules, "    iifname != \"%s\" %s daddr %s fib saddr type != local drop\n", interfaceName, addrKw, ip.String())
		}
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
%s    # Allow WireGuard tunnels
%s
    # Allow established connections
    ct state established,related accept
  }
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
%s
    # Allow DHCP responses
    udp sport 67 udp dport 68 accept
    # Allow DHCPv6 responses (H11)
    udp sport 547 udp dport 546 accept
    ct state established,related accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
%s
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
`, nftTable, endpointRules.String(), tunnelOutputRules.String(), tunnelInputRules.String(),
		forwardRules.String(), prerawRules.String(), fwmarkHex, fwmarkHex)

	if replace {
		if err := nftFlush(); err != nil && !isNftNotFound(err) {
			return err
		}
	}
	if err := nftApply(rules); err != nil {
		return err
	}
	return nil
}

// AddKillSwitchTunnel rebuilds the nftables ruleset with the new tunnel while
// preserving every existing interface and endpoint permit.
func (f *LinuxFirewall) AddKillSwitchTunnel(interfaceName string, ifaceAddresses []string, endpoints []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.killSwitchEnabled {
		return nil
	}
	if !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}
	f.killSwitchTunnels[interfaceName] = append([]string(nil), endpoints...)
	f.killSwitchAddresses[interfaceName] = append([]string(nil), ifaceAddresses...)
	return f.applyKillSwitchLocked(true)
}

// RemoveKillSwitchTunnel drops only one tunnel's permits and leaves the base
// blockade plus every surviving tunnel intact.
func (f *LinuxFirewall) RemoveKillSwitchTunnel(interfaceName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.killSwitchEnabled {
		return nil
	}
	delete(f.killSwitchTunnels, interfaceName)
	delete(f.killSwitchAddresses, interfaceName)
	return f.applyKillSwitchLocked(true)
}

// EnableEndpointProtection is a no-op on Linux. The loop class this guards
// against on Windows (userspace wireguard-go re-encrypting its own UDP
// because the /1 split route trapped it) doesn't exist on Linux: wg-quick
// installs an fwmark policy-routing rule that exempts WireGuard's own UDP
// socket from the tunnel route, so the kernel never recurses.
func (f *LinuxFirewall) EnableEndpointProtection(string, []string) error { return nil }

// DisableEndpointProtection mirrors the Linux no-op.
func (f *LinuxFirewall) DisableEndpointProtection(string) error { return nil }

func (f *LinuxFirewall) DisableKillSwitch() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Clear the in-memory flag regardless of the flush outcome: a "table
	// not found" error means the kill switch is already gone, which is
	// success for a disable. Leaving killSwitchEnabled=true on that error
	// (the previous behaviour) made IsKillSwitchEnabled() report a rule
	// that no longer exists.
	f.killSwitchEnabled = false
	f.killSwitchTunnels = make(map[string][]string)
	f.killSwitchAddresses = make(map[string][]string)
	if err := nftFlush(); err != nil {
		if isNftNotFound(err) {
			return nil
		}
		return err
	}
	return nil
}

// renderDNSTable renders the wireguide_dns nft script for a permit set. A
// pinned permit is bound to its interface by name; an unpinned permit (a
// resolver reached over the physical network, e.g. from a split tunnel) has no
// interface match. Invalid entries are skipped with a warning.
func renderDNSTable(permits []DNSPermit) string {
	var dnsAllowed []string
	seen := make(map[DNSPermit]struct{})
	for _, p := range permits {
		if net.ParseIP(p.Server) == nil {
			slog.Warn("skipping invalid DNS IP in nft rules", "dns", p.Server)
			continue
		}
		if p.Interface != "" && !validIfaceName.MatchString(p.Interface) {
			slog.Warn("skipping DNS permit with invalid interface", "interface", p.Interface, "dns", p.Server)
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		addrKw := "ip"
		if strings.Contains(p.Server, ":") {
			addrKw = "ip6"
		}
		oif := ""
		if p.Interface != "" {
			oif = fmt.Sprintf(" oifname %q", p.Interface)
		}
		for _, proto := range []string{"tcp", "udp"} {
			dnsAllowed = append(dnsAllowed,
				fmt.Sprintf("%s daddr %s %s dport 53%s accept", addrKw, p.Server, proto, oif))
		}
	}
	if len(dnsAllowed) == 0 {
		return ""
	}
	// Single atomic script: create-if-missing then delete, then define the
	// table fresh. Without the delete a repeated enable would APPEND a new
	// accept set after the previous set's drop rules.
	return fmt.Sprintf(`
add table inet %[1]s_dns
delete table inet %[1]s_dns
table inet %[1]s_dns {
  chain dns_output {
    type filter hook output priority -1; policy accept;
    # Allow DNS to loopback (systemd-resolved stub at 127.0.0.53, local
    # Pi-hole at 127.0.0.1, etc). Without this, systems using
    # systemd-resolved would have ALL DNS blocked.
    oif lo tcp dport 53 accept
    oif lo udp dport 53 accept
    %[2]s
    tcp dport 53 drop
    udp dport 53 drop
  }
}
`, nftTable, strings.Join(dnsAllowed, "\n    "))
}

// SetDNSPermits replaces the whole DNS permit set atomically. An empty (or
// fully invalid) set removes the DNS table.
func (f *LinuxFirewall) SetDNSPermits(permits []DNSPermit) error {
	rules := renderDNSTable(permits)
	f.mu.Lock()
	defer f.mu.Unlock()
	if rules == "" {
		if out, err := nftDeleteDNSTable(); err != nil && !isNftNotFound(fmt.Errorf("%s", out)) {
			// Surface the failure: the table (and its port-53 drop) is
			// still in the kernel, so the reconcile must not be marked
			// clean or it would never retry.
			slog.Warn("nft delete dns table failed", "error", err, "output", strings.TrimSpace(string(out)))
			return fmt.Errorf("nft delete dns table: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		f.dnsProtectionEnabled = false
		return nil
	}
	if err := nftApply(rules); err != nil {
		return err
	}
	f.dnsProtectionEnabled = true
	return nil
}

func (f *LinuxFirewall) EnableDNSProtection(interfaceName string, dnsServers []string) error {
	if len(dnsServers) == 0 {
		return nil
	}
	// Validate interface name before interpolating into nft rules.
	if !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}
	permits := make([]DNSPermit, 0, len(dnsServers))
	for _, dns := range dnsServers {
		permits = append(permits, DNSPermit{Interface: interfaceName, Server: dns})
	}
	return f.SetDNSPermits(permits)
}

func (f *LinuxFirewall) DisableDNSProtection() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// LOW: Log errors from nft delete
	if out, err := nftDeleteDNSTable(); err != nil && !isNftNotFound(fmt.Errorf("%s", out)) {
		slog.Warn("nft delete dns table failed", "error", err, "output", strings.TrimSpace(string(out)))
		return fmt.Errorf("nft delete dns table: %w (%s)", err, strings.TrimSpace(string(out)))
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

// RecoverFromCrash removes a wireguide_dns table left behind by a previous
// helper (nft tables are kernel state and outlive the process that made them).
// A stale DNS block would otherwise blackhole port 53 until the next protected
// connect. The kill-switch table is recreated on every EnableKillSwitch.
func (f *LinuxFirewall) RecoverFromCrash() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsProtectionEnabled = false
	if out, err := nftDeleteDNSTable(); err == nil {
		slog.Info("recovery: removed stale DNS protection table")
		return true
	} else if !isNftNotFound(fmt.Errorf("%s", out)) {
		slog.Warn("recovery: nft delete dns table failed", "error", err, "output", strings.TrimSpace(string(out)))
	}
	return false
}

func (f *LinuxFirewall) Cleanup() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killSwitchEnabled = false
	f.dnsProtectionEnabled = false
	flushErr := nftFlush()
	// Also clean up DNS table.
	if out, err := nftDeleteDNSTable(); err != nil {
		slog.Warn("nft delete dns table failed during cleanup", "error", err, "output", strings.TrimSpace(string(out)))
	}
	return flushErr
}

func nftApply(rules string) error {
	ctx, cancel := context.WithTimeout(context.Background(), nftCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("nft: timed out after %s (%s)", nftCmdTimeout, strings.TrimSpace(string(out)))
		}
		return fmt.Errorf("nft: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// nftDeleteDNSTable removes the wireguide_dns nftables table with a bounded
// timeout. Returns the same (output, error) shape callers expect.
var nftDeleteDNSTable = func() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nftCmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "nft", "delete", "table", "inet", nftTable+"_dns").CombinedOutput()
}

// nftFlush deletes the main wireguide nftables table and returns any error.
func nftFlush() error {
	ctx, cancel := context.WithTimeout(context.Background(), nftCmdTimeout)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", nftTable).CombinedOutput(); err != nil {
		return fmt.Errorf("nft delete table: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isNftNotFound reports whether an nft error means the target object
// didn't exist — which, for a delete/disable, is an already-done success
// rather than a failure. nft phrases this as "No such file or directory".
func isNftNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "does not exist")
}
