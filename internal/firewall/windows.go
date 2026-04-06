//go:build windows

package firewall

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const policyBackupFile = "fw-policy-backup.txt"

// validWinIfaceName matches Windows interface names: alphanumeric, hyphens,
// underscores, and spaces (Windows interface names commonly contain spaces).
var validWinIfaceName = regexp.MustCompile(`^[a-zA-Z0-9 _-]{1,256}$`)

// WindowsFirewall implements FirewallManager by changing the default firewall
// policy to block and adding named allow-rule exceptions.
//
// Previous approach (explicit block rules + allow rules) was broken: in Windows
// Firewall with Advanced Security, explicit block rules take precedence over
// allow rules by default. The correct approach is:
//   1. Save the current default outbound/inbound policy
//   2. Set the default profile policy to block all traffic
//   3. Add ALLOW rules as exceptions (these work because they are exceptions
//      to the default policy, not competing with explicit block rules)
//   4. On cleanup, restore the original default policy
//
// The original policy is persisted to disk so crash recovery can restore it.
type WindowsFirewall struct {
	mu                   sync.Mutex
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
}

func NewPlatformFirewall() FirewallManager {
	return &WindowsFirewall{}
}

func (f *WindowsFirewall) EnableKillSwitch(interfaceName string, _ []string, endpoints []string) error {
	// Validate interface name to prevent injection.
	if !validWinIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// H18: Check and return errors from critical netsh commands.

	// Step 1: Save and persist the current default firewall policy so we can
	// restore it on cleanup (including after a crash).
	if err := saveCurrentPolicy(); err != nil {
		return fmt.Errorf("saving current firewall policy: %w", err)
	}

	// Step 2: Add all ALLOW rules BEFORE changing the default policy to block.
	// This avoids a window where traffic is blocked with no exceptions.

	// Allow loopback (IPv4 + IPv6)
	if err := runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-AllowLoopback", "dir=out", "action=allow",
		"remoteip=127.0.0.0/8,::1", "enable=yes"); err != nil {
		return fmt.Errorf("adding loopback allow rule: %w", err)
	}

	// Allow each WG endpoint IP (for encrypted traffic to reach the server)
	for i, ep := range endpoints {
		ip, _, _ := net.SplitHostPort(ep)
		if ip == "" {
			ip = ep // fallback: bare IP without port
		}
		if net.ParseIP(ip) == nil {
			continue // skip invalid IPs
		}
		if err := runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=WireGuide-AllowEndpoint%d", i), "dir=out", "action=allow",
			"remoteip="+ip, "protocol=udp", "enable=yes"); err != nil {
			return fmt.Errorf("adding endpoint allow rule for %s: %w", ip, err)
		}
	}

	// Allow DHCP outbound (client port 68 -> server port 67)
	if err := runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-AllowDHCP-Out", "dir=out", "action=allow",
		"protocol=udp", "localport=68", "remoteport=67", "enable=yes"); err != nil {
		return fmt.Errorf("adding DHCP outbound rule: %w", err)
	}

	// LOW: Allow DHCP inbound (server port 67 -> client port 68)
	_ = runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-AllowDHCP-In", "dir=in", "action=allow",
		"protocol=udp", "localport=68", "remoteport=67", "enable=yes")

	// Allow IPv6 NDP (Neighbor Discovery Protocol) — ICMPv6 types 133-137.
	// Use PowerShell for type-specific filtering since netsh doesn't support
	// ICMPv6 type restrictions.
	for _, ndpType := range []string{"133", "134", "135", "136", "137"} {
		_ = exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`New-NetFirewallRule -DisplayName 'WireGuide-AllowNDP-%s' -Direction Outbound -Action Allow -Protocol ICMPv6 -IcmpType %s`, ndpType, ndpType)).Run()
		_ = exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`New-NetFirewallRule -DisplayName 'WireGuide-AllowNDP-%s-In' -Direction Inbound -Action Allow -Protocol ICMPv6 -IcmpType %s`, ndpType, ndpType)).Run()
	}

	// Allow all traffic on WG tunnel interface (both directions)
	if err := runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-AllowTunnel-Out", "dir=out", "action=allow",
		"enable=yes", "interface="+interfaceName); err != nil {
		return fmt.Errorf("adding tunnel outbound allow rule: %w", err)
	}
	_ = runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-AllowTunnel-In", "dir=in", "action=allow",
		"enable=yes", "interface="+interfaceName)

	// Step 3: Set the default policy to block all traffic.
	// The allow rules above act as exceptions to this default policy.
	// Unlike explicit block rules, allow rules DO take precedence over the
	// default policy, so all our exceptions will work correctly.
	if err := runWinFW("netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", "blockinbound,blockoutbound"); err != nil {
		return fmt.Errorf("setting default block policy: %w", err)
	}

	f.killSwitchEnabled = true
	return nil
}

func (f *WindowsFirewall) DisableKillSwitch() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cleanupWinRules()
	f.killSwitchEnabled = false
	return nil
}

func (f *WindowsFirewall) EnableDNSProtection(interfaceName string, dnsServers []string) error {
	if len(dnsServers) == 0 {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Validate and collect approved DNS server IPs.
	var validServers []string
	for _, dns := range dnsServers {
		if net.ParseIP(dns) != nil {
			validServers = append(validServers, dns)
		}
	}
	if len(validServers) == 0 {
		return nil
	}

	// Allow DNS (UDP+TCP) to specified servers — M12: cover both UDP and TCP.
	// These are allow-rule exceptions; when the kill switch default-block policy
	// is active, only these DNS servers will be reachable on port 53.
	// When the kill switch is NOT active, we add explicit block rules for
	// port 53 to prevent DNS leaks to non-approved servers.
	for i, dns := range validServers {
		if err := runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=WireGuide-AllowDNS-UDP%d", i), "dir=out", "action=allow",
			"protocol=udp", "remoteport=53", "remoteip="+dns, "enable=yes"); err != nil {
			return fmt.Errorf("adding DNS UDP allow rule for %s: %w", dns, err)
		}
		if err := runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=WireGuide-AllowDNS-TCP%d", i), "dir=out", "action=allow",
			"protocol=tcp", "remoteport=53", "remoteip="+dns, "enable=yes"); err != nil {
			return fmt.Errorf("adding DNS TCP allow rule for %s: %w", dns, err)
		}
	}

	// When the kill switch is active, its default-block policy already prevents
	// DNS to non-approved servers. When the kill switch is NOT active, we need
	// explicit block rules for port 53 to prevent DNS leaks.
	//
	// netsh does NOT support `remoteip=!` negation. Instead, we add ALLOW
	// rules for approved DNS servers (done above) and then add BLOCK rules for
	// ALL destinations on port 53. In WFAS, explicit block rules take
	// precedence over explicit allow rules by default, so we must use
	// PowerShell to set the allow rules to "override block" processing order.
	//
	// Strategy: block all port 53 traffic, then set the allow rules to override.

	// Add blanket block rules for all DNS traffic.
	if err := runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-BlockDNS-UDP", "dir=out", "action=block",
		"protocol=udp", "remoteport=53", "remoteip=any", "enable=yes"); err != nil {
		return fmt.Errorf("adding DNS block rule (UDP): %w", err)
	}
	if err := runWinFW("netsh", "advfirewall", "firewall", "add", "rule",
		"name=WireGuide-BlockDNS-TCP", "dir=out", "action=block",
		"protocol=tcp", "remoteport=53", "remoteip=any", "enable=yes"); err != nil {
		return fmt.Errorf("adding DNS block rule (TCP): %w", err)
	}

	// Set DNS allow rules to override block rules using PowerShell.
	// The -OverrideBlockRules flag makes allow rules take precedence over
	// explicit block rules, which is the only reliable way to achieve
	// "allow these specific IPs, block everything else" in WFAS.
	// This MUST succeed — if it fails, the DNS allow rules will NOT override
	// the DNS block rules, resulting in ALL DNS being blocked silently.
	if err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'WireGuide-AllowDNS-*' } | Set-NetFirewallRule -OverrideBlockRules $true`).Run(); err != nil {
		return fmt.Errorf("setting OverrideBlockRules on DNS allow rules: %w (DNS will be completely blocked without this)", err)
	}

	f.dnsProtectionEnabled = true
	return nil
}

func (f *WindowsFirewall) DisableDNSProtection() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cleanupDNSRules()
	f.dnsProtectionEnabled = false
	return nil
}

func (f *WindowsFirewall) IsKillSwitchEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killSwitchEnabled
}
func (f *WindowsFirewall) IsDNSProtectionEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dnsProtectionEnabled
}

// Cleanup removes ALL WireGuide-named firewall rules and restores the original
// default firewall policy. Safe to call from crash recovery — rule names are
// deleted by pattern (not in-memory counts), and the original policy is read
// from disk.
func (f *WindowsFirewall) Cleanup() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cleanupWinRules()
	f.killSwitchEnabled = false
	f.dnsProtectionEnabled = false
	return nil
}

// cleanupDNSRules removes all WireGuide DNS-related firewall rules by name.
// Uses PowerShell Remove-NetFirewallRule with -Name wildcard matching to avoid
// depending on in-memory counters that would be lost on crash.
func cleanupDNSRules() {
	// Remove DNS block rules
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=WireGuide-BlockDNS-UDP").Run()
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=WireGuide-BlockDNS-TCP").Run()
	// Legacy single BlockDNS rule
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=WireGuide-BlockDNS").Run()

	// Remove per-server DNS allow rules using PowerShell wildcard.
	// This catches all WireGuide-AllowDNS-UDP0, WireGuide-AllowDNS-UDP1, etc.
	// without needing to know how many were created.
	exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'WireGuide-AllowDNS-*' } | Remove-NetFirewallRule`).Run()
	// Legacy single-protocol rule names
	exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'WireGuide-AllowDNS[0-9]*' } | Remove-NetFirewallRule`).Run()
}

// cleanupWinRules removes all WireGuide firewall rules and restores the
// original default firewall policy. Does not depend on in-memory state.
func cleanupWinRules() {
	// Step 1: Restore the original default firewall policy from disk.
	restoreSavedPolicy()

	// Step 2: Remove all WireGuide allow rules by exact name.
	fixedNames := []string{
		"WireGuide-AllowLoopback",
		"WireGuide-AllowTunnel-Out", "WireGuide-AllowTunnel-In",
		"WireGuide-AllowDHCP-Out", "WireGuide-AllowDHCP-In",
		// Legacy rule names from previous versions
		"WireGuide-AllowTunnel", "WireGuide-AllowDHCP",
		// Legacy NDP rules (old broad ICMPv6 approach)
		"WireGuide-AllowNDP-Out", "WireGuide-AllowNDP-In",
		// Legacy block rules from old approach — clean them up if present
		"WireGuide-Block-Out", "WireGuide-Block-In",
	}
	for _, name := range fixedNames {
		exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	}

	// Remove numbered endpoint allow rules using PowerShell wildcard.
	// This avoids depending on an in-memory count that is lost on crash.
	exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'WireGuide-AllowEndpoint*' } | Remove-NetFirewallRule`).Run()

	// Remove type-specific NDP rules created by PowerShell.
	exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'WireGuide-AllowNDP-*' } | Remove-NetFirewallRule`).Run()

	// Step 3: Clean up DNS rules.
	cleanupDNSRules()
}

// policyBackupPath returns the full path to the policy backup file in DataDir.
func policyBackupPath() string {
	programData := os.Getenv("PROGRAMDATA")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "wireguide", policyBackupFile)
}

// saveCurrentPolicy queries the current default firewall policy for all
// profiles and writes it to disk so it can be restored after cleanup or crash.
func saveCurrentPolicy() error {
	backupPath := policyBackupPath()
	if err := os.MkdirAll(filepath.Dir(backupPath), 0755); err != nil {
		return fmt.Errorf("creating backup directory: %w", err)
	}

	// Don't overwrite if a backup already exists — it means the kill switch
	// was already active (possibly from a previous crash). The existing backup
	// holds the true original policy before we ever modified it.
	if _, err := os.Stat(backupPath); err == nil {
		return nil
	}

	// Use PowerShell for locale-independent output. The netsh output varies
	// by Windows display language, but PowerShell property names are stable.
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.DefaultInboundAction),$($_.DefaultOutboundAction)" }`).CombinedOutput()
	if err != nil {
		// Fallback to netsh
		cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles", "firewallpolicy")
		out, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("querying firewall policy: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}

	if err := os.WriteFile(backupPath, out, 0644); err != nil {
		return fmt.Errorf("writing policy backup: %w", err)
	}
	return nil
}

// restoreSavedPolicy reads the persisted policy backup and restores the
// default firewall policy for each profile. If no backup exists (nothing to
// restore), it falls back to the Windows default (blockinbound,allowoutbound).
func restoreSavedPolicy() {
	backupPath := policyBackupPath()
	data, err := os.ReadFile(backupPath)
	if err != nil {
		// No backup file — either the kill switch was never enabled or the
		// file was already cleaned up. Fall back to Windows default policy to
		// be safe (in case we're called from crash recovery and the backup
		// was lost).
		exec.Command("netsh", "advfirewall", "set", "allprofiles",
			"firewallpolicy", "blockinbound,allowoutbound").Run()
		return
	}

	// Parse the saved output to extract per-profile policies.
	// Each profile section contains a line like:
	//   Firewall Policy                   BlockInbound,AllowOutbound
	profiles := []string{"domainprofile", "privateprofile", "publicprofile"}
	policies := parsePolicies(string(data))

	for i, profile := range profiles {
		policy := "blockinbound,allowoutbound" // safe default
		if i < len(policies) && policies[i] != "" {
			policy = policies[i]
		}
		exec.Command("netsh", "advfirewall", "set", profile,
			"firewallpolicy", policy).Run()
	}

	// Remove the backup file — policy has been restored.
	os.Remove(backupPath)
}

// parsePolicies extracts firewall policy strings from saved policy output.
// Handles both PowerShell format ("Domain=Block,Allow") and netsh format.
// Returns up to 3 policies (domain, private, public) in profile order.
func parsePolicies(output string) []string {
	var policies []string

	// Try PowerShell format first: "Domain=Block,Allow"
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.TrimSpace(parts[1])
		val = strings.ToLower(val)
		// Convert PowerShell action names to netsh format
		val = strings.ReplaceAll(val, "notconfigured", "allow")
		// Construct netsh-compatible policy string: "blockinbound,allowoutbound"
		actions := strings.Split(val, ",")
		if len(actions) == 2 {
			policy := actions[0] + "inbound," + actions[1] + "outbound"
			policies = append(policies, policy)
		}
	}
	if len(policies) > 0 {
		return policies
	}

	// Fallback: netsh format (English locale)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "inbound") || !strings.Contains(lower, "outbound") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		val := strings.ToLower(fields[len(fields)-1])
		policies = append(policies, val)
	}
	return policies
}

func runWinFW(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
