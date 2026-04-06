//go:build darwin

package firewall

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// validIfaceName matches typical macOS interface names like utun4, en0, lo0.
var validIfaceName = regexp.MustCompile(`^[a-z]+[0-9]+$`)

// anchorName is the pf anchor where WireGuide loads its rules.  macOS ships
// with `anchor "com.apple/*" all` in pf.conf, so our anchor is automatically
// evaluated without modifying the main ruleset.
const anchorName = "com.apple.wireguide"

// dnsAnchorName is the sub-anchor for DNS protection rules.
const dnsAnchorName = anchorName + "/dns"

// savedPfStateFile persists whether pf was enabled before WireGuide modified
// it, so crash recovery can restore the original enabled/disabled state.
const savedPfStateFile = "/Library/Application Support/wireguide/pf-was-enabled"

// DarwinFirewall implements FirewallManager using macOS pf (packet filter).
//
// All WireGuide rules are loaded into the `com.apple.wireguide` anchor.
// macOS ships with `anchor "com.apple/*" all` in pf.conf, so our anchor
// is automatically evaluated without modifying the main ruleset.
// DNS protection rules live in a sub-anchor `com.apple.wireguide/dns`.
type DarwinFirewall struct {
	mu                   sync.Mutex
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
	// pfWasEnabled tracks whether pf was already enabled before we started,
	// so we know whether to turn pf back off on disable/cleanup.
	pfWasEnabled bool
}

func NewPlatformFirewall() FirewallManager {
	return &DarwinFirewall{}
}

func (f *DarwinFirewall) EnableKillSwitch(interfaceName string, _ []string, endpoints []string) error {
	// M1: Validate interface name
	if !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}

	// Snapshot pf state so we can restore enabled/disabled on teardown.
	pfWas := isPfEnabled()
	if err := persistPfEnabledState(pfWas); err != nil {
		slog.Warn("failed to persist pf enabled state to disk", "error", err)
	}

	// Build kill switch rules — loaded into the anchor, not the main ruleset.
	// macOS ships with `anchor "com.apple/*" all` in pf.conf, so our
	// anchor `com.apple.wireguide` is automatically evaluated without
	// modifying the main ruleset at all.
	var rules strings.Builder
	rules.WriteString("# WireGuide kill switch rules\n")
	rules.WriteString("# Allow loopback\n")
	rules.WriteString("pass quick on lo0 all\n")

	// Allow each WireGuard endpoint (restrict to proto udp + port when available).
	// Without port/protocol restriction, ALL traffic to the endpoint IP bypasses
	// the kill switch, which is a security concern if the WireGuard server runs
	// other services on the same IP.
	for _, ep := range endpoints {
		ip, port, _ := net.SplitHostPort(ep)
		if ip == "" {
			ip = ep // fallback: bare IP without port
		}
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid endpoint IP %q", ip)
		}
		if port != "" {
			fmt.Fprintf(&rules, "pass out quick proto udp to %s port %s\n", ip, port)
		} else {
			// No port info — allow all UDP to this IP (WireGuard is always UDP)
			fmt.Fprintf(&rules, "pass out quick proto udp to %s\n", ip)
		}
	}

	// Allow DHCP (so lease renewal works while kill switch is active)
	rules.WriteString("pass out quick proto udp from any port 68 to any port 67\n")
	// H7: Allow DHCPv6
	rules.WriteString("pass out quick proto udp from any port 546 to any port 547\n")

	// Allow WireGuard tunnel interface
	fmt.Fprintf(&rules, "pass quick on %s all\n", interfaceName)

	// DNS protection sub-anchor — must appear BEFORE the block rules so pf
	// evaluates DNS filtering rules loaded into the sub-anchor.
	fmt.Fprintf(&rules, "anchor \"%s\"\n", dnsAnchorName)

	// Block all other traffic
	rules.WriteString("block drop out all\n")
	rules.WriteString("block drop in all\n")

	// Load rules into the anchor.
	if err := loadAnchorRules(anchorName, rules.String()); err != nil {
		return fmt.Errorf("loading kill switch rules into anchor: %w", err)
	}

	// Enable pf if not already.
	if err := enablePf(); err != nil {
		slog.Warn("pfctl -e failed", "error", err)
	}

	f.mu.Lock()
	f.pfWasEnabled = pfWas
	f.killSwitchEnabled = true
	f.mu.Unlock()
	return nil
}

func (f *DarwinFirewall) DisableKillSwitch() error {
	f.mu.Lock()
	pfWas := f.pfWasEnabled
	f.mu.Unlock()

	// Flush the anchor rules — main ruleset is untouched.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("failed to flush anchor rules", "error", err)
	}

	// If pf was not enabled before we started, disable it now.
	if !pfWas {
		if err := disablePf(); err != nil {
			slog.Warn("pfctl -d failed", "error", err)
		}
	}

	// Clean up persisted state file.
	removePfStateFile()

	f.mu.Lock()
	f.killSwitchEnabled = false
	f.mu.Unlock()
	return nil
}

func (f *DarwinFirewall) EnableDNSProtection(interfaceName string, dnsServers []string) error {
	if len(dnsServers) == 0 {
		return nil
	}

	// M1: Validate interface name
	if !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}

	var dnsRules strings.Builder
	for _, dns := range dnsServers {
		if net.ParseIP(dns) == nil {
			return fmt.Errorf("invalid DNS server IP %q", dns)
		}
		fmt.Fprintf(&dnsRules, "pass out quick on %s proto {tcp, udp} to %s port 53\n", interfaceName, dns)
	}
	dnsRules.WriteString("block drop out quick proto {tcp, udp} to any port 53\n")

	f.mu.Lock()
	ksEnabled := f.killSwitchEnabled
	f.mu.Unlock()

	if ksEnabled {
		// Kill switch is active — its anchor rules already contain
		// `anchor "com.apple.wireguide/dns"`, so loading into the
		// sub-anchor works directly.
		if err := loadAnchorRules(dnsAnchorName, dnsRules.String()); err != nil {
			return fmt.Errorf("loading DNS anchor rules: %w", err)
		}
	} else {
		// No kill switch — load DNS rules into the main anchor.
		// macOS evaluates the anchor via the com.apple/* wildcard.
		pfWas := isPfEnabled()
		if err := persistPfEnabledState(pfWas); err != nil {
			slog.Warn("failed to persist pf enabled state to disk", "error", err)
		}

		if err := loadAnchorRules(anchorName, dnsRules.String()); err != nil {
			return fmt.Errorf("loading DNS rules into anchor: %w", err)
		}

		if err := enablePf(); err != nil {
			slog.Warn("pfctl -e failed while enabling DNS protection", "error", err)
		}

		f.mu.Lock()
		f.pfWasEnabled = pfWas
		f.mu.Unlock()
	}

	f.mu.Lock()
	f.dnsProtectionEnabled = true
	f.mu.Unlock()
	return nil
}

func (f *DarwinFirewall) DisableDNSProtection() error {
	// Snapshot state under lock.
	f.mu.Lock()
	ksEnabled := f.killSwitchEnabled
	pfWas := f.pfWasEnabled
	f.mu.Unlock()

	if ksEnabled {
		// Kill switch is active — DNS rules are in the sub-anchor, just flush it.
		cmd := exec.Command("pfctl", "-a", dnsAnchorName, "-F", "rules")
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("failed to flush DNS pf anchor", "error", err, "output", strings.TrimSpace(string(out)))
		}
	} else {
		// DNS rules were loaded into the main anchor.  Flush the anchor.
		if err := flushAllAnchors(); err != nil {
			slog.Warn("failed to flush anchor rules", "error", err)
		}

		removePfStateFile()

		if !pfWas {
			if err := disablePf(); err != nil {
				slog.Warn("pfctl -d failed", "error", err)
			}
		}
	}

	f.mu.Lock()
	f.dnsProtectionEnabled = false
	f.mu.Unlock()
	return nil
}

func (f *DarwinFirewall) IsKillSwitchEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killSwitchEnabled
}
func (f *DarwinFirewall) IsDNSProtectionEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dnsProtectionEnabled
}

func (f *DarwinFirewall) Cleanup() error {
	f.mu.Lock()
	dnsActive := f.dnsProtectionEnabled
	ksActive := f.killSwitchEnabled
	pfWas := f.pfWasEnabled
	f.dnsProtectionEnabled = false
	f.killSwitchEnabled = false
	f.mu.Unlock()

	// Flush all anchor rules regardless of what was active.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("cleanup: flush pf anchors failed", "error", err)
	}

	// Restore pf enabled/disabled state if we had anything active.
	if ksActive || dnsActive {
		if !pfWas {
			if err := disablePf(); err != nil {
				slog.Warn("cleanup: pfctl -d failed", "error", err)
			}
		}

		removePfStateFile()
	}

	return nil
}

// --- pf helper functions ---

// loadAnchorRules loads rules into the specified pf anchor.
func loadAnchorRules(anchor, rules string) error {
	cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -a %s -f -: %w (%s)", anchor, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isPfEnabled checks whether pf is currently enabled by parsing `pfctl -si`.
func isPfEnabled() bool {
	out, err := exec.Command("pfctl", "-si").CombinedOutput()
	if err != nil {
		return false
	}
	// Look for "Status: Enabled" in the output
	return strings.Contains(string(out), "Status: Enabled")
}

// enablePf enables the pf firewall.
func enablePf() error {
	out, err := exec.Command("pfctl", "-e").CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		// "pf already enabled" is not a real error
		if strings.Contains(outStr, "already enabled") {
			return nil
		}
		return fmt.Errorf("pfctl -e: %w (%s)", err, outStr)
	}
	return nil
}

// disablePf disables the pf firewall.
func disablePf() error {
	out, err := exec.Command("pfctl", "-d").CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		if strings.Contains(outStr, "already disabled") {
			return nil
		}
		return fmt.Errorf("pfctl -d: %w (%s)", err, outStr)
	}
	return nil
}

// persistPfEnabledState writes whether pf was enabled to disk for crash
// recovery.  The file contains "1" if enabled, "0" if disabled.
func persistPfEnabledState(enabled bool) error {
	dir := filepath.Dir(savedPfStateFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}
	val := "0"
	if enabled {
		val = "1"
	}
	if err := os.WriteFile(savedPfStateFile, []byte(val), 0600); err != nil {
		return fmt.Errorf("writing %s: %w", savedPfStateFile, err)
	}
	return nil
}

// readPersistedPfState reads the persisted pf enabled state from disk.
// Returns true (enabled) as the safe default if the file can't be read.
func readPersistedPfState() bool {
	data, err := os.ReadFile(savedPfStateFile)
	if err != nil {
		// Default to "was enabled" so we don't accidentally disable pf.
		return true
	}
	return strings.TrimSpace(string(data)) == "1"
}

// removePfStateFile removes the persisted pf state file.
func removePfStateFile() {
	if err := os.Remove(savedPfStateFile); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove pf state file", "path", savedPfStateFile, "error", err)
	}
}

// RecoverSavedRules checks for a persisted pf state file left behind by a
// crash and restores the original pf state by flushing all anchors and
// restoring the pf enabled/disabled state.  Returns true if recovery was
// performed.
func RecoverSavedRules() bool {
	pfWasEnabled := readPersistedPfState()

	// Check if the state file exists — if not, nothing to recover.
	if _, err := os.Stat(savedPfStateFile); err != nil {
		return false
	}

	slog.Info("recovering pf state from crash-recovery file", "pfWasEnabled", pfWasEnabled)

	// Flush all anchor rules.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("recovery: failed to flush anchors", "error", err)
	}

	// Restore pf enabled/disabled state.
	if !pfWasEnabled {
		if err := disablePf(); err != nil {
			slog.Warn("recovery: failed to disable pf", "error", err)
		}
	}

	removePfStateFile()
	slog.Info("pf state restored successfully from crash-recovery file")
	return true
}

// flushAllAnchors flushes all rules from the WireGuide anchors.
func flushAllAnchors() error {
	var errs []string

	// Flush the DNS sub-anchor first.
	if out, err := exec.Command("pfctl", "-a", dnsAnchorName, "-F", "rules").CombinedOutput(); err != nil {
		errs = append(errs, fmt.Sprintf("flush %s: %v (%s)", dnsAnchorName, err, strings.TrimSpace(string(out))))
	}
	// Flush the main anchor (this also covers any rules loaded directly).
	if out, err := exec.Command("pfctl", "-a", anchorName, "-Fa").CombinedOutput(); err != nil {
		errs = append(errs, fmt.Sprintf("flush %s: %v (%s)", anchorName, err, strings.TrimSpace(string(out))))
	}

	if len(errs) > 0 {
		return fmt.Errorf("flushAllAnchors: %s", strings.Join(errs, "; "))
	}
	return nil
}
