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

// anchorName is the pf anchor where WireGuide loads its rules.  Using an
// anchor avoids replacing the entire main pf ruleset.
const anchorName = "com.apple.wireguide"

// dnsAnchorName is the sub-anchor for DNS protection rules.
const dnsAnchorName = anchorName + "/dns"

// anchorRef is the directive added to the main ruleset to activate our anchor.
const anchorRef = `anchor "` + anchorName + `"`

// savedRulesFile is the path where we persist the original pf ruleset so it
// can be restored after a crash.  Using a well-known system-level path keeps
// it accessible to the privileged helper that manages pf.
const savedRulesFile = "/Library/Application Support/wireguide/pf-saved.rules"

// savedPfStateFile persists whether pf was enabled before WireGuide modified
// it, so crash recovery can restore the original enabled/disabled state.
const savedPfStateFile = "/Library/Application Support/wireguide/pf-was-enabled"

// DarwinFirewall implements FirewallManager using macOS pf (packet filter).
//
// All WireGuide rules are loaded into the `com.apple.wireguide` anchor.  The
// main pf ruleset is only modified to add/remove an `anchor` reference line.
// DNS protection rules live in a sub-anchor `com.apple.wireguide/dns`.
// The original main ruleset is saved in memory and to disk so it can be
// restored on disable or after a crash.
type DarwinFirewall struct {
	mu                   sync.Mutex
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
	// savedRules holds the main pf ruleset captured before we added the anchor
	// reference.
	savedRules string
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

	// Snapshot pf state before doing expensive I/O.
	pfWas := isPfEnabled()

	// Save current main ruleset so we can restore it on disable.
	saved, err := getCurrentPfRules()
	if err != nil {
		slog.Warn("failed to save current pf rules, will use empty restore", "error", err)
		saved = ""
	}

	// Persist saved rules and pf state to disk so they survive a process crash.
	if err := persistSavedRules(saved); err != nil {
		slog.Warn("failed to persist pf rules to disk", "error", err)
	}
	if err := persistPfEnabledState(pfWas); err != nil {
		slog.Warn("failed to persist pf enabled state to disk", "error", err)
	}

	// Build kill switch rules — loaded into the anchor, not the main ruleset.
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

	// Add the anchor reference to the main ruleset (preserving existing rules).
	if err := addAnchorToMainRules(saved); err != nil {
		return fmt.Errorf("adding anchor reference to main rules: %w", err)
	}

	// H6: Enable pf if not already, checking the error
	if err := enablePf(); err != nil {
		slog.Warn("pfctl -e failed", "error", err)
		// Non-fatal: pf may already be enabled (pfctl -e returns exit 1
		// with "pf already enabled" which is harmless).
	}

	f.mu.Lock()
	f.pfWasEnabled = pfWas
	f.savedRules = saved
	f.killSwitchEnabled = true
	f.mu.Unlock()
	return nil
}

func (f *DarwinFirewall) DisableKillSwitch() error {
	// Snapshot state under lock, then release for expensive I/O.
	f.mu.Lock()
	saved := f.savedRules
	pfWas := f.pfWasEnabled
	dnsActive := f.dnsProtectionEnabled
	f.mu.Unlock()

	// Flush the anchor rules.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("failed to flush anchor rules", "error", err)
	}

	// Restore the original main ruleset (without anchor reference).
	if err := restoreMainRules(saved); err != nil {
		slog.Warn("failed to restore original pf rules", "error", err)
	}

	// If DNS protection is still logically active but we just removed the
	// anchor, we need to note that its rules are gone.  The caller should
	// re-enable DNS protection separately if desired.
	_ = dnsActive

	// M3: If pf was not enabled before we started, disable it now
	if !pfWas {
		if err := disablePf(); err != nil {
			slog.Warn("pfctl -d failed", "error", err)
		}
	}

	// Clean up persisted files — no longer needed after successful restore.
	removeSavedRulesFile()
	removePfStateFile()

	f.mu.Lock()
	f.killSwitchEnabled = false
	f.savedRules = ""
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

	// Snapshot state under lock.
	f.mu.Lock()
	ksEnabled := f.killSwitchEnabled
	hasSaved := f.savedRules != ""
	f.mu.Unlock()

	if ksEnabled {
		// Kill switch is active — its anchor rules already contain
		// `anchor "com.apple.wireguide/dns"`, so loading into the
		// sub-anchor works directly.
		if err := loadAnchorRules(dnsAnchorName, dnsRules.String()); err != nil {
			return fmt.Errorf("loading DNS anchor rules: %w", err)
		}
	} else {
		// No kill switch — we still use the anchor approach.  Load DNS
		// rules into the main anchor and add the anchor reference.
		if !hasSaved {
			pfWas := isPfEnabled()
			saved, err := getCurrentPfRules()
			if err != nil {
				slog.Warn("failed to save current pf rules for DNS protection", "error", err)
				saved = ""
			}
			if err := persistSavedRules(saved); err != nil {
				slog.Warn("failed to persist pf rules to disk", "error", err)
			}
			if err := persistPfEnabledState(pfWas); err != nil {
				slog.Warn("failed to persist pf enabled state to disk", "error", err)
			}
			f.mu.Lock()
			f.savedRules = saved
			f.pfWasEnabled = pfWas
			f.mu.Unlock()
		}

		// Load DNS rules into the main anchor.
		if err := loadAnchorRules(anchorName, dnsRules.String()); err != nil {
			return fmt.Errorf("loading DNS rules into anchor: %w", err)
		}

		// Add anchor reference to main rules.
		f.mu.Lock()
		saved := f.savedRules
		f.mu.Unlock()

		if err := addAnchorToMainRules(saved); err != nil {
			return fmt.Errorf("adding anchor reference to main rules: %w", err)
		}

		if err := enablePf(); err != nil {
			slog.Warn("pfctl -e failed while enabling DNS protection", "error", err)
		}
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
	saved := f.savedRules
	pfWas := f.pfWasEnabled
	f.mu.Unlock()

	if ksEnabled {
		// Kill switch is active — DNS rules are in the sub-anchor, just flush it.
		cmd := exec.Command("pfctl", "-a", dnsAnchorName, "-F", "rules")
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("failed to flush DNS pf anchor", "error", err, "output", strings.TrimSpace(string(out)))
		}
	} else {
		// DNS rules were loaded into the main anchor.  Flush the anchor and
		// restore the original main ruleset.
		if err := flushAllAnchors(); err != nil {
			slog.Warn("failed to flush anchor rules", "error", err)
		}

		if err := restoreMainRules(saved); err != nil {
			slog.Warn("failed to restore original pf rules", "error", err)
		}

		f.mu.Lock()
		f.savedRules = ""
		f.mu.Unlock()
		removeSavedRulesFile()
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
	saved := f.savedRules
	pfWas := f.pfWasEnabled
	f.dnsProtectionEnabled = false
	f.killSwitchEnabled = false
	f.savedRules = ""
	f.mu.Unlock()

	// Flush all anchor rules regardless of what was active.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("cleanup: flush pf anchors failed", "error", err)
	}

	// Restore original main rules if we modified them (kill switch OR DNS-only).
	if ksActive || dnsActive {
		if err := restoreMainRules(saved); err != nil {
			slog.Warn("cleanup: failed to restore original pf rules", "error", err)
		}

		// Restore pf enabled/disabled state.
		if !pfWas {
			if err := disablePf(); err != nil {
				slog.Warn("cleanup: pfctl -d failed", "error", err)
			}
		}

		removeSavedRulesFile()
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

// addAnchorToMainRules appends the WireGuide anchor reference to the given
// saved rules and loads the result as the main ruleset.  If the anchor
// reference already exists in the saved rules it is not duplicated.
func addAnchorToMainRules(savedRules string) error {
	main := savedRules
	if !strings.Contains(main, anchorRef) {
		main = strings.TrimRight(main, "\n") + "\n" + anchorRef + "\n"
	}
	return loadMainPfRules(main)
}

// restoreMainRules restores the original main ruleset (without the anchor
// reference).  If saved is empty, loads a permissive ruleset.
func restoreMainRules(saved string) error {
	if saved != "" {
		// Strip any leftover anchor reference that may have been captured.
		cleaned := removeAnchorRefFromRules(saved)
		return loadMainPfRules(cleaned)
	}
	// No saved rules — load a permissive ruleset to clear ours.
	return loadMainPfRules("pass all\n")
}

// removeAnchorRefFromRules removes the WireGuide anchor directive from a
// ruleset string so restoring saved rules doesn't leave a dangling reference.
func removeAnchorRefFromRules(rules string) string {
	var out []string
	for _, line := range strings.Split(rules, "\n") {
		if strings.TrimSpace(line) == anchorRef {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// loadMainPfRules loads rules directly into the main pf ruleset (no anchor).
func loadMainPfRules(rules string) error {
	cmd := exec.Command("pfctl", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// getCurrentPfRules returns the current main pf ruleset via `pfctl -sr`.
func getCurrentPfRules() (string, error) {
	out, err := exec.Command("pfctl", "-sr").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("pfctl -sr: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
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

// persistSavedRules writes the original pf rules to disk so they can be
// recovered after a crash.
func persistSavedRules(rules string) error {
	dir := filepath.Dir(savedRulesFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}
	if err := os.WriteFile(savedRulesFile, []byte(rules), 0600); err != nil {
		return fmt.Errorf("writing %s: %w", savedRulesFile, err)
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

// removeSavedRulesFile removes the persisted rules file after a successful
// restore.
func removeSavedRulesFile() {
	if err := os.Remove(savedRulesFile); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove saved pf rules file", "path", savedRulesFile, "error", err)
	}
}

// removePfStateFile removes the persisted pf state file.
func removePfStateFile() {
	if err := os.Remove(savedPfStateFile); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove pf state file", "path", savedPfStateFile, "error", err)
	}
}

// RecoverSavedRules checks for a persisted saved-rules file left behind by a
// crash and restores the original pf ruleset and enabled/disabled state.
// Returns true if recovery was performed.
func RecoverSavedRules() bool {
	data, err := os.ReadFile(savedRulesFile)
	if err != nil {
		// No file means nothing to recover.
		return false
	}
	rules := string(data)
	pfWasEnabled := readPersistedPfState()
	slog.Info("recovering pf rules from crash-recovery file", "path", savedRulesFile, "pfWasEnabled", pfWasEnabled)

	// Flush all anchor rules first.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("recovery: failed to flush anchors", "error", err)
	}

	// Restore the main ruleset.
	if err := restoreMainRules(rules); err != nil {
		slog.Error("failed to restore pf rules from recovery file", "error", err)
		return false
	}

	// Restore pf enabled/disabled state.
	if !pfWasEnabled {
		if err := disablePf(); err != nil {
			slog.Warn("recovery: failed to disable pf", "error", err)
		}
	}

	removeSavedRulesFile()
	removePfStateFile()
	slog.Info("pf rules restored successfully from crash-recovery file")
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
