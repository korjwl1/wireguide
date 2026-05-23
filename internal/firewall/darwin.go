//go:build darwin

package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// pfCmdTimeout bounds every pfctl invocation. macOS pf can stall briefly
// when ruleset locks contend; this ceiling prevents helper hangs.
const pfCmdTimeout = 15 * time.Second

func runPfctl(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfCmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "pfctl", args...).CombinedOutput()
}

// validIfaceName matches typical macOS interface names like utun4, en0, lo0.
var validIfaceName = regexp.MustCompile(`^[a-z]+[0-9]+$`)

// anchorName is the pf anchor where WireGuide loads its rules.
//
// CRITICAL: the path MUST start with "com.apple/" (slash, not dot) so it
// matches the wildcard `anchor "com.apple/*"` declared in /etc/pf.conf.
// In pf, '/' is the parent/child anchor path separator while '.' is just
// a character — an anchor literally named "com.apple.wireguide" (dot)
// does NOT match the "com.apple/*" wildcard, so its rules would load
// silently and never be evaluated. That's exactly the bug we hit before
// switching to the slash form.
const anchorName = "com.apple/wireguide"

// dnsAnchorName is the sub-anchor for DNS protection rules.
const dnsAnchorName = anchorName + "/dns"

// dnsSubAnchorRel is the DNS sub-anchor name as referenced from *inside*
// the parent anchor's rule body. pf resolves `anchor "name"` relative
// to the current anchor scope, so writing the full path inside the
// parent would create a doubled path (com.apple/wireguide/com.apple/
// wireguide/dns) that never gets hit.
const dnsSubAnchorRel = "dns"

// savedPfStateFile persists whether pf was enabled before WireGuide modified
// it, so crash recovery can restore the original enabled/disabled state.
const savedPfStateFile = "/Library/Application Support/wireguide/pf-was-enabled"

// DarwinFirewall implements FirewallManager using macOS pf (packet filter).
//
// All WireGuide rules are loaded into the `com.apple/wireguide` anchor.
// macOS ships with `anchor "com.apple/*" all` in pf.conf, so any anchor
// under the com.apple/ path is automatically evaluated. DNS protection
// rules live in a sub-anchor `com.apple/wireguide/dns`.
type DarwinFirewall struct {
	mu                   sync.Mutex
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
	// pfWasEnabled tracks whether pf was already enabled before we started,
	// so we know whether to turn pf back off on disable/cleanup.
	pfWasEnabled bool
	// savedDNSInterface / savedDNSServers cache the most recent
	// EnableDNSProtection arguments so EnableKillSwitch can re-load
	// the DNS sub-anchor after rewriting the main anchor — without
	// this, enabling KS *after* DNS protection silently wipes the
	// DNS rules and DNS leaks despite dnsProtectionEnabled==true.
	savedDNSInterface string
	savedDNSServers   []string
	// savedTunnelIface / savedTunnelEndpoints cache the most recent
	// kill-switch tunnel parameters so AddKillSwitchTunnel /
	// RemoveKillSwitchTunnel can rebuild the pf anchor without losing
	// the active tunnel's permits when only one of (iface, dns) changes.
	savedTunnelIface     string
	savedTunnelEndpoints []string
}

func NewPlatformFirewall() FirewallManager {
	return &DarwinFirewall{}
}

// buildKillSwitchRules renders the pf rule text loaded into the
// `com.apple.wireguide` main anchor. interfaceName may be "" — when so,
// no per-iface permit ("pass quick on utunX all") is emitted, leaving
// only the base set (loopback + DHCP + endpoint permits if any) + the
// DNS sub-anchor directive + catch-all block. That's the layout used
// when the user toggles the kill switch on without an active tunnel.
func buildKillSwitchRules(interfaceName string, endpoints []string) (string, error) {
	var rules strings.Builder
	rules.WriteString("# WireGuide kill switch rules\n")
	rules.WriteString("# Allow loopback\n")
	rules.WriteString("pass quick on lo0 all\n")

	for _, ep := range endpoints {
		ip, port, _ := net.SplitHostPort(ep)
		if ip == "" {
			ip = ep
		}
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			return "", fmt.Errorf("invalid endpoint IP %q", ip)
		}
		if port != "" {
			fmt.Fprintf(&rules, "pass out quick proto udp to %s port %s\n", ip, port)
		} else {
			fmt.Fprintf(&rules, "pass out quick proto udp to %s\n", ip)
		}
	}

	rules.WriteString("pass out quick proto udp from any port 68 to any port 67\n")
	rules.WriteString("pass out quick proto udp from any port 546 to any port 547\n")

	if interfaceName != "" {
		fmt.Fprintf(&rules, "pass quick on %s all\n", interfaceName)
	}

	fmt.Fprintf(&rules, "anchor \"%s\"\n", dnsSubAnchorRel)
	rules.WriteString("block drop out all\n")
	rules.WriteString("block drop in all\n")
	return rules.String(), nil
}

func (f *DarwinFirewall) EnableKillSwitch(interfaceName string, _ []string, endpoints []string) error {
	// Empty interfaceName is a valid input — the user toggled the kill
	// switch on without an active tunnel. We install the base block-all
	// set only; once a tunnel connects, AddKillSwitchTunnel folds its
	// per-iface permit + endpoint permits in.
	if interfaceName != "" && !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}

	// Snapshot pf state so we can restore enabled/disabled on teardown.
	pfWas := isPfEnabled()
	if err := persistPfEnabledState(pfWas); err != nil {
		slog.Warn("failed to persist pf enabled state to disk", "error", err)
	}

	// Ensure the default pf ruleset is loaded so our anchor is
	// actually evaluated — see loadDefaultPfRuleset's docstring.
	if err := loadDefaultPfRuleset(); err != nil {
		slog.Warn("loading /etc/pf.conf failed; anchor may not be evaluated", "error", err)
	}

	rules, err := buildKillSwitchRules(interfaceName, endpoints)
	if err != nil {
		return err
	}

	if err := loadAnchorRules(anchorName, rules); err != nil {
		return fmt.Errorf("loading kill switch rules into anchor: %w", err)
	}

	// If DNS protection was enabled before this call, the previous
	// invocation wrote rules to the MAIN anchor (in EnableDNSProtection's
	// no-kill-switch branch). The loadAnchorRules call above just
	// overwrote those rules — leaving the `com.apple.wireguide/dns`
	// sub-anchor empty even though dnsProtectionEnabled==true. Re-
	// populate the sub-anchor here so DNS leaks don't silently start.
	f.reapplyDNSSubAnchorIfActive()

	// Enable pf if not already.
	if err := enablePf(); err != nil {
		slog.Warn("pfctl -e failed", "error", err)
	}

	f.mu.Lock()
	f.pfWasEnabled = pfWas
	f.killSwitchEnabled = true
	f.savedTunnelIface = interfaceName
	f.savedTunnelEndpoints = append([]string(nil), endpoints...)
	f.mu.Unlock()
	slog.Info("kill switch enabled", "interface", interfaceName, "endpoints", len(endpoints))
	return nil
}

// reapplyDNSSubAnchorIfActive re-loads the DNS sub-anchor under
// `com.apple.wireguide/dns` if DNS protection is currently active. The
// kill-switch main anchor only references the sub-anchor by name; the
// sub-anchor body lives independently in pf storage. We re-apply
// defensively after every main-anchor rewrite to keep the two in sync.
func (f *DarwinFirewall) reapplyDNSSubAnchorIfActive() {
	f.mu.Lock()
	dnsActive := f.dnsProtectionEnabled
	dnsIface := f.savedDNSInterface
	dnsServers := append([]string(nil), f.savedDNSServers...)
	f.mu.Unlock()
	if !dnsActive || dnsIface == "" || len(dnsServers) == 0 {
		return
	}
	if err := loadDNSSubAnchor(dnsIface, dnsServers); err != nil {
		slog.Warn("re-loading DNS sub-anchor failed", "error", err)
	}
}

// loadDNSSubAnchor builds the DNS-protection rule set for a given
// interface + server list and loads it into the sub-anchor. Pulled
// out of EnableDNSProtection so EnableKillSwitch can re-apply rules
// after rewriting the main anchor.
func loadDNSSubAnchor(interfaceName string, dnsServers []string) error {
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
	return loadAnchorRules(dnsAnchorName, dnsRules.String())
}

// AddKillSwitchTunnel folds a newly-connected tunnel's per-iface permit
// + endpoint permits into the kill-switch anchor. On darwin we only
// track one tunnel at a time in the anchor — the most-recently-added
// one wins. Multi-tunnel kill-switch on darwin is not supported.
//
// No-op when the kill switch isn't enabled (handleConnect should gate
// on IsKillSwitchEnabled before calling, but be defensive).
func (f *DarwinFirewall) AddKillSwitchTunnel(interfaceName string, endpoints []string) error {
	if interfaceName == "" {
		return fmt.Errorf("AddKillSwitchTunnel: empty interface name")
	}
	if !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}

	f.mu.Lock()
	if !f.killSwitchEnabled {
		f.mu.Unlock()
		return nil
	}
	f.mu.Unlock()

	rules, err := buildKillSwitchRules(interfaceName, endpoints)
	if err != nil {
		return err
	}
	if err := loadAnchorRules(anchorName, rules); err != nil {
		return fmt.Errorf("loading kill switch rules into anchor: %w", err)
	}
	f.reapplyDNSSubAnchorIfActive()

	f.mu.Lock()
	f.savedTunnelIface = interfaceName
	f.savedTunnelEndpoints = append([]string(nil), endpoints...)
	f.mu.Unlock()
	slog.Info("kill switch tunnel added", "interface", interfaceName, "endpoints", len(endpoints))
	return nil
}

// RemoveKillSwitchTunnel rebuilds the anchor without the disconnected
// tunnel's permits. Since darwin only stores one tunnel at a time, the
// rebuild drops to base-only (loopback + DHCP + DNS sub-anchor +
// catch-all block).
func (f *DarwinFirewall) RemoveKillSwitchTunnel(interfaceName string) error {
	f.mu.Lock()
	if !f.killSwitchEnabled {
		f.mu.Unlock()
		return nil
	}
	saved := f.savedTunnelIface
	f.mu.Unlock()

	// If the disconnected tunnel isn't the one we have permits for,
	// leave the anchor alone — another tunnel is still active.
	if saved != "" && saved != interfaceName {
		return nil
	}

	rules, err := buildKillSwitchRules("", nil)
	if err != nil {
		return err
	}
	if err := loadAnchorRules(anchorName, rules); err != nil {
		return fmt.Errorf("rebuilding kill switch anchor: %w", err)
	}
	f.reapplyDNSSubAnchorIfActive()

	f.mu.Lock()
	f.savedTunnelIface = ""
	f.savedTunnelEndpoints = nil
	f.mu.Unlock()
	slog.Info("kill switch tunnel removed", "interface", interfaceName)
	return nil
}

func (f *DarwinFirewall) DisableKillSwitch() error {
	f.mu.Lock()
	pfWas := f.pfWasEnabled
	dnsActive := f.dnsProtectionEnabled
	dnsIface := f.savedDNSInterface
	dnsServers := append([]string(nil), f.savedDNSServers...)
	f.mu.Unlock()

	// Flush the anchor rules — main ruleset is untouched.
	// flushAllAnchors wipes BOTH com.apple.wireguide (main) and
	// com.apple.wireguide/dns (sub). If DNS protection was active, those
	// rules just vanished — re-load them into the MAIN anchor (mirrors
	// EnableDNSProtection's no-kill-switch branch) so users who toggle
	// kill switch off don't get a silent DNS leak.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("failed to flush anchor rules", "error", err)
	}

	dnsReapplied := false
	if dnsActive && dnsIface != "" && len(dnsServers) > 0 {
		var dnsRules strings.Builder
		valid := true
		for _, dns := range dnsServers {
			if net.ParseIP(dns) == nil {
				valid = false
				break
			}
			fmt.Fprintf(&dnsRules, "pass out quick on %s proto {tcp, udp} to %s port 53\n", dnsIface, dns)
		}
		dnsRules.WriteString("block drop out quick proto {tcp, udp} to any port 53\n")
		if valid {
			if err := loadAnchorRules(anchorName, dnsRules.String()); err != nil {
				slog.Warn("re-loading DNS rules after kill switch disable failed",
					"error", err)
			} else {
				dnsReapplied = true
				slog.Info("DNS protection rules re-loaded after kill switch disable")
			}
		}
	}

	// If pf was not enabled before we started AND we did not re-load any
	// rules above, disable it now. If DNS was re-applied, leave pf on.
	if !pfWas && !dnsReapplied {
		if err := disablePf(); err != nil {
			slog.Warn("pfctl -d failed", "error", err)
		}
	}

	// Clean up persisted state file only when no further protection is active.
	if !dnsReapplied {
		removePfStateFile()
	}

	f.mu.Lock()
	f.killSwitchEnabled = false
	f.savedTunnelIface = ""
	f.savedTunnelEndpoints = nil
	f.mu.Unlock()
	slog.Info("kill switch disabled", "dns_reapplied", dnsReapplied)
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

		if err := loadDefaultPfRuleset(); err != nil {
			slog.Warn("loading /etc/pf.conf failed; anchor may not be evaluated", "error", err)
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
	f.savedDNSInterface = interfaceName
	f.savedDNSServers = append([]string(nil), dnsServers...)
	f.mu.Unlock()
	slog.Info("DNS protection enabled", "interface", interfaceName, "dns_servers", dnsServers)
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
		if out, err := runPfctl("-a", dnsAnchorName, "-F", "rules"); err != nil {
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
	f.savedDNSInterface = ""
	f.savedDNSServers = nil
	f.mu.Unlock()
	slog.Info("DNS protection disabled")
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
	// Snapshot what was active under the lock, but do NOT zero the cached
	// DNS interface/servers yet — if flushAllAnchors fails, a follow-up
	// resumeFirewall would need that info to re-apply DNS protection.
	// Clearing happens at the end only when the pf flush actually succeeded.
	f.mu.Lock()
	dnsActive := f.dnsProtectionEnabled
	ksActive := f.killSwitchEnabled
	pfWas := f.pfWasEnabled
	f.mu.Unlock()

	// Flush all anchor rules regardless of what was active.
	flushErr := flushAllAnchors()
	if flushErr != nil {
		slog.Warn("cleanup: flush pf anchors failed", "error", flushErr)
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

	// Clear in-memory state only after the flush. If flush failed, leave
	// savedDNS* intact so the next operation can still see what we tried
	// to manage — and surface the flush error so callers know cleanup was
	// only partial.
	f.mu.Lock()
	if flushErr == nil {
		f.savedDNSInterface = ""
		f.savedDNSServers = nil
	}
	f.dnsProtectionEnabled = false
	f.killSwitchEnabled = false
	f.savedTunnelIface = ""
	f.savedTunnelEndpoints = nil
	f.pfWasEnabled = false
	f.mu.Unlock()

	if flushErr != nil {
		return fmt.Errorf("firewall cleanup: %w", flushErr)
	}
	return nil
}

// --- pf helper functions ---

// loadAnchorRules loads rules into the specified pf anchor.
func loadAnchorRules(anchor, rules string) error {
	ctx, cancel := context.WithTimeout(context.Background(), pfCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -a %s -f -: %w (%s)", anchor, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isPfEnabled checks whether pf is currently enabled by parsing `pfctl -si`.
func isPfEnabled() bool {
	out, err := runPfctl("-si")
	if err != nil {
		return false
	}
	// Look for "Status: Enabled" in the output
	return strings.Contains(string(out), "Status: Enabled")
}

// loadDefaultPfRuleset re-loads /etc/pf.conf into pf's main ruleset.
// macOS' default pf.conf contains `anchor "com.apple/*" all`, which is
// the *only* reason our `com.apple.wireguide` anchor rules get evaluated
// at all. On a machine where pf has never been enabled (or where
// `pfctl -F all` wiped the main ruleset), pf runs with an empty main
// ruleset and our anchor is loaded but never visited — so traffic flows
// freely even though we think the kill switch is on. Re-loading the
// default ruleset is idempotent and cheap, so we do it on every enable
// path as a defense.
//
// Failures are non-fatal — older macOS releases or unusual /etc/pf.conf
// edits could fail to parse; we surface the error so callers can
// downgrade to a warning rather than abort the kill-switch install.
func loadDefaultPfRuleset() error {
	out, err := runPfctl("-f", "/etc/pf.conf")
	if err != nil {
		return fmt.Errorf("pfctl -f /etc/pf.conf: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// enablePf enables the pf firewall.
func enablePf() error {
	out, err := runPfctl("-e")
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
	out, err := runPfctl("-d")
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

// RecoverFromCrash satisfies the FirewallManager interface. Delegates to the
// package-level RecoverSavedRules so the helper init path can call it without
// importing darwin-specific symbols.
func (f *DarwinFirewall) RecoverFromCrash() bool {
	return RecoverSavedRules()
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
	if out, err := runPfctl("-a", dnsAnchorName, "-F", "rules"); err != nil {
		errs = append(errs, fmt.Sprintf("flush %s: %v (%s)", dnsAnchorName, err, strings.TrimSpace(string(out))))
	}
	// Flush the main anchor (this also covers any rules loaded directly).
	if out, err := runPfctl("-a", anchorName, "-Fa"); err != nil {
		errs = append(errs, fmt.Sprintf("flush %s: %v (%s)", anchorName, err, strings.TrimSpace(string(out))))
	}

	if len(errs) > 0 {
		return fmt.Errorf("flushAllAnchors: %s", strings.Join(errs, "; "))
	}
	return nil
}
