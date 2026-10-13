//go:build darwin

package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// pfCmdTimeout bounds every pfctl invocation. macOS pf can stall briefly
// when ruleset locks contend; this ceiling prevents helper hangs.
const pfCmdTimeout = 15 * time.Second

var runPfctl = func(args ...string) ([]byte, error) {
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
var savedPfStateFile = "/Library/Application Support/wireguide/pf-was-enabled"

// DarwinFirewall implements FirewallManager using macOS pf (packet filter).
//
// All WireGuide rules are loaded into the `com.apple/wireguide` anchor.
// macOS ships with `anchor "com.apple/*" all` in pf.conf, so any anchor
// under the com.apple/ path is automatically evaluated. DNS protection
// rules live in a sub-anchor `com.apple/wireguide/dns`.
type DarwinFirewall struct {
	// opMu serializes the mutating operations end to end. Each one reads
	// state under mu, shells out to pfctl without it, then writes state
	// back; two interleaved (e.g. a DNS re-apply loading the main anchor
	// while the kill switch is being enabled) overwrote each other's rules
	// and pf snapshot (issue #48). Linux and Windows hold their mu for the
	// whole operation. Lock order: opMu before mu.
	opMu                 sync.Mutex
	mu                   sync.Mutex
	killSwitchEnabled    bool
	dnsProtectionEnabled bool
	// pfWasEnabled tracks whether pf was already enabled before we started,
	// so we know whether to turn pf back off on disable/cleanup.
	pfWasEnabled bool
	// savedDNSAllow caches the most recent (normalized) EnableDNSProtection
	// set so EnableKillSwitch can re-load the DNS sub-anchor after
	// rewriting the main anchor — without this, enabling KS *after* DNS
	// protection silently wipes the DNS rules and DNS leaks despite
	// dnsProtectionEnabled==true.
	savedDNSAllow []DNSAllow
	// killSwitchTunnels is the complete interface -> endpoint permit model.
	// PF anchor loads replace the prior ruleset, so every add/remove must
	// render all survivors rather than only the most recently added utun.
	killSwitchTunnels map[string][]string
}

func NewPlatformFirewall() FirewallManager {
	return &DarwinFirewall{killSwitchTunnels: make(map[string][]string)}
}

// buildKillSwitchRules renders the pf rule text loaded into the
// `com.apple.wireguide` main anchor. interfaceName may be "" — when so,
// no per-iface permit ("pass quick on utunX all") is emitted, leaving
// only the base set (loopback + DHCP + endpoint permits if any) + the
// DNS sub-anchor directive + catch-all block. That's the layout used
// when the user toggles the kill switch on without an active tunnel.
func buildKillSwitchRules(interfaceName string, endpoints []string) (string, error) {
	tunnels := make(map[string][]string)
	if interfaceName != "" {
		tunnels[interfaceName] = endpoints
	}
	return buildKillSwitchRulesForTunnels(tunnels)
}

func buildKillSwitchRulesForTunnels(tunnels map[string][]string) (string, error) {
	var rules strings.Builder
	rules.WriteString("# WireGuide kill switch rules\n")
	rules.WriteString("# Allow loopback\n")
	rules.WriteString("pass quick on lo0 all\n")

	interfaces := make([]string, 0, len(tunnels))
	for interfaceName := range tunnels {
		if !validIfaceName.MatchString(interfaceName) {
			return "", fmt.Errorf("invalid interface name %q", interfaceName)
		}
		interfaces = append(interfaces, interfaceName)
	}
	sort.Strings(interfaces)
	seenEndpoints := make(map[string]struct{})
	for _, interfaceName := range interfaces {
		for _, ep := range tunnels[interfaceName] {
			if _, seen := seenEndpoints[ep]; seen {
				continue
			}
			seenEndpoints[ep] = struct{}{}
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
	}

	rules.WriteString("pass out quick proto udp from any port 68 to any port 67\n")
	rules.WriteString("pass out quick proto udp from any port 546 to any port 547\n")

	for _, interfaceName := range interfaces {
		fmt.Fprintf(&rules, "pass quick on %s all\n", interfaceName)
	}

	fmt.Fprintf(&rules, "anchor \"%s\"\n", dnsSubAnchorRel)
	rules.WriteString("block drop out all\n")
	rules.WriteString("block drop in all\n")
	return rules.String(), nil
}

func (f *DarwinFirewall) EnableKillSwitch(interfaceName string, _ []string, endpoints []string) error {
	f.opMu.Lock()
	defer f.opMu.Unlock()

	// Empty interfaceName is a valid input — the user toggled the kill
	// switch on without an active tunnel. We install the base block-all
	// set only; once a tunnel connects, AddKillSwitchTunnel folds its
	// per-iface permit + endpoint permits in.
	if interfaceName != "" && !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}

	// Snapshot pf state so we can restore enabled/disabled on teardown —
	// but only when none of our rules is up yet. Otherwise pf is on
	// because WE turned it on (DNS protection, or an earlier enable: the
	// GUI re-sends the kill switch after every connect), and re-taking the
	// snapshot would record that as the user's state and leave pf enabled
	// after everything is turned off (issue #48).
	f.mu.Lock()
	ownPf := f.killSwitchEnabled || f.dnsProtectionEnabled
	pfWas := f.pfWasEnabled
	f.mu.Unlock()
	if !ownPf {
		pfWas = isPfEnabled()
	}
	// Always (re-)write the crash-recovery file; with ownPf it may have
	// been removed by a failed reload while our rules stayed loaded.
	if err := persistPfEnabledState(pfWas); err != nil {
		slog.Warn("failed to persist pf enabled state to disk", "error", err)
	}

	// Ensure the default pf ruleset is loaded so our anchor is
	// actually evaluated — see loadDefaultPfRuleset's docstring.
	if err := loadDefaultPfRuleset(); err != nil {
		return fmt.Errorf("preparing pf anchor: %w", err)
	}

	tunnels := make(map[string][]string)
	if interfaceName != "" {
		tunnels[interfaceName] = append([]string(nil), endpoints...)
	}
	rules, err := buildKillSwitchRulesForTunnels(tunnels)
	if err != nil {
		if !ownPf {
			removePfStateFile() // nothing of ours is loaded
		}
		return err
	}

	if err := f.reapplyDNSSubAnchorIfActive(); err != nil {
		return err
	}
	if err := loadAnchorRules(anchorName, rules); err != nil {
		if !ownPf {
			// A first enable that loaded nothing must not leave the
			// crash-recovery file behind: the next start would "recover"
			// by flushing anchors and turning off a pf the user enabled.
			removePfStateFile()
		}
		return fmt.Errorf("loading kill switch rules into anchor: %w", err)
	}

	// Enable pf if not already.
	if err := f.activatePfWithRollback(); err != nil {
		return fmt.Errorf("enable pf: %w", err)
	}

	f.mu.Lock()
	f.pfWasEnabled = pfWas
	f.killSwitchEnabled = true
	f.killSwitchTunnels = tunnels
	f.mu.Unlock()
	slog.Info("kill switch enabled", "interface", interfaceName, "endpoints", len(endpoints))
	return nil
}

// A main-anchor load can succeed before PF activation/persistence fails.
// Restore the last committed model so an error never leaves new, untracked
// rules active under another owner's PF reference. Caller holds opMu.
func (f *DarwinFirewall) activatePfWithRollback() error {
	activationErr := enablePf()
	if activationErr == nil {
		return nil
	}
	f.mu.Lock()
	ks := f.killSwitchEnabled
	dns := f.dnsProtectionEnabled
	tunnels := cloneTunnelEndpoints(f.killSwitchTunnels)
	allow := append([]DNSAllow(nil), f.savedDNSAllow...)
	f.mu.Unlock()
	var rules string
	if ks {
		var err error
		rules, err = buildKillSwitchRulesForTunnels(tunnels)
		if err != nil {
			return errors.Join(activationErr, fmt.Errorf("PF rollback model: %w", err))
		}
	} else if dns {
		rules = pfDNSRules(allow)
	}
	if err := loadAnchorRules(anchorName, rules); err != nil {
		return errors.Join(activationErr, fmt.Errorf("PF main-anchor rollback: %w", err))
	}
	if !ks && !dns {
		removePfStateFile()
	}
	return activationErr
}

// reapplyDNSSubAnchorIfActive re-loads the DNS sub-anchor under
// `com.apple.wireguide/dns` if DNS protection is currently active. The
// kill-switch main anchor only references the sub-anchor by name; the
// sub-anchor body lives independently in pf storage. We re-apply
// defensively after every main-anchor rewrite to keep the two in sync.
func (f *DarwinFirewall) reapplyDNSSubAnchorIfActive() error {
	f.mu.Lock()
	dnsActive := f.dnsProtectionEnabled
	allow := f.savedDNSAllow
	f.mu.Unlock()
	if !dnsActive || len(allow) == 0 {
		return nil
	}
	if err := loadAnchorRules(dnsAnchorName, pfDNSRules(allow)); err != nil {
		return fmt.Errorf("re-loading DNS sub-anchor: %w", err)
	}
	return nil
}

// AddKillSwitchTunnel folds a newly-connected tunnel's per-iface permit and
// endpoint permits into the complete kill-switch anchor.
//
// No-op when the kill switch isn't enabled (handleConnect should gate
// on IsKillSwitchEnabled before calling, but be defensive).
func (f *DarwinFirewall) AddKillSwitchTunnel(interfaceName string, _ []string, endpoints []string) error {
	f.opMu.Lock()
	defer f.opMu.Unlock()

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
	tunnels := cloneTunnelEndpoints(f.killSwitchTunnels)
	tunnels[interfaceName] = append([]string(nil), endpoints...)
	f.mu.Unlock()

	rules, err := buildKillSwitchRulesForTunnels(tunnels)
	if err != nil {
		return err
	}
	if err := f.reapplyDNSSubAnchorIfActive(); err != nil {
		return err
	}
	if err := loadAnchorRules(anchorName, rules); err != nil {
		return fmt.Errorf("loading kill switch rules into anchor: %w", err)
	}

	f.mu.Lock()
	f.killSwitchTunnels = tunnels
	f.mu.Unlock()
	slog.Info("kill switch tunnel added", "interface", interfaceName, "endpoints", len(endpoints))
	return nil
}

// RemoveKillSwitchTunnel rebuilds the anchor without the disconnected
// tunnel's permits while preserving every other active utun.
func (f *DarwinFirewall) RemoveKillSwitchTunnel(interfaceName string) error {
	f.opMu.Lock()
	defer f.opMu.Unlock()

	f.mu.Lock()
	if !f.killSwitchEnabled {
		f.mu.Unlock()
		return nil
	}
	tunnels := cloneTunnelEndpoints(f.killSwitchTunnels)
	delete(tunnels, interfaceName)
	f.mu.Unlock()

	rules, err := buildKillSwitchRulesForTunnels(tunnels)
	if err != nil {
		return err
	}
	if err := f.reapplyDNSSubAnchorIfActive(); err != nil {
		return err
	}
	if err := loadAnchorRules(anchorName, rules); err != nil {
		return fmt.Errorf("rebuilding kill switch anchor: %w", err)
	}

	f.mu.Lock()
	f.killSwitchTunnels = tunnels
	f.mu.Unlock()
	slog.Info("kill switch tunnel removed", "interface", interfaceName)
	return nil
}

func cloneTunnelEndpoints(src map[string][]string) map[string][]string {
	dst := make(map[string][]string, len(src))
	for interfaceName, endpoints := range src {
		dst[interfaceName] = append([]string(nil), endpoints...)
	}
	return dst
}

// EnableEndpointProtection is a no-op on macOS — but NOT because the
// loop class is impossible here. wireguard-go's Darwin bind does NOT
// set IP_BOUND_IF on its UDP socket (the previous comment was wrong);
// conn/mark_default.go is a no-op SetMark for non-Linux/BSD targets
// and bind_std.go doesn't bind by interface on macOS. The /32 bypass
// host routes installed by DarwinManager.addBypassForIP are the only
// safety net against the encrypted-UDP-loops-through-utun bug class.
//
// The reason this hook is still a no-op on macOS is that pf (Packet
// Filter) doesn't expose a layer with the per-packet-classify +
// local-interface-LUID match equivalent to WFP's OUTBOUND_TRANSPORT.
// A pf "block out on utun proto udp to <endpoint>" rule would also
// catch the legitimate-but-mis-routed case during a network change,
// which is more dangerous than the current "bypass route ordering +
// fail-fast on missing gateway" approach in DarwinManager.AddRoutes.
//
// If/when we add a Darwin-side runaway-TX watchdog (mirror of
// loop_watchdog_windows.go via SIOCGIFDATA), that's where the residual
// safety net goes — not here.
func (f *DarwinFirewall) EnableEndpointProtection(string, []string) error { return nil }

// DisableEndpointProtection mirrors the macOS no-op.
func (f *DarwinFirewall) DisableEndpointProtection(string) error { return nil }

func (f *DarwinFirewall) DisableKillSwitch() error {
	f.opMu.Lock()
	defer f.opMu.Unlock()
	f.mu.Lock()
	dnsActive := f.dnsProtectionEnabled
	dnsAllow := append([]DNSAllow(nil), f.savedDNSAllow...)
	f.mu.Unlock()
	if dnsActive && len(dnsAllow) > 0 {
		// Replace the main anchor atomically. Flushing it first would remove
		// both protections if the subsequent DNS reload failed.
		if err := loadAnchorRules(anchorName, pfDNSRules(dnsAllow)); err != nil {
			return fmt.Errorf("retaining DNS while disabling kill switch: %w", err)
		}
		// The old sub-anchor is now unreferenced. Its cleanup is harmless to
		// defer if PF is busy; the effective main-anchor policy is already live.
		if out, err := runPfctl("-a", dnsAnchorName, "-F", "rules"); err != nil {
			slog.Warn("inactive DNS sub-anchor cleanup failed", "error", err, "output", strings.TrimSpace(string(out)))
		}
	} else {
		if err := flushAllAnchors(); err != nil {
			return err
		}
		if err := disablePf(); err != nil {
			return err
		}
		removePfStateFile()
	}
	f.mu.Lock()
	f.killSwitchEnabled = false
	f.killSwitchTunnels = make(map[string][]string)
	f.mu.Unlock()
	return nil
}

func (f *DarwinFirewall) EnableDNSProtection(allow []DNSAllow) error {
	f.opMu.Lock()
	defer f.opMu.Unlock()

	allow = normalizeDNSAllow(allow, validIfaceName.MatchString)
	if len(allow) == 0 {
		return f.disableDNSProtection()
	}
	rules := pfDNSRules(allow)

	f.mu.Lock()
	ksEnabled := f.killSwitchEnabled
	alreadyOn := f.dnsProtectionEnabled
	f.mu.Unlock()

	if ksEnabled {
		// Kill switch is active — its anchor rules already contain
		// `anchor "com.apple.wireguide/dns"`, so loading into the
		// sub-anchor works directly.
		if err := loadAnchorRules(dnsAnchorName, rules); err != nil {
			return fmt.Errorf("loading DNS anchor rules: %w", err)
		}
	} else {
		// No kill switch — load DNS rules into the main anchor.
		// macOS evaluates the anchor via the com.apple/* wildcard.
		if alreadyOn {
			// A re-apply (tunnel set changed): swap the rules, keep the pf
			// snapshot. Taking it again would record OUR pf-enabled state
			// as the user's, and disable would then leave pf on forever.
			// pf is still (re-)enabled: a failed reload in DisableKillSwitch
			// turns it off while DNS protection stays on.
			// Re-write the crash-recovery file from the kept snapshot: a
			// failed reload in DisableKillSwitch removes it while our rules
			// stay, and without it crash recovery wouldn't flush them.
			f.mu.Lock()
			pfWas := f.pfWasEnabled
			f.mu.Unlock()
			if err := persistPfEnabledState(pfWas); err != nil {
				slog.Warn("failed to persist pf enabled state to disk", "error", err)
			}
			if err := loadAnchorRules(anchorName, rules); err != nil {
				return fmt.Errorf("loading DNS rules into anchor: %w", err)
			}
			if err := f.activatePfWithRollback(); err != nil {
				return err
			}
		} else {
			pfWas := isPfEnabled()
			if err := persistPfEnabledState(pfWas); err != nil {
				slog.Warn("failed to persist pf enabled state to disk", "error", err)
			}

			if err := loadDefaultPfRuleset(); err != nil {
				return fmt.Errorf("preparing pf anchor: %w", err)
			}

			if err := loadAnchorRules(anchorName, rules); err != nil {
				removePfStateFile() // first enable loaded nothing; see EnableKillSwitch
				return fmt.Errorf("loading DNS rules into anchor: %w", err)
			}

			if err := f.activatePfWithRollback(); err != nil {
				return err
			}

			f.mu.Lock()
			f.pfWasEnabled = pfWas
			f.mu.Unlock()
		}
	}

	f.mu.Lock()
	f.dnsProtectionEnabled = true
	f.savedDNSAllow = allow
	f.mu.Unlock()
	slog.Info("DNS protection enabled", "allow", allow)
	return nil
}

func (f *DarwinFirewall) DisableDNSProtection() error {
	f.opMu.Lock()
	defer f.opMu.Unlock()
	return f.disableDNSProtection()
}

// disableDNSProtection is DisableDNSProtection's body. Caller MUST hold opMu.
func (f *DarwinFirewall) disableDNSProtection() error {
	// Snapshot state under lock.
	f.mu.Lock()
	ksEnabled := f.killSwitchEnabled
	dnsOn := f.dnsProtectionEnabled
	f.mu.Unlock()

	if !dnsOn {
		// Nothing of ours to remove. Without this, the no-kill-switch branch
		// below ran `pfctl -d` on a pf the user had enabled themselves
		// (pfWasEnabled is false when we never took the snapshot).
		return nil
	}

	if ksEnabled {
		// Kill switch is active — DNS rules are in the sub-anchor, just flush it.
		if out, err := runPfctl("-a", dnsAnchorName, "-F", "rules"); err != nil {
			return fmt.Errorf("flush DNS anchor: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	} else {
		// DNS rules were loaded into the main anchor.  Flush the anchor.
		if err := flushAllAnchors(); err != nil {
			return err
		}

		if err := disablePf(); err != nil {
			return err
		}
		removePfStateFile()
	}

	f.mu.Lock()
	f.dnsProtectionEnabled = false
	f.savedDNSAllow = nil
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
	f.opMu.Lock()
	defer f.opMu.Unlock()

	// Snapshot what was active under the lock, but do NOT zero the cached
	// DNS interface/servers yet — if flushAllAnchors fails, a follow-up
	// resumeFirewall would need that info to re-apply DNS protection.
	// Clearing happens at the end only when the pf flush actually succeeded.
	// Flush all anchor rules regardless of what was active.
	flushErr := flushAllAnchors()
	if flushErr != nil {
		return fmt.Errorf("firewall cleanup: %w", flushErr)
	}

	// Restore pf enabled/disabled state if we had anything active.
	if err := disablePf(); err != nil {
		return err
	}
	removePfStateFile()

	// Clear in-memory state only after the flush. If flush failed, leave
	// savedDNS* intact so the next operation can still see what we tried
	// to manage — and surface the flush error so callers know cleanup was
	// only partial.
	f.mu.Lock()
	if flushErr == nil {
		f.savedDNSAllow = nil
	}
	f.dnsProtectionEnabled = false
	f.killSwitchEnabled = false
	f.killSwitchTunnels = make(map[string][]string)
	f.pfWasEnabled = false
	f.mu.Unlock()

	if flushErr != nil {
		return fmt.Errorf("firewall cleanup: %w", flushErr)
	}
	return nil
}

// --- pf helper functions ---

// loadAnchorRules loads rules into the specified pf anchor.
var loadAnchorRules = func(anchor, rules string) error {
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
	current, err := runPfctl("-sr")
	if err != nil {
		return fmt.Errorf("reading pf main ruleset: %w", err)
	}
	if strings.Contains(string(current), `anchor "com.apple/*"`) {
		return nil
	}
	out, err := runPfctl("-f", "/etc/pf.conf")
	if err != nil {
		return fmt.Errorf("pfctl -f /etc/pf.conf: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// enablePf enables the pf firewall.
// persistPfEnabledState writes whether pf was enabled to disk for crash
// recovery.  The file contains "1" if enabled, "0" if disabled.
func persistPfEnabledState(enabled bool) error {
	pfLease.Lock()
	defer pfLease.Unlock()
	pfLease.state.WasEnabled = enabled
	return writePfLease(pfLease.state)
}

// removePfStateFile removes the persisted pf state file.
func removePfStateFile() {
	pfLease.Lock()
	defer pfLease.Unlock()
	if pfLease.state.Token != "" {
		return
	} // a failed release must remain recoverable
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

// RecoverSavedRules flushes both owned anchors on every helper start, even
// when a crash lost the recovery journal. Only a recorded same-boot token
// authorizes releasing a PF reference; missing metadata never authorizes
// globally disabling PF. Call before installing any new tunnel rules.
func RecoverSavedRules() bool {
	_, statErr := os.Stat(savedPfStateFile)
	if statErr != nil && !os.IsNotExist(statErr) {
		slog.Warn("recovery: cannot inspect pf lease journal", "error", statErr)
		return false
	}
	hasJournal := statErr == nil
	slog.Info("cleaning stale WireGuide pf anchors", "recovery_journal", hasJournal)

	// Flush all anchor rules.
	if err := flushAllAnchors(); err != nil {
		slog.Warn("recovery: failed to flush anchors", "error", err)
		return false
	}

	// Restore pf enabled/disabled state.
	if hasJournal {
		if err := disablePf(); err != nil {
			slog.Warn("recovery: failed to release pf reference", "error", err)
			return false
		}
		removePfStateFile()
	}
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
