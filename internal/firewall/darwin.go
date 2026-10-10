//go:build darwin

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// pfCmdTimeout bounds every pfctl invocation. macOS pf can stall briefly
// when ruleset locks contend; this ceiling prevents helper hangs.
const pfCmdTimeout = 15 * time.Second

// pfctlExec is the single exec seam for every pfctl invocation (including
// rule loads via `-f -`, which pass the rules as stdin). It is a package var
// so tests can record calls without touching the real packet filter.
var pfctlExec = func(stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pfctl", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// pfctlQuery runs a read-only pfctl query and returns STDOUT only. pfctl
// writes notices such as "No ALTQ support in kernel" and "DIOCGETRULES:
// Invalid argument" to stderr while still exiting 0, so combined output must
// never be used to decide whether rules exist.
var pfctlQuery = func(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pfCmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "pfctl", args...).Output()
}

// stateDir holds WireGuide's persisted pf state (the pf reference token).
var stateDir = "/Library/Application Support/wireguide"

// bootID returns kern.bootsessionuuid, which is constant for the whole boot
// (unlike kern.boottime, which the kernel shifts when the clock is stepped).
// A pf token is only meaningful within the boot that issued it.
var bootID = func() (string, error) {
	return unix.Sysctl("kern.bootsessionuuid")
}

const (
	// pfTokenFile persists the pf enable-reference token so a restarted
	// helper can release the reference its predecessor took.
	pfTokenFile = "pf-token"
	// legacyPfStateFile is the pre-token "was pf enabled" marker. It is only
	// ever deleted now; WireGuide never runs `pfctl -d`.
	legacyPfStateFile = "pf-was-enabled"
)

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

// pfMainRulesetMarker is what `pfctl -sr` must contain for our anchors to be
// evaluated at all (macOS pf.conf ships `anchor "com.apple/*" all`).
const pfMainRulesetMarker = `anchor "com.apple/*"`

// DarwinFirewall implements FirewallManager using macOS pf (packet filter).
//
// State is ONE model — kill switch on/off, its per-tunnel permits, and the
// DNS permit set — rendered by ONE renderer into two anchors:
//
//	com.apple/wireguide      kill-switch rules, or just `anchor "dns"`
//	com.apple/wireguide/dns  DNS protection rules
//
// Every mutation updates the model and calls applyLocked, so no code path can
// resurrect rules the model no longer contains. pf itself is enabled with
// reference counting (`pfctl -E` / `-X <token>`); WireGuide never runs
// `pfctl -e` or `-d`, which would disable pf under other holders.
type DarwinFirewall struct {
	mu                sync.Mutex
	killSwitchEnabled bool
	// killSwitchTunnels is the complete interface -> endpoint permit model.
	// PF anchor loads replace the prior ruleset, so every add/remove must
	// render all survivors rather than only the most recently added utun.
	killSwitchTunnels map[string][]string
	dnsPermits        []DNSPermit

	tokenHeld bool
	token     uint64

	// appliedMain / appliedDNS are the anchor bodies last loaded successfully
	// ("" = flushed). A failed apply rolls pf back to them so the two anchors
	// never end up out of step.
	appliedMain string
	appliedDNS  string
}

func NewPlatformFirewall() FirewallManager {
	return &DarwinFirewall{killSwitchTunnels: make(map[string][]string)}
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

// sanitizePermits validates and normalizes a permit set, warning about (and
// skipping) invalid entries instead of failing the whole set.
func sanitizePermits(in []DNSPermit) []DNSPermit {
	valid := make([]DNSPermit, 0, len(in))
	for _, p := range in {
		if p.Interface != "" && !validIfaceName.MatchString(p.Interface) {
			slog.Warn("skipping DNS permit with invalid interface", "interface", p.Interface, "server", p.Server)
			continue
		}
		if net.ParseIP(p.Server) == nil {
			slog.Warn("skipping DNS permit with invalid server", "interface", p.Interface, "server", p.Server)
			continue
		}
		valid = append(valid, p)
	}
	return normalizePermits(valid, false)
}

// normalizePermits is the silent half of sanitizePermits: it drops invalid
// entries, optionally drops unpinned ones (kill-switch mode never punches
// holes), canonicalises addresses, dedupes and sorts.
func normalizePermits(in []DNSPermit, dropUnpinned bool) []DNSPermit {
	seen := make(map[DNSPermit]struct{}, len(in))
	out := make([]DNSPermit, 0, len(in))
	for _, p := range in {
		ip := net.ParseIP(p.Server)
		if ip == nil {
			continue
		}
		if p.Interface != "" && !validIfaceName.MatchString(p.Interface) {
			continue
		}
		if p.Interface == "" && dropUnpinned {
			continue
		}
		n := DNSPermit{Interface: p.Interface, Server: ip.String()}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].Server < out[j].Server
	})
	return out
}

// renderDNSAnchor renders the com.apple/wireguide/dns body, or "" when no
// permit survives (no rules at all, so the anchor is flushed instead).
func renderDNSAnchor(killSwitch bool, permits []DNSPermit) string {
	eff := normalizePermits(permits, killSwitch)
	if len(eff) == 0 {
		return ""
	}
	var b strings.Builder
	// Local resolvers (127.0.0.1:53, mDNSResponder stubs) must keep working.
	b.WriteString("pass out quick on lo0 proto {tcp, udp} to any port 53\n")
	for _, p := range eff {
		if p.Interface != "" {
			fmt.Fprintf(&b, "pass out quick on %s proto {tcp, udp} to %s port 53\n", p.Interface, p.Server)
		} else {
			fmt.Fprintf(&b, "pass out quick proto {tcp, udp} to %s port 53\n", p.Server)
		}
	}
	b.WriteString("block drop out quick proto {tcp, udp} to any port 53\n")
	return b.String()
}

// renderMainAnchor renders the com.apple/wireguide body: the full kill switch
// when enabled, just the DNS sub-anchor reference when only DNS protection is
// active, or "" (flush) otherwise.
func renderMainAnchor(killSwitch bool, tunnels map[string][]string, permits []DNSPermit) (string, error) {
	if killSwitch {
		return buildKillSwitchRulesForTunnels(tunnels)
	}
	if len(normalizePermits(permits, false)) > 0 {
		return fmt.Sprintf("anchor \"%s\"\n", dnsSubAnchorRel), nil
	}
	return "", nil
}

// applyLocked reconciles pf with the model. Caller holds f.mu.
//
// The two anchors are loaded in an order that keeps pf fail-closed (main first
// when the kill switch is on, DNS first otherwise). If the second load fails,
// the first anchor is rolled back to its last applied body so the pair stays
// consistent. Callers restore their model on error (see snapshot/restore).
func (f *DarwinFirewall) applyLocked() error {
	mainRules, err := renderMainAnchor(f.killSwitchEnabled, f.killSwitchTunnels, f.dnsPermits)
	if err != nil {
		return err
	}
	dnsRules := renderDNSAnchor(f.killSwitchEnabled, f.dnsPermits)

	if mainRules == "" && dnsRules == "" {
		if err := flushAllAnchors(); err != nil {
			return err
		}
		f.appliedMain, f.appliedDNS = "", ""
		// The rules are gone; a failed release must not make the caller roll
		// the model back to a state pf no longer has.
		if err := f.releasePfLocked(); err != nil {
			slog.Warn("releasing pf reference failed after flush", "error", err)
		}
		return nil
	}

	ensureMainRuleset()
	loadMain := func(body string) error {
		if body != "" {
			if err := loadAnchorRules(anchorName, body); err != nil {
				return fmt.Errorf("loading rules into anchor: %w", err)
			}
			return nil
		}
		return flushAnchor(anchorName, "all")
	}
	loadDNS := func(body string) error {
		if body != "" {
			if err := loadAnchorRules(dnsAnchorName, body); err != nil {
				return fmt.Errorf("loading DNS rules into anchor: %w", err)
			}
			return nil
		}
		return flushAnchor(dnsAnchorName, "rules")
	}

	first, second := loadDNS, loadMain
	firstBody, secondBody := dnsRules, mainRules
	rollbackFirst := func() { _ = loadDNS(f.appliedDNS) }
	if f.killSwitchEnabled {
		first, second = loadMain, loadDNS
		firstBody, secondBody = mainRules, dnsRules
		rollbackFirst = func() { _ = loadMain(f.appliedMain) }
	}
	if err := first(firstBody); err != nil {
		rollbackFirst()
		return err
	}
	if err := second(secondBody); err != nil {
		rollbackFirst()
		return err
	}
	f.appliedMain, f.appliedDNS = mainRules, dnsRules
	return f.acquirePfLocked()
}

// pfModel is a snapshot of the firewall model, used to undo a mutation whose
// apply failed so IsKillSwitchEnabled/IsDNSProtectionEnabled keep matching
// what is actually loaded in pf.
type pfModel struct {
	ks      bool
	tunnels map[string][]string
	permits []DNSPermit
}

func (f *DarwinFirewall) snapshotLocked() pfModel {
	return pfModel{
		ks:      f.killSwitchEnabled,
		tunnels: cloneTunnelEndpoints(f.killSwitchTunnels),
		permits: append([]DNSPermit(nil), f.dnsPermits...),
	}
}

func (f *DarwinFirewall) restoreLocked(m pfModel) {
	f.killSwitchEnabled = m.ks
	f.killSwitchTunnels = m.tunnels
	f.dnsPermits = m.permits
}

// mainRulesetEvaluatesAppleAnchors reports whether `pfctl -sr` output contains
// a FILTER anchor line for com.apple/*. scrub-/nat-/rdr-/dummynet-anchor lines
// also contain the marker as a substring but do not make pf evaluate filter
// rules inside our anchors, so the match is per line and prefix-anchored.
func mainRulesetEvaluatesAppleAnchors(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), pfMainRulesetMarker) {
			return true
		}
	}
	return false
}

// ensureMainRuleset re-loads /etc/pf.conf only when the active main ruleset
// does not evaluate com.apple/* anchors. Reloading unconditionally would
// clobber any ruleset another tool installed.
func ensureMainRuleset() {
	out, err := pfctlQuery("-sr")
	if err == nil && mainRulesetEvaluatesAppleAnchors(string(out)) {
		return
	}
	if out, err := pfctlExec("", "-f", "/etc/pf.conf"); err != nil {
		slog.Warn("loading /etc/pf.conf failed; anchor may not be evaluated",
			"error", err, "output", strings.TrimSpace(string(out)))
	}
}

// --- pf enable reference counting ---

type pfTokenState struct {
	Token  uint64 `json:"token"`
	BootID string `json:"boot_id"`
}

var pfTokenRe = regexp.MustCompile(`(?i)token\s*:\s*(\d+)`)

func tokenPath() string { return filepath.Join(stateDir, pfTokenFile) }

// acquirePfLocked takes one pf enable reference (`pfctl -E`) unless this
// process already holds one, and persists the token for crash recovery.
func (f *DarwinFirewall) acquirePfLocked() error {
	if f.tokenHeld {
		if pfRunning() {
			return nil
		}
		// An external `pfctl -d` stopped pf and invalidated every token, ours
		// included. Drop it and take a fresh reference below.
		slog.Warn("pf is not enabled although a token is held; re-enabling", "token", f.token)
		f.tokenHeld = false
		f.token = 0
	}
	out, err := pfctlExec("", "-E")
	if err != nil {
		return fmt.Errorf("pfctl -E: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	m := pfTokenRe.FindStringSubmatch(string(out))
	if m == nil {
		slog.Warn("pfctl -E returned no token; pf enable reference cannot be released later",
			"output", strings.TrimSpace(string(out)))
		return nil
	}
	tok, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		slog.Warn("pfctl -E returned unparseable token", "token", m[1])
		return nil
	}
	f.tokenHeld = true
	f.token = tok
	boot, berr := bootID()
	if berr != nil {
		slog.Warn("cannot read kern.bootsessionuuid; pf token will be treated as stale after restart", "error", berr)
		boot = ""
	}
	if err := writeTokenFile(pfTokenState{Token: tok, BootID: boot}); err != nil {
		slog.Warn("failed to persist pf token", "error", err)
	}
	return nil
}

// pfRunning reports whether pf is currently enabled (`pfctl -s info`).
func pfRunning() bool {
	out, err := pfctlQuery("-s", "info")
	return err == nil && strings.Contains(string(out), "Status: Enabled")
}

// pfTokenGone reports whether a failed `pfctl -X <token>` means the token can
// no longer be live: pf is stopped (DIOCSTOP invalidates every token) or the
// kernel rejected the token as unknown. Only a pfctl rejection counts; other
// failures (e.g. a timeout) leave the token in place for a later retry.
func pfTokenGone(out []byte) bool {
	s := string(out)
	if strings.Contains(s, "pf not enabled") || strings.Contains(s, "token invalid") {
		return true
	}
	return !pfRunning()
}

func writeTokenFile(st pfTokenState) error {
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", stateDir, err)
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(tokenPath(), data, 0600)
}

func removeStateFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// releasePfLocked drops this process's pf enable reference (`pfctl -X`) and
// removes the token file. If no reference is held in memory it falls back to
// the persisted token, which is released only when it was issued in the
// current boot (pf tokens do not survive a reboot). Files are deleted only
// when the corresponding operation succeeded or the token was stale.
func (f *DarwinFirewall) releasePfLocked() error {
	if f.tokenHeld {
		if out, err := pfctlExec("", "-X", strconv.FormatUint(f.token, 10)); err != nil {
			if !pfTokenGone(out) {
				return fmt.Errorf("pfctl -X: %w (%s)", err, strings.TrimSpace(string(out)))
			}
			slog.Warn("pf token already invalid; dropping it", "error", err, "output", strings.TrimSpace(string(out)))
		}
		f.tokenHeld = false
		f.token = 0
		if err := removeStateFile(tokenPath()); err != nil {
			slog.Warn("failed to remove pf token file", "error", err)
		}
		return nil
	}
	_, err := releasePersistedToken()
	return err
}

// releasePersistedToken releases a token left in the state file by a previous
// helper. Reports whether a token file existed.
func releasePersistedToken() (bool, error) {
	data, err := os.ReadFile(tokenPath())
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("reading pf token file: %w", err)
	}
	var st pfTokenState
	if jerr := json.Unmarshal(data, &st); jerr != nil || st.Token == 0 {
		slog.Warn("discarding unreadable pf token file", "error", jerr)
		return true, removeStateFile(tokenPath())
	}
	boot, berr := bootID()
	if berr != nil || st.BootID == "" || boot != st.BootID {
		slog.Info("discarding stale pf token from a previous boot", "token_boot", st.BootID, "boot", boot)
		return true, removeStateFile(tokenPath())
	}
	if out, err := pfctlExec("", "-X", strconv.FormatUint(st.Token, 10)); err != nil {
		if !pfTokenGone(out) {
			return true, fmt.Errorf("pfctl -X: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		slog.Warn("persisted pf token already invalid; dropping it", "error", err, "output", strings.TrimSpace(string(out)))
	}
	return true, removeStateFile(tokenPath())
}

// --- FirewallManager ---

func (f *DarwinFirewall) EnableKillSwitch(interfaceName string, _ []string, endpoints []string) error {
	// Empty interfaceName is a valid input — the user toggled the kill
	// switch on without an active tunnel. We install the base block-all
	// set only; once a tunnel connects, AddKillSwitchTunnel folds its
	// per-iface permit + endpoint permits in.
	if interfaceName != "" && !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}
	tunnels := make(map[string][]string)
	if interfaceName != "" {
		tunnels[interfaceName] = append([]string(nil), endpoints...)
	}
	// Validate before touching the model so a bad endpoint can't leave a
	// half-enabled state.
	if _, err := buildKillSwitchRulesForTunnels(tunnels); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	prev := f.snapshotLocked()
	f.killSwitchEnabled = true
	f.killSwitchTunnels = tunnels
	if err := f.applyLocked(); err != nil {
		f.restoreLocked(prev)
		return fmt.Errorf("enabling kill switch: %w", err)
	}
	slog.Info("kill switch enabled", "interface", interfaceName, "endpoints", len(endpoints))
	return nil
}

// AddKillSwitchTunnel folds a newly-connected tunnel's per-iface permit and
// endpoint permits into the complete kill-switch anchor.
//
// No-op when the kill switch isn't enabled (handleConnect should gate
// on IsKillSwitchEnabled before calling, but be defensive).
func (f *DarwinFirewall) AddKillSwitchTunnel(interfaceName string, _ []string, endpoints []string) error {
	if interfaceName == "" {
		return fmt.Errorf("AddKillSwitchTunnel: empty interface name")
	}
	if !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.killSwitchEnabled {
		return nil
	}
	tunnels := cloneTunnelEndpoints(f.killSwitchTunnels)
	tunnels[interfaceName] = append([]string(nil), endpoints...)
	if _, err := buildKillSwitchRulesForTunnels(tunnels); err != nil {
		return err
	}
	prev := f.snapshotLocked()
	f.killSwitchTunnels = tunnels
	if err := f.applyLocked(); err != nil {
		f.restoreLocked(prev)
		return fmt.Errorf("loading kill switch rules into anchor: %w", err)
	}
	slog.Info("kill switch tunnel added", "interface", interfaceName, "endpoints", len(endpoints))
	return nil
}

// RemoveKillSwitchTunnel rebuilds the anchor without the disconnected
// tunnel's permits while preserving every other active utun.
func (f *DarwinFirewall) RemoveKillSwitchTunnel(interfaceName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.killSwitchEnabled {
		return nil
	}
	tunnels := cloneTunnelEndpoints(f.killSwitchTunnels)
	delete(tunnels, interfaceName)
	prev := f.snapshotLocked()
	f.killSwitchTunnels = tunnels
	if err := f.applyLocked(); err != nil {
		f.restoreLocked(prev)
		return fmt.Errorf("rebuilding kill switch anchor: %w", err)
	}
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
	f.mu.Lock()
	defer f.mu.Unlock()
	prev := f.snapshotLocked()
	f.killSwitchEnabled = false
	f.killSwitchTunnels = make(map[string][]string)
	if err := f.applyLocked(); err != nil {
		f.restoreLocked(prev)
		return err
	}
	slog.Info("kill switch disabled", "dns_permits", len(f.dnsPermits))
	return nil
}

// SetDNSPermits replaces the whole DNS permit set. An empty set removes every
// DNS rule (and releases pf if nothing else needs it). Invalid entries are
// skipped with a warning rather than failing the set.
func (f *DarwinFirewall) SetDNSPermits(permits []DNSPermit) error {
	clean := sanitizePermits(permits)
	f.mu.Lock()
	defer f.mu.Unlock()
	prev := f.snapshotLocked()
	f.dnsPermits = clean
	if err := f.applyLocked(); err != nil {
		f.restoreLocked(prev)
		return fmt.Errorf("applying DNS permits: %w", err)
	}
	slog.Info("DNS permits applied", "count", len(clean))
	return nil
}

// EnableDNSProtection pins each IP entry of dnsServers to interfaceName.
// Non-IP entries (search domains) are ignored; a list without any IP is a
// no-op rather than an error.
func (f *DarwinFirewall) EnableDNSProtection(interfaceName string, dnsServers []string) error {
	var permits []DNSPermit
	for _, s := range dnsServers {
		s = strings.TrimSpace(s)
		if net.ParseIP(s) == nil {
			continue
		}
		permits = append(permits, DNSPermit{Interface: interfaceName, Server: s})
	}
	if len(permits) == 0 {
		return nil
	}
	if !validIfaceName.MatchString(interfaceName) {
		return fmt.Errorf("invalid interface name %q", interfaceName)
	}
	return f.SetDNSPermits(permits)
}

func (f *DarwinFirewall) DisableDNSProtection() error {
	return f.SetDNSPermits(nil)
}

func (f *DarwinFirewall) IsKillSwitchEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killSwitchEnabled
}

func (f *DarwinFirewall) IsDNSProtectionEnabled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dnsPermits) > 0
}

// Cleanup flushes both anchors and releases the pf reference. State files are
// removed only when the corresponding operation succeeded (or the token was
// stale); the in-memory model is always cleared.
func (f *DarwinFirewall) Cleanup() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	flushErr := flushAllAnchors()
	var relErr error
	if flushErr == nil {
		relErr = f.releasePfLocked()
	}
	f.killSwitchEnabled = false
	f.killSwitchTunnels = make(map[string][]string)
	f.dnsPermits = nil
	if err := errors.Join(flushErr, relErr); err != nil {
		return fmt.Errorf("firewall cleanup: %w", err)
	}
	return nil
}

// --- pf helper functions ---

// loadAnchorRules loads rules into the specified pf anchor.
func loadAnchorRules(anchor, rules string) error {
	out, err := pfctlExec(rules, "-a", anchor, "-f", "-")
	if err != nil {
		return fmt.Errorf("pfctl -a %s -f -: %w (%s)", anchor, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// flushAnchor flushes one anchor. what is the pfctl -F modifier.
func flushAnchor(anchor, what string) error {
	if out, err := pfctlExec("", "-a", anchor, "-F", what); err != nil {
		return fmt.Errorf("flush %s: %w (%s)", anchor, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// flushAllAnchors flushes all rules from the WireGuide anchors.
func flushAllAnchors() error {
	var errs []string
	// The DNS sub-anchor is flushed separately: -F on the parent does not
	// recurse into children.
	if err := flushAnchor(dnsAnchorName, "rules"); err != nil {
		errs = append(errs, err.Error())
	}
	if err := flushAnchor(anchorName, "all"); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("flushAllAnchors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// anchorHasRules reports whether pf currently has rules loaded in the anchor.
func anchorHasRules(anchor string) bool {
	out, err := pfctlQuery("-q", "-a", anchor, "-sr")
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// RecoverFromCrash satisfies the FirewallManager interface. A helper restart
// means every utun the previous process owned is gone, so no WireGuide rule
// can still be valid: flush unconditionally.
func (f *DarwinFirewall) RecoverFromCrash() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killSwitchEnabled = false
	f.killSwitchTunnels = make(map[string][]string)
	f.dnsPermits = nil
	f.tokenHeld = false
	f.token = 0
	f.appliedMain, f.appliedDNS = "", ""
	return RecoverSavedRules()
}

// RecoverSavedRules always flushes both anchors, releases a persisted pf
// token that belongs to the current boot (a token from an earlier boot is
// just deleted), and deletes a legacy pf-was-enabled marker without ever
// disabling pf. Returns true if anything was found or flushed.
func RecoverSavedRules() bool {
	found := anchorHasRules(anchorName) || anchorHasRules(dnsAnchorName)

	flushErr := flushAllAnchors()
	if flushErr != nil {
		slog.Warn("recovery: failed to flush anchors", "error", flushErr)
	}

	legacy := filepath.Join(stateDir, legacyPfStateFile)
	if _, err := os.Stat(legacy); err == nil {
		found = true
		slog.Info("removing legacy pf-was-enabled marker (pf is no longer toggled by WireGuide)")
		if err := removeStateFile(legacy); err != nil {
			slog.Warn("recovery: failed to remove legacy pf state file", "error", err)
		}
	}

	if flushErr == nil {
		existed, err := releasePersistedToken()
		if err != nil {
			slog.Warn("recovery: failed to release pf token", "error", err)
		}
		if existed {
			found = true
		}
	} else if _, err := os.Stat(tokenPath()); err == nil {
		found = true
	}

	if found {
		slog.Info("pf state recovered from previous helper instance")
	}
	return found
}
