package helper

import (
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/network"
)

// reconcileTunnel is one CONNECTED tunnel as seen by the reconcile logic.
// Callers must only pass tunnels that are actually up (non-empty Iface).
type reconcileTunnel struct {
	Name  string
	Iface string
	Cfg   *domain.WireGuardConfig
}

// serverRoutedViaTunnel reports whether traffic to ip leaves through the
// tunnel. locals (nil = none) is the snapshot of local physical addresses
// (network.LocalPhysicalAddrs, only meaningful on macOS). Two LAN effects
// are modelled:
//   - AddRoutes skips an AllowedIPs range that overlaps the local network
//     (network.LocalNetworkOverlapIn), so such a range routes nothing;
//   - the connected LAN route is more specific than a broader range (0/0,
//     the /1 pair, a supernet), so the tunnel only wins when the most
//     specific non-skipped range containing ip is strictly longer than every
//     same-family local on-link subnet containing ip.
func serverRoutedViaTunnel(cfg *domain.WireGuardConfig, ip net.IP, locals []*net.IPNet) bool {
	best := -1
	for _, peer := range cfg.Peers {
		for _, a := range peer.AllowedIPs {
			_, cidr, err := net.ParseCIDR(strings.TrimSpace(a))
			if err != nil || !cidr.Contains(ip) {
				continue
			}
			if _, skipped := network.LocalNetworkOverlapIn(cidr.String(), locals); skipped {
				continue
			}
			if ones, _ := cidr.Mask.Size(); ones > best {
				best = ones
			}
		}
	}
	if best < 0 {
		return false
	}
	ipBits := net.IPv6len * 8
	if ip.To4() != nil {
		ipBits = net.IPv4len * 8
	}
	for _, l := range locals {
		if l == nil || l.IP == nil || l.Mask == nil {
			continue
		}
		lones, lbits := l.Mask.Size()
		if lbits != ipBits {
			continue
		}
		lan := &net.IPNet{IP: l.IP.Mask(l.Mask), Mask: l.Mask}
		if lan.Contains(ip) && best <= lones {
			return false
		}
	}
	return true
}

// desiredDNSPermits computes the complete DNS permit set the firewall should
// enforce for the given connected tunnels. Pure.
//
// A tunnel is "protected" when DNS protection is wanted and it has plain
// (non-split) DNS servers, or - on Windows only - when it is a full tunnel
// with such servers (preserving the historic full-tunnel auto-protection,
// which defends against multi-homed resolver leaks). If no tunnel is
// protected the result is nil: no DNS rules may exist at all.
//
// Otherwise the block is global, so every resolver that must keep working
// gets a permit:
//   - a protected tunnel's servers, pinned to its interface when they are
//     routed through it (inside AllowedIPs; a /0 or /1-pair default route
//     covers every address of its own family) and unpinned (any interface) when they are reached over the
//     physical network, e.g. a split tunnel using 1.1.1.1;
//   - the servers of split-DNS / unprotected tunnels that sit inside their
//     own AllowedIPs, pinned, so another tunnel's block never breaks them.
//
// locals (nil = none) is the local physical address snapshot; servers the
// LAN reaches instead of the tunnel (see serverRoutedViaTunnel) count as
// off-tunnel.
func desiredDNSPermits(tunnels []reconcileTunnel, goos string, dnsWanted bool, locals []*net.IPNet) []firewall.DNSPermit {
	type entry struct {
		t         reconcileTunnel
		servers   []string
		protected bool
	}
	var entries []entry
	anyProtected := false
	for _, t := range tunnels {
		if t.Iface == "" || t.Cfg == nil {
			continue
		}
		dns := t.Cfg.Interface.ParseDNS()
		split := len(dns.Match) > 0
		hasServers := len(dns.Servers) > 0
		protected := (dnsWanted && !split && hasServers) ||
			(goos == "windows" && t.Cfg.IsFullTunnel() && hasServers && !split)
		if protected {
			anyProtected = true
		}
		entries = append(entries, entry{t: t, servers: dns.Servers, protected: protected})
	}
	if !anyProtected {
		return nil
	}

	seen := make(map[firewall.DNSPermit]struct{})
	var out []firewall.DNSPermit
	add := func(iface, server string) {
		p := firewall.DNSPermit{Interface: iface, Server: server}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, e := range entries {
		for _, s := range e.servers {
			ip := net.ParseIP(s)
			if ip == nil {
				continue
			}
			inside := serverRoutedViaTunnel(e.t.Cfg, ip, locals)
			// Pin only when the server is actually routed through the
			// tunnel. A default route in the OTHER address family (e.g. ::/0
			// with an IPv4 resolver) does not route this server via the
			// tunnel, so pinning it would blackhole it.
			switch {
			case inside:
				add(e.t.Iface, s)
			case e.protected:
				add("", s)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].Server < out[j].Server
	})
	return out
}

// localAddrsFor returns the local physical address snapshot used to model
// LAN-overlap route skipping. Only macOS skips such ranges. Enumerated once
// per reconcile.
func localAddrsFor(goos string) []*net.IPNet {
	if goos != "darwin" {
		return nil
	}
	return network.LocalPhysicalAddrs()
}

// reconcileDirtyKey marks a failed reconcile; see reconcileFirewallErrLocked.
const reconcileDirtyKey = "\x00dirty"

// reconcileBackoff is the delay before the safety net retries after n
// consecutive failed reconciles: 2s, 4s, ... capped at 60s. Each attempt can
// hold connectMu for a pfctl timeout, so it must not run every tick.
func reconcileBackoff(n int) time.Duration {
	d := 2 * time.Second
	for i := 1; i < n && d < time.Minute; i++ {
		d *= 2
	}
	if d > time.Minute {
		d = time.Minute
	}
	return d
}

// connSnapshot is a consistent view of the connected tunnels.
type connSnapshot struct {
	ifaces map[string]string // tunnel name -> interface
	cfgs   map[string]*domain.WireGuardConfig
}

func (h *Helper) snapshotConnected() connSnapshot {
	h.mu.Lock()
	cfgs := h.copyActiveCfgs()
	h.mu.Unlock()
	return connSnapshot{ifaces: h.manager.ConnectedInterfaces(), cfgs: cfgs}
}

// tunnels returns the connected tunnels (with cached configs) sorted by name.
func (s connSnapshot) tunnels() []reconcileTunnel {
	names := make([]string, 0, len(s.ifaces))
	for n := range s.ifaces {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []reconcileTunnel
	for _, n := range names {
		cfg := s.cfgs[n]
		if cfg == nil {
			continue
		}
		out = append(out, reconcileTunnel{Name: n, Iface: s.ifaces[n], Cfg: cfg})
	}
	return out
}

// key identifies the set of connected (tunnel, iface) pairs.
func (s connSnapshot) key() string { return connectedKey(s.ifaces) }

func connectedKey(ifaces map[string]string) string {
	parts := make([]string, 0, len(ifaces))
	for n, i := range ifaces {
		parts = append(parts, n+"="+i)
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func (s connSnapshot) ifaceSet() map[string]string {
	set := make(map[string]string, len(s.ifaces))
	for n, i := range s.ifaces {
		set[i] = n
	}
	return set
}

func (h *Helper) wantedState() (dnsWanted, ksWanted bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dnsWanted, h.ksWanted
}

func (h *Helper) setDNSWanted(v bool) {
	h.mu.Lock()
	h.dnsWanted = v
	h.mu.Unlock()
}

func (h *Helper) setKSWanted(v bool) {
	h.mu.Lock()
	h.ksWanted = v
	h.mu.Unlock()
}

// reconcileFirewallLocked drives the firewall toward the state the helper
// WANTS (dnsWanted / ksWanted) given the tunnels that are actually up. It is
// idempotent and is the single place DNS-protection rules are installed or
// removed, so they can never outlive the tunnels that justify them. Failures
// are logged; callers that must surface them use reconcileFirewallErrLocked.
//
// Caller MUST hold h.connectMu.
func (h *Helper) reconcileFirewallLocked(reason string) {
	if err := h.reconcileFirewallErrLocked(reason); err != nil {
		slog.Warn("firewall reconcile failed", "reason", reason, "error", err)
	}
}

// reconcileFirewallErrLocked is reconcileFirewallLocked returning the first
// error. While a reconnect has the firewall suspended it does nothing: the
// matching resume reconciles.
func (h *Helper) reconcileFirewallErrLocked(reason string) error {
	if h.fwSuspendDepth > 0 {
		return nil
	}
	snap := h.snapshotConnected()
	dnsErr := h.applyDNSLocked(reason, snap)
	ksErr := h.applyKillSwitchLocked(reason, snap)
	h.mu.Lock()
	if dnsErr == nil && ksErr == nil {
		h.reconciledKey = snap.key()
		h.reconcileFails = 0
		h.reconcileRetryAt = time.Time{}
	} else {
		// Never record a failed reconcile as handled: the sentinel can't equal
		// a real key (not even "" for zero tunnels), so the safety net retries
		// with backoff.
		h.reconciledKey = reconcileDirtyKey
		h.reconcileFails++
		h.reconcileRetryAt = time.Now().Add(reconcileBackoff(h.reconcileFails))
	}
	h.mu.Unlock()
	if dnsErr != nil {
		return dnsErr
	}
	return ksErr
}

// reconcileDNSLocked reconciles only the DNS rules. doConnectHeld uses it
// before Connect: the kill switch is deliberately suspended at that point and
// must not be re-enabled by a full reconcile.
func (h *Helper) reconcileDNSLocked(reason string) {
	if h.fwSuspendDepth > 0 {
		return
	}
	if err := h.applyDNSLocked(reason, h.snapshotConnected()); err != nil {
		slog.Warn("DNS reconcile failed", "reason", reason, "error", err)
	}
}

func permitsEqual(a, b []firewall.DNSPermit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (h *Helper) applyDNSLocked(reason string, snap connSnapshot) error {
	dnsWanted, _ := h.wantedState()
	tunnels := snap.tunnels()
	desired := desiredDNSPermits(tunnels, runtime.GOOS, dnsWanted, localAddrsFor(runtime.GOOS))

	// Nothing to do when the same set is already applied and the firewall
	// agrees it is (not) active.
	if h.dnsApplied && permitsEqual(desired, h.lastPermits) &&
		h.firewall.IsDNSProtectionEnabled() == (len(desired) > 0) {
		return nil
	}

	var err error
	if setter, ok := h.firewall.(firewall.DNSPermitSetter); ok {
		err = setter.SetDNSPermits(desired)
	} else if len(desired) == 0 {
		if h.firewall.IsDNSProtectionEnabled() {
			err = h.firewall.DisableDNSProtection()
		}
	} else {
		iface, servers := legacyDNSArgs(desired, tunnels)
		err = h.firewall.EnableDNSProtection(iface, servers)
	}
	if err != nil {
		h.dnsApplied = false
		return fmt.Errorf("apply DNS protection: %w", err)
	}
	if !h.dnsApplied || !permitsEqual(desired, h.lastPermits) {
		slog.Info("DNS protection permits changed", "reason", reason,
			"dns_wanted", dnsWanted, "permits", formatPermits(desired))
	}
	h.dnsApplied = true
	h.lastPermits = desired
	return nil
}

// legacyDNSArgs maps a permit set onto the single-interface
// EnableDNSProtection API used by the nftables and WFP backends: the
// interface of the first pinned permit (else the first connected tunnel) and
// the unique servers.
func legacyDNSArgs(permits []firewall.DNSPermit, tunnels []reconcileTunnel) (string, []string) {
	iface := ""
	seen := make(map[string]struct{})
	var servers []string
	for _, p := range permits {
		if iface == "" && p.Interface != "" {
			iface = p.Interface
		}
		if _, dup := seen[p.Server]; dup {
			continue
		}
		seen[p.Server] = struct{}{}
		servers = append(servers, p.Server)
	}
	if iface == "" && len(tunnels) > 0 {
		iface = tunnels[0].Iface
	}
	return iface, servers
}

func formatPermits(p []firewall.DNSPermit) string {
	parts := make([]string, 0, len(p))
	for _, x := range p {
		if x.Interface == "" {
			parts = append(parts, x.Server)
		} else {
			parts = append(parts, x.Interface+":"+x.Server)
		}
	}
	return strings.Join(parts, ",")
}

// applyKillSwitchLocked keeps the kill switch aligned with ksWanted: it
// restores a missing blockade (always fail-closed: with zero tunnels the base
// blockade stays) and folds tunnel arrivals/departures into the permit set.
func (h *Helper) applyKillSwitchLocked(reason string, snap connSnapshot) error {
	_, ksWanted := h.wantedState()
	if !ksWanted {
		return nil
	}
	if !h.firewall.IsKillSwitchEnabled() {
		slog.Info("restoring kill switch", "reason", reason)
		return h.enableKillSwitchForActiveTunnels()
	}
	cur := snap.ifaceSet()
	var firstErr error
	for iface := range h.ksIfaces {
		if _, still := cur[iface]; still {
			continue
		}
		if err := h.firewall.RemoveKillSwitchTunnel(iface); err != nil {
			slog.Warn("RemoveKillSwitchTunnel failed", "interface", iface, "reason", reason, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	var endpoints []string
	for iface, name := range cur {
		if _, had := h.ksIfaces[iface]; had {
			continue
		}
		if endpoints == nil {
			endpoints = h.manager.ResolvedEndpoints()
		}
		var addrs []string
		if cfg := snap.cfgs[name]; cfg != nil {
			addrs = append(addrs, cfg.Interface.Address...)
		}
		if err := h.firewall.AddKillSwitchTunnel(iface, addrs, endpoints); err != nil {
			slog.Warn("AddKillSwitchTunnel failed", "interface", iface, "reason", reason, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if firstErr == nil {
		set := make(map[string]struct{}, len(cur))
		for iface := range cur {
			set[iface] = struct{}{}
		}
		h.ksIfaces = set
	}
	return firstErr
}

// suspendFirewall is the reconnect monitor's pre-disconnect hook: clear every
// DNS rule and drop the kill switch so stale rules for the dying utun cannot
// block the new connection. It records nothing about the old firewall state;
// resumeFirewall rebuilds from the helper's wanted state and the tunnels that
// are actually up.
func (h *Helper) suspendFirewall() error {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	h.fwSuspendDepth++

	ksEnabled := h.firewall.IsKillSwitchEnabled()
	if ksEnabled {
		// A kill switch that is on is a kill switch the user wants back.
		h.setKSWanted(true)
	}
	var firstErr error
	// Clear DNS first (on pf it is a sub-anchor of the kill switch).
	h.dnsApplied = false
	h.lastPermits = nil
	if setter, ok := h.firewall.(firewall.DNSPermitSetter); ok {
		if err := setter.SetDNSPermits(nil); err != nil {
			slog.Warn("suspendFirewall: failed to clear DNS permits", "error", err)
			firstErr = err
		}
	} else if h.firewall.IsDNSProtectionEnabled() {
		if err := h.firewall.DisableDNSProtection(); err != nil {
			slog.Warn("suspendFirewall: failed to disable DNS protection", "error", err)
			firstErr = err
		}
	}
	if ksEnabled {
		if err := h.firewall.DisableKillSwitch(); err != nil {
			return fmt.Errorf("suspendFirewall: disable kill switch: %w", err)
		}
	}
	slog.Info("firewall suspended for reconnect", "kill_switch", ksEnabled)
	return firstErr
}

// resumeFirewall is the matching hook: once the last concurrent suspension is
// released it reconciles against the CURRENT connected tunnels. With zero
// tunnels and the kill switch wanted the base blockade comes back (fail
// closed) and no DNS rule is installed. Idempotent; safe to call on every
// exit path of a reconnect attempt.
func (h *Helper) resumeFirewall() error {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	if h.fwSuspendDepth > 0 {
		h.fwSuspendDepth--
	}
	if h.fwSuspendDepth > 0 {
		return nil
	}
	slog.Info("resuming firewall after reconnect")
	return h.reconcileFirewallErrLocked("reconnect-resume")
}

// maybeReconcileOnTunnelChange is the event-loop safety net: when the set of
// connected (tunnel, iface) pairs differs from what the last reconcile saw
// (loop-watchdog teardown, any direct manager call), reconcile - unless the
// lock holder is mid-operation, in which case it will reconcile itself and we
// retry on the next tick.
func (h *Helper) maybeReconcileOnTunnelChange() {
	key := connectedKey(h.manager.ConnectedInterfaces())
	h.mu.Lock()
	same := key == h.reconciledKey
	backingOff := h.reconciledKey == reconcileDirtyKey && time.Now().Before(h.reconcileRetryAt)
	h.mu.Unlock()
	if same || backingOff {
		return
	}
	if !h.connectMu.TryLock() {
		return
	}
	defer h.connectMu.Unlock()
	h.reconcileFirewallLocked("tunnel-set-change")
}
