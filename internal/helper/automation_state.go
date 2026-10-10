package helper

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/network"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// settleTimerSlack is added to the remaining settle time so the deferred
// re-evaluation lands just after the window has elapsed.
const settleTimerSlack = 250 * time.Millisecond

// gatewayWaitBudget bounds how long a legacy reconnect waits for a default
// route to exist before trying to bring tunnels up.
const gatewayWaitBudget = 10 * time.Second

// netProbeResult is the raw OS view of the network that automation builds
// its NetworkContext from. A seam so tests don't shell out.
type netProbeResult struct {
	Gateway       string
	Iface         string
	GatewayMAC    string
	IPs           []net.IP
	Subnets       []string
	PrimaryIsWiFi bool
}

var probeNetwork = func() netProbeResult {
	gw, iface := wifi.DefaultRoute()
	r := netProbeResult{
		Gateway:    gw,
		Iface:      iface,
		GatewayMAC: wifi.GatewayMAC(),
		IPs:        wifi.PhysicalInterfaceIPs(),
		// Primary interface only: virtual bridges (bridge100, vmenet) count
		// as physical for PhysicalIPs but flap and would restart the settle
		// window forever.
		Subnets: primarySubnets(iface),
	}
	// Unknown primary interface reads as Wi-Fi so an empty SSID holds.
	r.PrimaryIsWiFi = iface == "" || wifi.IsWiFiInterface(iface)
	return r
}

// primarySubnets returns the masked network CIDRs (IPv4 and non-link-local
// IPv6) of iface's addresses, sorted. A seam so tests don't need real
// interfaces.
var primarySubnets = func(iface string) []string {
	if iface == "" {
		return nil
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	return subnetsOfAddrs(addrs)
}

// subnetsOfAddrs masks each address down to its network CIDR, skipping
// loopback and link-local; duplicates removed, output sorted.
func subnetsOfAddrs(addrs []net.Addr) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		if ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() || ipnet.IP.IsLinkLocalMulticast() {
			continue
		}
		cidr := (&net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}).String()
		if !seen[cidr] {
			seen[cidr] = true
			out = append(out, cidr)
		}
	}
	sort.Strings(out)
	return out
}

// defaultRouteProbe reports whether a default route exists (seam for tests).
var defaultRouteProbe = func() bool {
	gw, iface := wifi.DefaultRoute()
	return gw != "" || iface != ""
}

// localOverlapProbe finds an AllowedIPs range overlapping a local physical
// address (seam for tests).
var localOverlapProbe = network.FirstLocalNetworkOverlap

// manualLatch records an explicit user connect/disconnect and the network
// it was made on. Automation leaves the tunnel alone until the network
// settles on a different identity.
type manualLatch struct {
	identity     string
	disconnected bool // true: user turned it off; false: user turned it on
	// unknown: identity was recorded while the network was unknown (offline
	// or a blank SSID on Wi-Fi). It is replaced by the first settled, known
	// identity instead of being compared against.
	unknown bool
}

// networkState is one snapshot of the context plus the bookkeeping the
// engine and the latch need.
type networkState struct {
	ctx             wifi.NetworkContext
	identity        string
	identityKnown   bool // false: offline, or blank SSID on Wi-Fi
	settleRemaining time.Duration
}

// networkIdentity names the network a manual override was made on: the SSID
// when known, else the interface + gateway MAC + subnets.
func networkIdentity(ssid, iface, gwMAC string, subnets []string) string {
	if ssid != "" {
		return "ssid:" + ssid
	}
	return "net:" + iface + "|" + gwMAC + "|" + strings.Join(subnets, ",")
}

// currentNetworkState builds the NetworkContext (see currentNetworkContext
// for the SSID staleness rules) and feeds the settle tracker.
func (h *Helper) currentNetworkState() networkState {
	return h.networkState(true)
}

// peekNetworkState is currentNetworkState for read-only callers (the
// automation preview the GUI polls): it reads the settle tracker without
// recording the sampled fingerprint, so polling cannot restart the window.
func (h *Helper) peekNetworkState() networkState {
	return h.networkState(false)
}

func (h *Helper) networkState(observe bool) networkState {
	ssid := ""
	if h.wifiMon != nil {
		ssid = strings.TrimSpace(h.wifiMon.LastSSID())
	}
	probe := probeNetwork()
	gw := probe.GatewayMAC
	// The gateway stamp guards against a stale SSID once no GUI is left to
	// refresh it. While a GUI is attached its CoreWLAN-reported SSID is
	// authoritative: a primary-interface change that keeps Wi-Fi associated
	// (e.g. iPhone USB tethering ranked above Wi-Fi) changes the gateway
	// without changing the SSID, and must not blank it.
	if ssid != "" && gw != "" && !h.guiAttached() {
		h.wifiMu.Lock()
		fromGUI := h.ssidFromGUI
		stamp := h.ssidStampGW
		if !fromGUI {
			// Helper-read SSID (Linux/Windows poll or events): always fresh.
			stamp = gw
		} else if stamp == "" {
			// Lazy stamp: the gateway MAC was not resolvable when the GUI
			// reported this SSID (no ARP entry yet). The SSID is still the
			// one last reported, so bind it to the gateway known now;
			// otherwise a GUI-less helper would trust it across a move to
			// another network forever.
			h.ssidStampGW = gw
			stamp = gw
		}
		h.wifiMu.Unlock()
		if stamp != gw {
			slog.Debug("SSID considered stale: gateway changed since GUI report",
				"ssid", ssid, "stamped_gw", stamp, "current_gw", gw)
			ssid = ""
		}
	}
	subnets := append([]string(nil), probe.Subnets...)
	sort.Strings(subnets)
	fp := wifi.NetworkFingerprint(ssid, probe.Iface, gw, subnets)
	h.settleMu.Lock()
	if h.settle == nil {
		h.settle = wifi.NewSettleTracker(nil)
	}
	tracker := h.settle
	h.settleMu.Unlock()
	var settled bool
	var remaining time.Duration
	if observe {
		settled, remaining = tracker.Observe(fp)
	} else {
		settled, remaining = tracker.Peek(fp)
	}
	return networkState{
		ctx: wifi.NetworkContext{
			SSID:          ssid,
			PhysicalIPs:   probe.IPs,
			GatewayMAC:    gw,
			Settled:       settled,
			PrimaryIface:  probe.Iface,
			PrimaryIsWiFi: probe.PrimaryIsWiFi,
			Online:        probe.Gateway != "" || probe.Iface != "",
		},
		identity:        networkIdentity(ssid, probe.Iface, gw, subnets),
		identityKnown:   (probe.Gateway != "" || probe.Iface != "") && !(ssid == "" && probe.PrimaryIsWiFi),
		settleRemaining: remaining,
	}
}

// armSettleTimer (re)schedules a re-evaluation for when the network will
// have been stable for the settle window. Without it nothing would
// re-trigger a held negated rule once the window passes (macOS has no
// poll). The callback re-checks h.done.
func (h *Helper) armSettleTimer(remaining time.Duration) {
	h.settleMu.Lock()
	defer h.settleMu.Unlock()
	select {
	case <-h.done:
		return
	default:
	}
	if h.settleTimer != nil {
		h.settleTimer.Stop()
	}
	var t *time.Timer
	t = time.AfterFunc(remaining+settleTimerSlack, func() {
		// Fired: no longer armed (the preview's drift check reads this).
		h.settleMu.Lock()
		if h.settleTimer == t {
			h.settleTimer = nil
		}
		h.settleMu.Unlock()
		select {
		case <-h.done:
			return
		default:
		}
		h.reevaluateAutomation("settled")
	})
	h.settleTimer = t
}

// settleTimerArmed reports whether a settle re-evaluation is pending.
func (h *Helper) settleTimerArmed() bool {
	h.settleMu.Lock()
	defer h.settleMu.Unlock()
	return h.settleTimer != nil
}

// stopSettleTimer cancels any pending settle re-evaluation (cleanup).
func (h *Helper) stopSettleTimer() {
	h.settleMu.Lock()
	defer h.settleMu.Unlock()
	if h.settleTimer != nil {
		h.settleTimer.Stop()
		h.settleTimer = nil
	}
}

// recordManualOverride latches name after an explicit user connect
// (disconnected=false) or disconnect (true) so automation doesn't undo it
// until the network settles on a different identity. Never called for
// automation's own connects/disconnects.
func (h *Helper) recordManualOverride(name string, disconnected bool) {
	if name == "" {
		return
	}
	st := h.currentNetworkState()
	h.wifiMu.Lock()
	if h.manualOverride == nil {
		h.manualOverride = make(map[string]manualLatch)
	}
	h.manualOverride[name] = manualLatch{identity: st.identity, disconnected: disconnected, unknown: !st.identityKnown}
	h.wifiMu.Unlock()
	slog.Info("automation: manual override latched", "tunnel", name,
		"disconnected", disconnected, "network", st.identity)
}

// pruneManualOverrides drops latches once the network has SETTLED on a known
// identity different from the one they were made on. Transient roam blips
// (unsettled) and unknown networks (offline, blank SSID on Wi-Fi) never clear
// a latch; a latch recorded while the network was unknown adopts the first
// settled, known identity instead.
func (h *Helper) pruneManualOverrides(st networkState) {
	if !st.ctx.Settled || !st.identityKnown {
		return
	}
	h.wifiMu.Lock()
	defer h.wifiMu.Unlock()
	for name, l := range h.manualOverride {
		if l.unknown {
			l.identity, l.unknown = st.identity, false
			h.manualOverride[name] = l
			continue
		}
		if l.identity != st.identity {
			slog.Info("automation: manual override cleared, network changed",
				"tunnel", name, "was", l.identity, "now", st.identity)
			delete(h.manualOverride, name)
		}
	}
}

// manualLatchFor returns the latch for name, if any.
func (h *Helper) manualLatchFor(name string) (manualLatch, bool) {
	h.wifiMu.Lock()
	defer h.wifiMu.Unlock()
	l, ok := h.manualOverride[name]
	return l, ok
}

// hasManualOverrides reports whether any manual latch is held.
func (h *Helper) hasManualOverrides() bool {
	h.wifiMu.Lock()
	defer h.wifiMu.Unlock()
	return len(h.manualOverride) > 0
}

// forgetManualOverride drops name's latch (tunnel deleted).
func (h *Helper) forgetManualOverride(name string) {
	h.wifiMu.Lock()
	delete(h.manualOverride, name)
	h.wifiMu.Unlock()
}

// tunnelAllowedIPs flattens every peer's AllowedIPs.
func tunnelAllowedIPs(cfg *domain.WireGuardConfig) []string {
	var out []string
	if cfg == nil {
		return nil
	}
	for _, p := range cfg.Peers {
		out = append(out, p.AllowedIPs...)
	}
	return out
}

// overlapsLocalNetwork reports whether any of cfg's AllowedIPs contains a
// current physical-interface address. Bringing such a tunnel up on its own
// (automation, legacy reconnect) would route the machine's own LAN —
// gateway and resolver included — into the tunnel.
func overlapsLocalNetwork(cfg *domain.WireGuardConfig) (cidr string, addr net.IP, ok bool) {
	return localOverlapProbe(tunnelAllowedIPs(cfg))
}

// waitForDefaultRoute blocks until a default route exists, the budget
// elapses (proceeds anyway) or ctx is cancelled (returns its error).
func waitForDefaultRoute(ctx context.Context, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for !defaultRouteProbe() {
		if time.Now().After(deadline) {
			slog.Warn("no default route after waiting; reconnecting anyway", "waited", budget)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil
}

// cancelLegacyRetryIfIdle ends the legacy all-tunnels ("") reconnect retry
// once it has nothing left to restore: activeCfgs (what the retry restores
// from) is empty. Based on the cache, not on which tunnels are up — a tunnel
// the retry is still restoring is down, and cancelling because ANOTHER
// tunnel was disconnected would abandon it. Otherwise the retry keeps
// cycling (suspending the firewall each tick) and bounces a tunnel brought
// up later. Both teardown paths evict activeCfgs before calling this. Caller
// holds connectMu; CancelRetryFor takes only the monitor's own lock.
func (h *Helper) cancelLegacyRetryIfIdle() {
	if h.monitor == nil {
		return
	}
	h.mu.Lock()
	idle := len(h.activeCfgs) == 0
	h.mu.Unlock()
	if idle {
		h.monitor.CancelRetryFor("")
	}
}

// pruneLatchesWithoutRules drops latches for tunnels that no longer have
// automation rules (rules removed, tunnel deleted): the latch has nothing
// left to override and a stale one would block rules added later.
func (h *Helper) pruneLatchesWithoutRules(rules map[string][]wifi.Rule) {
	h.wifiMu.Lock()
	defer h.wifiMu.Unlock()
	for name := range h.manualOverride {
		if len(rules[name]) == 0 {
			delete(h.manualOverride, name)
		}
	}
}
