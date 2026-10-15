package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// loadUserSettings reads the user's config.json directly. Reading
// fresh on every SSID transition (instead of caching + IPC sync from
// the GUI) means rule edits made in Settings take effect on the next
// network change without any explicit push, and there's no "in-memory
// state diverged from disk" failure mode.
func (h *Helper) loadUserSettings() (*storage.Settings, error) {
	if h.userAppSupport == "" {
		return nil, fmt.Errorf("user app-support dir not derived")
	}
	path := filepath.Join(h.userAppSupport, "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return storage.DefaultSettings(), nil
		}
		return nil, err
	}
	s := storage.DefaultSettings()
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	return s, nil
}

// currentNetworkContext builds the NetworkContext automation rules are
// evaluated against — the single source for both the live engine
// (reevaluateAutomation) and the read-only preview, so `wireguide ctl
// automation` always shows exactly what the engine would act on.
//
// SSID staleness: on macOS the SSID only arrives via GUI reports (the
// root helper can't read it). If the GUI has exited and the machine then
// moved networks, that value is stale. A gateway MAC different from the
// one stamped at report time proves the network changed since the report,
// so the SSID is treated as unknown — SSID rules stop matching rather
// than misfiring on the old network's name, while subnet/MAC rules keep
// working off fresh data. An empty stamp (no report yet, or gateway
// unknown at report time) never invalidates.
//
// The context also carries the default-route interface, whether that is
// Wi-Fi, whether a default route exists, and whether the network
// fingerprint has settled (see automation_state.go).
func (h *Helper) currentNetworkContext() wifi.NetworkContext {
	return h.currentNetworkState().ctx
}

// handleSSIDChange is one trigger for Automation re-evaluation: the
// Wi-Fi monitor fires it on every SSID transition. The actual decision
// logic lives in reevaluateAutomation so the network-change and poll
// triggers share it.
func (h *Helper) handleSSIDChange(oldSSID, newSSID string) {
	h.reevaluateAutomation("ssid-change")
}

// reevaluateAutomation drives every tunnel that has Automation rules
// toward its desired state for the current network context (SSID +
// physical-interface subnets). This runs entirely inside the helper, so
// rules keep firing whether or not a GUI is alive.
//
// Semantics (issue #12): a rule can connect OR disconnect its tunnel
// regardless of how the tunnel was brought up — unlike the legacy path
// which only touched helper-auto-connected tunnels. A tunnel with NO
// rules is never touched. reevalMu serialises evaluations so the slow
// connect/disconnect calls from two overlapping triggers can't race.
func (h *Helper) reevaluateAutomation(reason string) {
	if h.activated && !h.guiSeen.Load() {
		return
	}
	h.reevalMu.Lock()
	defer h.reevalMu.Unlock()

	settings, err := h.loadUserSettings()
	if err != nil {
		slog.Debug("automation: cannot load settings", "error", err)
		return
	}
	settings.EnsureAutomation()
	auto := settings.Automation
	if auto == nil || len(auto.PerTunnel) == 0 {
		h.pruneLatchesWithoutRules(nil)
		return
	}

	st := h.currentNetworkState()
	ctx := st.ctx
	h.pruneManualOverrides(st)
	h.pruneLatchesWithoutRules(auto.PerTunnel)

	active := make(map[string]bool)
	for _, n := range h.manager.ActiveTunnels() {
		active[n] = true
	}

	anyNegated := false
	for _, name := range auto.TunnelNames() {
		rules := auto.PerTunnel[name]
		if wifi.HasNegated(rules) {
			anyNegated = true
		}
		if latch, ok := h.manualLatchFor(name); ok {
			slog.Debug("automation: tunnel latched by manual override, skipping",
				"tunnel", name, "disconnected", latch.disconnected, "reason", reason)
			continue
		}
		state, info := wifi.EvaluateDetailed(rules, ctx)
		if info.Held {
			slog.Debug("automation: negated rule undecidable, holding",
				"tunnel", name, "rule", info.RuleIndex, "reason", reason,
				"ssid", ctx.SSID, "settled", ctx.Settled, "online", ctx.Online)
		}
		switch state {
		case wifi.StateConnect:
			if !active[name] && !h.isWatchdogBlocked(name) {
				h.automationConnect(name, reason, ctx.SSID)
			}
		case wifi.StateDisconnect:
			if active[name] {
				slog.Info("automation: rule disconnect", "tunnel", name, "reason", reason, "ssid", ctx.SSID)
				h.disconnectAutoManaged(name)
			} else {
				if h.monitor != nil {
					h.monitor.CancelRetryFor(name)
				}
				h.withdrawPendingDesired(name)
			}
		}
	}

	// A negated rule can't act, and a manual latch can't clear, until the
	// network has been stable for the settle window, and nothing else
	// re-triggers evaluation then.
	if (anyNegated || h.hasManualOverrides()) && !ctx.Settled {
		h.armSettleTimer(st.settleRemaining)
	}
}

// handleAutomationPreview is a read-only dry-run of the Automation
// engine: it reports the current network context and each rule-bearing
// tunnel's evaluated decision, without connecting or disconnecting
// anything. Backs `wireguide ctl automation` and answers "why did this
// tunnel (dis)connect?".
func (h *Helper) handleAutomationPreview(_ json.RawMessage) (interface{}, error) {
	settings, err := h.loadUserSettings()
	if err != nil {
		return nil, err
	}
	settings.EnsureAutomation()
	auto := settings.Automation

	st := h.peekNetworkState()
	ctx := st.ctx

	ipStrs := make([]string, 0, len(ctx.PhysicalIPs))
	for _, ip := range ctx.PhysicalIPs {
		ipStrs = append(ipStrs, ip.String())
	}

	active := make(map[string]bool)
	for _, n := range h.manager.ActiveTunnels() {
		active[n] = true
	}

	h.previewDriftCheck(auto, st)

	resp := ipc.AutomationPreviewResponse{
		SSID: ctx.SSID, PhysicalIPs: ipStrs, GatewayMAC: ctx.GatewayMAC,
		PrimaryIface: ctx.PrimaryIface, PrimaryIsWiFi: ctx.PrimaryIsWiFi,
		Online: ctx.Online, Settled: ctx.Settled,
		SettleRemainingSec: int((st.settleRemaining + time.Second - 1) / time.Second),
	}
	if auto != nil {
		for _, name := range auto.TunnelNames() {
			rules := auto.PerTunnel[name]
			decision := "unmanaged"
			state, info := wifi.EvaluateDetailed(rules, ctx)
			switch state {
			case wifi.StateConnect:
				decision = "connect"
			case wifi.StateDisconnect:
				decision = "disconnect"
			}
			_, latched := h.manualLatchFor(name)
			if info.Held {
				decision = "held"
			}
			if latched {
				decision = "latched"
			}
			resp.Tunnels = append(resp.Tunnels, ipc.AutomationTunnelDecision{
				Name:      name,
				RuleCount: len(rules),
				Decision:  decision,
				Active:    active[name],
				Held:      info.Held,
				Latched:   latched,
			})
		}
	}
	return resp, nil
}

// automationConnect brings up a tunnel a rule matched and records it in
// the auto-managed map. Caller holds reevalMu.
func (h *Helper) automationConnect(name, reason, ssid string) {
	if h.userTunnelStore == nil {
		slog.Warn("automation: tunnel store unavailable, cannot connect", "tunnel", name)
		return
	}
	cfg, err := h.userTunnelStore.Load(name)
	if err != nil {
		slog.Warn("automation: cannot load tunnel config", "tunnel", name, "error", err)
		return
	}
	if cidr, addr, overlaps := overlapsLocalNetwork(cfg); overlaps {
		h.reportAutomationOverlap(name, cidr, addr)
		return
	}
	h.clearAutomationSkip(name)
	slog.Info("automation: rule connect", "tunnel", name, "reason", reason, "ssid", ssid)
	h.connectMu.Lock()
	// A manual connect/disconnect may have landed while we waited for
	// connectMu (our own route churn re-triggers evaluation within
	// milliseconds); its latch is recorded before it releases the lock.
	if _, latched := h.manualLatchFor(name); latched || h.isWatchdogBlocked(name) {
		h.connectMu.Unlock()
		slog.Info("automation: connect skipped, manual override latched", "tunnel", name)
		return
	}
	err = h.doConnectWithOwnerHeld(cfg, &ssid)
	if err == nil {
		// Same firewall follow-up a manual connect does — otherwise a
		// headless automation connect gets no DNS protection and, if the
		// kill switch is already on, its endpoints are never permitted so
		// the tunnel can't pass traffic (issue #12).
		h.applyPostConnectFirewall(cfg)
	}
	h.connectMu.Unlock()
	if err != nil {
		slog.Warn("automation connect failed", "tunnel", name, "error", err)
		return
	}
	// Notify GUI so it runs the same post-connect refresh as a manual connect.
	h.server.Broadcast(ipc.EventAutoConnect, ipc.AutoConnectPayload{TunnelName: name})
}

// disconnectAutoManaged tears down a tunnel a Wi-Fi rule turned off.
// Caller holds reevalMu; connectMu is taken here, as handleDisconnect
// does, so the teardown and its desired-state write can't interleave with
// a connect of the same tunnel.
func (h *Helper) disconnectAutoManaged(name string) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	if _, latched := h.manualLatchFor(name); latched {
		return
	}
	h.teardownTunnelHeld(name, "rule-driven disconnect, no GUI attached")
}

// teardownTunnelHeld disconnects a tunnel the user didn't turn off by hand
// (a Wi-Fi rule, or the loop watchdog) and clears every cache that
// referenced it: activeCfgs, pendingDesired, autoConnectedBy, the latency
// cache, its in-flight retry, and the desired-state file. Without each of
// these the helper's recovery paths would resurrect the tunnel: the
// reconnect monitor would fire its pending retry, the wake reconnect would
// re-Connect from a stale activeCfgs entry, the next SSID change would try
// to disconnect a tunnel already gone, and the issue #44 restore would bring
// it back after a helper restart. Caller holds connectMu.
func (h *Helper) teardownTunnelHeld(name, shutdownReason string) {
	if h.monitor != nil {
		h.monitor.CancelRetryFor(name)
	}
	// Snapshot the interface name before teardown so we can strip it from
	// the kill-switch filter set afterwards, exactly as handleDisconnect
	// does. Without this a rule-driven disconnect leaves a dead tunnel's
	// LUID permitted in the WFP filters (issue #12).
	iface := ""
	if h.firewall.IsKillSwitchEnabled() {
		for _, st := range tunnelStatuses(h) {
			if st != nil && st.TunnelName == name && st.InterfaceName != "" {
				iface = st.InterfaceName
				break
			}
		}
	}
	if err := h.manager.DisconnectTunnel(name); err != nil {
		slog.Warn("tunnel teardown failed", "tunnel", name, "error", err)
	}
	if iface != "" {
		if err := h.removeKillSwitchPermit(iface, time.Now()); err != nil {
			slog.Warn("RemoveKillSwitchTunnel after teardown failed",
				"interface", iface, "error", err)
		}
	}
	if err := h.reapplyDNSProtection(); err != nil {
		slog.Warn("DNS protection after teardown failed", "error", err)
	}
	h.mu.Lock()
	delete(h.activeCfgs, name)
	delete(h.pendingDesired, name)
	nothingLeft := len(h.activeCfgs) == 0 && len(h.pendingDesired) == 0
	h.mu.Unlock()
	if nothingLeft && h.monitor != nil {
		// Same as handleDisconnect: the all-tunnels retry has nothing left
		// to bring back.
		h.monitor.CancelRetry()
	}
	h.wifiMu.Lock()
	delete(h.autoConnectedBy, name)
	h.wifiMu.Unlock()
	// Prune the latency cache exactly as handleDisconnect does — otherwise
	// the status broadcast keeps reporting the dead tunnel's last RTT.
	h.latencyMu.Lock()
	delete(h.latencyByTunnel, name)
	h.latencyMu.Unlock()
	h.persistDesiredState()
	h.maybeArmShutdownAfterTeardown(shutdownReason)
}

// previewDriftInterval rate-limits the preview's self-heal evaluation.
const previewDriftInterval = 5 * time.Second

// previewDriftCheck heals a stale settle tracker. The preview only Peeks,
// so if rules exist that depend on settling (a negated rule, or a manual
// latch awaiting a settled identity) but the tracker has not settled and
// no settle timer is pending, nothing would ever Observe the network and
// the GUI would show "settling" forever. One real evaluation observes the
// fingerprint and arms the timer. Asynchronous and rate-limited; never runs
// under reevalMu/connectMu.
func (h *Helper) previewDriftCheck(auto *wifi.Automation, st networkState) {
	if st.ctx.Settled {
		return
	}
	needs := h.hasManualOverrides()
	if auto != nil && !needs {
		for _, rules := range auto.PerTunnel {
			if wifi.HasNegated(rules) {
				needs = true
				break
			}
		}
	}
	if !needs || h.settleTimerArmed() {
		return
	}
	now := time.Now()
	if h.previewDriftNow != nil {
		now = h.previewDriftNow()
	}
	h.previewDriftMu.Lock()
	if !h.previewDriftLast.IsZero() && now.Sub(h.previewDriftLast) < previewDriftInterval {
		h.previewDriftMu.Unlock()
		return
	}
	h.previewDriftLast = now
	h.previewDriftMu.Unlock()
	h.goSafe("previewDrift", func() { h.triggerReevaluate("preview-drift") })
}

// triggerReevaluate runs an automation evaluation, or the test hook.
func (h *Helper) triggerReevaluate(reason string) {
	if h.reevalTrigger != nil {
		h.reevalTrigger(reason)
		return
	}
	h.reevaluateAutomation(reason)
}

// rulesWatchDefaultInterval is how often config.json is polled for
// Automation changes.
const rulesWatchDefaultInterval = 2 * time.Second

// rulesWatcher remembers the last config.json stat and automation hash.
type rulesWatcher struct {
	mtime, size int64
	hash        string
}

func (h *Helper) rulesStatFn(path string) (int64, int64, error) {
	if h.rulesStat != nil {
		return h.rulesStat(path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	return fi.ModTime().UnixNano(), fi.Size(), nil
}

// automationHash is a canonical hash of ONLY the automation block, so
// unrelated settings changes (theme, ...) don't trigger evaluations.
func (h *Helper) automationHash() (string, bool) {
	settings, err := h.loadUserSettings()
	if err != nil {
		return "", false
	}
	settings.EnsureAutomation()
	b, err := json.Marshal(settings.Automation)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), true
}

// rulesWatchTick checks config.json once. When its stat changed and the
// automation block differs from the last one seen it re-evaluates. Holds no
// locks while statting/loading.
func (h *Helper) rulesWatchTick(w *rulesWatcher) {
	mt, sz, err := h.rulesStatFn(filepath.Join(h.userAppSupport, "config.json"))
	if err != nil || (mt == w.mtime && sz == w.size) {
		return
	}
	hash, ok := h.automationHash()
	if !ok {
		return
	} // Retry an interrupted/partial write on the next tick.
	w.mtime, w.size = mt, sz
	if hash == w.hash {
		return
	}
	w.hash = hash
	slog.Info("automation rules changed; re-evaluating")
	h.triggerReevaluate("rules-changed")
}

// rulesWatchLoop polls config.json for Automation changes (see
// rulesWatchTick). The baseline is recorded without triggering: the
// startup evaluation already covers the rules present at start.
func (h *Helper) rulesWatchLoop() {
	if h.userAppSupport == "" {
		return
	}
	w := &rulesWatcher{}
	w.mtime, w.size, _ = h.rulesStatFn(filepath.Join(h.userAppSupport, "config.json"))
	w.hash, _ = h.automationHash()
	interval := h.rulesWatchInterval
	if interval <= 0 {
		interval = rulesWatchDefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			h.rulesWatchTick(w)
		}
	}
}
