package helper

import (
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

// loadUserSettings reads the user's settings.json directly. Reading
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
func (h *Helper) currentNetworkContext() wifi.NetworkContext {
	ssid := ""
	if h.wifiMon != nil {
		ssid = h.wifiMon.LastSSID()
	}
	gw := wifi.GatewayMAC()
	if ssid != "" && gw != "" {
		h.wifiMu.Lock()
		stamp := h.ssidStampGW
		h.wifiMu.Unlock()
		if stamp != "" && stamp != gw {
			slog.Debug("SSID considered stale: gateway changed since GUI report",
				"ssid", ssid, "stamped_gw", stamp, "current_gw", gw)
			ssid = ""
		}
	}
	return wifi.NetworkContext{
		SSID:        ssid,
		PhysicalIPs: wifi.PhysicalInterfaceIPs(),
		GatewayMAC:  gw,
	}
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
		return
	}

	ctx := h.currentNetworkContext()

	active := make(map[string]bool)
	for _, n := range h.manager.ActiveTunnels() {
		active[n] = true
	}

	for _, name := range auto.TunnelNames() {
		state := wifi.Evaluate(auto.PerTunnel[name], ctx)
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
				h.withdrawPendingDesired(name)
			}
		}
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

	ctx := h.currentNetworkContext()

	ipStrs := make([]string, 0, len(ctx.PhysicalIPs))
	for _, ip := range ctx.PhysicalIPs {
		ipStrs = append(ipStrs, ip.String())
	}

	active := make(map[string]bool)
	for _, n := range h.manager.ActiveTunnels() {
		active[n] = true
	}

	resp := ipc.AutomationPreviewResponse{SSID: ctx.SSID, PhysicalIPs: ipStrs, GatewayMAC: ctx.GatewayMAC}
	if auto != nil {
		for _, name := range auto.TunnelNames() {
			rules := auto.PerTunnel[name]
			decision := "unmanaged"
			switch wifi.Evaluate(rules, ctx) {
			case wifi.StateConnect:
				decision = "connect"
			case wifi.StateDisconnect:
				decision = "disconnect"
			}
			resp.Tunnels = append(resp.Tunnels, ipc.AutomationTunnelDecision{
				Name:      name,
				RuleCount: len(rules),
				Decision:  decision,
				Active:    active[name],
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
	h.connectMu.Lock()
	if h.isWatchdogBlocked(name) {
		h.connectMu.Unlock()
		slog.Warn("automation: tunnel needs a manual reconnect after watchdog trip", "tunnel", name)
		return
	}
	slog.Info("automation: rule connect", "tunnel", name, "reason", reason, "ssid", ssid)
	err = h.doConnectHeld(cfg)
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
	h.wifiMu.Lock()
	h.autoConnectedBy[name] = ssid
	h.wifiMu.Unlock()
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
		for _, st := range h.manager.AllStatuses() {
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
