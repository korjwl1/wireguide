package helper

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/korjwl1/wireguide/internal/automation"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
)

// pendingDesiredCfgs loads configs for pendingDesired — tunnels a restore
// tried and failed to bring up. It reads the set, not the file: the file can
// briefly list a tunnel a concurrent Disconnect just dropped from
// activeCfgs, and adopting that as pending would undo the Disconnect.
// Pending tunnels whose config is gone from the tunnel store are dropped.
func (h *Helper) pendingDesiredCfgs() map[string]*domain.WireGuardConfig {
	h.mu.Lock()
	candidates := make([]string, 0, len(h.pendingDesired))
	for name := range h.pendingDesired {
		if _, active := h.activeCfgs[name]; !active {
			candidates = append(candidates, name)
		}
	}
	h.mu.Unlock()
	if len(candidates) == 0 || h.userTunnelStore == nil {
		return nil
	}

	cfgs := make(map[string]*domain.WireGuardConfig, len(candidates))
	var dropped []string
	for _, name := range candidates {
		cfg, err := h.userTunnelStore.Load(name)
		if err != nil {
			slog.Warn("desired-state: config no longer loadable, dropping",
				"tunnel", name, "error", err)
			dropped = append(dropped, name)
			continue
		}
		cfgs[name] = cfg
	}
	if len(dropped) > 0 {
		h.mu.Lock()
		for _, name := range dropped {
			delete(h.pendingDesired, name)
		}
		h.mu.Unlock()
		h.wifiMu.Lock()
		for _, name := range dropped {
			delete(h.autoConnectedBy, name)
		}
		h.wifiMu.Unlock()
		// Rewrite so the same failures aren't re-logged on every trigger.
		h.persistDesiredState()
		h.maybeArmShutdownAfterTeardown("pending configs removed, no GUI attached")
	}
	return cfgs
}

// withdrawPendingDesired drops a pending (restore-failed) tunnel that an
// Automation rule now wants off, so a later wake retry won't bring it back.
func (h *Helper) withdrawPendingDesired(name string) {
	if h.dropPendingRestore(name) {
		slog.Info("automation: rule says off, withdrawing pending restore", "tunnel", name)
		h.persistDesiredState()
		h.maybeArmShutdownAfterTeardown("pending restore withdrawn, no GUI attached")
	}
}

func (h *Helper) dropPendingRestore(name string) bool {
	h.mu.Lock()
	_, ok := h.pendingDesired[name]
	delete(h.pendingDesired, name)
	_, active := h.activeCfgs[name]
	h.mu.Unlock()
	if ok && !active {
		h.wifiMu.Lock()
		delete(h.autoConnectedBy, name)
		h.wifiMu.Unlock()
	}
	return ok
}

// Register wanted work before slow startup probes, including when a client's
// Disconnect arrives first. Caller holds connectMu. Never re-adopt a withdrawn
// snapshot: read the current journal and preserve already-active manual intent.
func (h *Helper) registerPendingRestore() {
	h.mu.Lock()
	restoring := h.restoreInProgress && h.restoreOnStart
	h.mu.Unlock()
	if !restoring {
		return
	}
	intent := loadDesiredIntent(h.dataDir)
	adopted := make(map[string]bool)
	h.mu.Lock()
	for _, name := range intent.Tunnels {
		_, active := h.activeCfgs[name]
		_, blocked := h.watchdogBlocked[name]
		if !active && !blocked {
			if h.pendingDesired == nil {
				h.pendingDesired = make(map[string]struct{})
			}
			h.pendingDesired[name] = struct{}{}
			adopted[name] = true
		}
	}
	h.mu.Unlock()
	h.wifiMu.Lock()
	for _, name := range intent.Automatic {
		if adopted[name] {
			if h.autoConnectedBy == nil {
				h.autoConnectedBy = make(map[string]string)
			}
			h.autoConnectedBy[name] = ""
		}
	}
	h.wifiMu.Unlock()
}

// connectPendingDesired connects one pending tunnel through the same path as
// a restore. It re-checks under connectMu that the tunnel is still pending: a
// user Disconnect may have withdrawn it, or a manual Connect brought it up,
// while this retry waited.
func (h *Helper) connectPendingDesired(ctx context.Context, cfg *domain.WireGuardConfig) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("reconnect %q cancelled before Connect: %w", cfg.Name, err)
	}
	// Checked before connectMu, as in restore: the network lookup shells out.
	if restoreRuleSaysOff(h, cfg.Name) {
		h.withdrawPendingDesired(cfg.Name)
		return nil
	}
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	h.mu.Lock()
	_, stillPending := h.pendingDesired[cfg.Name]
	h.mu.Unlock()
	if !stillPending {
		return nil
	}
	if h.automaticLANConflict(cfg) {
		return reconnect.ErrNothingToReconnect
	}
	return restoreConnect(h, cfg)
}

// restoreConnect connects one restored or pending tunnel. It runs the same
// firewall follow-up a manual/automation connect gets — a headless restore
// must not skip DNS protection / kill-switch permits (parity with issue #12)
// — and tells the GUI the same way automation does so it refreshes.
// A package var so tests can exercise restore without a real tunnel.
// Caller MUST hold h.connectMu.
var restoreConnect = func(h *Helper, cfg *domain.WireGuardConfig) error {
	if err := h.doConnectHeld(cfg); err != nil {
		return err
	}
	h.applyConnectedFirewall(cfg, false)
	h.server.Broadcast(ipc.EventAutoConnect, ipc.AutoConnectPayload{TunnelName: cfg.Name})
	return nil
}

// restoreRuleSaysOff reports whether an Automation rule wants name OFF on the
// current network. Unknown SSID counts as "no verdict", the same guard the
// startup rule pass uses: a none_match rule would otherwise disconnect a
// tunnel before we know which network we're on. A package var for tests.
var restoreRuleSaysOff = func(h *Helper, name string) bool {
	settings, err := h.loadUserSettings()
	if err != nil {
		return false
	}
	settings.EnsureAutomation()
	auto := settings.Automation
	if auto == nil || len(auto.PerTunnel[name]) == 0 {
		return false
	}
	ctx := h.currentNetworkContext()
	if ctx.SSID == "" {
		return false
	}
	return automation.Evaluate(auto.PerTunnel[name], ctx) == automation.StateDisconnect
}

// connectUnderKillSwitch is reconnectFn's connect for a cached tunnel while
// the kill switch blockade is up. A package var so tests can observe the
// choice without a real tunnel. Caller MUST hold h.connectMu.
var connectUnderKillSwitch = func(h *Helper, cfg *domain.WireGuardConfig) error {
	return h.doConnectHeld(cfg)
}

// systemBootTimeNow is a test seam over the platform-specific boot-time
// readers in boottime_*.go.
var systemBootTimeNow = systemBootTime
