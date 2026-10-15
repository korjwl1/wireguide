package helper

import (
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

func (h *Helper) handleDisconnect(params json.RawMessage) (interface{}, error) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	// Parse optional tunnel name from request. len() on a nil slice
	// returns 0, so the previous explicit `params != nil` check was
	// redundant (S1009).
	var tunnelName string
	if len(params) > 0 {
		var req ipc.DisconnectRequest
		if err := json.Unmarshal(params, &req); err == nil {
			tunnelName = req.TunnelName
		}
		// If unmarshal fails (e.g. empty params), disconnect first tunnel (backward compat).
	}

	return h.disconnectHeld(tunnelName)
}

// disconnectHeld runs under connectMu for both explicit Off and atomic delete.
func (h *Helper) disconnectHeld(tunnelName string) (interface{}, error) {
	h.registerPendingRestore()

	if tunnelName != "" {
		h.recordManualOverride(tunnelName, true)
	} else {
		h.mu.Lock()
		names := make(map[string]bool)
		for name := range h.activeCfgs {
			names[name] = true
		}
		for name := range h.pendingDesired {
			names[name] = true
		}
		h.mu.Unlock()
		for _, name := range h.manager.ActiveTunnels() {
			names[name] = true
		}
		for name := range names {
			h.recordManualOverride(name, true)
		}
	}

	// A disconnect also withdraws any pending restore for the same
	// tunnel(s), even if it isn't up — otherwise the next wake trigger
	// would bring back a tunnel the user just turned off (issue #44).
	h.mu.Lock()
	withdrew := len(h.pendingDesired) > 0
	if tunnelName != "" {
		_, withdrew = h.pendingDesired[tunnelName]
		delete(h.pendingDesired, tunnelName)
	} else {
		clear(h.pendingDesired)
	}
	h.mu.Unlock()
	if withdrew {
		// Persist now: a pending tunnel isn't up, so the teardown below
		// fails with not-connected and returns before the later persist.
		h.persistDesiredState()
	}

	// Cancel only the in-flight reconnect for the tunnel(s) being
	// torn down — a per-tunnel disconnect of A must not abort a
	// healthy retry for B.
	if h.monitor != nil {
		if tunnelName != "" {
			h.monitor.CancelRetryFor(tunnelName)
		} else {
			h.monitor.CancelRetry()
		}
	}

	// Snapshot interface names BEFORE disconnect so we can remove their
	// kill-switch permits after teardown. After DisconnectTunnel the
	// engine pointer (and its ifaceName) is gone.
	var ifaceSnapshot []string
	if h.firewall.IsKillSwitchEnabled() {
		for _, st := range tunnelStatuses(h) {
			if st == nil || st.InterfaceName == "" {
				continue
			}
			if tunnelName != "" && st.TunnelName != tunnelName {
				continue
			}
			ifaceSnapshot = append(ifaceSnapshot, st.InterfaceName)
		}
	}
	// Some teardowns can succeed before a sibling fails. Reconcile on
	// every exit while connectMu is still held, including error returns.
	defer h.reconcileDisconnectFirewall(ifaceSnapshot)

	if tunnelName != "" {
		if err := h.manager.DisconnectTunnel(tunnelName); err != nil {
			// A wake retry may already have torn the tunnel down and still
			// be trying to bring it back from activeCfgs. The user's "off"
			// stands: drop the cached config below so the retry can't
			// reconnect it (issue #44). Anything else is a real failure.
			h.mu.Lock()
			_, cached := h.activeCfgs[tunnelName]
			h.mu.Unlock()
			var te *tunnel.TunnelError
			if (!cached && !withdrew) || !errors.As(err, &te) || te.Kind != tunnel.ErrNotConnected {
				return nil, err
			}
			slog.Info("disconnect: tunnel already down (retry pending); dropping it", "tunnel", tunnelName)
		}
		h.mu.Lock()
		delete(h.activeCfgs, tunnelName)
		nothingLeft := len(h.activeCfgs) == 0 && len(h.pendingDesired) == 0
		h.mu.Unlock()
		if nothingLeft && h.monitor != nil {
			// The all-tunnels retry has nothing left to bring back; stop it
			// instead of letting it back off forever on an empty cache.
			h.monitor.CancelRetry()
		}
		h.wifiMu.Lock()
		delete(h.autoConnectedBy, tunnelName)
		h.wifiMu.Unlock()
		h.latencyMu.Lock()
		delete(h.latencyByTunnel, tunnelName)
		h.latencyMu.Unlock()
	} else {
		// Legacy "no name" path: tear down EVERY active tunnel via
		// per-tunnel calls so manager.Disconnect()'s "pick the first"
		// semantic doesn't leave half the snapshot still up while we
		// blanket-evict their cached configs. Each successful per-
		// tunnel disconnect drops its cache entry; partial failures
		// leave the still-up tunnels intact in activeCfgs so the
		// reconnect monitor can still recover them.
		toDisconnect := h.manager.ActiveTunnels()
		var firstErr error
		for _, name := range toDisconnect {
			if err := h.manager.DisconnectTunnel(name); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				slog.Warn("legacy disconnect: tunnel teardown failed",
					"tunnel", name, "error", err)
				continue
			}
			h.mu.Lock()
			delete(h.activeCfgs, name)
			h.mu.Unlock()
			h.wifiMu.Lock()
			delete(h.autoConnectedBy, name)
			h.wifiMu.Unlock()
			h.latencyMu.Lock()
			delete(h.latencyByTunnel, name)
			h.latencyMu.Unlock()
		}
		// Cached tunnels that aren't up — a wake retry tore them down and
		// is trying to bring them back — are part of "disconnect all" too;
		// left in activeCfgs, the next wake trigger would reconnect them.
		stillUp := make(map[string]bool)
		for _, name := range h.manager.ActiveTunnels() {
			stillUp[name] = true
		}
		h.mu.Lock()
		for name := range h.activeCfgs {
			if !stillUp[name] {
				delete(h.activeCfgs, name)
			}
		}
		h.mu.Unlock()
		if firstErr != nil {
			// Record the tunnels that did go down; the failed ones are
			// still in activeCfgs and stay listed.
			h.persistDesiredState()
			return nil, firstErr
		}
	}

	// User intent: the torn-down tunnels are no longer wanted. Failed
	// teardowns returned early above, so this snapshot exactly matches
	// what remains wanted (issue #44 desired state).
	h.persistDesiredState()
	return ipc.Empty{}, nil
}

// reconcileDisconnectFirewall preserves permits for surviving tunnels and
// immediately removes obsolete DNS/kill-switch rules after partial teardown.
// Caller holds connectMu. Errors remain pending in the DNS reconcile worker.
func (h *Helper) reconcileDisconnectFirewall(ifaceSnapshot []string) {
	live := make(map[string]bool)
	for _, st := range tunnelStatuses(h) {
		if st != nil && st.State != domain.StateDisconnected && st.InterfaceName != "" {
			live[st.InterfaceName] = true
		}
	}
	for _, iface := range ifaceSnapshot {
		if live[iface] {
			continue
		}
		if err := h.removeKillSwitchPermit(iface, time.Now()); err != nil {
			slog.Warn("RemoveKillSwitchTunnel after disconnect failed",
				"interface", iface, "error", err)
		}
	}
	// DNS rules named the torn-down interfaces; rebuild them for what is
	// still up (issue #48). Best-effort, like the kill-switch cleanup.
	if err := h.reapplyDNSProtection(); err != nil {
		slog.Warn("DNS protection after disconnect failed", "error", err)
	}
	h.maybeArmShutdownAfterTeardown("tunnel disconnected, no GUI attached")
}
