package helper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// reconnectFn is the callback passed to reconnect.Monitor. When name is
// non-empty, it reconnects only that specific tunnel. When name is empty
// (legacy sleep/wake path), it reconnects all cached tunnels.
// The connectMu is held during Connect to prevent races with concurrent
// GUI connect/disconnect calls.
//
// Cancellation is checked before retries and between connect phases. Platform
// commands also have their own timeouts; an in-flight OS call may finish later.
func (h *Helper) reconnectFn(ctx context.Context, name string) error {
	// DNS rules must follow whatever is up afterwards, on every path —
	// including attempts the monitor didn't suspend/resume around (nothing
	// was up, or the suspend itself failed) (issue #48).
	defer func() {
		if dnsErr := h.reapplyDNSProtection(); dnsErr != nil {
			slog.Warn("reconnect: DNS protection rebuild failed", "error", dnsErr)
		}
	}()
	h.mu.Lock()
	cfgs := h.copyActiveCfgs()
	h.mu.Unlock()
	// Tunnels that are wanted but not up because the helper restarted and
	// its startup restore failed (issue #44). They go through the full
	// connect path, not a bare manager connect: nothing about them is in
	// the firewall yet, and success must move them into activeCfgs.
	pending := h.pendingDesiredCfgs()

	if name != "" {
		cfg, ok := cfgs[name]
		if !ok {
			if pcfg, isPending := pending[name]; isPending {
				return h.connectPendingDesired(ctx, pcfg)
			}
			return fmt.Errorf("no cached config for tunnel %q", name)
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("reconnect %q cancelled before Connect: %w", name, err)
		}
		h.connectMu.Lock()
		defer h.connectMu.Unlock()
		if !h.stillCached(name) {
			return nil // disconnected while this retry waited (issue #44)
		}
		if h.automaticLANConflict(cfg) {
			return reconnect.ErrNothingToReconnect
		}
		if latch, ok := h.manualLatchFor(name); ok && latch.disconnected {
			return reconnect.ErrNothingToReconnect
		}
		return alreadyConnectedIsOK(h.manager.ConnectWithContext(ctx, cfg))
	}

	// Legacy path: reconnect all tunnels.
	if len(cfgs) == 0 && len(pending) == 0 {
		return reconnect.ErrNothingToReconnect
	}
	var lastErr error
	attempted := 0
	for _, cfg := range cfgs {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("reconnect-all cancelled mid-loop: %w", err)
		}
		err := func() error {
			h.connectMu.Lock()
			defer h.connectMu.Unlock()
			// cfgs is a snapshot from before this retry waited on connectMu.
			// A Disconnect that ran meanwhile dropped the tunnel from
			// activeCfgs (and may have cancelled ctx); bringing it back from
			// the stale copy would undo the user's "off" (issue #44).
			latch, latched := h.manualLatchFor(cfg.Name)
			if ctx.Err() != nil || !h.stillCached(cfg.Name) || (latched && latch.disconnected) {
				return nil
			}
			if h.automaticLANConflict(cfg) {
				return nil
			}
			attempted++
			var err error
			if h.firewall.IsKillSwitchEnabled() {
				// The monitor did not suspend the firewall this attempt (nothing
				// was up — e.g. the previous attempt failed and resume put the
				// base blockade back). A bare connect would run under the
				// blockade, which drops DNS and WireGuard UDP, and nothing
				// would ever permit the new interface. doConnectHeld lifts the
				// blockade for the connect and rebuilds it with this tunnel.
				err = connectUnderKillSwitch(h, cfg)
			} else {
				err = h.manager.ConnectWithContext(ctx, cfg)
			}
			return err
		}()
		// Already up (a GUI connect raced the retry) is the goal state.
		var te *tunnel.TunnelError
		if errors.As(err, &te) && te.Kind == tunnel.ErrAlreadyConnected {
			err = nil
		}
		if err != nil {
			lastErr = err
		}
	}
	for _, cfg := range pending {
		if err := h.connectPendingDesired(ctx, cfg); err != nil {
			lastErr = err
		}
	}
	if attempted == 0 && len(pending) == 0 {
		return reconnect.ErrNothingToReconnect
	}
	return lastErr
}

// stillCached reports whether name is still in activeCfgs.
func (h *Helper) stillCached(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.activeCfgs[name]
	return ok
}

// guiAttached reports whether a GUI control connection is attached. Safe on
// a helper without a server (tests).
func (h *Helper) guiAttached() bool {
	if h.guiAttachedFn != nil {
		return h.guiAttachedFn()
	}
	return h.server != nil && h.server.HasControlConn()
}

// alreadyConnectedIsOK maps tunnel.ErrAlreadyConnected to success: the
// reconnect's goal (the tunnel is up) already holds, so it must not count
// as a failed attempt that backs off and retries.
func alreadyConnectedIsOK(err error) error {
	var te *tunnel.TunnelError
	if errors.As(err, &te) && te.Kind == tunnel.ErrAlreadyConnected {
		return nil
	}
	return err
}

// copyActiveCfgs returns a shallow copy of the active configs map.
// Caller MUST hold h.mu.
func (h *Helper) copyActiveCfgs() map[string]*domain.WireGuardConfig {
	cp := make(map[string]*domain.WireGuardConfig, len(h.activeCfgs))
	for k, v := range h.activeCfgs {
		cp[k] = v
	}
	return cp
}

// onReconnectState forwards reconnection state changes to any subscribed GUI.
func (h *Helper) onReconnectState(state reconnect.State) {
	h.server.Broadcast(ipc.EventReconnect, ipc.ReconnectStateDTO{
		Reconnecting: state.Reconnecting,
		Attempt:      state.Attempt,
		MaxAttempts:  state.MaxAttempts,
		NextRetry:    state.NextRetry,
	})
}
