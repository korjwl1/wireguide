package helper

import (
	"log/slog"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

func (h *Helper) isWatchdogBlocked(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, blocked := h.watchdogBlocked[name]
	return blocked
}

// clearWatchdogBlockHeld acknowledges a successful manual Connect. Caller
// holds connectMu, so an automation pass cannot slip between the clear and
// its durable write.
func (h *Helper) clearWatchdogBlockHeld(name string) {
	h.mu.Lock()
	_, blocked := h.watchdogBlocked[name]
	delete(h.watchdogBlocked, name)
	h.mu.Unlock()
	if blocked {
		h.persistDesiredState()
	}
}

// handleForcedDisconnect runs the teardown for a tunnel the Manager's
// endpoint-route watchdog tripped on (issue #49). The endpoint routes
// back into this tunnel, so it is dropped from every cache
// and the desired state: neither the wake reconnect nor a crash restore
// may bring it back. The user reconnects by hand once the network is sane.
func (h *Helper) handleForcedDisconnect(ev tunnel.ForcedDisconnect) {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	select {
	case <-h.done:
		return // cleanup() tears everything down
	default:
	}
	if !ev.Current() {
		slog.Info("forced disconnect: session already gone, nothing to do",
			"tunnel", ev.TunnelName, "reason", ev.Reason)
		return
	}
	slog.Error("forced disconnect", "tunnel", ev.TunnelName,
		"interface", ev.Interface, "reason", ev.Reason)
	// A Wi-Fi rule can ask for this tunnel again on the next poll, network
	// change, or helper restart. Record the block with the desired state so
	// only an explicit manual Connect can resume a suspected loop.
	h.mu.Lock()
	if h.watchdogBlocked == nil {
		h.watchdogBlocked = make(map[string]struct{})
	}
	h.watchdogBlocked[ev.TunnelName] = struct{}{}
	h.mu.Unlock()
	// Write the block before the slow OS teardown. If the helper crashes
	// during teardown, the next instance must see the block even while the
	// old desired-tunnel entry is still in this first snapshot.
	h.persistDesiredState()
	h.teardownTunnelHeld(ev.TunnelName, "forced disconnect, no GUI attached")
	h.server.Broadcast(ipc.EventForcedDisconnect, ipc.ForcedDisconnectPayload{
		TunnelName: ev.TunnelName,
		Reason:     ev.Reason,
	})
}
