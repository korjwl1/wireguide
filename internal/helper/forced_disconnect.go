package helper

import (
	"log/slog"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// handleForcedDisconnect runs the teardown for a tunnel the Manager's
// runaway-TX watchdog tripped on (issue #49). The trip means traffic was
// looping back into the tunnel, so the tunnel is dropped from every cache
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
	h.teardownTunnelHeld(ev.TunnelName, "forced disconnect, no GUI attached")
	h.server.Broadcast(ipc.EventForcedDisconnect, ipc.ForcedDisconnectPayload{
		TunnelName: ev.TunnelName,
		Reason:     ev.Reason,
	})
}
