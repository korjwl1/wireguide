package helper

import (
	"log/slog"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

type permitRemovalRetry struct {
	at    time.Time
	delay time.Duration
}

// Caller holds connectMu. Keep failed removals until the OS accepts them;
// a successfully disconnected tunnel must not leave a permanent exception.
func (h *Helper) removeKillSwitchPermit(iface string, now time.Time) error {
	err := h.firewall.RemoveKillSwitchTunnel(iface)
	if err == nil {
		delete(h.permitRemovalRetries, iface)
		return nil
	}
	if h.permitRemovalRetries == nil {
		h.permitRemovalRetries = make(map[string]permitRemovalRetry)
	}
	retry := h.permitRemovalRetries[iface]
	retry.delay = min(30*time.Second, max(time.Second, retry.delay*2))
	retry.at = now.Add(retry.delay)
	h.permitRemovalRetries[iface] = retry
	return err
}

// Called by the periodic DNS/firewall safety net under connectMu. An
// interface can be reused by a new connection before the retry: preserve
// that live connection's permit instead of applying an obsolete removal.
func (h *Helper) retryKillSwitchPermitRemovals(now time.Time) {
	select {
	case <-h.done:
		return
	default:
	}
	if len(h.permitRemovalRetries) == 0 {
		return
	}
	if !h.firewall.IsKillSwitchEnabled() {
		clear(h.permitRemovalRetries)
		return
	}
	live := make(map[string]bool)
	for _, st := range tunnelStatuses(h) {
		if st != nil && st.State != domain.StateDisconnected && st.InterfaceName != "" {
			live[st.InterfaceName] = true
		}
	}
	for iface, retry := range h.permitRemovalRetries {
		if live[iface] {
			delete(h.permitRemovalRetries, iface)
			continue
		}
		if now.Before(retry.at) {
			continue
		}
		if err := h.removeKillSwitchPermit(iface, now); err != nil {
			slog.Warn("kill-switch permit cleanup failed; will retry", "interface", iface, "error", err)
		}
	}
}
