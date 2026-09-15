package helper

import (
	"context"
	"log/slog"
	"reflect"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/healthcheck"
)

type pingHealthState struct {
	policy healthcheck.State
	seen   time.Time
}

// pingHealthLoop keeps health policy separate from display-only latency probes.
// It continues while a tunnel is active even if the GUI is closed.
func (h *Helper) pingHealthLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-h.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	states := map[string]*pingHealthState{}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			// Settings may change while the tunnel is down in retry backoff.
			// Invalidate those retries before filtering for connected tunnels.
			h.monitor.CancelInvalidRetries()
			if h.userTunnelStore == nil {
				continue
			}
			for _, status := range h.manager.AllStatuses() {
				if ctx.Err() != nil {
					return
				}
				if status == nil || status.State != domain.StateConnected {
					continue
				}
				name := status.TunnelName
				meta, err := h.userTunnelStore.LoadMeta(name)
				if err != nil || meta == nil || meta.PingHealth == nil || !meta.PingHealth.Enabled {
					delete(states, name)
					continue
				}
				config, err := meta.PingHealth.Normalize()
				if err != nil {
					delete(states, name)
					continue
				}
				h.mu.Lock()
				cfg := h.activeCfgs[name]
				h.mu.Unlock()
				if cfg == nil {
					continue
				}
				var allowed []string
				for _, peer := range cfg.Peers {
					allowed = append(allowed, peer.AllowedIPs...)
				}
				valid := true
				for _, target := range config.Targets {
					if !healthcheck.Covered(target, allowed) {
						valid = false
						break
					}
				}
				if !valid {
					delete(states, name)
					continue
				}
				state := states[name]
				if state == nil {
					state = &pingHealthState{}
					states[name] = state
				}
				state.seen = now
				if !state.policy.Due(now, status.ConnectedAt, config) {
					continue
				}
				reachable, err := healthcheck.Check(ctx, status.InterfaceName, config.Targets, healthcheck.Probe)
				if err != nil {
					return
				}
				// A manual disconnect, rename, reconnect or settings edit during the
				// probe invalidates it. Serialize the final check with user actions so
				// a late failed packet cannot reconnect a tunnel the user just stopped.
				h.connectMu.Lock()
				current := h.manager.StatusFor(name)
				latest, loadErr := h.userTunnelStore.LoadMeta(name)
				if current != nil && current.State == domain.StateConnected && current.ConnectedAt.Equal(status.ConnectedAt) && current.InterfaceName == status.InterfaceName && loadErr == nil && latest != nil && latest.PingHealth != nil {
					latestConfig, err := latest.PingHealth.Normalize()
					if err == nil && reflect.DeepEqual(config, latestConfig) && ctx.Err() == nil && state.policy.Observe(time.Now(), reachable) {
						slog.Warn("ping targets failed repeatedly; reconnecting tunnel", "tunnel", name, "failures", config.FailureThreshold)
						h.monitor.ReconnectTunnelIfIdle(name, h.pingRetryGuard(name, config))
					}
				}
				h.connectMu.Unlock()
			}
			// Retain cooldown briefly while a tunnel is reconnecting, but avoid
			// accumulating state forever for removed/renamed tunnels.
			for name, state := range states {
				if now.Sub(state.seen) > 10*time.Minute {
					delete(states, name)
				}
			}
		}
	}
}

// Retain the triggering settings for the lifetime of this retry, including
// failed connection attempts. Save/edit/disable/rename/delete invalidates the
// old reason without canceling retries caused by other health signals.
func (h *Helper) pingRetryGuard(name string, triggered healthcheck.Config) func() bool {
	return func() bool {
		_, meta, err := h.userTunnelStore.LoadWithMeta(name)
		if err != nil || meta == nil || meta.PingHealth == nil {
			return false
		}
		latest, err := meta.PingHealth.Normalize()
		return err == nil && latest.Enabled && reflect.DeepEqual(triggered, latest)
	}
}
