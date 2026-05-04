package helper

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
)

// pingTargetForTunnel picks the best ICMP target to measure latency
// of a connected tunnel. The public WG endpoint often blocks ICMP
// (typical of corporate VPNs), so probing the endpoint IP directly
// returns "Host unreachable" everywhere.
//
// Selection order:
//
//  1. A specific peer host (/32 entry in AllowedIPs) — split-tunnel
//     setups list the reachable hosts explicitly; ping one of them
//     directly to measure tunnel RTT.
//
//  2. For full-tunnel configs (AllowedIPs contains 0.0.0.0/0 or ::/0)
//     ping a known well-pingable public IP (8.8.8.8 — Google's anycast
//     public DNS responds to ICMP from anywhere). Traffic routes
//     through the tunnel by virtue of the default route, so the RTT
//     reflects tunnel + underlay + remote peer NAT + peer→target hop.
//
//  3. Interface subnet gateway derived from a non-/32 Interface
//     Address (e.g. 10.5.6.7/24 → 10.5.6.1).
//
//  4. Public endpoint as last resort. Almost always fails with
//     "Host unreachable" but it's not wrong to try.
func pingTargetForTunnel(cfg *domain.WireGuardConfig, fallbackEndpoint string) string {
	if cfg == nil {
		return fallbackEndpoint
	}

	hasFullTunnel := false
	for _, peer := range cfg.Peers {
		for _, allowed := range peer.AllowedIPs {
			// (1) specific peer host wins — most accurate
			if strings.HasSuffix(allowed, "/32") {
				return strings.TrimSuffix(allowed, "/32")
			}
			if strings.HasSuffix(allowed, "/128") {
				return strings.TrimSuffix(allowed, "/128")
			}
			if allowed == "0.0.0.0/0" || allowed == "::/0" {
				hasFullTunnel = true
			}
		}
	}

	// (2) full-tunnel public probe
	if hasFullTunnel {
		return "8.8.8.8"
	}

	// (3) subnet gateway guess
	for _, addr := range cfg.Interface.Address {
		_, network, err := net.ParseCIDR(addr)
		if err != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if ones == bits {
			continue
		}
		gw := make(net.IP, len(network.IP))
		copy(gw, network.IP)
		gw[len(gw)-1] |= 1
		return gw.String()
	}

	// (4) fallback
	return fallbackEndpoint
}


// statusDTO returns the current connection status for broadcast.
// Pulled from manager.AllStatuses() in a single call — the previous
// version queried the primary tunnel via Status() AND again via
// AllStatuses(), doubling UAPI round-trips on every 1Hz tick for the
// common single-tunnel case.
func (h *Helper) statusDTO() ipc.ConnectionStatus {
	allStats := h.manager.AllStatuses()
	if len(allStats) == 0 {
		// Mirror the previous Status()==nil behavior with an empty
		// disconnected struct so subscribers don't spuriously see
		// "tunnel disappeared" events on idle helpers.
		return ipc.ConnectionStatus{State: domain.StateDisconnected}
	}

	// Pick the primary the same way manager.Status() did: prefer
	// the first connected tunnel; otherwise the first non-nil entry.
	var primary *domain.ConnectionStatus
	for _, ts := range allStats {
		if ts == nil {
			continue
		}
		if ts.State == domain.StateConnected {
			primary = ts
			break
		}
		if primary == nil {
			primary = ts
		}
	}
	if primary == nil {
		return ipc.ConnectionStatus{State: domain.StateDisconnected}
	}
	result := *primary

	// Snapshot the latency cache once per call so we don't take the
	// lock per-tunnel inside the loop.
	h.latencyMu.Lock()
	latencies := make(map[string]float64, len(h.latencyByTunnel))
	for k, v := range h.latencyByTunnel {
		latencies[k] = v
	}
	h.latencyMu.Unlock()

	if lat, ok := latencies[result.TunnelName]; ok {
		result.LatencyMs = lat
	}

	// Include lightweight per-tunnel info (name + state + handshake
	// presence + latency) so the frontend can show correct badges.
	// Pre-allocate to avoid the latent-bug of `append` aliasing a
	// slice on the manager-returned struct.
	if len(allStats) > 1 {
		result.Tunnels = make([]domain.ConnectionStatus, 0, len(allStats))
		for _, ts := range allStats {
			if ts == nil {
				continue
			}
			sub := domain.ConnectionStatus{
				State:         ts.State,
				TunnelName:    ts.TunnelName,
				LastHandshake: ts.LastHandshake,
			}
			if lat, ok := latencies[ts.TunnelName]; ok {
				sub.LatencyMs = lat
			}
			result.Tunnels = append(result.Tunnels, sub)
		}
	}
	return result
}

// latencyLoop probes each connected tunnel's endpoint with an ICMP
// ping every 30 seconds and stores the result in latencyByTunnel.
// Runs in a goroutine supervised by goSafe — panics are logged and
// restarted up to maxRestarts times.
//
// Each measurement uses diag.PingEndpoint which has its own 15s ctx
// timeout. Tunnel pings dispatch in parallel (one goroutine per
// connected tunnel) so total wall time is max(per-tunnel) instead of
// sum — a row of N hung tunnels no longer multiplies the loop by N
// and risks chewing through the 30s tick.
func (h *Helper) latencyLoop() {
	const tickInterval = 30 * time.Second
	// Sleep briefly on startup so we don't ping immediately during
	// helper boot, when the tunnel state is still settling.
	select {
	case <-h.done:
		return
	case <-time.After(5 * time.Second):
	}

	for {
		h.measureLatencies()

		select {
		case <-h.done:
			return
		case <-time.After(tickInterval):
		}
	}
}

// measureLatencies pings each connected tunnel's preferred latency
// target and updates the cache. The target is the tunnel's internal
// gateway when derivable (most VPNs respond to ICMP within their own
// network), with the public endpoint as fallback. Failures store 0,
// which the frontend renders as "—".
func (h *Helper) measureLatencies() {
	statuses := h.manager.AllStatuses()
	var wg sync.WaitGroup
	for _, s := range statuses {
		if s == nil || s.State != domain.StateConnected || s.Endpoint == "" {
			continue
		}
		h.mu.Lock()
		cfg := h.activeCfgs[s.TunnelName]
		h.mu.Unlock()

		wg.Add(1)
		go func(tunnelName, endpoint string, cfg *domain.WireGuardConfig) {
			defer wg.Done()
			target := pingTargetForTunnel(cfg, endpoint)
			viaTunnel := target != endpoint
			result := diag.PingEndpoint(target)

			// If through-tunnel target failed (gateway doesn't exist /
			// blocks ICMP on this network), fall back to the public
			// endpoint. Many VPN endpoints DO drop ICMP — the through-
			// tunnel path is just usually more permissive.
			if !result.Reachable && viaTunnel {
				result = diag.PingEndpoint(endpoint)
				viaTunnel = false
			}

			latency := 0.0
			if result.Reachable {
				latency = result.LatencyMs
			}
			h.latencyMu.Lock()
			h.latencyByTunnel[tunnelName] = latency
			h.latencyMu.Unlock()
			slog.Info("endpoint latency measured",
				"tunnel", tunnelName, "target", target,
				"via_tunnel", viaTunnel,
				"reachable", result.Reachable, "latency_ms", latency)
		}(s.TunnelName, s.Endpoint, cfg)
	}
	wg.Wait()
}

// eventLoop broadcasts status updates to subscribed GUIs on change. Change
// detection is done by JSON round-trip compare (robust against field swaps).
func (h *Helper) eventLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastJSON []byte
	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			status := h.statusDTO()
			currentJSON, err := json.Marshal(status)
			if err != nil {
				continue
			}
			if !bytes.Equal(lastJSON, currentJSON) {
				lastJSON = currentJSON
				h.server.Broadcast(ipc.EventStatus, status)
			}
		}
	}
}
