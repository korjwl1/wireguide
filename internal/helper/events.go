package helper

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
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


// statusDTO returns the current connection status for broadcast. Since the
// tunnel package's ConnectionStatus is already an alias for the domain type
// with wire-safe JSON tags, we just dereference and return it — no field-by-
// field translation.
func (h *Helper) statusDTO() ipc.ConnectionStatus {
	s := h.manager.Status()
	if s == nil {
		return ipc.ConnectionStatus{}
	}
	result := *s

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

	// Include lightweight per-tunnel info (name + state + handshake presence
	// + latency) so the frontend can show correct badges. Full stats
	// (rx/tx/duration) are only in the primary status to avoid sending
	// redundant data every second.
	if allStats := h.manager.AllStatuses(); len(allStats) > 1 {
		for _, ts := range allStats {
			if ts != nil {
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
	}
	return result
}

// latencyLoop probes each connected tunnel's endpoint with an ICMP
// ping every 30 seconds and stores the result in latencyByTunnel.
// Runs in a goroutine supervised by goSafe — panics are logged and
// restarted up to maxRestarts times.
//
// Each measurement uses diag.PingEndpoint which has its own 15s ctx
// timeout, so a slow / unreachable peer can stretch the loop slightly
// past 30s, but multiple hung peers don't compound (we ping in
// sequence; the next loop iteration just starts later). This is fine
// for the low-resolution display use case — users don't need
// sub-second updates of latency in the UI.
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
	for _, s := range statuses {
		if s == nil || s.State != domain.StateConnected || s.Endpoint == "" {
			continue
		}
		h.mu.Lock()
		cfg := h.activeCfgs[s.TunnelName]
		h.mu.Unlock()

		target := pingTargetForTunnel(cfg, s.Endpoint)
		viaTunnel := target != s.Endpoint
		result := diag.PingEndpoint(target)

		// If through-tunnel target failed (gateway doesn't exist /
		// blocks ICMP on this network), fall back to the public
		// endpoint. Many VPN endpoints DO drop ICMP — the through-
		// tunnel path is just usually more permissive.
		if !result.Reachable && viaTunnel {
			result = diag.PingEndpoint(s.Endpoint)
			viaTunnel = false
		}

		latency := 0.0
		if result.Reachable {
			latency = result.LatencyMs
		}
		h.latencyMu.Lock()
		h.latencyByTunnel[s.TunnelName] = latency
		h.latencyMu.Unlock()
		slog.Info("endpoint latency measured",
			"tunnel", s.TunnelName, "target", target,
			"via_tunnel", viaTunnel,
			"reachable", result.Reachable, "latency_ms", latency)
	}
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
