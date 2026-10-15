package helper

import (
	"encoding/json"
	"log/slog"
	"runtime"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

// fullTunnelForcesDNSProtection is the Windows-only auto-enable below; a
// package var so tests on other platforms can exercise it.
var fullTunnelForcesDNSProtection = runtime.GOOS == "windows"

// tunnelStatuses is the per-tunnel status source for DNS protection. A
// package var so tests can present connected tunnels without real ones.
var tunnelStatuses = func(h *Helper) []*tunnel.ConnectionStatus {
	return h.manager.ConnectedInterfaces()
}

// DNS protection follows the tunnel set (issue #48). The system resolver is
// given the union of every connected tunnel's DNS servers, so the rules must
// let each tunnel's servers through that tunnel's interface — not one
// tunnel's servers on one interface, which dropped every query to the other
// tunnels' servers and kept pointing at a dead interface after disconnect.
// Every transition that changes the connected set calls
// reapplyDNSProtection, which renders the rules from scratch.

// dnsAllowList computes resolver permits from all connected routes, rather
// than assuming every configured resolver is inside its owner's tunnel.
func (h *Helper) dnsAllowList() []firewall.DNSAllow {
	h.mu.Lock()
	cfgs := h.copyActiveCfgs()
	h.mu.Unlock()
	return resolverPermits(cfgs, tunnelStatuses(h))
}

// dnsProtectionNeeded reports whether DNS rules should be installed: the
// user turned DNS protection on, or (Windows only) a connected full tunnel
// has DNS servers. That Windows rule predates issue #48 and keeps its old
// behaviour: Windows' "smart multi-homed name resolution" queries every
// interface's DNS in parallel (wireguard-windows netquirk.md), so a full
// tunnel connect turns DNS protection on regardless of the setting, and an
// explicit "off" from the user holds until the next full-tunnel connect.
func (h *Helper) dnsProtectionNeeded() bool {
	h.mu.Lock()
	wanted := h.dnsProtectionWanted
	autoOff := h.dnsAutoOff
	cfgs := h.copyActiveCfgs()
	h.mu.Unlock()
	for _, st := range tunnelStatuses(h) {
		if st == nil || st.State != domain.StateConnected {
			continue
		}
		if cfg := cfgs[st.TunnelName]; cfg != nil && !cfg.Interface.IsSplitDNS() && len(cfg.Interface.ParseDNS().Servers) > 0 {
			if wanted || (!autoOff && fullTunnelForcesDNSProtection && cfg.IsFullTunnel()) {
				return true
			}
		}
	}
	return false
}

// reapplyDNSProtection installs DNS rules for the current tunnel set, or
// removes them when DNS protection isn't needed. With protection on but no
// connected tunnel that has DNS servers, the firewall removes its rules;
// the next connect installs them again.
func (h *Helper) reapplyDNSProtection() error {
	return h.reconcileDNSProtection(true, time.Now())
}

// reconcileDNSProtection records only successful OS changes. The periodic
// pass retries a failed transition, with bounded backoff, without reloading
// healthy rules on every tick. Explicit user transitions are immediate.
func (h *Helper) reconcileDNSProtection(force bool, now time.Time) error {
	h.dnsMu.Lock()
	defer h.dnsMu.Unlock()
	select {
	case <-h.done:
		// Shutdown began: cleanup tears the firewall down, and a connect
		// finishing late must not put DNS rules back after it.
		return nil
	default:
	}
	if h.dnsSuspended {
		return nil
	}
	needed := h.dnsProtectionNeeded()
	allow := h.dnsAllowList()
	encoded, _ := json.Marshal(struct {
		Needed bool
		Allow  []firewall.DNSAllow
	}{needed, allow})
	signature := string(encoded)
	if signature != h.dnsPending {
		h.dnsPending = signature
		h.dnsRetryDelay = 0
		h.dnsRetryAt = time.Time{}
	}
	expectedActive := needed && len(allow) > 0
	if !force && ((signature == h.dnsApplied && expectedActive == h.firewall.IsDNSProtectionEnabled()) || now.Before(h.dnsRetryAt)) {
		return nil
	}
	var err error
	if !needed {
		if h.firewall.IsDNSProtectionEnabled() {
			err = h.firewall.DisableDNSProtection()
		}
	} else {
		slog.Debug("DNS protection: applying", "tunnels", len(allow))
		err = h.firewall.EnableDNSProtection(allow)
	}
	if err != nil {
		h.dnsApplied = ""
		h.dnsRetryDelay = min(30*time.Second, max(time.Second, h.dnsRetryDelay*2))
		h.dnsRetryAt = now.Add(h.dnsRetryDelay)
		return err
	}
	h.dnsApplied = signature
	h.dnsRetryDelay = 0
	h.dnsRetryAt = time.Time{}
	return nil
}

func (h *Helper) dnsReconcileLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.done:
			return
		case now := <-ticker.C:
			h.connectMu.Lock()
			h.manager.RetryPendingDNSCleanup()
			h.retryKillSwitchPermitRemovals(now)
			h.repairFirewallEnforcement()
			if err := h.reconcileKillSwitch(false, now); err != nil {
				slog.Warn("kill-switch reconciliation failed; will retry", "error", err)
			}
			err := h.reconcileDNSProtection(false, now)
			h.connectMu.Unlock()
			if err != nil {
				slog.Warn("DNS protection reconciliation failed; will retry", "error", err)
			}
		}
	}
}

// repairFirewallEnforcement lets the backend restore protection that was lost
// outside WireGuide (e.g. an external `pfctl -d`) while its model still
// reports it active; model comparisons alone would never notice. Runs before
// the reconciliations so they compare against enforced state. Caller holds
// connectMu.
func (h *Helper) repairFirewallEnforcement() {
	r, ok := h.firewall.(firewall.EnforcementRepairer)
	if !ok || h.fwSuspendDepth > 0 {
		// A reconnect suspended the rules on purpose; its resume reapplies.
		return
	}
	if repaired, err := r.RepairEnforcement(); err != nil {
		slog.Error("firewall enforcement lost and not yet restored; will retry", "error", err)
	} else if repaired {
		slog.Warn("firewall enforcement was lost outside WireGuide and has been restored")
	}
}
