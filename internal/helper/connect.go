package helper

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
)

// doConnectHeld caches cfg BEFORE calling manager.Connect (so the reconnect
// monitor sees the config during Connect), then rolls back on failure.
// Caller MUST hold h.connectMu.
func (h *Helper) doConnectHeld(cfg *domain.WireGuardConfig) error {
	h.wifiMu.Lock()
	owner, automatic := h.autoConnectedBy[cfg.Name]
	h.wifiMu.Unlock()
	if automatic {
		return h.doConnectWithOwnerHeld(cfg, &owner)
	}
	return h.doConnectWithOwnerHeld(cfg, nil)
}

// A nil owner denotes manual intent; recovery retains the recorded owner.
// Ownership is committed with the first successful desired-state snapshot.
func (h *Helper) doConnectWithOwnerHeld(cfg *domain.WireGuardConfig, owner *string) error {
	if err := h.manager.PreflightConnect(cfg); err != nil {
		return err
	}
	// A firewall cannot permit a not-yet-created tunnel interface, and a
	// pre-enabled base kill switch deliberately blocks DNS and WireGuard UDP.
	// This applies equally to nftables, PF, and WFP (and is fatal before Engine
	// creation when a peer endpoint is a hostname). Suspend it for the bounded
	// Connect transaction, then rebuild the complete permit set from every
	// active tunnel. A failed Connect restores the previous blockade too.
	h.rememberEnabledKillSwitch()
	h.mu.Lock()
	restoreKillSwitch := h.killSwitchWanted && h.fwSuspendDepth == 0
	h.mu.Unlock()
	if restoreKillSwitch && h.firewall.IsKillSwitchEnabled() {
		h.ksApplied = ""
		if err := h.firewall.DisableKillSwitch(); err != nil {
			return fmt.Errorf("temporarily disable kill switch for connect: %w", err)
		}
	}

	h.mu.Lock()
	prevCfgs := h.copyActiveCfgs()
	h.activeCfgs[cfg.Name] = cfg
	h.mu.Unlock()

	if err := h.manager.Connect(cfg); err != nil {
		h.mu.Lock()
		delete(h.activeCfgs, cfg.Name)
		if prev, ok := prevCfgs[cfg.Name]; ok {
			h.activeCfgs[cfg.Name] = prev
		}
		h.mu.Unlock()
		h.maybeArmShutdownAfterTeardown("connect failed, no GUI attached")
		if restoreKillSwitch {
			if restoreErr := h.reconcileKillSwitch(true, time.Now()); restoreErr != nil {
				return fmt.Errorf("connect: %v; restore kill switch: %w", err, restoreErr)
			}
		}
		return err
	}

	if restoreKillSwitch {
		if err := h.reconcileKillSwitch(true, time.Now()); err != nil {
			// Do not report a successful connection while the user's requested
			// blockade is absent. Roll the new tunnel back and make one last
			// attempt to restore the pre-connect kill-switch state.
			disconnectErr := h.manager.DisconnectTunnel(cfg.Name)
			h.mu.Lock()
			delete(h.activeCfgs, cfg.Name)
			if prev, ok := prevCfgs[cfg.Name]; ok {
				h.activeCfgs[cfg.Name] = prev
			}
			h.mu.Unlock()
			restoreErr := h.reconcileKillSwitch(true, time.Now())
			h.maybeArmShutdownAfterTeardown("connect rolled back, no GUI attached")
			return fmt.Errorf("restore kill switch after connect: %v (disconnect rollback: %v; blockade restore: %v)",
				err, disconnectErr, restoreErr)
		}
	}
	// User intent: this tunnel should stay active across helper restarts
	// (issue #44 desired state). The failure paths above need no write —
	// they roll activeCfgs back to the pre-call state the file already
	// records.
	h.mu.Lock()
	delete(h.pendingDesired, cfg.Name)
	h.mu.Unlock()
	h.wifiMu.Lock()
	if owner == nil {
		delete(h.autoConnectedBy, cfg.Name)
	} else {
		if h.autoConnectedBy == nil {
			h.autoConnectedBy = make(map[string]string)
		}
		h.autoConnectedBy[cfg.Name] = *owner
	}
	h.wifiMu.Unlock()
	h.persistDesiredState()
	return nil
}

// enableKillSwitchForActiveTunnels reconciles the base blockade and every
// live tunnel permit. Enable is used only when the blockade is absent; active
// backends use idempotent add/remove operations. A partial failure retains
// the blockade and tracked permits so the next reconciliation can finish.
//
// Caller MUST hold h.connectMu so Connect/Disconnect cannot invalidate the
// status snapshot while the firewall rules are being rebuilt.
func (h *Helper) enableKillSwitchForActiveTunnels() error {
	type activeTunnel struct {
		name          string
		interfaceName string
		addresses     []string
	}
	h.mu.Lock()
	activeCfgs := h.copyActiveCfgs()
	h.mu.Unlock()
	var active []activeTunnel
	for _, st := range tunnelStatuses(h) {
		if st == nil || st.State != domain.StateConnected || st.InterfaceName == "" {
			continue
		}
		var addresses []string
		if cfg := activeCfgs[st.TunnelName]; cfg != nil {
			addresses = append([]string(nil), cfg.Interface.Address...)
		}
		active = append(active, activeTunnel{name: st.TunnelName, interfaceName: st.InterfaceName, addresses: addresses})
	}

	sort.Slice(active, func(i, j int) bool { return active[i].name < active[j].name })
	live := make(map[string]bool, len(active))
	for _, t := range active {
		live[t.interfaceName] = true
	}
	enabled := h.firewall.IsKillSwitchEnabled()
	if !enabled {
		h.ksIfaces = make(map[string]struct{})
	}
	if h.ksIfaces == nil {
		h.ksIfaces = make(map[string]struct{})
	}
	// Windows Enable on an already-enabled backend only adds permits. Remove
	// old interfaces explicitly; the safety net must close stale exceptions.
	for iface := range h.ksIfaces {
		if live[iface] {
			continue
		}
		if err := h.firewall.RemoveKillSwitchTunnel(iface); err != nil {
			return err
		}
		delete(h.ksIfaces, iface)
		delete(h.permitRemovalRetries, iface)
	}
	endpoints := h.manager.ResolvedEndpoints()
	start := 0
	if !enabled {
		if len(active) == 0 {
			return h.firewall.EnableKillSwitch("", nil, nil)
		}
		first := active[0]
		if err := h.firewall.EnableKillSwitch(first.interfaceName, first.addresses, endpoints); err != nil {
			return err
		}
		h.ksIfaces[first.interfaceName] = struct{}{}
		start = 1
	}
	// Add is idempotent on every backend. In particular Linux Enable must
	// not be replayed against an existing table (it would append rules).
	for _, t := range active[start:] {
		if err := h.firewall.AddKillSwitchTunnel(t.interfaceName, t.addresses, endpoints); err != nil {
			// Keep the base blockade on partial failure; retry the permits.
			return fmt.Errorf("add tunnel %q to kill switch: %w", t.name, err)
		}
		h.ksIfaces[t.interfaceName] = struct{}{}
	}
	return nil
}

func (h *Helper) handleConnect(params json.RawMessage) (interface{}, error) {
	// Serialize Connect calls so two GUIs can't race on activeCfg.
	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	var req ipc.ConnectRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}
	if req.Config == nil {
		return nil, fmt.Errorf("config is required")
	}
	// Re-validate config server-side (don't trust client).
	if result := config.Validate(req.Config); !result.IsValid() {
		return nil, fmt.Errorf("invalid config: %s", strings.Join(result.ErrorMessages(), "; "))
	}

	// Log if the config contains scripts — they are parsed but ignored.
	if req.Config.HasScripts() {
		slog.Info("config contains Pre/PostUp/Down scripts; ignoring (not supported in GUI client)",
			"tunnel", req.Config.Name)
	}

	// Check for routing conflicts with existing interfaces (Tailscale etc).
	// Log warnings but don't block — users can override via UI.
	var allowedIPs []string
	for _, peer := range req.Config.Peers {
		allowedIPs = append(allowedIPs, peer.AllowedIPs...)
	}
	if conflicts, err := diag.CheckConflicts(allowedIPs); err == nil && len(conflicts) > 0 {
		for _, c := range conflicts {
			slog.Warn("routing conflict detected",
				"interface", c.InterfaceName,
				"owner", c.Owner,
				"overlaps", c.OverlappingIPs)
		}
	}

	if err := h.doConnectWithOwnerHeld(req.Config, nil); err != nil {
		return nil, err
	}
	h.clearWatchdogBlockHeld(req.Config.Name)

	h.applyPostConnectFirewall(req.Config)
	h.recordManualOverride(req.Config.Name, false)
	return ipc.Empty{}, nil
}

// applyPostConnectFirewall runs the firewall follow-up that must happen
// after a tunnel comes up, shared by manual (handleConnect) and
// automation (automationConnect) connects. Extracting it fixes a real
// gap: the automation engine called doConnectHeld directly, so a tunnel
// brought up by a rule while no GUI was running got NEITHER of these —
// and, worst case, could not pass traffic at all because an
// already-enabled kill switch never learned its endpoints (issue #12).
// Best-effort: logs and continues on error, exactly like manual connect.
func (h *Helper) applyPostConnectFirewall(cfg *domain.WireGuardConfig) {
	h.applyConnectedFirewall(cfg, true)
}

// Recovery repairs transport without treating it as a new user request.
// In particular, it must preserve a DNS Off received during the restore.
func (h *Helper) applyConnectedFirewall(cfg *domain.WireGuardConfig, newConnect bool) {
	// DNS protection covers every connected tunnel, this one included
	// (issue #48); on Windows a full tunnel also turns it on by itself,
	// overriding an earlier explicit "off" as it always did.
	if newConnect && cfg.IsFullTunnel() {
		h.mu.Lock()
		h.dnsAutoOff = false
		h.dnsIntentExplicit = true
		h.mu.Unlock()
		// doConnectHeld wrote the previous override before this follow-up.
		// A crash now must retain the new connection's automatic protection.
		h.persistDesiredState()
	}
	if err := h.reapplyDNSProtection(); err != nil {
		slog.Warn("DNS protection after connect failed", "tunnel", cfg.Name, "error", err)
	}

	h.rememberEnabledKillSwitch()
	if err := h.reconcileKillSwitch(true, time.Now()); err != nil {
		slog.Warn("kill switch after connect pending retry", "tunnel", cfg.Name, "error", err)
	}
}
