package helper

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// suspendFirewall saves the current firewall state and disables all firewall
// rules. Called by the reconnect monitor before Disconnect so that old pf rules
// referencing the previous utun interface name don't block the new connection.
func (h *Helper) suspendFirewall() error {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	if h.fwSuspendDepth > 0 {
		h.fwSuspendDepth++
		return nil
	}
	// Capture an already-active backend without overwriting a pending wanted
	// state with the temporarily disabled OS state.
	h.rememberEnabledKillSwitch()
	h.dnsMu.Lock()
	h.dnsSuspended = true
	h.dnsApplied = ""
	h.dnsMu.Unlock()
	h.ksApplied = ""

	// A failed suspend owns no level: roll back through the same retryable
	// wanted-state reconciliation the normal resume uses. The defer also
	// repairs a panic inside the backend before a suspend is committed.
	committed := false
	defer func() {
		if !committed {
			h.cancelFailedFirewallSuspend()
		}
	}()
	if h.firewall.IsDNSProtectionEnabled() {
		if err := h.firewall.DisableDNSProtection(); err != nil {
			return fmt.Errorf("suspendFirewall: disable DNS protection: %w", err)
		}
	}
	if h.firewall.IsKillSwitchEnabled() {
		if err := h.firewall.DisableKillSwitch(); err != nil {
			return fmt.Errorf("suspendFirewall: disable kill switch: %w", err)
		}
	}
	h.fwSuspendDepth = 1
	committed = true
	return nil
}

// Caller holds connectMu. A failed rollback remains pending for the periodic
// safety net; it must not leave a suspension that has no matching owner.
func (h *Helper) cancelFailedFirewallSuspend() {
	h.dnsMu.Lock()
	h.dnsSuspended = false
	h.dnsMu.Unlock()
	if err := h.reconcileKillSwitch(true, time.Now()); err != nil {
		slog.Error("failed suspend: kill-switch rollback pending", "error", err)
	}
	if err := h.reapplyDNSProtection(); err != nil {
		slog.Error("failed suspend: DNS rollback pending", "error", err)
	}
}

// resumeFirewall releases one successful suspension. Desired settings remain
// intact on apply failure so the safety net can retry after the OS recovers.
func (h *Helper) resumeFirewall() error {
	h.connectMu.Lock()
	defer h.connectMu.Unlock()
	if h.fwSuspendDepth > 0 {
		h.fwSuspendDepth--
	}
	if h.fwSuspendDepth > 0 {
		return nil
	}
	h.dnsMu.Lock()
	h.dnsSuspended = false
	h.dnsApplied = ""
	h.dnsMu.Unlock()
	ksErr := h.reconcileKillSwitch(true, time.Now())
	dnsErr := h.reapplyDNSProtection()
	return errors.Join(ksErr, dnsErr)
}
