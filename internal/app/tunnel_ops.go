package app

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

// SetTunnelNotes persists a freeform note for a tunnel. Empty notes still
// write an empty .meta.json — that matches the contract the frontend
// expects (write always succeeds, no special-case for "clear").
//
// Existence check first to avoid orphaning a .meta.json sidecar after the
// .conf was deleted: TunnelDetail's onDestroy can fire-and-forget a
// pending-edit flush after the user deletes a tunnel, and writing the
// sidecar in that window would leave a stale file the next tunnel-of-the-
// same-name would inherit.
func (s *TunnelService) SetTunnelNotes(name, notes string) error {
	return s.tunnelStore.UpdateMeta(name, func(meta *storage.TunnelMeta) {
		meta.Notes = notes
	})
}

// SetTunnelLatencyProbeTarget persists the optional per-tunnel ICMP target
// used only for latency display. The value is deliberately stored outside the
// WireGuard .conf so exports remain compatible with other clients.
func (s *TunnelService) SetTunnelLatencyProbeTarget(name, target string) error {
	target = strings.TrimSpace(target)
	if target != "" && !config.IsValidHostOrIP(target) {
		return fmt.Errorf("latency target %q is not a valid IP address or hostname", target)
	}
	return s.tunnelStore.UpdateMeta(name, func(meta *storage.TunnelMeta) {
		meta.LatencyProbeTarget = target
	})
}

// CheckConflicts loads a tunnel's config and scans local network interfaces
// for routing overlaps (e.g. Tailscale, another WireGuard instance). Runs
// entirely in the GUI process — no IPC needed. The frontend calls this before
// Connect so it can show a warning dialog if conflicts exist.
func (s *TunnelService) CheckConflicts(name string) ([]diag.ConflictInfo, error) {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return nil, fmt.Errorf("loading tunnel %s: %w", name, err)
	}
	var allowedIPs []string
	for _, peer := range cfg.Peers {
		allowedIPs = append(allowedIPs, peer.AllowedIPs...)
	}
	conflicts, err := diag.CheckConflicts(allowedIPs)
	if err != nil {
		slog.Warn("conflict check failed", "tunnel", name, "error", err)
		// Non-fatal — don't block connect if the scan itself fails.
		return nil, nil
	}
	return conflicts, nil
}

// Connect loads a tunnel config from local storage and asks the helper to
// bring it up. The helper re-validates server-side.
//
// Session lifecycle is owned entirely by ReconcileHistoryFromStatus —
// opening here would race the helper's StateConnecting status broadcast,
// which already includes the tunnel name in ActiveTunnels. The race
// produced spurious "Reconnected" rows on every user-initiated connect
// before this was unified.
func (s *TunnelService) Connect(name string) error {
	cfg, err := s.tunnelStore.Load(name)
	if err != nil {
		return fmt.Errorf("loading tunnel %s: %w", name, err)
	}

	// Mark the RPC as in-flight so the health monitor doesn't falsely
	// detect helper death while the server is busy processing Connect
	// (which blocks the per-connection request loop, preventing pings).
	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()

	return s.callLong(ipc.MethodConnect, ipc.ConnectRequest{
		Config: cfg,
	}, nil)
}

// Disconnect tears down whatever tunnel the helper currently has active.
// If the call fails with a "client closed" error (the health monitor may have
// swapped the client during a recovery), retry once with the fresh client.
//
// We mark lastKnownStats with reason "user" so the upcoming Reconcile (after
// the next status event with the tunnel gone) labels the closed session as
// a user disconnect. Existing fresh rx/tx counters from Reconcile's per-tick
// refresh are preserved — markUserDisconnect overwrites only the reason,
// not the bytes. This is what protects against rapid double-clicks: the
// second Disconnect's snapshot may be 0/0 (helper already tearing down)
// but the cache still holds the fresh values from the steady state.
func (s *TunnelService) Disconnect() error {
	name, rx, tx := s.snapshotActiveStats("")
	s.markUserDisconnect(name, rx, tx)

	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()
	err := s.callLong(ipc.MethodDisconnect, nil, nil)
	if err != nil && isClientClosed(err) {
		slog.Info("disconnect got client-closed, retrying with fresh client")
		err = s.callLong(ipc.MethodDisconnect, nil, nil)
	}
	if err != nil {
		// IPC failed — the "user" hint is suspect (helper might still
		// have the tunnel up). Clear the hint, KEEP the rx/tx so a
		// genuine helper-driven close still has accurate counters.
		s.clearUserDisconnect(name)
	}
	return err
}

// DisconnectTunnel disconnects a specific tunnel by name. Mirrors
// Disconnect()'s "client closed" retry: a helper recovery during a
// per-tunnel disconnect (e.g. user clicks the tray's per-tunnel
// item right when the health monitor swaps clients) should be
// transparent, not surfaced as a confusing error.
func (s *TunnelService) DisconnectTunnel(name string) error {
	_, rx, tx := s.snapshotActiveStats(name)
	s.markUserDisconnect(name, rx, tx)

	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()
	err := s.callLong(ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: name}, nil)
	if err != nil && isClientClosed(err) {
		slog.Info("disconnect-tunnel got client-closed, retrying with fresh client",
			"tunnel", name)
		err = s.callLong(ipc.MethodDisconnect, ipc.DisconnectRequest{TunnelName: name}, nil)
	}
	if err != nil {
		s.clearUserDisconnect(name)
	}
	return err
}

// isClientClosed returns true for errors caused by the IPC client being closed
// mid-call (e.g., health monitor swapped clients during recovery). Uses
// errors.Is so wrapped errors still match — substring matching would have
// false positives on unrelated errors whose messages happen to contain
// "client closed".
func isClientClosed(err error) bool {
	return errors.Is(err, ipc.ErrClientClosed)
}

// GetStatus queries the helper for the current connection status. IPC errors
// are surfaced to the caller — the frontend needs to distinguish "helper says
// disconnected" from "helper unreachable".
func (s *TunnelService) GetStatus() (*ConnectionStatus, error) {
	var status ConnectionStatus
	if err := s.call(ipc.MethodStatus, nil, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// GetTunnelDetail returns the full WireGuardConfig for a tunnel. Used by the
// detail pane to show allowed IPs, DNS, public keys, etc.
func (s *TunnelService) GetTunnelDetail(name string) (*domain.WireGuardConfig, error) {
	return s.tunnelStore.Load(name)
}

// isActiveTunnel returns true if `name` is currently up. Uses the
// multi-tunnel ActiveTunnels list, NOT ActiveName, because the
// latter only returns the lexicographically-first connected tunnel
// — which made delete/rename/update incorrectly succeed against a
// non-primary connected tunnel and orphan the live interface.
func (s *TunnelService) isActiveTunnel(name string) (bool, error) {
	var resp ipc.ActiveTunnelsResponse
	if err := s.call(ipc.MethodActiveTunnels, nil, &resp); err != nil {
		return false, err
	}
	for _, n := range resp.Names {
		if n == name {
			return true, nil
		}
	}
	return false, nil
}

// DeleteTunnel removes a tunnel from local storage. Rejects deletion of the
// currently connected tunnel (would orphan the interface).
func (s *TunnelService) DeleteTunnel(name string) error {
	s.clients.MarkInflight()
	defer s.clients.UnmarkInflight()
	if err := s.callLong(ipc.MethodDelete, ipc.DeleteRequest{TunnelName: name}, nil); err != nil {
		return fmt.Errorf("deleting tunnel through helper: %w", err)
	}
	// Drop the tunnel's automation rules so they don't linger and re-attach
	// to a future same-named tunnel (issue #12). Best-effort — the tunnel
	// is already gone.
	if err := s.settingsStore.Update(func(cfg *storage.Settings) error {
		cfg.DeleteTunnelRules(name)
		return nil
	}); err != nil {
		slog.Warn("deleted tunnel but could not remove its automation rules", "tunnel", name, "error", err)
	}
	return nil
}

// RenameTunnel changes a tunnel's name. Rejects rename of the connected
// tunnel since the interface name is derived from it.
//
// Routes through the helper's Tunnel.Rename so the active-tunnel check and
// the file rename both happen under the helper's connectMu — closing the
// race where a Connect arriving between the GUI's check and the rename
// could leave the new name in activeCfgs while the file path moved.
//
// Falls back to a direct local rename if the helper rejects the method
// (older helper that hasn't been upgraded yet).
func (s *TunnelService) RenameTunnel(oldName, newName string) error {
	if err := storage.ValidateTunnelName(newName); err != nil {
		return err
	}
	if oldName == newName {
		return nil
	}
	err := s.call(ipc.MethodRename, ipc.RenameRequest{OldName: oldName, NewName: newName}, nil)
	if err != nil {
		if !isMethodNotFound(err) {
			return err
		}
		active, activeErr := s.isActiveTunnel(oldName)
		if activeErr != nil {
			return fmt.Errorf("cannot verify tunnel state (helper unreachable): %w", activeErr)
		}
		if active {
			return fmt.Errorf("cannot rename connected tunnel %q — disconnect first", oldName)
		}
		if err := s.tunnelStore.Rename(oldName, newName); err != nil {
			return err
		}
	}
	// Carry the tunnel's automation rules over to the new name so they
	// aren't orphaned (issue #12). Best-effort — the rename succeeded.
	if err := s.settingsStore.Update(func(cfg *storage.Settings) error {
		cfg.RenameTunnelRules(oldName, newName)
		return nil
	}); err != nil {
		slog.Warn("renamed tunnel but could not move its automation rules",
			"from", oldName, "to", newName, "error", err)
	}
	return nil
}

// isMethodNotFound classifies an IPC error as "old helper doesn't know
// this method" so callers can fall back to a local-only path.
func isMethodNotFound(err error) bool {
	if err == nil {
		return false
	}
	var coded *ipc.Error
	if errors.As(err, &coded) {
		return coded.Code == ipc.ErrCodeMethodNotFound
	}
	return false
}

// TunnelExists reports whether a tunnel with the given name is stored.
func (s *TunnelService) TunnelExists(name string) bool {
	return s.tunnelStore.Exists(name)
}
