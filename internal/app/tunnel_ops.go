package app

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/diag"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

// ListTunnelsLocal returns stored tunnels WITHOUT asking the helper which one
// is active — callers that already know the active name (e.g. the system
// tray, which tracks it from the status event stream) should use this to
// avoid an IPC round-trip on every refresh. IsConnected is always false in
// the returned slice; the caller is responsible for applying its own
// active-name match.
func (s *TunnelService) ListTunnelsLocal() ([]TunnelInfo, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}
	lastUsed := s.lastUsedByTunnel()
	var result []TunnelInfo
	for _, name := range names {
		cfg, meta, err := s.tunnelStore.LoadWithMeta(name)
		if err != nil {
			slog.Warn("skipping broken tunnel config", "name", name, "error", err)
			continue
		}
		endpoint := ""
		if len(cfg.Peers) > 0 {
			endpoint = cfg.Peers[0].Endpoint
		}
		notes := ""
		latencyProbeTarget := ""
		if meta != nil {
			notes = meta.Notes
			latencyProbeTarget = meta.LatencyProbeTarget
		}
		result = append(result, TunnelInfo{
			Name:               name,
			Endpoint:           endpoint,
			Notes:              notes,
			LatencyProbeTarget: latencyProbeTarget,
			CreatedAtUnix:      s.tunnelStore.ModTimeUnix(name),
			LastUsedUnix:       lastUsed[name],
		})
	}
	return result, nil
}

// lastUsedByTunnel maps each tunnel name to the Unix time of its most
// recent connection start, from history. Missing tunnels get the zero
// value (0 = never connected). Computed once per list call.
func (s *TunnelService) lastUsedByTunnel() map[string]int64 {
	out := map[string]int64{}
	if s.historyStore == nil {
		return out
	}
	for _, sess := range s.historyStore.GetAll() {
		if t := sess.StartTime.Unix(); t > out[sess.TunnelName] {
			out[sess.TunnelName] = t
		}
	}
	return out
}

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
	if !s.tunnelStore.Exists(name) {
		return fmt.Errorf("tunnel %q does not exist", name)
	}
	return s.tunnelStore.UpdateMeta(name, func(meta *storage.TunnelMeta) {
		meta.Notes = notes
	})
}

// SetTunnelLatencyProbeTarget persists the optional per-tunnel ICMP target
// used only for latency display. The value is deliberately stored outside the
// WireGuard .conf so exports remain compatible with other clients.
func (s *TunnelService) SetTunnelLatencyProbeTarget(name, target string) error {
	if !s.tunnelStore.Exists(name) {
		return fmt.Errorf("tunnel %q does not exist", name)
	}
	target = strings.TrimSpace(target)
	if target != "" && !config.IsValidHostOrIP(target) {
		return fmt.Errorf("latency target %q is not a valid IP address or hostname", target)
	}
	return s.tunnelStore.UpdateMeta(name, func(meta *storage.TunnelMeta) {
		meta.LatencyProbeTarget = target
	})
}

// ListTunnels returns every stored tunnel with its summary info.
//
// The active-tunnel marker used to come from an IPC round-trip on every call.
// That made the tray's rebuild-menu path slow when it was being invoked on
// the status event stream. The frontend now learns the active tunnel from
// the status event itself, and the tray caches it internally — so this
// function stays fully local (disk-only, no IPC) and returns IsConnected
// purely as a best-effort flag based on a single active-name probe that is
// safe to skip entirely on slow paths.
func (s *TunnelService) ListTunnels() ([]TunnelInfo, error) {
	names, err := s.tunnelStore.List()
	if err != nil {
		return nil, err
	}

	// One cheap probe for the active tunnel — used by the frontend's initial
	// load before it has received its first status event. The tray no longer
	// relies on this (it tracks active tunnel via the status stream).
	var active ipc.StringResponse
	_ = s.call(ipc.MethodActiveName, nil, &active)

	lastUsed := s.lastUsedByTunnel()
	var result []TunnelInfo
	for _, name := range names {
		cfg, meta, err := s.tunnelStore.LoadWithMeta(name)
		if err != nil {
			slog.Warn("skipping broken tunnel config", "name", name, "error", err)
			continue
		}
		endpoint := ""
		if len(cfg.Peers) > 0 {
			endpoint = cfg.Peers[0].Endpoint
		}
		notes := ""
		latencyProbeTarget := ""
		if meta != nil {
			notes = meta.Notes
			latencyProbeTarget = meta.LatencyProbeTarget
		}
		result = append(result, TunnelInfo{
			Name:               name,
			IsConnected:        name == active.Value,
			Endpoint:           endpoint,
			Notes:              notes,
			LatencyProbeTarget: latencyProbeTarget,
			CreatedAtUnix:      s.tunnelStore.ModTimeUnix(name),
			LastUsedUnix:       lastUsed[name],
		})
	}
	return result, nil
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

// markUserDisconnect sets the reason hint on a tunnel's lastKnownStats to
// "user", preserving any rx/tx the Reconcile-driven cache refresh has
// already recorded. snapRx/snapTx is a fallback for the cold case (no
// cache entry yet — first Disconnect before any status event was reconciled).
func (s *TunnelService) markUserDisconnect(name string, snapRx, snapTx int64) {
	if name == "" {
		return
	}
	if cached, ok := s.lastKnownStats.Load(name); ok {
		if st, ok := cached.(lastKnownTunnelStats); ok {
			s.lastKnownStats.Store(name, lastKnownTunnelStats{rx: st.rx, tx: st.tx, reason: "user"})
			return
		}
	}
	s.lastKnownStats.Store(name, lastKnownTunnelStats{rx: snapRx, tx: snapTx, reason: "user"})
}

// clearUserDisconnect removes the "user" reason hint after a failed
// Disconnect IPC, leaving rx/tx intact. Other reasons (or empty) are left
// alone — only the hint we set ourselves is cleared.
func (s *TunnelService) clearUserDisconnect(name string) {
	if name == "" {
		return
	}
	if cached, ok := s.lastKnownStats.Load(name); ok {
		if st, ok := cached.(lastKnownTunnelStats); ok && st.reason == "user" {
			s.lastKnownStats.Store(name, lastKnownTunnelStats{rx: st.rx, tx: st.tx, reason: ""})
		}
	}
}

// snapshotActiveStats returns (tunnelName, rx, tx) for the tunnel about to
// disconnect. Empty wantName picks the primary active tunnel. Returns zero
// values on any error — capturing stats is best-effort and never blocks
// disconnect.
func (s *TunnelService) snapshotActiveStats(wantName string) (string, int64, int64) {
	status, err := s.GetStatus()
	if err != nil || status == nil {
		return wantName, 0, 0
	}
	if wantName == "" {
		if status.TunnelName != "" {
			return status.TunnelName, status.RxBytes, status.TxBytes
		}
		if len(status.Tunnels) > 0 {
			t := status.Tunnels[0]
			return t.TunnelName, t.RxBytes, t.TxBytes
		}
		return "", 0, 0
	}
	if status.TunnelName == wantName {
		return wantName, status.RxBytes, status.TxBytes
	}
	for _, t := range status.Tunnels {
		if t.TunnelName == wantName {
			return wantName, t.RxBytes, t.TxBytes
		}
	}
	return wantName, 0, 0
}

// ReconcileHistoryFromStatus is the SINGLE source of truth for opening and
// closing history sessions. The event bridge calls it on every status event;
// it diffs the active set against activeSessions and:
//
//   - opens a session for any active tunnel not currently tracked (covers
//     both user-initiated Connect and helper-driven auto-reconnect / wifi
//     rules engine / sleep-wake)
//   - closes a session for any tracked tunnel that has disappeared (using
//     cached rx/tx + cached reason from lastKnownStats; falls back to
//     disappearReason — defaults to "reconnect")
//
// Stats cache is always refreshed for currently-active tunnels so disconnect
// closes have ≤ 1 status-event-tick stale counters. Reason hints set by
// user-initiated Disconnect / DisconnectTunnel are preserved across cache
// refreshes — only LoadAndDelete on close clears them.
//
// Fast-path: if the sorted active set hasn't changed since the prior call
// (the steady-state case at 1 Hz), we skip the activeSessions Range and the
// open-session loop. The stats cache still gets updated so the eventual
// disappear-close uses fresh counters.
func (s *TunnelService) ReconcileHistoryFromStatus(activeNames []string, rxByTunnel, txByTunnel map[string]int64, disappearReason string) {
	if s.historyStore == nil {
		return
	}
	if disappearReason == "" {
		disappearReason = "reconnect"
	}
	active := make(map[string]struct{}, len(activeNames))
	for _, n := range activeNames {
		if n != "" {
			active[n] = struct{}{}
		}
	}

	// Refresh cache for currently-active tunnels. Always done — even on the
	// fast path — so the next disappearance close sees fresh stats. Preserve
	// any reason hint already in the cache (set by Disconnect/DisconnectTunnel
	// before the IPC call).
	for name := range active {
		var rx, tx int64
		if rxByTunnel != nil {
			rx = rxByTunnel[name]
		}
		if txByTunnel != nil {
			tx = txByTunnel[name]
		}
		reason := ""
		if cached, ok := s.lastKnownStats.Load(name); ok {
			if st, ok := cached.(lastKnownTunnelStats); ok {
				reason = st.reason
			}
		}
		s.lastKnownStats.Store(name, lastKnownTunnelStats{rx: rx, tx: tx, reason: reason})
	}

	// Build a stable signature of the active set and compare to the prior
	// one. If unchanged, we know there are no new appearances or
	// disappearances to record. The cache update above handles the steady
	// state; this skip just avoids the (cheap but constant) diff work at 1 Hz.
	sig := activeSetSignature(activeNames)
	s.reconcileMu.Lock()
	unchanged := sig == s.lastReconcileSig
	s.lastReconcileSig = sig
	s.reconcileMu.Unlock()
	if unchanged {
		return
	}

	s.activeSessions.Range(func(k, v any) bool {
		name, _ := k.(string)
		id, _ := v.(string)
		if _, stillActive := active[name]; stillActive {
			return true
		}
		if id != "" {
			var rx, tx int64
			reason := disappearReason
			// Prefer cached last-seen counters and reason — the current event's
			// maps don't include this tunnel since it just disappeared, and a
			// pre-set reason from user Disconnect overrides the default.
			if cached, ok := s.lastKnownStats.LoadAndDelete(name); ok {
				if st, ok := cached.(lastKnownTunnelStats); ok {
					rx = st.rx
					tx = st.tx
					if st.reason != "" {
						reason = st.reason
					}
				}
			}
			s.historyStore.RecordDisconnect(id, rx, tx, reason)
		}
		s.activeSessions.Delete(k)
		return true
	})

	for _, name := range activeNames {
		if name == "" {
			continue
		}
		if _, exists := s.activeSessions.Load(name); exists {
			continue
		}
		id := s.historyStore.RecordConnect(name)
		s.activeSessions.Store(name, id)
	}
}

// activeSetSignature returns a stable string representation of activeNames
// suitable for equality comparison across status events. Sorted so the
// helper's order is irrelevant; null byte separator avoids collisions
// between names like ["a", "bc"] and ["ab", "c"].
func activeSetSignature(names []string) string {
	if len(names) == 0 {
		return ""
	}
	cp := make([]string, 0, len(names))
	for _, n := range names {
		if n != "" {
			cp = append(cp, n)
		}
	}
	sort.Strings(cp)
	return strings.Join(cp, "\x00")
}

// CloseHistorySessions closes any open history sessions with the given reason.
// Called from gui.Run during shutdown so the UI doesn't show phantom "Active"
// rows after a quit.
//
// Single GetStatus probe — the previous one-IPC-per-session pattern made
// shutdown latency scale linearly with active tunnel count. The status
// response carries every active tunnel's rx/tx, so one round-trip is enough.
// Falls back to the lastKnownStats cache (and ultimately zeros) when the
// helper is already unreachable. Skipped entirely when no sessions are open
// (the common quit-while-disconnected case) so shutdown stays snappy.
func (s *TunnelService) CloseHistorySessions(reason string) {
	if s.historyStore == nil {
		return
	}
	hasOpen := false
	s.activeSessions.Range(func(_, _ any) bool {
		hasOpen = true
		return false // first hit is enough
	})
	if !hasOpen {
		// Still call CloseOpenSessions: a previous crash could have left
		// open rows in the file that the GUI never tracked.
		s.historyStore.CloseOpenSessions(reason)
		return
	}
	rxByTunnel := make(map[string]int64)
	txByTunnel := make(map[string]int64)
	if status, err := s.GetStatus(); err == nil && status != nil {
		if status.TunnelName != "" {
			rxByTunnel[status.TunnelName] = status.RxBytes
			txByTunnel[status.TunnelName] = status.TxBytes
		}
		for _, ts := range status.Tunnels {
			rxByTunnel[ts.TunnelName] = ts.RxBytes
			txByTunnel[ts.TunnelName] = ts.TxBytes
		}
	}
	s.activeSessions.Range(func(k, v any) bool {
		name, _ := k.(string)
		id, _ := v.(string)
		if id != "" {
			rx, tx := rxByTunnel[name], txByTunnel[name]
			// Fall back to last-known cache when the helper status
			// didn't include this tunnel (e.g. helper already torn
			// down the interface but the GUI's session map is fresh).
			if rx == 0 && tx == 0 {
				if cached, ok := s.lastKnownStats.Load(name); ok {
					if st, ok := cached.(lastKnownTunnelStats); ok {
						rx, tx = st.rx, st.tx
					}
				}
			}
			s.historyStore.RecordDisconnect(id, rx, tx, reason)
		}
		s.activeSessions.Delete(k)
		s.lastKnownStats.Delete(k)
		return true
	})
	s.historyStore.CloseOpenSessions(reason)
}

// GetConnectionHistory returns recorded sessions newest-first. Always returns
// a non-nil slice so the frontend doesn't have to special-case "no history
// yet" vs. "load failed".
func (s *TunnelService) GetConnectionHistory() ([]storage.Session, error) {
	if s.historyStore == nil {
		return []storage.Session{}, nil
	}
	out := s.historyStore.GetAll()
	if out == nil {
		out = []storage.Session{}
	}
	return out, nil
}

// ClearConnectionHistory wipes the history file.
func (s *TunnelService) ClearConnectionHistory() error {
	if s.historyStore == nil {
		return nil
	}
	return s.historyStore.Clear()
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
	active, err := s.isActiveTunnel(name)
	if err != nil {
		return fmt.Errorf("cannot verify tunnel state (helper unreachable): %w", err)
	}
	if active {
		return fmt.Errorf("cannot delete connected tunnel %q — disconnect first", name)
	}
	return s.tunnelStore.Delete(name)
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
	if err == nil {
		return nil
	}
	if isMethodNotFound(err) {
		active, activeErr := s.isActiveTunnel(oldName)
		if activeErr != nil {
			return fmt.Errorf("cannot verify tunnel state (helper unreachable): %w", activeErr)
		}
		if active {
			return fmt.Errorf("cannot rename connected tunnel %q — disconnect first", oldName)
		}
		return s.tunnelStore.Rename(oldName, newName)
	}
	return err
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
