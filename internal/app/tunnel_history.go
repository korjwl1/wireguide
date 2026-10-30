package app

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

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

// markUserDisconnect sets the reason hint on a tunnel's lastKnownStats to
// "user", preserving any rx/tx the Reconcile-driven cache refresh has
// already recorded. snapRx/snapTx is a fallback for the cold case (no
// cache entry yet — first Disconnect before any status event was reconciled).
func (s *TunnelService) markUserDisconnect(name string, snapRx, snapTx int64) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if name == "" {
		return
	}
	if cached, ok := s.lastKnownStats.Load(name); ok {
		if st, ok := cached.(lastKnownTunnelStats); ok {
			st.reason = "user"
			s.lastKnownStats.Store(name, st)
			return
		}
	}
	s.lastKnownStats.Store(name, lastKnownTunnelStats{rx: snapRx, tx: snapTx, rawRx: snapRx, rawTx: snapTx, reason: "user"})
}

// clearUserDisconnect removes the "user" reason hint after a failed
// Disconnect IPC, leaving rx/tx intact. Other reasons (or empty) are left
// alone — only the hint we set ourselves is cleared.
func (s *TunnelService) clearUserDisconnect(name string) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if name == "" {
		return
	}
	if cached, ok := s.lastKnownStats.Load(name); ok {
		if st, ok := cached.(lastKnownTunnelStats); ok && st.reason == "user" {
			st.reason = ""
			s.lastKnownStats.Store(name, st)
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
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if s.historyClosed {
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
		// Fold the reading into the session totals instead of overwriting:
		// a Connecting/Disconnecting tunnel reports 0/0 while still active.
		var prev lastKnownTunnelStats
		if cached, ok := s.lastKnownStats.Load(name); ok {
			prev, _ = cached.(lastKnownTunnelStats)
		}
		// With no open session this is the first reading of a new one, so a
		// cache entry still left by an earlier session must not be carried
		// into it (entries of absent tunnels are dropped below, so this
		// covers a Disconnect clicked while the tunnel was listed). A
		// zeroed reading proves nothing and keeps the entry: it may be the
		// pre-disconnect snapshot of the session about to be opened. The
		// reason hint survives only if the counters did not go backwards.
		if _, open := s.activeSessions.Load(name); !open && (rx != 0 || tx != 0) {
			reason := prev.reason
			if rx < prev.rawRx || tx < prev.rawTx {
				reason = ""
			}
			prev = lastKnownTunnelStats{reason: reason}
		}
		s.lastKnownStats.Store(name, prev.merge(rx, tx))
	}

	// A cache entry with no active tunnel and no open session belongs to no
	// session: it was left by a Disconnect that never got a session opened,
	// or by a cold snapshot. Drop it here, before the fast path below, so it
	// cannot seed (or label "user") a later session whose first reading is
	// a zeroed Connecting tick. A tunnel closing on this tick is still in
	// activeSessions, so its counters survive for RecordDisconnect.
	s.lastKnownStats.Range(func(k, _ any) bool {
		name, _ := k.(string)
		if _, isActive := active[name]; isActive {
			return true
		}
		if _, open := s.activeSessions.Load(name); open {
			return true
		}
		s.lastKnownStats.Delete(k)
		return true
	})

	// Build a stable signature of the active set and compare to the prior
	// one. If unchanged, we know there are no new appearances or
	// disappearances to record. The cache update above handles the steady
	// state; this skip just avoids the (cheap but constant) diff work at 1 Hz.
	sig := activeSetSignature(activeNames)
	unchanged := sig == s.lastReconcileSig
	s.lastReconcileSig = sig
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
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	s.historyClosed = true
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var status ConnectionStatus
	if err := s.callWithContext(ctx, ipc.MethodStatus, nil, &status); err == nil {
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
			// Merge rather than only fall back on zero: a status taken
			// mid-teardown can report small non-zero counters from a fresh
			// device that are below what the session already transferred.
			if cached, ok := s.lastKnownStats.Load(name); ok {
				if st, ok := cached.(lastKnownTunnelStats); ok {
					m := st.merge(rx, tx)
					rx, tx = m.rx, m.tx
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
