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
type counterSample struct {
	historyID string
	snapshot  bool
	name      string
	epoch     string
	rx, tx    int64
}

func countersFromStatus(status ConnectionStatus) map[string]counterSample {
	out := make(map[string]counterSample, len(status.Tunnels)+1)
	add := func(st ConnectionStatus) {
		if st.TunnelName == "" {
			return
		}
		if previous, ok := out[st.TunnelName]; ok && previous.epoch != "" && st.CounterEpoch == "" {
			return
		}
		out[st.TunnelName] = counterSample{name: st.TunnelName, epoch: st.CounterEpoch, rx: st.RxBytes, tx: st.TxBytes}
	}
	add(status)
	for _, st := range status.Tunnels {
		add(st)
	}
	return out
}

func ObserveHistoryStatus(s *TunnelService, status ConnectionStatus) {
	s.reconcileHistoryFromStatus(status.ActiveTunnels, countersFromStatus(status), "")
}

func (s *TunnelService) snapshotCounterSamples() map[string]counterSample {
	historyIDs := make(map[string]string)
	s.activeSessions.Range(func(k, v any) bool { name, _ := k.(string); id, _ := v.(string); historyIDs[name] = id; return true })
	status, err := s.GetStatus()
	if err != nil || status == nil {
		return nil
	}
	samples := countersFromStatus(*status)
	for name, sample := range samples {
		sample.historyID, sample.snapshot = historyIDs[name], true
		samples[name] = sample
	}
	return samples
}

func (s *TunnelService) snapshotCounterSample(wantName string) counterSample {
	if sample, ok := s.snapshotCounterSamples()[wantName]; ok {
		return sample
	}
	return counterSample{name: wantName}
}

func (s *TunnelService) markUserDisconnectSample(sample counterSample) string {
	if sample.epoch == "" {
		return s.markUserDisconnect(sample.name, sample.rx, sample.tx)
	}
	if sample.name == "" {
		return ""
	}
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if s.historyClosed {
		return ""
	}
	id, open := s.activeSessions.Load(sample.name)
	currentID, _ := id.(string)
	var previous lastKnownTunnelStats
	if cached, ok := s.lastKnownStats.Load(sample.name); ok {
		previous, _ = cached.(lastKnownTunnelStats)
	}
	if s.foldTerminalSampleLocked(sample.name, sample) {
		if open {
			previous.reason = "user"
			s.lastKnownStats.Store(sample.name, previous)
		}
		return currentID
	}
	if sample.snapshot && sample.historyID != currentID {
		if !open {
			return ""
		}
		if peak, sameEngine := previous.epochs[sample.epoch]; previous.epoch != sample.epoch && (!sameEngine || peak.inherited) {
			previous.reason = "user"
			s.lastKnownStats.Store(sample.name, previous)
			return currentID
		}
	}
	if !open && s.staleClosedEpochLocked(sample.name, sample) {
		return ""
	}
	if !open && s.historyStore != nil {
		previous = s.seedClosedPeaksLocked(sample.name, lastKnownTunnelStats{})
		delete(s.closedPeaks, sample.name)
		currentID = s.historyStore.RecordConnect(sample.name)
		s.activeSessions.Store(sample.name, currentID)
		s.refreshHistorySignature()
	}
	updated := previous.mergeEpoch(sample.rx, sample.tx, sample.epoch)
	updated.reason = "user"
	s.lastKnownStats.Store(sample.name, updated)
	return currentID
}

func (s *TunnelService) refreshHistorySignature() {
	var active []string
	s.activeSessions.Range(func(k, _ any) bool {
		name, _ := k.(string)
		active = append(active, name)
		return true
	})
	s.lastReconcileSig = activeSetSignature(active)
}

func (s *TunnelService) finishUserDisconnect(name, historyID string) {
	if s.historyStore == nil || historyID == "" {
		return
	}
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if s.historyClosed {
		return
	}
	id, ok := s.activeSessions.Load(name)
	if !ok || id != historyID {
		return
	}
	var stats lastKnownTunnelStats
	if cached, ok := s.lastKnownStats.LoadAndDelete(name); ok {
		stats, _ = cached.(lastKnownTunnelStats)
	}
	if stats.epoch != "" {
		if _, seen := stats.epochs[stats.epoch]; !seen {
			if stats.epochs == nil {
				stats.epochs = make(map[string]counterPeak)
			}
			stats.epochs[stats.epoch] = counterPeak{}
		}
	}
	for epoch, peak := range stats.epochs {
		if !peak.inherited || epoch == stats.epoch && !peak.terminal {
			peak.inherited = false
			peak.terminal, peak.historyID = true, historyID
			stats.epochs[epoch] = peak
		}
	}
	s.rememberClosedPeaksLocked(name, stats)
	s.historyStore.RecordDisconnect(historyID, stats.rx, stats.tx, "user")
	s.activeSessions.Delete(name)
	s.refreshHistorySignature()
}

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
func (s *TunnelService) markUserDisconnect(name string, snapRx, snapTx int64) string {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if name == "" || s.historyClosed {
		return ""
	}
	id, _ := s.activeSessions.Load(name)
	currentID, _ := id.(string)
	if cached, ok := s.lastKnownStats.Load(name); ok {
		if st, ok := cached.(lastKnownTunnelStats); ok {
			st.reason = "user"
			s.lastKnownStats.Store(name, st)
			return currentID
		}
	}
	s.lastKnownStats.Store(name, lastKnownTunnelStats{rx: snapRx, tx: snapTx, rawRx: snapRx, rawTx: snapTx, reason: "user"})
	return currentID
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
	samples := make(map[string]counterSample, len(activeNames))
	for _, name := range activeNames {
		samples[name] = counterSample{name: name, rx: rxByTunnel[name], tx: txByTunnel[name]}
	}
	s.reconcileHistoryFromStatus(activeNames, samples, disappearReason)
}

func (s *TunnelService) reconcileHistoryFromStatus(activeNames []string, samples map[string]counterSample, disappearReason string) {
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

	stale := make(map[string]bool)
	for name := range active {
		sample := samples[name]
		rx, tx := sample.rx, sample.tx
		_, open := s.activeSessions.Load(name)
		if s.foldTerminalSampleLocked(name, sample) {
			if !open {
				stale[name] = true
			}
			continue
		}
		if !open && s.staleClosedEpochLocked(name, sample) {

			stale[name] = true
			continue
		}

		var prev lastKnownTunnelStats
		if cached, ok := s.lastKnownStats.Load(name); ok {
			prev, _ = cached.(lastKnownTunnelStats)
		}

		if !open && (rx != 0 || tx != 0) {
			reason := prev.reason
			if rx < prev.rawRx || tx < prev.rawTx {
				reason = ""
			}
			prev = lastKnownTunnelStats{reason: reason}
		}
		if !open {

			prev = s.seedClosedPeaksLocked(name, prev)
		}
		s.lastKnownStats.Store(name, prev.mergeEpoch(rx, tx, sample.epoch))
	}

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

	opening := make([]string, 0, len(activeNames))
	for _, name := range activeNames {
		if !stale[name] {
			opening = append(opening, name)
		}
	}
	sig := activeSetSignature(opening)
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

			if cached, ok := s.lastKnownStats.LoadAndDelete(name); ok {
				if st, ok := cached.(lastKnownTunnelStats); ok {
					rx = st.rx
					tx = st.tx
					if st.reason != "" {
						reason = st.reason
					}
					s.rememberClosedPeaksLocked(name, st)
				}
			}
			s.historyStore.RecordDisconnect(id, rx, tx, reason)
		}
		s.activeSessions.Delete(k)
		return true
	})

	for _, name := range opening {
		if name == "" {
			continue
		}
		if _, exists := s.activeSessions.Load(name); exists {
			continue
		}
		id := s.historyStore.RecordConnect(name)
		s.activeSessions.Store(name, id)
		delete(s.closedPeaks, name)
	}
}

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
	s.closedPeaks = nil
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
	var samples map[string]counterSample
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var status ConnectionStatus
	if err := s.callWithContext(ctx, ipc.MethodStatus, nil, &status); err == nil {
		samples = countersFromStatus(status)
	}
	s.activeSessions.Range(func(k, v any) bool {
		name, _ := k.(string)
		id, _ := v.(string)
		if id != "" {
			sample := samples[name]
			rx, tx := sample.rx, sample.tx
			// Fall back to last-known cache when the helper status
			// didn't include this tunnel (e.g. helper already torn
			// down the interface but the GUI's session map is fresh).
			// Merge rather than only fall back on zero: a status taken
			// mid-teardown can report small non-zero counters from a fresh
			// device that are below what the session already transferred.
			if cached, ok := s.lastKnownStats.Load(name); ok {
				if st, ok := cached.(lastKnownTunnelStats); ok {
					m := st.mergeEpoch(rx, tx, sample.epoch)
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

func (s *TunnelService) staleClosedEpochLocked(name string, sample counterSample) bool {
	if sample.epoch == "" {
		return false
	}
	peak, ok := s.closedPeaks[name][sample.epoch]
	return ok && (peak.terminal || sample.rx <= peak.rx && sample.tx <= peak.tx)
}

func (s *TunnelService) seedClosedPeaksLocked(name string, st lastKnownTunnelStats) lastKnownTunnelStats {
	closed := s.closedPeaks[name]
	if len(closed) == 0 {
		return st
	}
	epochs := make(map[string]counterPeak, len(st.epochs)+len(closed))
	for epoch, peak := range st.epochs {
		epochs[epoch] = peak
	}
	for epoch, peak := range closed {
		if _, ok := epochs[epoch]; !ok {
			peak.inherited = true
			epochs[epoch] = peak
		}
	}
	st.epochs = epochs
	return st
}

func (s *TunnelService) rememberClosedPeaksLocked(name string, st lastKnownTunnelStats) {
	own := make(map[string]counterPeak, len(st.epochs))
	for epoch, peak := range st.epochs {
		if !peak.inherited {
			own[epoch] = peak
		}
	}
	if len(own) == 0 {
		delete(s.closedPeaks, name)
		return
	}
	if s.closedPeaks == nil {
		s.closedPeaks = make(map[string]map[string]counterPeak)
	}
	s.closedPeaks[name] = own
}

func (s *TunnelService) foldTerminalSampleLocked(name string, sample counterSample) bool {
	var peaks map[string]counterPeak
	if cached, ok := s.lastKnownStats.Load(name); ok {
		if stats, ok := cached.(lastKnownTunnelStats); ok {
			peaks = stats.epochs
		}
	}
	peak, known := peaks[sample.epoch]
	if !known || !peak.terminal {
		peaks = s.closedPeaks[name]
		peak, known = peaks[sample.epoch]
	}
	if !known || !peak.terminal {
		return false
	}
	rx, tx := max(sample.rx-peak.rx, 0), max(sample.tx-peak.tx, 0)
	if rx != 0 || tx != 0 {
		peak.rx, peak.tx = max(peak.rx, sample.rx), max(peak.tx, sample.tx)
		peaks[sample.epoch] = peak
		s.historyStore.AddClosedSessionTraffic(peak.historyID, rx, tx)
	}
	return true
}
