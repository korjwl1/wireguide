package app

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

// lastUsedByTunnel maps each tunnel name to the Unix time of its most
// recent connection start, from history. Missing tunnels get the zero
// value (0 = never connected). Computed once per list call.
type counterSample struct {
	source    *ipc.Client
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

func ObserveHistoryStatus(s *TunnelService, status ConnectionStatus, sources ...*ipc.Client) {
	s.reconcileHistoryFromStatus(status.ActiveTunnels, countersFromStatus(status), "", sources...)
}

func (s *TunnelService) snapshotCounterSamples() map[string]counterSample {
	historyIDs := make(map[string]string)
	s.activeSessions.Range(func(k, v any) bool { name, _ := k.(string); id, _ := v.(string); historyIDs[name] = id; return true })
	status, source, err := s.statusSnapshot()
	if err != nil || status == nil {
		return nil
	}
	samples := countersFromStatus(*status)
	for name, sample := range samples {
		sample.historyID, sample.snapshot, sample.source = historyIDs[name], true, source
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

type disconnectTarget struct {
	historyID string
	epoch     string
	source    *ipc.Client
}

func (s *TunnelService) markUserDisconnectSample(sample counterSample) string {
	return s.prepareUserDisconnect(sample).historyID
}

func (s *TunnelService) prepareUserDisconnect(sample counterSample) disconnectTarget {
	if sample.epoch == "" {
		return disconnectTarget{historyID: s.markUserDisconnect(sample.name, sample.rx, sample.tx, sample.source), source: sample.source}
	}
	if sample.name == "" {
		return disconnectTarget{}
	}
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if s.historyClosed || !s.currentHistorySource(sample.source) {
		return disconnectTarget{}
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
		return disconnectTarget{historyID: currentID, epoch: previous.epoch, source: sample.source}
	}
	if sample.snapshot && sample.historyID != currentID {
		if !open {
			return disconnectTarget{}
		}
		if peak, sameEngine := previous.epochs[sample.epoch]; previous.epoch != sample.epoch && (!sameEngine || peak.inherited) {
			previous.reason = "user"
			s.lastKnownStats.Store(sample.name, previous)
			return disconnectTarget{historyID: currentID, epoch: previous.epoch, source: sample.source}
		}
	}
	if !open && s.staleClosedEpochLocked(sample.name, sample) {
		return disconnectTarget{}
	}
	if !open && s.historyStore != nil {
		previous = s.seedClosedPeaksLocked(sample.name, lastKnownTunnelStats{})
		currentID = s.historyStore.RecordConnect(sample.name)
		s.activeSessions.Store(sample.name, currentID)
		s.refreshHistorySignature()
	}
	updated := previous.mergeEpoch(sample.rx, sample.tx, sample.epoch)
	updated.reason = "user"
	s.lastKnownStats.Store(sample.name, updated)
	return disconnectTarget{historyID: currentID, epoch: updated.epoch, source: sample.source}
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

func (s *TunnelService) finishUserDisconnect(name string, target disconnectTarget) {
	historyID := target.historyID
	if s.historyStore == nil || historyID == "" {
		return
	}
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if s.historyClosed || !s.currentHistorySource(target.source) {
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
	if target.epoch == "" {
		target.epoch = stats.epoch
	}
	stats.ensureEpochIdentity(stats.epoch)
	future := lastKnownTunnelStats{epochs: make(map[string]counterPeak)}
	owner, cutoff, ordered := domain.ParseCounterEpoch(target.epoch)
	currentOwner, _, currentOrdered := domain.ParseCounterEpoch(stats.epoch)
	for epoch, peak := range stats.epochs {
		incarnation, sequence, ok := domain.ParseCounterEpoch(epoch)
		newer := ordered && ok && (owner == incarnation && sequence > cutoff || currentOrdered && currentOwner != owner && incarnation == currentOwner)
		if !ordered {
			newer = epoch == stats.epoch && epoch != target.epoch
		}
		if !newer {
			continue
		}
		rx, tx := peak.rx-peak.baseRx, peak.tx-peak.baseTx
		future.rx += rx
		future.tx += tx
		stats.rx -= rx
		stats.tx -= tx
		future.epochs[epoch] = peak
		if future.epoch == "" || earlierCounterEpoch(future.epoch, epoch) || epoch == stats.epoch {
			future.epoch = epoch
			future.rawRx = peak.rx
			future.rawTx = peak.tx
		}
		delete(stats.epochs, epoch)
	}
	stats.epoch = target.epoch
	stats.ensureEpochIdentity(target.epoch)

	for epoch, peak := range stats.epochs {
		if !peak.inherited || epoch == stats.epoch && !peak.terminal {
			peak.inherited = false
			peak.terminal, peak.historyID = true, historyID
			stats.epochs[epoch] = peak
		}
	}
	s.rememberClosedPeaksLocked(name, stats, historyID)
	s.historyStore.RecordDisconnect(historyID, stats.rx, stats.tx, "user")
	s.activeSessions.Delete(name)
	if len(future.epochs) > 0 {
		s.activeSessions.Store(name, s.historyStore.RecordConnect(name))
		s.lastKnownStats.Store(name, future)
	}
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
func (s *TunnelService) markUserDisconnect(name string, snapRx, snapTx int64, sources ...*ipc.Client) string {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if name == "" || s.historyClosed || !s.currentHistorySources(sources) {
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
func (s *TunnelService) clearUserDisconnect(name string, historyIDs ...string) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	s.clearUserDisconnectLocked(name, historyIDs)
}

func (s *TunnelService) clearUserDisconnectLocked(name string, historyIDs []string) {
	if len(historyIDs) != 0 {
		id, _ := s.activeSessions.Load(name)
		currentID, _ := id.(string)
		if currentID != historyIDs[0] {
			return
		}
	}
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

func (s *TunnelService) reconcileHistoryFromStatus(activeNames []string, samples map[string]counterSample, disappearReason string, sources ...*ipc.Client) {
	if s.historyStore == nil {
		return
	}
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if s.historyClosed || !s.currentHistorySources(sources) {
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
					s.rememberClosedPeaksLocked(name, st, id)
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
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if err := s.historyStore.Clear(); err != nil {
		return err
	}
	s.closedPeaks = nil
	return nil
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
		if peak.terminal {
			continue
		}
		if _, ok := epochs[epoch]; !ok {
			peak.inherited = true
			peak.baseRx, peak.baseTx = peak.rx, peak.tx
			epochs[epoch] = peak
		}
	}
	st.epochs = epochs
	return st
}

func (s *TunnelService) rememberClosedPeaksLocked(name string, st lastKnownTunnelStats, historyID string) {
	if s.closedPeaks == nil {
		s.closedPeaks = make(map[string]map[string]counterPeak)
	}
	peaks := make(map[string]counterPeak, len(st.epochs)+len(s.closedPeaks[name]))
	for epoch, peak := range s.closedPeaks[name] {
		if peak.terminal {
			peaks[epoch] = peak
		}
	}
	for epoch, peak := range st.epochs {
		if peak.inherited {
			continue
		}
		if peak.historyID == "" {
			peak.historyID = historyID
		}
		if previous, exists := peaks[epoch]; !exists || !previous.terminal {
			peaks[epoch] = peak
		}
	}
	s.closedPeaks[name] = peaks
	incarnation, _, ordered := domain.ParseCounterEpoch(st.epoch)
	if ordered {
		watermark := s.closedWatermarks[name]
		if watermark.incarnation != incarnation {
			watermark = counterWatermark{incarnation: incarnation}
		}
		for epoch, peak := range peaks {
			owner, sequence, ok := domain.ParseCounterEpoch(epoch)
			if ok && owner == incarnation && peak.terminal {
				watermark.sequence = max(watermark.sequence, sequence)
			}
		}
		if watermark.sequence != 0 {
			if s.closedWatermarks == nil {
				s.closedWatermarks = make(map[string]counterWatermark)
			}
			s.closedWatermarks[name] = watermark
		}
	}
	retained := make(map[string]bool)
	for _, session := range s.historyStore.GetAll() {
		retained[session.ID] = true
	}
	for tunnel, entries := range s.closedPeaks {
		for epoch, peak := range entries {
			if !retained[peak.historyID] {
				delete(entries, epoch)
			}
		}
		if len(entries) == 0 {
			delete(s.closedPeaks, tunnel)
		}
	}
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
		incarnation, sequence, ordered := domain.ParseCounterEpoch(sample.epoch)
		watermark := s.closedWatermarks[name]
		return ordered && watermark.incarnation == incarnation && sequence <= watermark.sequence
	}
	rx, tx := max(sample.rx-peak.rx, 0), max(sample.tx-peak.tx, 0)
	if rx != 0 || tx != 0 {
		peak.rx, peak.tx = max(peak.rx, sample.rx), max(peak.tx, sample.tx)
		peaks[sample.epoch] = peak
		s.historyStore.AddClosedSessionTraffic(peak.historyID, rx, tx)
	}
	return true
}

func (s *TunnelService) currentHistorySource(source *ipc.Client) bool {
	return source == nil || s.clients != nil && s.clients.Get() == source
}

func (s *TunnelService) currentHistorySources(sources []*ipc.Client) bool {
	return len(sources) == 0 || s.currentHistorySource(sources[0])
}

func (s *TunnelService) observeHistoryCounters(status ConnectionStatus, source *ipc.Client) {
	samples := countersFromStatus(status)
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if s.historyClosed || !s.currentHistorySource(source) {
		return
	}
	for _, name := range status.ActiveTunnels {
		sample := samples[name]
		if s.foldTerminalSampleLocked(name, sample) {
			continue
		}
		if _, open := s.activeSessions.Load(name); !open {
			continue
		}
		if cached, ok := s.lastKnownStats.Load(name); ok {
			previous, _ := cached.(lastKnownTunnelStats)
			s.lastKnownStats.Store(name, previous.mergeEpoch(sample.rx, sample.tx, sample.epoch))
		}
	}
}

func (s *TunnelService) clearDisconnectTarget(name string, target disconnectTarget) {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if !s.currentHistorySource(target.source) {
		return
	}
	s.clearUserDisconnectLocked(name, []string{target.historyID})
}
