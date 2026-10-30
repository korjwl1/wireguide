package app

import (
	"testing"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func newHistoryTestService(t *testing.T) *TunnelService {
	t.Helper()
	hs := storage.NewHistoryStore(t.TempDir())
	return &TunnelService{historyStore: hs, clients: ipc.NewClientHolder(nil)}
}

func lastSession(t *testing.T, s *TunnelService) storage.Session {
	t.Helper()
	all := s.historyStore.GetAll()
	if len(all) == 0 {
		t.Fatal("no sessions recorded")
	}
	return all[0]
}

func rxtx(name string, rx, tx int64) (map[string]int64, map[string]int64) {
	return map[string]int64{name: rx}, map[string]int64{name: tx}
}

// The helper lists a tunnel as active while it is Disconnecting
// (or Connecting during a reconnect) but reports 0/0 counters for it. The
// zero reading must not replace the cached counters, or the session closed on
// the next tick would record 0 B rx/tx.
func TestReconcileKeepsCountersAcrossZeroedTeardownTick(t *testing.T) {
	for _, reason := range []string{"user", "reconnect", "app_quit"} {
		t.Run(reason, func(t *testing.T) {
			s := newHistoryTestService(t)
			rx, tx := rxtx("a", 1000, 500)
			s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
			rx, tx = rxtx("a", 5000, 2500)
			s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
			if reason == "user" {
				s.markUserDisconnect("a", 0, 0)
			}
			// Teardown tick: still active, counters zeroed.
			rx, tx = rxtx("a", 0, 0)
			s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
			// Gone.
			disappear := reason
			if reason == "user" {
				disappear = ""
			}
			s.ReconcileHistoryFromStatus(nil, nil, nil, disappear)
			got := lastSession(t, s)
			if got.RxBytes != 5000 || got.TxBytes != 2500 {
				t.Errorf("rx/tx = %d/%d, want 5000/2500", got.RxBytes, got.TxBytes)
			}
		})
	}
}

// A reconnect rebuilds the WireGuard device, so its counters restart low; the
// session total must keep counting from where it was.
func TestReconcileAccumulatesAcrossCounterReset(t *testing.T) {
	s := newHistoryTestService(t)
	rx, tx := rxtx("a", 1000, 400)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	rx, tx = rxtx("a", 0, 0)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	rx, tx = rxtx("a", 50, 20)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "reconnect")
	got := lastSession(t, s)
	if got.RxBytes != 1050 || got.TxBytes != 420 {
		t.Errorf("rx/tx = %d/%d, want 1050/420", got.RxBytes, got.TxBytes)
	}
}

// CloseHistorySessions at app quit: the helper is unreachable (zero reading),
// the cache must supply the counters.
func TestCloseHistorySessionsUsesCachedCountersWhenHelperGone(t *testing.T) {
	s := newHistoryTestService(t)
	rx, tx := rxtx("a", 7000, 3000)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	rx, tx = rxtx("a", 0, 0) // teardown tick before quit
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.CloseHistorySessions("app_quit")
	got := lastSession(t, s)
	if got.RxBytes != 7000 || got.TxBytes != 3000 || got.DisconnectReason != "app_quit" {
		t.Errorf("got %+v", got)
	}
}

// A new device resets both directions, so a drop in only one of them still
// means the earlier totals of both must be kept.
func TestReconcileCounterResetWhenOnlyOneDirectionDrops(t *testing.T) {
	s := newHistoryTestService(t)
	rx, tx := rxtx("a", 10_000_000, 2_000)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	// New device: rx restarts below, tx already past its old value.
	rx, tx = rxtx("a", 5_000, 3_000)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "reconnect")
	got := lastSession(t, s)
	if got.RxBytes != 10_005_000 || got.TxBytes != 5_000 {
		t.Errorf("rx/tx = %d/%d, want 10005000/5000", got.RxBytes, got.TxBytes)
	}
}

// A user-disconnect snapshot left for a tunnel that never got a session must
// not be added to the next session of that tunnel, nor label it "user".
func TestReconcileDropsStaleSnapshotBeforeFirstSession(t *testing.T) {
	s := newHistoryTestService(t)
	s.markUserDisconnect("a", 9_000, 4_000)
	rx, tx := rxtx("a", 100, 50)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	got := lastSession(t, s)
	if got.RxBytes != 100 || got.TxBytes != 50 || got.DisconnectReason != "reconnect" {
		t.Errorf("got rx/tx %d/%d reason %q, want 100/50 reconnect", got.RxBytes, got.TxBytes, got.DisconnectReason)
	}
}

// A Disconnect clicked before the first status tick: the tunnel is still
// listed with zeroed counters, so the snapshot and the "user" reason belong
// to the session being opened and closed.
func TestReconcileKeepsSnapshotWhenFirstReadingIsZeroed(t *testing.T) {
	s := newHistoryTestService(t)
	s.markUserDisconnect("a", 9_000, 4_000)
	rx, tx := rxtx("a", 0, 0)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	got := lastSession(t, s)
	if got.RxBytes != 9_000 || got.TxBytes != 4_000 || got.DisconnectReason != "user" {
		t.Errorf("got rx/tx %d/%d reason %q, want 9000/4000 user", got.RxBytes, got.TxBytes, got.DisconnectReason)
	}
}

// A Connect lists the tunnel at 0/0 (Connecting) before any non-zero
// reading. A snapshot left by an earlier Disconnect must already be gone by
// then, or the first lower reading counts as a reset and the stale totals
// become the base of the new session.
func TestReconcileDropsStaleSnapshotAcrossZeroedFirstTick(t *testing.T) {
	s := newHistoryTestService(t)
	s.markUserDisconnect("a", 9_000, 4_000)
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	rx, tx := rxtx("a", 0, 0)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	rx, tx = rxtx("a", 100, 50)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	got := lastSession(t, s)
	if got.RxBytes != 100 || got.TxBytes != 50 || got.DisconnectReason != "reconnect" {
		t.Errorf("got rx/tx %d/%d reason %q, want 100/50 reconnect", got.RxBytes, got.TxBytes, got.DisconnectReason)
	}
}

// A cold snapshot (status did not list the tunnel) leaves a zeroed "user"
// entry. It must not label the next session once ticks have passed without
// the tunnel.
func TestReconcileDropsColdSnapshotReason(t *testing.T) {
	s := newHistoryTestService(t)
	s.markUserDisconnect("a", 0, 0)
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	rx, tx := rxtx("a", 0, 0)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	rx, tx = rxtx("a", 100, 50)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	got := lastSession(t, s)
	if got.DisconnectReason != "reconnect" {
		t.Errorf("reason %q, want reconnect", got.DisconnectReason)
	}
}

// A Disconnect followed by the tunnel vanishing before any session opened
// records nothing and leaves no cache entry behind.
func TestReconcileStaleSnapshotRecordsNothingWithoutSession(t *testing.T) {
	s := newHistoryTestService(t)
	s.markUserDisconnect("a", 9_000, 4_000)
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	for _, sess := range s.historyStore.GetAll() {
		if sess.TunnelName == "a" {
			t.Errorf("unexpected session for a: %+v", sess)
		}
	}
	if _, ok := s.lastKnownStats.Load("a"); ok {
		t.Error("stale lastKnownStats entry for a was kept")
	}
}

// A tunnel closing on this tick keeps its counters for RecordDisconnect.
func TestReconcileKeepsCountersOfClosingSession(t *testing.T) {
	s := newHistoryTestService(t)
	rx, tx := rxtx("a", 700, 300)
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.ReconcileHistoryFromStatus([]string{"a"}, rx, tx, "")
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	got := lastSession(t, s)
	if got.RxBytes != 700 || got.TxBytes != 300 {
		t.Errorf("rx/tx = %d/%d, want 700/300", got.RxBytes, got.TxBytes)
	}
}
