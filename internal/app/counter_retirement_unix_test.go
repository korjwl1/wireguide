//go:build !windows

package app

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func retireTestEpoch(t *testing.T, s *TunnelService, epoch string, rx int64) string {
	t.Helper()
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: epoch, RxBytes: rx, ActiveTunnels: []string{"a"}})
	id := s.markUserDisconnectSample(counterSample{name: "a", epoch: epoch, rx: rx})
	s.finishUserDisconnect("a", disconnectTarget{historyID: id})
	return id
}

func TestTerminalEpochSurvivesManySessionsAndHistoryEviction(t *testing.T) {
	s := newHistoryTestService(t)
	first := domain.NewCounterEpoch()
	firstID := retireTestEpoch(t, s, first, 10)
	for i := 0; i < 12; i++ {
		retireTestEpoch(t, s, domain.NewCounterEpoch(), 20)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: first, RxBytes: 15, ActiveTunnels: []string{"a"}})
	all := s.historyStore.GetAll()
	if len(all) != 13 {
		t.Fatalf("late epoch opened a phantom: %d", len(all))
	}
	found := false
	for _, row := range all {
		if row.ID == firstID {
			found = true
			if row.RxBytes != 15 || row.DisconnectReason != "user" {
				t.Fatalf("wrong correction: %+v", row)
			}
		}
	}
	if !found {
		t.Fatal("first retained row vanished")
	}
	for i := 0; i < storage.HistoryMaxRecords+10; i++ {
		retireTestEpoch(t, s, domain.NewCounterEpoch(), 30)
	}
	if len(s.closedPeaks["a"]) > storage.HistoryMaxRecords {
		t.Fatalf("peak cache outgrew retained rows: %d", len(s.closedPeaks["a"]))
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: first, RxBytes: 99999, ActiveTunnels: []string{"a"}})
	if got := s.historyStore.GetAll(); len(got) != storage.HistoryMaxRecords {
		t.Fatalf("retired epoch resurrected after eviction: %d", len(got))
	}
	for _, row := range s.historyStore.GetAll() {
		if row.DisconnectReason != "user" || row.RxBytes != 30 {
			t.Fatalf("evicted epoch became traffic: %+v", row)
		}
	}
	if err := s.ClearConnectionHistory(); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: first, RxBytes: 100000, ActiveTunnels: []string{"a"}})
	if got := s.historyStore.GetAll(); len(got) != 0 {
		t.Fatalf("old epoch repopulated cleared history: %+v", got)
	}
	retireTestEpoch(t, s, domain.NewCounterEpoch(), 7)
	if got := lastSession(t, s); got.RxBytes != 7 {
		t.Fatalf("new epoch was suppressed: %+v", got)
	}
	s.historyStore.Flush()
}

func TestOpaqueTerminalEpochCorrectionAfterFollowingSessions(t *testing.T) {
	s := newHistoryTestService(t)
	firstID := retireTestEpoch(t, s, "opaque-old", 10)
	for _, epoch := range []string{"opaque-b", "opaque-c", "opaque-d", "opaque-e", "opaque-f"} {
		retireTestEpoch(t, s, epoch, 20)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "opaque-old", RxBytes: 15, ActiveTunnels: []string{"a"}})
	rows := s.historyStore.GetAll()
	if len(rows) != 6 {
		t.Fatalf("opaque epoch phantom: %d", len(rows))
	}
	for _, row := range rows {
		if row.ID == firstID && row.RxBytes != 15 {
			t.Fatalf("wrong old row: %+v", row)
		}
	}
}

func TestDisconnectAllPartialFailureKeepsConfirmedUserReason(t *testing.T) {
	for _, modern := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "epochs"}[modern], func(t *testing.T) {
			a, b := "", ""
			if modern {
				a = domain.NewCounterEpoch()
				b = domain.NewCounterEpoch()
			}
			initial := ConnectionStatus{TunnelName: "a", CounterEpoch: a, RxBytes: 150, ActiveTunnels: []string{"a", "b"}, Tunnels: []ConnectionStatus{{TunnelName: "a", CounterEpoch: a, RxBytes: 150}, {TunnelName: "b", CounterEpoch: b, RxBytes: 300}}}
			current := initial
			var mu sync.Mutex
			s := epochRPCServiceWithStatus(t, func() ConnectionStatus { mu.Lock(); defer mu.Unlock(); return current }, func(json.RawMessage) (interface{}, error) {
				mu.Lock()
				current = ConnectionStatus{TunnelName: "b", CounterEpoch: b, RxBytes: 350, ActiveTunnels: []string{"b"}}
				mu.Unlock()
				return nil, errors.New("b failed to disconnect")
			})
			ObserveHistoryStatus(s, initial)
			if err := s.Disconnect(); err == nil {
				t.Fatal("partial error was swallowed")
			}
			if !modern {
				mu.Lock()
				after := current
				mu.Unlock()
				ObserveHistoryStatus(s, after)
			}
			for _, row := range s.historyStore.GetAll() {
				if row.TunnelName == "a" && (row.EndTime == nil || row.DisconnectReason != "user" || row.RxBytes != 150) {
					t.Fatalf("successful close mislabeled: %+v", row)
				}
				if row.TunnelName == "b" && row.EndTime != nil {
					t.Fatalf("failed close ended history: %+v", row)
				}
			}
			ObserveHistoryStatus(s, ConnectionStatus{})
			for _, row := range s.historyStore.GetAll() {
				if row.TunnelName == "b" && (row.DisconnectReason == "user" || row.RxBytes != 350) {
					t.Fatalf("failure contaminated later close: %+v", row)
				}
			}
		})
	}
}

func TestOldHelperStatusCannotCrossClientReplacement(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	s := epochRPCServiceWithStatus(t, func() ConnectionStatus { close(started); <-release; return ConnectionStatus{TunnelName: "old"} }, func(json.RawMessage) (interface{}, error) { return ipc.Empty{}, nil })
	replacement := epochRPCService(t, ConnectionStatus{TunnelName: "new"})
	s.clients.MarkInflight()
	result := make(chan error, 1)
	go func() { defer s.clients.UnmarkInflight(); _, err := s.GetStatus(); result <- err }()
	<-started
	swapped := make(chan struct{})
	go func() { s.clients.Set(replacement.clients.Get()); close(swapped) }()
	deadline := time.After(2 * time.Second)
	for s.clients.Get() != replacement.clients.Get() {
		select {
		case <-deadline:
			t.Fatal("client replacement did not publish")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(release)
	if err := <-result; !errors.Is(err, ipc.ErrClientClosed) {
		t.Fatalf("old helper snapshot escaped: %v", err)
	}
	<-swapped
}

func TestFailedOldRequestDoesNotClearReplacementUserReason(t *testing.T) {
	s := newHistoryTestService(t)
	oldID := retireTestEpoch(t, s, domain.NewCounterEpoch(), 10)
	epoch := domain.NewCounterEpoch()
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: epoch, RxBytes: 20, ActiveTunnels: []string{"a"}})
	s.markUserDisconnectSample(counterSample{name: "a", epoch: epoch, rx: 20})
	s.clearUserDisconnect("a", oldID)
	ObserveHistoryStatus(s, ConnectionStatus{})
	if got := lastSession(t, s); got.DisconnectReason != "user" {
		t.Fatalf("old error cleared replacement: %+v", got)
	}
}

func TestDisconnectCompletionPreservesAConcurrentNewEngine(t *testing.T) {
	for _, zero := range []bool{false, true} {
		t.Run(map[bool]string{false: "traffic", true: "idle"}[zero], func(t *testing.T) {
			old, newEpoch := domain.NewCounterEpoch(), domain.NewCounterEpoch()
			initialRx, nextRx := int64(10), int64(3)
			if zero {
				initialRx, nextRx = 0, 0
			}
			initial := ConnectionStatus{TunnelName: "a", CounterEpoch: old, RxBytes: initialRx, ActiveTunnels: []string{"a"}}
			var s *TunnelService
			s = epochRPCServiceWithDisconnect(t, initial, func(json.RawMessage) (interface{}, error) {
				ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: newEpoch, RxBytes: nextRx, ActiveTunnels: []string{"a"}})
				return ipc.Empty{}, nil
			})
			ObserveHistoryStatus(s, initial)
			if err := s.DisconnectTunnel("a"); err != nil {
				t.Fatal(err)
			}
			if _, open := s.activeSessions.Load("a"); !open {
				t.Fatal("new live epoch was closed with the old request")
			}
			ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: newEpoch, RxBytes: 500, ActiveTunnels: []string{"a"}})
			ObserveHistoryStatus(s, ConnectionStatus{})
			var total int64
			for _, row := range s.historyStore.GetAll() {
				total += row.RxBytes
				if row.RxBytes >= 500 && row.DisconnectReason == "user" {
					t.Fatalf("live traffic folded into user-closed row: %+v", row)
				}
			}
			if total != initialRx+500 {
				t.Fatalf("split lost or duplicated traffic: %d", total)
			}
		})
	}
}

func TestDeferredOldClientEventAndSnapshotAreDiscarded(t *testing.T) {
	old := epochRPCService(t, ConnectionStatus{TunnelName: "old"})
	replacement := epochRPCService(t, ConnectionStatus{TunnelName: "new"})
	source := old.clients.Get()
	sample := counterSample{name: "a", epoch: domain.NewCounterEpoch(), rx: 10, snapshot: true, source: source}
	old.clients.Set(replacement.clients.Get())
	ObserveHistoryStatus(old, ConnectionStatus{TunnelName: "a", CounterEpoch: sample.epoch, RxBytes: 10, ActiveTunnels: []string{"a"}}, source)
	if id := old.prepareUserDisconnect(sample).historyID; id != "" {
		t.Fatalf("old helper snapshot opened history: %s", id)
	}
	if rows := old.historyStore.GetAll(); len(rows) != 0 {
		t.Fatalf("old helper callback opened history: %+v", rows)
	}
}
