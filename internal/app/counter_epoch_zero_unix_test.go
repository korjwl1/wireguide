//go:build !windows

package app

import (
	"testing"
	"time"
)

func dumpSessions(t *testing.T, s *TunnelService) (total int, rx int64) {
	for _, x := range s.historyStore.GetAll() {
		if x.DisconnectReason != "user" {
			t.Errorf("non-user row %q (phantom)", x.DisconnectReason)
		}
		t.Logf("session %+v", x)
		total++
		rx += x.RxBytes
	}
	return
}

func TestFinalZeroSnapshotThenLateBroadcastOpensPhantom(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", ActiveTunnels: []string{"a"}})
	time.Sleep(1100 * time.Millisecond)
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 40, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	if total, rx := dumpSessions(t, s); total > 1 || (total == 1 && rx != 40) {
		t.Fatalf("phantom/after-terminal: sessions=%d rx=%d", total, rx)
	}
}

func TestFinalZeroObservedThenSnapshotThenTail(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 150, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", ActiveTunnels: []string{"a"}})
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 170, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	if total, rx := dumpSessions(t, s); total != 1 || rx != 170 {
		t.Fatalf("sessions=%d rx=%d want 1/170", total, rx)
	}
}

func TestFinalSnapshotBeforeZeroBroadcastLosesSnapshotAndPhantom(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 150, ActiveTunnels: []string{"a"}})
	sample := s.snapshotCounterSample("a")
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", ActiveTunnels: []string{"a"}})
	time.Sleep(1100 * time.Millisecond)
	id := s.markUserDisconnectSample(sample)
	s.finishUserDisconnect("a", id)
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 170, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	if total, rx := dumpSessions(t, s); total != 1 || rx != 170 {
		t.Fatalf("sessions=%d rx=%d want 1/170", total, rx)
	}
}

func TestFinalStaleSecondSnapshotAfterFinishDropsPeak(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 150, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 100, ActiveTunnels: []string{"a"}})
	second := s.snapshotCounterSample("a")
	second.rx = 190
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	if id := s.markUserDisconnectSample(second); id != "" {
		t.Logf("second mark returned %q", id)
	}
	ObserveHistoryStatus(s, ConnectionStatus{})
	if total, rx := dumpSessions(t, s); total != 1 || rx != 190 {
		t.Fatalf("sessions=%d rx=%d want 1/190", total, rx)
	}
}
