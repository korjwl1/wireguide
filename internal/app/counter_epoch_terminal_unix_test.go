//go:build !windows

package app

import (
	"testing"
)

func openSessions(s *TunnelService) (open, total int) {
	for _, sess := range s.historyStore.GetAll() {
		total++
		if sess.EndTime == nil {
			open++
		}
	}
	return
}

func TestReviewDelayedSameEpochBroadcastAfterFinishOpensPhantom(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 150, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 100, ActiveTunnels: []string{"a"}})
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 170, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	if open, total := openSessions(s); total != 1 {
		for _, x := range s.historyStore.GetAll() {
			t.Logf("session %+v", x)
		}
		t.Fatalf("phantom session: open=%d total=%d", open, total)
	}
}

func TestReviewLegacyDelayedBroadcastAfterFinishDoubleCounts(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", RxBytes: 150, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", RxBytes: 100, ActiveTunnels: []string{"a"}})
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", RxBytes: 150, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	var sum int64
	for _, x := range s.historyStore.GetAll() {
		t.Logf("session %+v", x)
		sum += x.RxBytes
	}
	if _, total := openSessions(s); total != 1 || sum != 150 {
		t.Fatalf("legacy phantom/double count: sessions=%d rxSum=%d", total, sum)
	}
}

func TestReviewDisconnectingBroadcastAfterFinishOpensPhantom(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 150, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 100, ActiveTunnels: []string{"a"}})
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", State: "disconnecting", ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	if open, total := openSessions(s); total != 1 {
		for _, x := range s.historyStore.GetAll() {
			t.Logf("session %+v", x)
		}
		t.Fatalf("phantom session: open=%d total=%d", open, total)
	}
}
