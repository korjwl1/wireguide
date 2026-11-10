//go:build !windows

package app

import "testing"

func TestConcurrentDisconnectSnapshotTailIsNotLost(t *testing.T) {
	s := newHistoryTestService(t)
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 100, ActiveTunnels: []string{"a"}})
	id, _ := s.activeSessions.Load("a")
	later := counterSample{name: "a", epoch: "E", rx: 170, snapshot: true, historyID: id.(string)}
	first := s.markUserDisconnectSample(counterSample{name: "a", epoch: "E", rx: 150, snapshot: true, historyID: id.(string)})
	s.finishUserDisconnect("a", first)
	s.markUserDisconnectSample(later)
	if got := lastSession(t, s); got.RxBytes != 170 {
		t.Fatalf("lost observed concurrent snapshot: %+v", got)
	}
}
