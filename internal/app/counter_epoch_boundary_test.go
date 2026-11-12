package app

import "testing"

func TestClosedEngineTailCountsOnlyItsIncrease(t *testing.T) {
	s := newHistoryTestService(t)
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "e", RxBytes: 100, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "f", RxBytes: 30, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "e", RxBytes: 110, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	all := s.historyStore.GetAll()
	if len(all) != 2 || all[1].RxBytes != 100 || all[0].RxBytes != 40 {
		t.Fatalf("closed engine re-counted: %+v", all)
	}
	if len(s.closedPeaks["a"]) != 1 {
		t.Fatalf("inherited peaks carried forward: %+v", s.closedPeaks)
	}
}

func TestLegacyThenEpochZeroFirstKeepsLegacyParity(t *testing.T) {
	var st, legacy lastKnownTunnelStats
	for _, x := range []counterSample{{rx: 100}, {epoch: "e"}, {epoch: "e", rx: 50}, {epoch: "e", rx: 120}} {
		st = st.mergeEpoch(x.rx, x.tx, x.epoch)
		legacy = legacy.merge(x.rx, x.tx)
	}
	if st.rx != 220 || legacy.rx != 220 {
		t.Fatalf("got epoch=%d legacy=%d, want 220", st.rx, legacy.rx)
	}
}

func TestSnapshotFromOwnedEngineSurvivesIDChange(t *testing.T) {
	s := newHistoryTestService(t)
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "e", RxBytes: 100, ActiveTunnels: []string{"a"}})
	s.markUserDisconnectSample(counterSample{name: "a", epoch: "e", rx: 150, snapshot: true, historyID: ""})
	ObserveHistoryStatus(s, ConnectionStatus{})
	if got := lastSession(t, s); got.RxBytes != 150 || got.DisconnectReason != "user" {
		t.Fatalf("owned-engine snapshot dropped: %+v", got)
	}
}

func TestEpochHistoryConcurrentAccess(t *testing.T) {
	s := newHistoryTestService(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := int64(0); i < 2000; i++ {
			active := []string{"a"}
			if i%7 == 0 {
				active = nil
			}
			ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: []string{"x", "y"}[i%2], RxBytes: i, ActiveTunnels: active})
		}
	}()
	for i := int64(0); i < 2000; i++ {
		s.markUserDisconnectSample(counterSample{name: "a", epoch: "z", rx: i})
		s.clearUserDisconnect("a")
	}
	<-done
	s.CloseHistorySessions("app_quit")
}
