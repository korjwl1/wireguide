package app

import "testing"

func TestReviewShortSessionWithoutFollowupBroadcastMergesIntoNextConnect(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "short", RxBytes: 150, ActiveTunnels: []string{"a"}})
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}

	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "second", RxBytes: 10, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	all := s.historyStore.GetAll()
	if len(all) != 2 {
		t.Fatalf("want 2 sessions (short user session + later session), got %d: %+v", len(all), all)
	}
}

func TestReviewShortSessionStaysOpenWithoutFollowupBroadcast(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "short", RxBytes: 150, ActiveTunnels: []string{"a"}})
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	if got := lastSession(t, s); got.EndTime == nil {
		t.Fatalf("short session still open after successful Disconnect RPC: %+v", got)
	}
}

func TestReviewLegacyThenEpochZeroFirst(t *testing.T) {
	var st lastKnownTunnelStats
	for _, x := range []counterSample{{rx: 100}, {epoch: "E"}, {epoch: "E", rx: 50}, {epoch: "E", rx: 120}} {
		st = st.mergeEpoch(x.rx, x.tx, x.epoch)
	}
	var legacy lastKnownTunnelStats
	for _, x := range []int64{100, 0, 50, 120} {
		legacy = legacy.merge(x, 0)
	}
	t.Logf("epoch path=%d legacy-only path=%d", st.rx, legacy.rx)
	if st.rx < legacy.rx {
		t.Fatalf("epoch path counts less than the legacy heuristic it replaces: %d < %d", st.rx, legacy.rx)
	}
}

func TestReviewLegacyThenEpochOvertake(t *testing.T) {
	var st lastKnownTunnelStats
	for _, x := range []counterSample{{rx: 100}, {epoch: "E", rx: 150}} {
		st = st.mergeEpoch(x.rx, x.tx, x.epoch)
	}
	t.Logf("legacy 100 then new-helper epoch 150 -> %d (known nuance)", st.rx)
}

func TestReviewSameEpochSnapshotDroppedOnIDRace(t *testing.T) {
	s := newHistoryTestService(t)
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 100, ActiveTunnels: []string{"a"}})
	s.markUserDisconnectSample(counterSample{name: "a", epoch: "E", rx: 150, snapshot: true, historyID: ""})
	ObserveHistoryStatus(s, ConnectionStatus{})
	if got := lastSession(t, s).RxBytes; got != 150 {
		t.Fatalf("same epoch snapshot lost: %d", got)
	}
}

func TestReviewConcurrentRace(t *testing.T) {
	s := newHistoryTestService(t)
	done := make(chan struct{})
	go func() {
		for i := int64(0); i < 2000; i++ {
			ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: []string{"x", "y"}[i%2], RxBytes: i, ActiveTunnels: []string{"a"}})
		}
		close(done)
	}()
	for i := int64(0); i < 2000; i++ {
		s.markUserDisconnectSample(counterSample{name: "a", epoch: "z", rx: i})
		s.clearUserDisconnect("a")
	}
	<-done
	s.CloseHistorySessions("app_quit")
}
