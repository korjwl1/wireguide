//go:build !windows

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
