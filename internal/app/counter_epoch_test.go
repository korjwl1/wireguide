package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
)

func TestCounterEpochCases(t *testing.T) {
	cases := []struct {
		name    string
		samples []counterSample
		rx, tx  int64
	}{
		{"new engine overtakes old counters", []counterSample{{epoch: "a", rx: 100, tx: 40}, {epoch: "b", rx: 150, tx: 60}}, 250, 100},
		{"connecting stub preserves old generation", []counterSample{{epoch: "a", rx: 100}, {}, {epoch: "b", rx: 150}}, 250, 0},
		{"new engine starts at zero", []counterSample{{epoch: "a", rx: 100}, {epoch: "b"}, {epoch: "b", rx: 150}}, 250, 0},
		{"shutdown duplicate and delayed old-engine tail", []counterSample{{epoch: "a", rx: 100}, {epoch: "b", rx: 150}, {epoch: "b", rx: 150}, {epoch: "a", rx: 120}, {epoch: "b", rx: 160}}, 280, 0},
		{"older engine first arrives late", []counterSample{{epoch: "b", rx: 150}, {epoch: "a", rx: 100}, {epoch: "b", rx: 160}}, 260, 0},
		{"same engine transient zero", []counterSample{{epoch: "a", rx: 1000}, {epoch: "a"}, {epoch: "a", rx: 1010}}, 1010, 0},
		{"same engine reordered sample", []counterSample{{epoch: "a", rx: 1000}, {epoch: "a", rx: 900}, {epoch: "a", rx: 1010}}, 1010, 0},
		{"directions have independent high water", []counterSample{{epoch: "a", rx: 100, tx: 100}, {epoch: "a", rx: 120, tx: 90}, {epoch: "a", rx: 110, tx: 130}}, 120, 130},
		{"legacy helper preserves reset behavior", []counterSample{{rx: 100}, {}, {rx: 50}}, 150, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var st lastKnownTunnelStats
			for _, sample := range tc.samples {
				st = st.mergeEpoch(sample.rx, sample.tx, sample.epoch)
			}
			if st.rx != tc.rx || st.tx != tc.tx {
				t.Fatalf("got %d/%d, want %d/%d", st.rx, st.tx, tc.rx, tc.tx)
			}
		})
	}
}

func TestHistoryEpochsKeepTunnelsIndependent(t *testing.T) {
	s := newHistoryTestService(t)
	observe := func(aEpoch string, aRx, bRx int64) {
		ObserveHistoryStatus(s, ConnectionStatus{ActiveTunnels: []string{"a", "b"}, Tunnels: []ConnectionStatus{
			{TunnelName: "a", CounterEpoch: aEpoch, RxBytes: aRx},
			{TunnelName: "b", CounterEpoch: "b1", RxBytes: bRx},
		}})
	}
	observe("a1", 100, 400)
	observe("a2", 150, 450)
	s.markUserDisconnectSample(counterSample{name: "a", epoch: "a2", rx: 170})
	s.ReconcileHistoryFromStatus(nil, nil, nil, "")
	for _, session := range s.historyStore.GetAll() {
		if session.TunnelName == "a" && (session.RxBytes != 270 || session.DisconnectReason != "user") {
			t.Fatalf("fresh disconnect snapshot lost: %+v", session)
		}
		if session.TunnelName == "b" && session.RxBytes != 450 {
			t.Fatalf("sibling accumulated another tunnel's epoch: %+v", session)
		}
	}
}

func TestCounterEpochJSONKeepsConnectedAtPrivate(t *testing.T) {
	data, err := json.Marshal(domain.ConnectionStatus{ConnectedAt: time.Now(), CounterEpoch: "epoch"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["counter_epoch"] != "epoch" || fields["ConnectedAt"] != nil || fields["connected_at"] != nil {
		t.Fatalf("unexpected status fields: %s", data)
	}
	var legacy domain.ConnectionStatus
	if err := json.Unmarshal([]byte(`{"state":"connected","rx_bytes":42}`), &legacy); err != nil || legacy.CounterEpoch != "" {
		t.Fatalf("legacy status rejected: %+v %v", legacy, err)
	}
}

func TestDisconnectSnapshotCannotPolluteAReplacementHistorySession(t *testing.T) {
	s := newHistoryTestService(t)
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "current", RxBytes: 200, ActiveTunnels: []string{"a"}})
	s.markUserDisconnectSample(counterSample{name: "a", epoch: "old", rx: 150, snapshot: true, historyID: "closed-session"})
	ObserveHistoryStatus(s, ConnectionStatus{})
	if got := lastSession(t, s); got.RxBytes != 200 || got.DisconnectReason != "user" {
		t.Fatalf("stale snapshot changed the new session: %+v", got)
	}
}

func TestClosedSnapshotCannotMarkNextSessionAsUserDisconnect(t *testing.T) {
	s := newHistoryTestService(t)
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "old", RxBytes: 100, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	s.markUserDisconnectSample(counterSample{name: "a", epoch: "old", rx: 150, snapshot: true, historyID: "already-closed"})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "next", RxBytes: 200, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	if got := lastSession(t, s); got.DisconnectReason == "user" || got.RxBytes != 200 {
		t.Fatalf("stale reason leaked: %+v", got)
	}
}

func TestDisconnectCompletionDoesNotMergeAnUnknownOldSnapshotIntoReplacement(t *testing.T) {
	s := newHistoryTestService(t)
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "new", RxBytes: 200, ActiveTunnels: []string{"a"}})
	stale := counterSample{name: "a", epoch: "old", rx: 150, snapshot: true, historyID: "closed"}
	id := s.markUserDisconnectSample(stale)
	s.finishUserDisconnect("a", disconnectTarget{historyID: id})
	if got := lastSession(t, s); got.RxBytes != 200 {
		t.Fatalf("old snapshot polluted replacement: %+v", got)
	}
}
