//go:build !windows

package app

import (
	"testing"
	"time"
)

func zrRows(t *testing.T, s *TunnelService) (rows []string, rx map[string]int64) {
	rx = map[string]int64{}
	for _, x := range s.historyStore.GetAll() {
		t.Logf("row %s reason=%q rx=%d tx=%d end=%v", x.TunnelName, x.DisconnectReason, x.RxBytes, x.TxBytes, x.EndTime != nil)
		rows = append(rows, x.TunnelName+":"+x.DisconnectReason)
		rx[x.TunnelName] += x.RxBytes
	}
	return
}

func TestZRUnknownSnapshotNotMergedIntoZeroReplacement(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E1", RxBytes: 160, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E1", RxBytes: 150, ActiveTunnels: []string{"a"}})
	old := s.snapshotCounterSample("a")
	time.Sleep(1100 * time.Millisecond)
	ObserveHistoryStatus(s, ConnectionStatus{})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E2", ActiveTunnels: []string{"a"}})
	time.Sleep(1100 * time.Millisecond)
	id := s.markUserDisconnectSample(old)
	s.finishUserDisconnect("a", disconnectTarget{historyID: id})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E2", RxBytes: 30, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	rows, rx := zrRows(t, s)
	if len(rows) != 2 || rx["a"] != 180 {
		t.Fatalf("rows=%v rx=%d want 2 rows, 150+30", rows, rx["a"])
	}
}

func TestZRLegacyThenZeroEpochTail(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", RxBytes: 100, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", ActiveTunnels: []string{"a"}})
	time.Sleep(1100 * time.Millisecond)
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 30, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	rows, rx := zrRows(t, s)
	if len(rows) != 1 || rows[0] != "a:user" || rx["a"] != 130 {
		t.Fatalf("rows=%v rx=%d want [a:user] 130", rows, rx["a"])
	}
}

func TestZRDisconnectAllZeroTails(t *testing.T) {
	st := ConnectionStatus{ActiveTunnels: []string{"a", "b"}, Tunnels: []ConnectionStatus{
		{TunnelName: "a", CounterEpoch: "A"}, {TunnelName: "b", CounterEpoch: "B"}}}
	s := epochRPCService(t, st)
	ObserveHistoryStatus(s, st)
	time.Sleep(1100 * time.Millisecond)
	if err := s.Disconnect(); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{ActiveTunnels: []string{"a", "b"}, Tunnels: []ConnectionStatus{
		{TunnelName: "a", CounterEpoch: "A", RxBytes: 5}, {TunnelName: "b", CounterEpoch: "B", RxBytes: 7}}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	rows, rx := zrRows(t, s)
	if len(rows) != 2 || rx["a"] != 5 || rx["b"] != 7 {
		t.Fatalf("rows=%v rx=%v", rows, rx)
	}
	for _, r := range rows {
		if r != "a:user" && r != "b:user" {
			t.Fatalf("phantom row %v", rows)
		}
	}
}

func TestZRDuplicateZeroAfterFinish(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", ActiveTunnels: []string{"a"}})
	time.Sleep(1100 * time.Millisecond)
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})

	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E9", RxBytes: 3, ActiveTunnels: []string{"a"}})
	rows, _ := zrRows(t, s)
	if len(rows) != 2 {
		t.Fatalf("rows=%v want closed user row + new open row", rows)
	}
}

func TestZRInheritedContinuedPeakTail(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 80, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 50, ActiveTunnels: []string{"a"}})
	time.Sleep(1100 * time.Millisecond)
	ObserveHistoryStatus(s, ConnectionStatus{})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 70, ActiveTunnels: []string{"a"}})
	time.Sleep(1100 * time.Millisecond)
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 90, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	rows, rx := zrRows(t, s)
	t.Logf("rows=%v rx=%d", rows, rx["a"])
	if len(rows) != 2 || rx["a"] != 90 {
		t.Errorf("INFO pre-existing: rows=%v rx=%d (ideal 2 rows / 90)", rows, rx["a"])
	}
}
