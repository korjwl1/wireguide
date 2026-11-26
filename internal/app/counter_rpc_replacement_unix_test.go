//go:build !windows

package app

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
)

func TestClaudeF1SwapAfterSuccessfulDisconnectLosesUserReason(t *testing.T) {
	e1 := domain.NewCounterEpoch()
	live := ConnectionStatus{TunnelName: "a", CounterEpoch: e1, RxBytes: 10, ActiveTunnels: []string{"a"}}
	replacement := epochRPCServiceWithStatus(t, func() ConnectionStatus { return ConnectionStatus{} }, func(json.RawMessage) (interface{}, error) {
		return nil, errors.New(`tunnel "a" is not connected`)
	})
	var s *TunnelService
	s = epochRPCServiceWithStatus(t, func() ConnectionStatus { return live }, func(json.RawMessage) (interface{}, error) {
		go s.clients.Set(replacement.clients.Get())
		for s.clients.Get() != replacement.clients.Get() {
			time.Sleep(time.Millisecond)
		}
		return ipc.Empty{}, nil
	})
	ObserveHistoryStatus(s, live, s.clients.Get())
	err := s.DisconnectTunnel("a")
	ObserveHistoryStatus(s, ConnectionStatus{}, replacement.clients.Get())
	got := lastSession(t, s)
	if err != nil || got.DisconnectReason != "user" {
		t.Fatalf("successful user disconnect: err=%v row=%+v", err, got)
	}
}

func TestClaudeF2StaleSnapshotCutoffSplitsKilledEngineIntoNonUserRow(t *testing.T) {
	e1 := domain.NewCounterEpoch()
	e2 := domain.NewCounterEpoch()
	first := ConnectionStatus{TunnelName: "a", CounterEpoch: e1, RxBytes: 10, ActiveTunnels: []string{"a"}}
	newer := ConnectionStatus{TunnelName: "a", CounterEpoch: e2, RxBytes: 40, ActiveTunnels: []string{"a"}}
	var s *TunnelService
	calls := 0
	s = epochRPCServiceWithStatus(t, func() ConnectionStatus {
		calls++
		if calls == 1 {

			ObserveHistoryStatus(s, newer, s.clients.Get())
		}
		return first
	}, func(json.RawMessage) (interface{}, error) { return ipc.Empty{}, nil })
	ObserveHistoryStatus(s, first, s.clients.Get())
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	ObserveHistoryStatus(s, ConnectionStatus{}, s.clients.Get())
	for _, row := range s.historyStore.GetAll() {
		if row.DisconnectReason != "user" {
			t.Fatalf("traffic of the engine the user disconnected landed in a non-user row: %+v (all=%+v)", row, s.historyStore.GetAll())
		}
	}
}
