//go:build !windows

package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func epochRPCService(t *testing.T, sample ConnectionStatus) *TunnelService {
	return epochRPCServiceWithDisconnect(t, sample, func(json.RawMessage) (interface{}, error) { return ipc.Empty{}, nil })
}

func epochRPCServiceWithDisconnect(t *testing.T, sample ConnectionStatus, disconnect func(json.RawMessage) (interface{}, error)) *TunnelService {
	return epochRPCServiceWithStatus(t, func() ConnectionStatus { return sample }, disconnect)
}

func epochRPCServiceWithStatus(t *testing.T, status func() ConnectionStatus, disconnect func(json.RawMessage) (interface{}, error)) *TunnelService {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wgce-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	address := filepath.Join(dir, "s")
	listener, err := ipc.Listen(address, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(listener)
	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) { return ipc.PingResponse{Version: ipc.ProtocolVersion}, nil })
	server.Handle(ipc.MethodStatus, func(json.RawMessage) (interface{}, error) { return status(), nil })
	server.Handle(ipc.MethodDisconnect, disconnect)
	go server.Serve()
	t.Cleanup(func() { server.Shutdown() })
	client, err := ipc.NewClient(address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return NewTunnelService(nil, storage.NewSettingsStore(t.TempDir()), storage.NewHistoryStore(t.TempDir()), ipc.NewClientHolder(client))
}

func TestCounterEpochShutdownAndDisconnectSnapshots(t *testing.T) {
	for _, path := range []string{"shutdown", "disconnect"} {
		t.Run(path, func(t *testing.T) {
			s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "new", RxBytes: 150, TxBytes: 60, ActiveTunnels: []string{"a"}})
			ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "old", RxBytes: 100, TxBytes: 40, ActiveTunnels: []string{"a"}})
			status, err := s.GetStatus()
			if err != nil || status.CounterEpoch != "new" {
				t.Fatalf("RPC lost the epoch: %+v %v", status, err)
			}
			if path == "shutdown" {
				s.CloseHistorySessions("app_quit")
			} else {
				if err := s.DisconnectTunnel("a"); err != nil {
					t.Fatal(err)
				}
				ObserveHistoryStatus(s, ConnectionStatus{})
			}
			got := lastSession(t, s)
			if got.RxBytes != 250 || got.TxBytes != 100 {
				t.Fatalf("%s lost an observed generation: %+v", path, got)
			}
		})
	}
}

func TestDisconnectSnapshotRecordsAShortUnbroadcastSession(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "short", RxBytes: 150, ActiveTunnels: []string{"a"}})
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	if got := lastSession(t, s); got.EndTime == nil || got.RxBytes != 150 || got.DisconnectReason != "user" {
		t.Fatalf("observed short session lost: %+v", got)
	}
}

func TestDisconnectSuccessClosesOnlySelectedSession(t *testing.T) {
	s := epochRPCServiceWithDisconnect(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "a1", RxBytes: 150, ActiveTunnels: []string{"a", "b"}}, func(raw json.RawMessage) (interface{}, error) {
		var req ipc.DisconnectRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.TunnelName != "a" {
			return nil, errors.New("disconnect did not target the sampled tunnel")
		}
		return ipc.Empty{}, nil
	})
	ObserveHistoryStatus(s, ConnectionStatus{ActiveTunnels: []string{"a", "b"}, Tunnels: []ConnectionStatus{
		{TunnelName: "a", CounterEpoch: "a1", RxBytes: 100}, {TunnelName: "b", CounterEpoch: "b1", RxBytes: 200},
	}})
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	for _, sess := range s.historyStore.GetAll() {
		if sess.TunnelName == "a" && (sess.EndTime == nil || sess.RxBytes != 150 || sess.DisconnectReason != "user") {
			t.Fatalf("selected session not closed: %+v", sess)
		}
		if sess.TunnelName == "b" && sess.EndTime != nil {
			t.Fatalf("sibling closed: %+v", sess)
		}
	}
}

func TestDisconnectFailureKeepsSessionOpenAndClearsUserReason(t *testing.T) {
	s := epochRPCServiceWithDisconnect(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 150, ActiveTunnels: []string{"a"}}, func(json.RawMessage) (interface{}, error) { return nil, errors.New("disconnect failed") })
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 100, ActiveTunnels: []string{"a"}})
	if err := s.DisconnectTunnel("a"); err == nil {
		t.Fatal("wanted RPC error")
	}
	if got := lastSession(t, s); got.EndTime != nil {
		t.Fatalf("failed RPC closed history: %+v", got)
	}
	ObserveHistoryStatus(s, ConnectionStatus{})
	if got := lastSession(t, s); got.DisconnectReason == "user" || got.RxBytes != 150 {
		t.Fatalf("failure accounting changed: %+v", got)
	}
}

func TestDisconnectCompletionCannotCloseReplacementSession(t *testing.T) {
	s := newHistoryTestService(t)
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "old", RxBytes: 100, ActiveTunnels: []string{"a"}})
	oldID := s.markUserDisconnectSample(counterSample{name: "a", epoch: "old", rx: 150})
	ObserveHistoryStatus(s, ConnectionStatus{})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "new", RxBytes: 200, ActiveTunnels: []string{"a"}})
	s.finishUserDisconnect("a", disconnectTarget{historyID: oldID})
	var open int
	for _, sess := range s.historyStore.GetAll() {
		if sess.EndTime == nil {
			open++
		}
	}
	if open != 1 {
		t.Fatalf("replacement closed by prior request: %d open", open)
	}
}

func TestDisconnectAllPreservesTheNoNameRPCAndClosesAllEpochSessions(t *testing.T) {
	status := ConnectionStatus{TunnelName: "a", CounterEpoch: "A", RxBytes: 150, ActiveTunnels: []string{"a", "b"}, Tunnels: []ConnectionStatus{{TunnelName: "a", CounterEpoch: "A", RxBytes: 150}, {TunnelName: "b", CounterEpoch: "B", RxBytes: 200}}}
	s := epochRPCServiceWithDisconnect(t, status, func(raw json.RawMessage) (interface{}, error) {
		if len(raw) != 0 && string(raw) != "null" {
			return nil, errors.New("no-name disconnect changed its RPC contract")
		}
		return ipc.Empty{}, nil
	})
	ObserveHistoryStatus(s, status)
	if err := s.Disconnect(); err != nil {
		t.Fatal(err)
	}
	all := s.historyStore.GetAll()
	if len(all) != 2 {
		t.Fatalf("sessions: %+v", all)
	}
	for _, sess := range all {
		if sess.EndTime == nil || sess.DisconnectReason != "user" {
			t.Fatalf("all-tunnel close incomplete: %+v", sess)
		}
	}
}

func TestTerminalEpochTailUpdatesTheClosedRowWithoutChangingItsEnd(t *testing.T) {
	s := epochRPCService(t, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 150, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 100, ActiveTunnels: []string{"a"}})
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	closed := lastSession(t, s)
	for _, rx := range []int64{170, 160, 170} {
		ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: rx, ActiveTunnels: []string{"a"}})
	}
	if got := lastSession(t, s); got.RxBytes != 170 || got.ID != closed.ID || !got.EndTime.Equal(*closed.EndTime) || got.DurationSec != closed.DurationSec || got.DisconnectReason != "user" {
		t.Fatalf("tail changed lifecycle or counters: %+v", got)
	}
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "F", RxBytes: 20, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{TunnelName: "a", CounterEpoch: "E", RxBytes: 175, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	all := s.historyStore.GetAll()
	if len(all) != 2 || all[0].RxBytes != 20 || all[1].RxBytes != 175 {
		t.Fatalf("terminal tail polluted replacement: %+v", all)
	}
}
