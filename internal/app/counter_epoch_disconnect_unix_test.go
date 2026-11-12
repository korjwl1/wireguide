//go:build !windows

package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

type fakeHelper struct {
	mu     sync.Mutex
	status ConnectionStatus
}

func (f *fakeHelper) set(st ConnectionStatus) { f.mu.Lock(); f.status = st; f.mu.Unlock() }
func (f *fakeHelper) get() ConnectionStatus   { f.mu.Lock(); defer f.mu.Unlock(); return f.status }

func fakeHelperService(t *testing.T, initial ConnectionStatus) (*TunnelService, *fakeHelper) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wgcd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	address := filepath.Join(dir, "s")
	listener, err := ipc.Listen(address, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeHelper{status: initial}
	server := ipc.NewServer(listener)
	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) { return ipc.PingResponse{Version: ipc.ProtocolVersion}, nil })
	server.Handle(ipc.MethodStatus, func(json.RawMessage) (interface{}, error) { return f.get(), nil })
	server.Handle(ipc.MethodDisconnect, func(json.RawMessage) (interface{}, error) {
		f.set(ConnectionStatus{State: "disconnected"})
		return ipc.Empty{}, nil
	})
	go server.Serve()
	t.Cleanup(func() { server.Shutdown() })
	client, err := ipc.NewClient(address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return NewTunnelService(nil, storage.NewSettingsStore(t.TempDir()), storage.NewHistoryStore(t.TempDir()), ipc.NewClientHolder(client)), f
}

func TestShortSessionClosesWithoutAFollowupBroadcast(t *testing.T) {
	for _, path := range []string{"named", "primary"} {
		t.Run(path, func(t *testing.T) {
			s, f := fakeHelperService(t, ConnectionStatus{State: "connected", TunnelName: "a", CounterEpoch: "short", RxBytes: 150, ActiveTunnels: []string{"a"}})
			var err error
			if path == "named" {
				err = s.DisconnectTunnel("a")
			} else {
				err = s.Disconnect()
			}
			if err != nil {
				t.Fatal(err)
			}
			got := lastSession(t, s)
			if got.EndTime == nil || got.RxBytes != 150 || got.DisconnectReason != "user" {
				t.Fatalf("short session not closed by the disconnect path: %+v", got)
			}

			f.set(ConnectionStatus{State: "connected", TunnelName: "a", CounterEpoch: "second", RxBytes: 10, ActiveTunnels: []string{"a"}})
			ObserveHistoryStatus(s, f.get())
			ObserveHistoryStatus(s, ConnectionStatus{})
			all := s.historyStore.GetAll()
			if len(all) != 2 {
				t.Fatalf("want 2 sessions, got %d: %+v", len(all), all)
			}
			if all[0].RxBytes != 10 || all[0].DisconnectReason == "user" {
				t.Fatalf("next session inherited the short session: %+v", all[0])
			}
		})
	}
}

func TestLateBroadcastAfterDisconnectCloseIsIgnored(t *testing.T) {
	s, f := fakeHelperService(t, ConnectionStatus{State: "connected", TunnelName: "a", CounterEpoch: "e", RxBytes: 100, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, f.get())
	f.set(ConnectionStatus{State: "connected", TunnelName: "a", CounterEpoch: "e", RxBytes: 150, ActiveTunnels: []string{"a"}})
	if err := s.DisconnectTunnel("a"); err != nil {
		t.Fatal(err)
	}
	late := ConnectionStatus{State: "connected", TunnelName: "a", CounterEpoch: "e", RxBytes: 140, ActiveTunnels: []string{"a"}}
	ObserveHistoryStatus(s, late)
	ObserveHistoryStatus(s, ConnectionStatus{})
	all := s.historyStore.GetAll()
	if len(all) != 1 || all[0].RxBytes != 150 || all[0].DisconnectReason != "user" {
		t.Fatalf("late broadcast changed history: %+v", all)
	}

	ObserveHistoryStatus(s, ConnectionStatus{State: "connecting", TunnelName: "a", ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{State: "connected", TunnelName: "a", CounterEpoch: "f", RxBytes: 7, ActiveTunnels: []string{"a"}})
	ObserveHistoryStatus(s, ConnectionStatus{})
	all = s.historyStore.GetAll()
	if len(all) != 2 || all[0].RxBytes != 7 {
		t.Fatalf("reconnect after a stale broadcast was lost: %+v", all)
	}
}
