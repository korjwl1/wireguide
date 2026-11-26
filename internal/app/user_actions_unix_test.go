//go:build !windows

package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

// Connect and Disconnect (window and tray both call these) must record the
// action for the whole RPC and for the lingering status lag afterwards, even
// when the helper reports a failure — otherwise the notifier would report a
// failed user connect as a change "outside the app".
func TestTunnelServiceRecordsUserActions(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wgu-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	l, err := ipc.Listen(filepath.Join(dir, "s"), -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(l)
	store := storage.NewTunnelStore(t.TempDir())
	cfg := &config.WireGuardConfig{Name: "office-vpn"}
	cfg.Interface.PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	s := &TunnelService{tunnelStore: store, userActions: NewUserActions()}

	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: ipc.ProtocolVersion}, nil
	})
	var duringConnect, duringDisconnect, duringDisconnectTunnel atomic.Bool
	server.Handle(ipc.MethodConnect, func(json.RawMessage) (interface{}, error) {
		duringConnect.Store(s.userActions.Recent("office-vpn", true, time.Now()))
		return nil, errors.New("connect failed")
	})
	server.Handle(ipc.MethodDisconnect, func(params json.RawMessage) (interface{}, error) {
		var req ipc.DisconnectRequest
		_ = json.Unmarshal(params, &req)
		if req.TunnelName == "" {
			duringDisconnect.Store(s.userActions.Recent("anything", false, time.Now()))
		} else {
			duringDisconnectTunnel.Store(s.userActions.Recent(req.TunnelName, false, time.Now()))
		}
		return ipc.Empty{}, nil
	})
	go server.Serve()
	defer server.Shutdown()
	client, err := ipc.NewClient(filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	s.clients = ipc.NewClientHolder(client)

	if s.userActions.Recent("office-vpn", true, time.Now()) {
		t.Fatal("no action recorded yet")
	}
	if err := s.Connect("office-vpn"); err == nil {
		t.Fatal("expected the helper's connect failure")
	}
	if !duringConnect.Load() {
		t.Error("connect was not recorded while the RPC was in flight")
	}
	if !s.userActions.Recent("office-vpn", true, time.Now()) {
		t.Error("failed connect must keep covering the status lag afterwards")
	}
	if err := s.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if !duringDisconnect.Load() {
		t.Error("Disconnect must record a wildcard action")
	}
	if err := s.DisconnectTunnel("lab-vpn"); err != nil {
		t.Fatal(err)
	}
	if !duringDisconnectTunnel.Load() {
		t.Error("DisconnectTunnel was not recorded")
	}
	if !s.userActions.Recent("lab-vpn", false, time.Now()) {
		t.Error("disconnect must keep covering the status lag afterwards")
	}
	if s.userActions.Recent("other", true, time.Now()) {
		t.Error("an unrelated tunnel must not be covered")
	}
}
