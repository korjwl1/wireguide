//go:build !windows

package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
)

func TestListTunnelsMarksEveryActiveTunnel(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wgl-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	addr := filepath.Join(dir, "s")
	l, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(l)
	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: ipc.ProtocolVersion}, nil
	})
	server.Handle(ipc.MethodActiveTunnels, func(json.RawMessage) (interface{}, error) {
		return ipc.ActiveTunnelsResponse{Names: []string{"a", "b"}}, nil
	})
	go server.Serve()
	defer server.Shutdown()
	client, err := ipc.NewClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	store := storage.NewTunnelStore(t.TempDir())
	for _, name := range []string{"a", "b", "offline"} {
		cfg := &config.WireGuardConfig{Name: name}
		cfg.Interface.PrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		if err := store.Save(cfg); err != nil {
			t.Fatal(err)
		}
	}
	s := &TunnelService{tunnelStore: store, clients: ipc.NewClientHolder(client)}
	rows, err := s.ListTunnels()
	if err != nil || len(rows) != 3 {
		t.Fatalf("list = %+v, %v", rows, err)
	}
	for _, row := range rows {
		if row.IsConnected != (row.Name != "offline") {
			t.Fatalf("active marker = %+v", row)
		}
	}
}
