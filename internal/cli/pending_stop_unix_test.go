//go:build !windows

package cli

import (
	"encoding/json"
	"github.com/korjwl1/wireguide/internal/ipc"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestStopCancelsHeadlessPendingRestoreOverIPC(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wg-pending-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "h.sock")
	listener, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(listener)
	var quit atomic.Bool
	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		p := ipc.PingResponse{Version: ipc.ProtocolVersion}
		if !quit.Load() {
			p.WantedTunnels = []string{"work"}
		}
		return p, nil
	})
	server.Handle(ipc.MethodActiveTunnels, func(json.RawMessage) (interface{}, error) { return ipc.ActiveTunnelsResponse{}, nil })
	server.Handle(ipc.MethodRequestQuit, func(json.RawMessage) (interface{}, error) { quit.Store(true); return ipc.RequestQuitResponse{}, nil })
	go server.Serve()
	t.Cleanup(server.Shutdown)
	old := helperSocketPath
	helperSocketPath = func() string { return addr }
	t.Cleanup(func() { helperSocketPath = old })
	if code := cmdStop(nil); code != 0 || !quit.Load() {
		t.Fatalf("pending restore ignored: stop=%d quit=%v", code, quit.Load())
	}
}
