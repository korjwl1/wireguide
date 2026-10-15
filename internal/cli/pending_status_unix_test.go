//go:build !windows

package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
)

func TestStatusShowsPendingAlongsideActive(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wg-status-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "h.sock")
	ln, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	server := ipc.NewServer(ln)
	var connecting atomic.Bool
	server.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: ipc.ProtocolVersion, WantedTunnels: []string{"home", "work"}}, nil
	})
	server.Handle(ipc.MethodActiveTunnels, func(json.RawMessage) (interface{}, error) {
		return ipc.ActiveTunnelsResponse{Names: []string{"home"}}, nil
	})
	server.Handle(ipc.MethodStatus, func(json.RawMessage) (interface{}, error) {
		state := domain.StateConnected
		if connecting.Load() {
			state = domain.StateConnecting
		}
		return domain.ConnectionStatus{Tunnels: []domain.ConnectionStatus{{TunnelName: "home", State: state}}}, nil
	})
	go server.Serve()
	t.Cleanup(server.Shutdown)
	oldPath := helperSocketPath
	helperSocketPath = func() string { return addr }
	t.Cleanup(func() { helperSocketPath = oldPath })
	for _, tc := range []struct{ jsonOut, connecting bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		jsonOut := tc.jsonOut
		connecting.Store(tc.connecting)
		rd, wr, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		saved := os.Stdout
		os.Stdout = wr
		var args []string
		if jsonOut {
			args = []string{"--json"}
		}
		code := cmdStatus(args)
		os.Stdout = saved
		wr.Close()
		out, err := io.ReadAll(rd)
		rd.Close()
		if err != nil || code != 0 {
			t.Fatalf("status code=%d err=%v", code, err)
		}
		if jsonOut {
			var rows []domain.ConnectionStatus
			if err := json.Unmarshal(out, &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 || rows[0].TunnelName != "home" || rows[1].TunnelName != "work" || rows[1].State != domain.StateConnecting {
				t.Fatalf("status rows=%+v", rows)
			}
		} else if tc.connecting && !strings.Contains(string(out), "home  connecting") {
			t.Fatalf("active connecting row mislabeled: %s", out)
		} else if !strings.Contains(string(out), "home") || !strings.Contains(string(out), "work  waiting to reconnect") {
			t.Fatalf("pending hidden: %s", out)
		}
	}
}
