//go:build !windows

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/korjwl1/wireguide/internal/ipc"
)

func TestDeleteUsesHeadlessHelperAndPreservesItsFailure(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wgd-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	addr := filepath.Join(dir, "s")
	l, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	s := ipc.NewServer(l)
	s.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: ipc.ProtocolVersion}, nil // no GUI
	})
	received := make(chan ipc.DeleteRequest, 1)
	s.Handle(ipc.MethodDelete, func(params json.RawMessage) (interface{}, error) {
		var req ipc.DeleteRequest
		if err := json.Unmarshal(params, &req); err != nil {
			return nil, err
		}
		received <- req
		return nil, fmt.Errorf("cannot disconnect this tunnel")
	})
	go s.Serve()
	defer s.Shutdown()
	oldPath := helperSocketPath
	helperSocketPath = func() string { return addr }
	defer func() { helperSocketPath = oldPath }()
	// A failure must return before touching any real user store/settings.
	if code := cmdDelete([]string{"review-delete"}); code != 1 {
		t.Fatalf("delete ignored helper failure: exit %d", code)
	}
	select {
	case req := <-received:
		if req.TunnelName != "review-delete" || !req.Disconnect {
			t.Fatalf("delete request = %+v", req)
		}
	default:
		t.Fatal("headless helper was bypassed")
	}
}
