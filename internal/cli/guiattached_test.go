package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/korjwl1/wireguide/internal/ipc"
)

func TestAppRunning(t *testing.T) {
	for _, tt := range []struct {
		name string
		ping ipc.PingResponse
		want bool
	}{
		{"GUI attached", ipc.PingResponse{Version: "1.2", GUIAttached: true}, true},
		{"no GUI attached", ipc.PingResponse{Version: "1.2", GUIAttached: false}, false},
		{"old helper cannot say, assumed running", ipc.PingResponse{Version: "1.1"}, true},
		{"legacy wire version", ipc.PingResponse{Version: "1"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := appRunning(tt.ping); got != tt.want {
				t.Fatalf("appRunning = %v, want %v", got, tt.want)
			}
		})
	}
}

// cmdStop success is "no app attached and no tunnel up" — never "the socket
// stopped answering", since a probe dial re-activates a launchd helper.
func TestQuitComplete(t *testing.T) {
	cur := ipc.PingResponse{Version: ipc.ProtocolVersion}
	if quitComplete(ipc.PingResponse{Version: cur.Version, GUIAttached: true}, 0) {
		t.Error("GUI still attached counted as stopped")
	}
	if quitComplete(cur, 1) {
		t.Error("active tunnel counted as stopped")
	}
	if quitComplete(cur, -1) {
		t.Error("unknown tunnel count counted as stopped")
	}
	if !quitComplete(cur, 0) {
		t.Error("no GUI and no tunnels should count as stopped")
	}
	if quitComplete(ipc.PingResponse{Version: "1.1"}, 0) {
		t.Error("an old helper that cannot report GUIAttached must not count as stopped while it still answers")
	}
}

// serveFakeHelper runs a helper stub on a private socket and points the CLI
// at it. The returned pointers let a test change what the helper reports.
func serveFakeHelper(t *testing.T) (attached *bool, active *[]string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wg-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "h.sock")
	if runtime.GOOS == "windows" {
		t.Skip("unix socket test")
	}
	l, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Skipf("cannot listen on %s: %v", filepath.Base(addr), err)
	}
	old := helperSocketPath
	helperSocketPath = func() string { return addr }
	t.Cleanup(func() { helperSocketPath = old })
	srv := ipc.NewServer(l)
	attached, active = new(bool), new([]string)
	srv.Handle(ipc.MethodPing, func(json.RawMessage) (interface{}, error) {
		return ipc.PingResponse{Version: ipc.ProtocolVersion, GUIAttached: *attached}, nil
	})
	srv.Handle(ipc.MethodActiveTunnels, func(json.RawMessage) (interface{}, error) {
		return ipc.ActiveTunnelsResponse{Names: *active}, nil
	})
	go srv.Serve()
	t.Cleanup(srv.Shutdown)
	return attached, active
}

// dialHelper over a real socket: a helper without a GUI is "not running" -
// unless a tunnel is still up, which is live state the CLI's guards (delete,
// rename, set, disconnect) must see.
func TestDialHelperHonoursGUIAttached(t *testing.T) {
	attached, active := serveFakeHelper(t)

	if c, err := dialHelper(); !errors.Is(err, errAppNotRunning) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("dialHelper with no GUI: err = %v, want errAppNotRunning", err)
	}

	*active = []string{"work"}
	c, err := dialHelper()
	if err != nil {
		t.Fatalf("dialHelper with no GUI but a live tunnel: %v", err)
	}
	c.Close()
	if c, err := dialHelperStrict(); !errors.Is(err, errAppNotRunning) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("dialHelperStrict with no GUI: err = %v, want errAppNotRunning", err)
	}

	*active = nil
	*attached = true
	c, err = dialHelper()
	if err != nil {
		t.Fatalf("dialHelper with GUI attached: %v", err)
	}
	c.Close()
}

// A headless helper with a tunnel up must still engage `delete`'s guard: the
// helper refuses the disconnect here, so the config file has to survive.
func TestDeleteGuardsLiveTunnelOnHeadlessHelper(t *testing.T) {
	_, active := serveFakeHelper(t)
	*active = []string{"work"}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	store, err := tunnelStore()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportFromContent("work", "[Interface]\nPrivateKey = 4OnLoxSBnWDtTxMcDZGM0IYBGBEw6rnWSkAkSDZ0DmY=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = 4OnLoxSBnWDtTxMcDZGM0IYBGBEw6rnWSkAkSDZ0DmY=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n"); err != nil {
		t.Fatalf("seed tunnel: %v", err)
	}
	if rc := cmdDelete([]string{"work"}); rc == 0 {
		t.Fatal("delete succeeded although the helper refused to disconnect the live tunnel")
	}
	if !store.Exists("work") {
		t.Fatal("live tunnel's config was deleted")
	}
}
