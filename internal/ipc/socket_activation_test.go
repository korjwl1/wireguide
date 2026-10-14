package ipc

import (
	"encoding/json"
	"runtime"
	"testing"
)

func TestMinorOfAndGUIKnown(t *testing.T) {
	for v, want := range map[string]int{"1": 0, "1.0": 0, "1.1": 1, "1.2": 2, "1.12": 12, "1.x": 0, "": 0} {
		if got := MinorOf(v); got != want {
			t.Errorf("MinorOf(%q) = %d, want %d", v, got, want)
		}
	}
	if !(PingResponse{Version: ProtocolVersion}).GUIKnown() {
		t.Error("current protocol must report GUIAttached")
	}
	if (PingResponse{Version: "1.1"}).GUIKnown() {
		t.Error("protocol 1.1 predates GUIAttached")
	}
}

func TestPingGUIAttachedWireField(t *testing.T) {
	b, err := json.Marshal(PingResponse{Version: ProtocolVersion, GUIAttached: true})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["gui_attached"] != true {
		t.Fatalf("wire form = %s, want gui_attached=true", b)
	}
}

func TestDarwinSocketPaths(t *testing.T) {
	if DarwinSocketPath != "/var/run/com.wireguide.helper.sock" {
		t.Errorf("DarwinSocketPath = %q", DarwinSocketPath)
	}
	if LegacyDarwinSocketPath != "/var/run/wireguide/wireguide.sock" {
		t.Errorf("LegacyDarwinSocketPath = %q", LegacyDarwinSocketPath)
	}
	if runtime.GOOS == "darwin" {
		// The plist's SockPathName is fixed, so XDG_RUNTIME_DIR must not move it.
		for _, xdg := range []string{"", "/tmp/xdg-test"} {
			t.Setenv("XDG_RUNTIME_DIR", xdg)
			if got := DefaultSocketPath(); got != DarwinSocketPath {
				t.Errorf("DefaultSocketPath() on darwin with XDG_RUNTIME_DIR=%q = %q, want %q", xdg, got, DarwinSocketPath)
			}
		}
	}
}

// ipc.Listen must never manage a shared runtime directory: it would chmod
// /var/run itself and unlink launchd's socket.
func TestListenRefusesSharedRuntimeDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets only")
	}
	for _, addr := range []string{DarwinSocketPath, "/run/wireguide-test.sock"} {
		if l, err := Listen(addr, -1, ""); err == nil {
			l.Close()
			t.Errorf("Listen(%q) succeeded, want refusal", addr)
		}
	}
}
