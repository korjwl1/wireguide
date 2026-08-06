package ipc

import (
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// shortSocketPath is testSocketPath with a deliberately tiny directory
// name. t.TempDir() embeds the (long) test name in the path, and a Unix
// domain socket path is capped at ~104 bytes on macOS — the tests in this
// file have names long enough to blow that budget.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return `\\.\pipe\wireguide-test-` + t.Name()
	}
	dir, err := os.MkdirTemp("", "wgt")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// startTransientTestServer spins up a server that counts OnConnect /
// OnDisconnect firings, the two callbacks that drive the helper's shutdown
// grace window.
func startTransientTestServer(t *testing.T) (addr string, connects, disconnects *atomic.Int32, srv *Server) {
	t.Helper()
	addr = shortSocketPath(t)
	listener, err := Listen(addr, -1, "")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	connects = &atomic.Int32{}
	disconnects = &atomic.Int32{}

	srv = NewServer(listener)
	registerTestPing(srv)
	srv.OnConnect(func() { connects.Add(1) })
	srv.OnDisconnect(func() { disconnects.Add(1) })
	go srv.Serve()
	t.Cleanup(srv.Shutdown)

	time.Sleep(100 * time.Millisecond) // listener ready
	return addr, connects, disconnects, srv
}

// TestTransientClientIsNotAControlConn is the regression guard for the bug
// where a single `wireguide ctl status` cut a GUI-less helper's remaining
// life from 60s to 10s.
//
// The CLI connects, pings and exits within milliseconds. If that counts as a
// control connection, the helper sees "GUI attached" immediately followed by
// "GUI disconnected" and re-arms its 10s shutdown window — so merely asking
// the helper a question would kill it.
func TestTransientClientIsNotAControlConn(t *testing.T) {
	addr, connects, disconnects, srv := startTransientTestServer(t)

	client, err := NewTransientClient(addr)
	if err != nil {
		t.Fatalf("NewTransientClient: %v", err)
	}
	// NewTransientClient already sent a Ping — the request the server
	// inspects when deciding whether to upgrade the connection.
	if got := connects.Load(); got != 0 {
		t.Errorf("OnConnect fired %d time(s) for a transient client, want 0", got)
	}
	if srv.HasControlConn() {
		t.Error("HasControlConn() = true for a transient client, want false")
	}

	client.Close()
	time.Sleep(200 * time.Millisecond)
	if got := disconnects.Load(); got != 0 {
		t.Errorf("OnDisconnect fired %d time(s) when a transient client left, want 0 "+
			"— this is what shortened the helper's shutdown grace window", got)
	}
}

// TestControlClientCountsAsControlConn pins the other half: the GUI's client
// MUST drive the grace window, otherwise a helper would never notice its GUI
// going away and would outlive it.
func TestControlClientCountsAsControlConn(t *testing.T) {
	addr, connects, disconnects, srv := startTransientTestServer(t)

	client, err := NewClient(addr)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got := connects.Load(); got != 1 {
		t.Fatalf("OnConnect fired %d time(s) for a normal client, want 1", got)
	}
	if !srv.HasControlConn() {
		t.Error("HasControlConn() = false while a normal client is attached, want true")
	}

	client.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && disconnects.Load() == 0 {
		time.Sleep(50 * time.Millisecond)
	}
	if got := disconnects.Load(); got != 1 {
		t.Errorf("OnDisconnect fired %d time(s) when the normal client left, want 1", got)
	}
	if srv.HasControlConn() {
		t.Error("HasControlConn() = true after the only control client left, want false")
	}
}

// TestTransientClientDoesNotMaskAGUI checks the mixed case: a CLI command
// running while the GUI is attached must not disturb the GUI's control
// connection, and must not fire OnDisconnect when it exits.
func TestTransientClientDoesNotMaskAGUI(t *testing.T) {
	addr, connects, disconnects, srv := startTransientTestServer(t)

	gui, err := NewClient(addr)
	if err != nil {
		t.Fatalf("NewClient (gui): %v", err)
	}
	defer gui.Close()

	cli, err := NewTransientClient(addr)
	if err != nil {
		t.Fatalf("NewTransientClient: %v", err)
	}
	cli.Close()
	time.Sleep(200 * time.Millisecond)

	if got := connects.Load(); got != 1 {
		t.Errorf("OnConnect fired %d time(s), want 1 (the GUI only)", got)
	}
	if got := disconnects.Load(); got != 0 {
		t.Errorf("OnDisconnect fired %d time(s) while the GUI is still attached, want 0", got)
	}
	if !srv.HasControlConn() {
		t.Error("HasControlConn() = false while the GUI is still attached, want true")
	}
}
