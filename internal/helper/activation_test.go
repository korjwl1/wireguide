package helper

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/launchd"
)

// Until a GUI attaches the helper is dormant: reevaluateAutomation must
// return before taking reevalMu (so it cannot touch settings or tunnels).
func TestReevaluateAutomationDormantBeforeGUISeen(t *testing.T) {
	h := &Helper{}
	h.reevalMu.Lock() // a non-dormant evaluation would block here
	done := make(chan struct{})
	go func() {
		h.reevaluateAutomation("test")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reevaluateAutomation ran (blocked on reevalMu) before any GUI attached")
	}
	h.reevalMu.Unlock()

}

func TestMarkGUISeenReleasesWaiters(t *testing.T) {
	h := &Helper{guiSeenCh: make(chan struct{})}
	if h.guiSeen.Load() {
		t.Fatal("guiSeen set before any GUI attached")
	}
	select {
	case <-h.guiSeenCh:
		t.Fatal("guiSeenCh closed too early")
	default:
	}
	h.markGUISeen()
	h.markGUISeen() // idempotent
	if !h.guiSeen.Load() {
		t.Fatal("guiSeen not set after markGUISeen")
	}
	select {
	case <-h.guiSeenCh:
	default:
		t.Fatal("guiSeenCh not closed by markGUISeen")
	}
}

func TestStartupGraceFor(t *testing.T) {
	if got := startupGraceFor(true); got != 15*time.Second {
		t.Errorf("activated grace = %v, want 15s", got)
	}
	if got := startupGraceFor(false); got != 60*time.Second {
		t.Errorf("non-activated grace = %v, want 60s", got)
	}
}

// Run arms the short grace window for a launchd-activated helper with no
// GUI, and the long one otherwise (active-tunnel guard is armShutdownTimer's).
func TestStartupGraceArmedByActivation(t *testing.T) {
	for _, tt := range []struct {
		activated bool
		want      time.Duration
	}{{true, 15 * time.Second}, {false, 60 * time.Second}} {
		h := &Helper{activated: tt.activated}
		h.armStartupGrace()
		h.mu.Lock()
		timer, got := h.shutdownTimer, h.armedGrace
		h.mu.Unlock()
		if timer == nil {
			t.Fatalf("activated=%v: no shutdown timer armed", tt.activated)
		}
		timer.Stop()
		if got != tt.want {
			t.Errorf("activated=%v: armed %v, want %v", tt.activated, got, tt.want)
		}
	}
}

func TestFallbackAddr(t *testing.T) {
	if got := fallbackAddr(ipc.DarwinSocketPath); got != ipc.LegacyDarwinSocketPath {
		t.Errorf("fallbackAddr(launchd path) = %q, want legacy path", got)
	}
	other := "/tmp/wg-x/s.sock"
	if got := fallbackAddr(other); got != other {
		t.Errorf("fallbackAddr(%q) = %q, want unchanged", other, got)
	}
}

func TestAcquireListenerDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("launchd activation is darwin-only")
	}
	orig := activateLaunchd
	t.Cleanup(func() { activateLaunchd = orig })
	dir, err := os.MkdirTemp("/tmp", "wg-acq-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "s.sock")

	t.Run("activated socket is used and ipc.Listen is skipped", func(t *testing.T) {
		inner, err := net.Listen("unix", filepath.Join(dir, "launchd.sock"))
		if err != nil {
			t.Fatal(err)
		}
		defer inner.Close()
		activateLaunchd = func() ([]net.Listener, error) { return []net.Listener{inner}, nil }
		l, _, activated, err := acquireListener(addr, -1, "")
		if err != nil || !activated || l != inner {
			t.Fatalf("got listener=%v activated=%v err=%v", l, activated, err)
		}
		if _, err := os.Stat(addr); !os.IsNotExist(err) {
			t.Fatalf("ipc.Listen ran although launchd supplied the socket (stat: %v)", err)
		}
	})
	for _, notActivated := range []error{launchd.ErrNotManaged, launchd.ErrNoSocketEntry} {
		t.Run("falls back on "+notActivated.Error(), func(t *testing.T) {
			activateLaunchd = func() ([]net.Listener, error) { return nil, notActivated }
			l, _, activated, err := acquireListener(addr, -1, "")
			if err != nil || activated {
				t.Fatalf("activated=%v err=%v", activated, err)
			}
			defer l.Close()
			if _, err := os.Stat(addr); err != nil {
				t.Fatalf("fallback did not listen at %s: %v", addr, err)
			}
		})
	}
	t.Run("other activation errors are fatal", func(t *testing.T) {
		boom := errors.New("boom")
		activateLaunchd = func() ([]net.Listener, error) { return nil, boom }
		if _, _, _, err := acquireListener(filepath.Join(dir, "fatal.sock"), -1, ""); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want wrapped boom", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "fatal.sock")); !os.IsNotExist(err) {
			t.Fatal("fatal activation error still fell back to ipc.Listen")
		}
	})
}

// Ping reports GUIAttached from the server's control-connection count: a
// transient CLI probe does not count, a GUI-style client does.
func TestPingReportsGUIAttached(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "wg-ping-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "s.sock")
	l, err := ipc.Listen(addr, -1, "")
	if err != nil {
		t.Fatal(err)
	}
	h := &Helper{server: ipc.NewServer(l)}
	h.server.Handle(ipc.MethodPing, h.handlePing)
	go h.server.Serve()
	t.Cleanup(h.server.Shutdown)

	ping := func(c *ipc.Client) ipc.PingResponse {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var resp ipc.PingResponse
		if err := c.CallWithContext(ctx, ipc.MethodPing, nil, &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	cli, err := ipc.NewTransientClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if r := ping(cli); r.GUIAttached || !r.GUIKnown() {
		t.Fatalf("transient probe: GUIAttached=%v known=%v, want false/true", r.GUIAttached, r.GUIKnown())
	}
	gui, err := ipc.NewClient(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer gui.Close()
	if r := ping(gui); !r.GUIAttached {
		t.Fatal("GUI ping: GUIAttached = false, want true")
	}
	if r := ping(cli); !r.GUIAttached {
		t.Fatal("CLI ping while GUI attached: GUIAttached = false, want true")
	}
}
