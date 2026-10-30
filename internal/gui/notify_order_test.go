package gui

import (
	"sync"
	"testing"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/storage"
)

type captured struct {
	mu   sync.Mutex
	msgs []string
}

func (c *captured) add(_, body string) {
	c.mu.Lock()
	c.msgs = append(c.msgs, body)
	c.mu.Unlock()
}

func (c *captured) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

func (c *captured) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.msgs...)
}

func testNotifier() (*notifier, *captured) {
	c := &captured{}
	n := newNotifier(nil, wgapp.NewUserActions())
	n.post = c.add
	n.systemLanguage = func() string { return "en" }
	n.pendingDelay = 30 * time.Millisecond
	return n, c
}

// auto_connected lands before the status tick that shows the tunnel up.
func TestNotifierAutoBeforeStatus(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil) // baseline
	n.onAutoConnected("Office")
	n.onStatus([]string{"Office"})
	time.Sleep(150 * time.Millisecond)
	if got := c.count(); got != 1 {
		t.Fatalf("want exactly 1 notification, got %d: %v", got, c.all())
	}
}

// status shows the tunnel connected, then auto_connected arrives inside
// the hold-back window: the timer is cancelled, one notification total.
func TestNotifierAutoAfterStatusWithinDelay(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.onStatus([]string{"Office"})
	n.onAutoConnected("Office")
	time.Sleep(150 * time.Millisecond)
	if got := c.count(); got != 1 {
		t.Fatalf("want 1, got %d: %v", got, c.all())
	}
	if msgs := c.all(); msgs[0] != "Automation connected “Office”." {
		t.Fatalf("auto_connected must name the tunnel, got %q", msgs[0])
	}
}

// Without any helper event a connect nobody here asked for still notifies.
func TestNotifierOutsideConnectAndDisconnect(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.onStatus([]string{"Office"})
	waitForCount(t, c, 1)
	n.onStatus(nil)
	waitForCount(t, c, 2)
	msgs := c.all()
	if len(msgs) != 2 || msgs[0] != "“Office” connected outside the app." || msgs[1] != "“Office” disconnected outside the app." {
		t.Fatalf("got %v", msgs)
	}
}

// Tunnels already up when the GUI starts never notify.
func TestNotifierFirstStatusSeedsBaseline(t *testing.T) {
	n, c := testNotifier()
	n.onStatus([]string{"Office"})
	time.Sleep(100 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("baseline must be silent, got %v", c.all())
	}
}

func TestNotifierUserConnectSilent(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.actions.Begin("Office", true)
	n.onStatus([]string{"Office"})
	n.onStatus(nil) // failed connect drops it again
	time.Sleep(150 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("user-initiated change must be silent, got %v", c.all())
	}
}

func TestNotifierUserDisconnectSilent(t *testing.T) {
	n, c := testNotifier()
	n.onStatus([]string{"Office", "Lab"})
	n.actions.Begin(wgapp.AnyTunnel, false) // "disconnect whatever is active"
	n.onStatus(nil)
	time.Sleep(100 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("user disconnect must be silent, got %v", c.all())
	}
}

// A down shortly after a user connect (the attempt failed) is not reported
// as "disconnected outside the app", even after the call has returned.
func TestNotifierFailedUserConnectSilent(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.actions.Begin("Office", true)
	n.onStatus([]string{"Office"})
	n.actions.End("Office", true)
	n.onStatus(nil)
	time.Sleep(100 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("failed user connect must be silent, got %v", c.all())
	}
}

func TestNotifierStopSilences(t *testing.T) {
	n, c := testNotifier()
	n.onStatus([]string{"Office"})
	n.stop()
	n.onStatus(nil)
	n.onCriticalError("x")
	n.onAutoConnected("Office")
	n.onForcedDisconnect("Office")
	time.Sleep(100 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("stopped notifier must be silent, got %v", c.all())
	}
}

// Quitting while a change is held back drops it.
func TestNotifierStopCancelsPending(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.onStatus([]string{"Office"})
	n.stop()
	time.Sleep(100 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("pending notification must not survive quit, got %v", c.all())
	}
}

// forced_disconnect and the status tick showing the tunnel down describe
// one change, in either order.
func TestNotifierForcedDisconnectDedupes(t *testing.T) {
	for _, eventFirst := range []bool{true, false} {
		n, c := testNotifier()
		n.onStatus([]string{"Office"})
		if eventFirst {
			n.onForcedDisconnect("Office")
			n.onStatus(nil)
		} else {
			n.onStatus(nil)
			n.onForcedDisconnect("Office")
		}
		time.Sleep(150 * time.Millisecond)
		msgs := c.all()
		if len(msgs) != 1 || msgs[0] == "“Office” disconnected outside the app." {
			t.Fatalf("eventFirst=%v: want exactly the forced-disconnect message, got %v", eventFirst, msgs)
		}
	}
}

// Claims expire: a later, unrelated automatic change notifies again.
func TestNotifierClaimExpires(t *testing.T) {
	n, c := testNotifier()
	n.onStatus(nil)
	n.onAutoConnected("Office")
	n.mu.Lock()
	n.claimed[changeKey("Office", true)] = time.Now().Add(-2 * claimTTL)
	n.mu.Unlock()
	n.onStatus([]string{"Office"})
	time.Sleep(150 * time.Millisecond)
	if got := c.count(); got != 2 { // the event itself plus the unclaimed change
		t.Fatalf("want 2, got %v", c.all())
	}
}

func TestNotifierCriticalError(t *testing.T) {
	n, c := testNotifier()
	n.onCriticalError("eventLoop")
	waitForCount(t, c, 1)
	if msgs := c.all(); len(msgs) != 1 {
		t.Fatalf("got %v", msgs)
	}
}

// The Settings toggle turns every automatic notification off.
func TestNotifierToggleOff(t *testing.T) {
	store := storage.NewSettingsStore(t.TempDir())
	if err := store.Update(func(s *storage.Settings) error { s.NotifyAutoChanges = false; return nil }); err != nil {
		t.Fatal(err)
	}
	c := &captured{}
	n := newNotifier(store, wgapp.NewUserActions())
	n.post = c.add
	n.pendingDelay = 30 * time.Millisecond
	n.onStatus(nil)
	n.onStatus([]string{"Office"})
	n.onAutoConnected("Office")
	n.onForcedDisconnect("Office")
	n.onCriticalError("x")
	time.Sleep(150 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("toggle off must be silent, got %v", c.all())
	}
}

// A nil notifier (bridge without one) is a no-op.
func TestNilNotifierSafe(t *testing.T) {
	var n *notifier
	n.onStatus([]string{"a"})
	n.onAutoConnected("a")
	n.onForcedDisconnect("a")
	n.onCriticalError("a")
	n.reset()
	n.stop()
}

// pendingCount reports how many status-diff messages are held back.
func pendingCount(n *notifier) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.pending)
}

// A reconnect (wake, health check) takes the tunnel down and back up inside
// the hold-back window: neither direction is announced. The delay is long
// enough that no timer can fire during the test, so the assertions do not
// depend on sleeps.
func TestNotifierReconnectFlapSilent(t *testing.T) {
	for _, startUp := range []bool{true, false} {
		n, c := testNotifier()
		n.pendingDelay = time.Hour
		if startUp {
			n.onStatus([]string{"Office"}) // baseline: up
			n.onStatus(nil)                // down, held back
			if got := pendingCount(n); got != 1 {
				t.Fatalf("startUp=%v: down must be held back, pending=%d", startUp, got)
			}
			n.onStatus([]string{"Office"}) // back up
		} else {
			n.onStatus(nil)                // baseline: down
			n.onStatus([]string{"Office"}) // up, held back
			if got := pendingCount(n); got != 1 {
				t.Fatalf("startUp=%v: up must be held back, pending=%d", startUp, got)
			}
			n.onStatus(nil) // down again
		}
		if got := pendingCount(n); got != 0 {
			t.Fatalf("startUp=%v: a reversed change must leave nothing pending, pending=%d", startUp, got)
		}
		if got := c.count(); got != 0 {
			t.Fatalf("startUp=%v: a reversed change must be silent, got %v", startUp, c.all())
		}
	}
}

// A slow reconnect (the tunnel comes back after the up hold-back but inside
// the down hold-back) announces nothing.
func TestNotifierSlowReconnectSilent(t *testing.T) {
	n, c := testNotifier()
	n.pendingDelay = 30 * time.Millisecond
	n.downPendingDelay = 2 * time.Second
	n.onStatus([]string{"Office"})
	n.onStatus(nil)                    // down, held back for the long delay
	time.Sleep(150 * time.Millisecond) // well past pendingDelay
	if got := c.count(); got != 0 {
		t.Fatalf("down must still be held back, got %v", c.all())
	}
	n.onStatus([]string{"Office"}) // back up
	if got := pendingCount(n); got != 0 {
		t.Fatalf("reconnect must leave nothing pending, pending=%d", got)
	}
	time.Sleep(150 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("slow reconnect must be silent, got %v", c.all())
	}
}

// A tunnel that stays down is announced once, after the down hold-back.
func TestNotifierDownWithoutUpAnnouncesOnce(t *testing.T) {
	n, c := testNotifier()
	n.pendingDelay = 30 * time.Millisecond
	n.downPendingDelay = 300 * time.Millisecond
	n.onStatus([]string{"Office"})
	n.onStatus(nil)
	time.Sleep(100 * time.Millisecond)
	if got := c.count(); got != 0 {
		t.Fatalf("down must not be announced before its delay, got %v", c.all())
	}
	waitForCount(t, c, 1)
	time.Sleep(100 * time.Millisecond)
	if msgs := c.all(); len(msgs) != 1 || msgs[0] != "“Office” disconnected outside the app." {
		t.Fatalf("got %v", msgs)
	}
}

// Once the held-back message has gone out, the reverse change is a new
// change and is announced.
func TestNotifierReverseAfterDeliveryNotifies(t *testing.T) {
	n, c := testNotifier()
	n.onStatus([]string{"Office"})
	n.onStatus(nil)
	waitForCount(t, c, 1)
	n.onStatus([]string{"Office"})
	waitForCount(t, c, 2)
	msgs := c.all()
	if msgs[0] != "“Office” disconnected outside the app." || msgs[1] != "“Office” connected outside the app." {
		t.Fatalf("got %v", msgs)
	}
}

// waitForCount waits until c holds want messages (failing after a generous
// deadline) instead of sleeping for a fixed time.
func waitForCount(t *testing.T, c *captured, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.count() < want {
		if time.Now().After(deadline) {
			t.Fatalf("want %d notifications, got %v", want, c.all())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
