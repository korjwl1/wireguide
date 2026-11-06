package gui

import (
	"errors"
	"sync"
	"testing"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/storage"
)

// fakeTimer is a hold-back timer the test fires by hand. Firing a stopped
// timer models the race where the timer had already expired when it was
// cancelled, so the callback's own checkpoint is what must drop the message.
type fakeTimer struct {
	f       func()
	stopped bool
}

func (t *fakeTimer) Stop() bool {
	was := !t.stopped
	t.stopped = true
	return was
}

type fakeClock struct {
	timers []*fakeTimer
}

func (c *fakeClock) afterFunc(_ time.Duration, f func()) stopper {
	t := &fakeTimer{f: f}
	c.timers = append(c.timers, t)
	return t
}

// cancelNotifier builds a notifier on a real settings store that runs the
// real send -> deliver path synchronously against a fake backend, with
// hand-fired timers. It installs the production preferences hook so
// TunnelService.UpdateSettings reaches it exactly as in gui.Run.
func cancelNotifier(t *testing.T) (*notifier, *wgapp.TunnelService, *fakeClock, *fakeBackend, *int) {
	t.Helper()
	store := storage.NewSettingsStore(t.TempDir())
	svc := wgapp.NewTunnelService(nil, store, nil, nil)
	n := newNotifier(store, wgapp.NewUserActions())
	n.systemLanguage = func() string { return "en" }
	clock := &fakeClock{}
	n.afterFunc = clock.afterFunc
	n.spawn = func(f func()) { f() }
	b := &fakeBackend{granted: true}
	n.newBackend = func() notificationBackend { return b }
	fallbacks := new(int)
	n.fallback = func(string, string) error { *fallbacks++; return nil }
	installPreferencesHook(t, n)
	return n, svc, clock, b, fallbacks
}

func installPreferencesHook(t *testing.T, n *notifier) {
	t.Helper()
	wgapp.SetGUIPreferencesChanged(preferencesChangedHook(n, nil))
	// atomic.Value cannot store nil; leave a no-op behind.
	t.Cleanup(func() { wgapp.SetGUIPreferencesChanged(func() {}) })
}

func setNotifyAutoChanges(t *testing.T, svc *wgapp.TunnelService, on bool) {
	t.Helper()
	if err := svc.UpdateSettings(wgapp.SettingsPatch{NotifyAutoChanges: &on}); err != nil {
		t.Fatal(err)
	}
}

// A "disconnected outside the app" message is held back, then the user
// turns the toggle off through UpdateSettings: the held-back message must
// not be delivered, even if its timer had already expired.
func TestNotifierQueueThenDisableDrops(t *testing.T) {
	n, svc, clock, b, fallbacks := cancelNotifier(t)
	n.onStatus([]string{"Office"})
	n.onStatus(nil) // down, held back
	if len(clock.timers) != 1 {
		t.Fatalf("want one held-back message, got %d timers", len(clock.timers))
	}
	setNotifyAutoChanges(t, svc, false)
	clock.timers[0].f()
	if b.sentCount() != 0 || *fallbacks != 0 {
		t.Errorf("queued message delivered after disable: sent=%d fallbacks=%d", b.sentCount(), *fallbacks)
	}
	if !clock.timers[0].stopped || pendingCount(n) != 0 {
		t.Errorf("disable must cancel held-back messages: stopped=%v pending=%d", clock.timers[0].stopped, pendingCount(n))
	}
}

// Disable then re-enable: the message queued before the disable stays
// dropped, while changes after the re-enable notify again.
func TestNotifierDisableReEnableDropsStaleKeepsNew(t *testing.T) {
	n, svc, clock, b, fallbacks := cancelNotifier(t)
	n.onStatus([]string{"Office"})
	n.onStatus(nil) // down, held back
	setNotifyAutoChanges(t, svc, false)
	setNotifyAutoChanges(t, svc, true)
	clock.timers[0].f() // the stale timer fires after the re-enable
	if got := b.sentCount(); got != 0 {
		t.Fatalf("stale message delivered after re-enable: sent=%d", got)
	}
	n.onStatus([]string{"Office"}) // a new change after the re-enable
	if len(clock.timers) != 2 {
		t.Fatalf("new change must be held back, got %d timers", len(clock.timers))
	}
	clock.timers[1].f()
	n.onCriticalError("eventLoop")
	if got := b.sentCount(); got != 2 || *fallbacks != 0 {
		t.Fatalf("new events after re-enable must notify: sent=%d fallbacks=%d", got, *fallbacks)
	}
}

// A helper restart (reset) drops a message held back before it.
func TestNotifierResetDropsQueued(t *testing.T) {
	n, _, clock, b, _ := cancelNotifier(t)
	n.onStatus(nil)
	n.onStatus([]string{"Office"}) // up, held back
	n.reset()
	clock.timers[0].f()
	if got := b.sentCount(); got != 0 {
		t.Fatalf("message queued before reset delivered: sent=%d", got)
	}
}

// blockingBackend holds the authorization request (or the non-prompting
// re-check) until the test answers it.
type blockingBackend struct {
	fakeBackend
	waiting chan struct{}
	answer  chan bool
}

func (b *blockingBackend) requestAuth() (bool, error) {
	b.mu.Lock()
	b.asked++
	b.mu.Unlock()
	close(b.waiting)
	return <-b.answer, nil
}

func (b *blockingBackend) checkAuth() (bool, error) {
	b.mu.Lock()
	b.checked++
	b.mu.Unlock()
	close(b.waiting)
	return <-b.answer, nil
}

// The app quits (or the toggle is turned off) while delivery waits on the
// authorization prompt or on the re-check after a timed-out prompt; the
// user then grants authorization. Nothing may be posted, through the
// service or the fallback. Runs the real onCriticalError -> send -> deliver
// path on its own goroutine, synchronised only by channels.
func TestNotifierAuthWaitThenStopDrops(t *testing.T) {
	for _, wait := range []string{"request", "recheck"} {
		for _, interrupt := range []string{"stop", "disable"} {
			t.Run(wait+"/"+interrupt, func(t *testing.T) {
				store := storage.NewSettingsStore(t.TempDir())
				svc := wgapp.NewTunnelService(nil, store, nil, nil)
				n := newNotifier(store, wgapp.NewUserActions())
				n.systemLanguage = func() string { return "en" }
				installPreferencesHook(t, n)
				b := &blockingBackend{waiting: make(chan struct{}), answer: make(chan bool)}
				n.newBackend = func() notificationBackend { return b }
				if wait == "recheck" {
					n.svcStarted, n.svcUsable, n.svc = true, true, b
					n.authAsked, n.authTimedOut = true, true
				}
				var mu sync.Mutex
				fallbacks := 0
				n.fallback = func(string, string) error { mu.Lock(); fallbacks++; mu.Unlock(); return nil }
				done := make(chan struct{})
				n.post = func(gen uint64, title, body string) {
					defer close(done)
					n.deliver(gen, title, body)
				}

				n.onCriticalError("eventLoop")
				<-b.waiting
				if interrupt == "stop" {
					n.stop()
				} else {
					setNotifyAutoChanges(t, svc, false)
				}
				b.answer <- true
				<-done

				mu.Lock()
				defer mu.Unlock()
				if got := b.sentCount(); got != 0 || fallbacks != 0 {
					t.Fatalf("delivered after %s during the authorization wait: sent=%d fallbacks=%d", interrupt, got, fallbacks)
				}
			})
		}
	}
}

var errTestSend = errors.New("send failed")

// The service fails while the app is quitting: the fallback must not post
// the now-stale message either.
func TestDeliverStopBeforeFallbackDrops(t *testing.T) {
	b := &fakeBackend{granted: true, sendErr: errTestSend}
	n, fallbacks := deliverNotifier(b)
	b.onSend = n.stop
	n.deliver(n.generation(), "WireGuide", "one")
	if *fallbacks != 0 {
		t.Fatalf("fallback posted after stop: fallbacks=%d", *fallbacks)
	}
}
