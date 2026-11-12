package gui

import (
	"sync"
	"testing"
	"time"
)

type pfLateStopper struct{ stopped bool }

func (s *pfLateStopper) Stop() bool { s.stopped = true; return false }

type pfCountBackend struct {
	mu    sync.Mutex
	sends []string
}

func (b *pfCountBackend) start() error               { return nil }
func (b *pfCountBackend) requestAuth() (bool, error) { return true, nil }
func (b *pfCountBackend) checkAuth() (bool, error)   { return true, nil }
func (b *pfCountBackend) send(_, _, body string) error {
	b.mu.Lock()
	b.sends = append(b.sends, body)
	b.mu.Unlock()
	return nil
}

func TestNotifierRunningCallbackFlapCoalesces(t *testing.T) {
	n := newNotifier(nil, nil)
	b := &pfCountBackend{}
	n.newBackend = func() notificationBackend { return b }
	n.fallback = nil
	n.systemLanguage = func() string { return "en" }
	n.spawn = func(f func()) { f() }
	var cbs []func()
	n.afterFunc = func(_ time.Duration, f func()) stopper { cbs = append(cbs, f); return &pfLateStopper{} }

	n.onStatus([]string{"office"})
	n.onStatus([]string{})
	n.onStatus([]string{"office"})
	for _, f := range cbs {
		f()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	t.Logf("timers=%d delivered=%q", len(cbs), b.sends)
	if len(b.sends) != 0 {
		t.Fatalf("flap within the pending window should coalesce to nothing, delivered %q", b.sends)
	}
}
