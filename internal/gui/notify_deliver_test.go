package gui

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

type fakeBackend struct {
	mu       sync.Mutex
	startErr error
	granted  bool
	authErr  error
	// checkOK / checkErr answer checkAuth, the non-prompting re-check.
	checkOK  bool
	checkErr error
	checked  int
	sendErr  error
	sent     int
	asked    int
}

func (f *fakeBackend) start() error { return f.startErr }

func (f *fakeBackend) requestAuth() (bool, error) {
	f.mu.Lock()
	f.asked++
	f.mu.Unlock()
	return f.granted, f.authErr
}

func (f *fakeBackend) checkAuth() (bool, error) {
	f.mu.Lock()
	f.checked++
	f.mu.Unlock()
	return f.checkOK, f.checkErr
}

func (f *fakeBackend) send(string, string, string) error {
	f.mu.Lock()
	f.sent++
	f.mu.Unlock()
	return f.sendErr
}

func deliverNotifier(b *fakeBackend) (*notifier, *int) {
	fallbacks := new(int)
	n := newNotifier(nil, nil)
	n.newBackend = func() notificationBackend { return b }
	n.fallback = func(string, string) error { *fallbacks++; return nil }
	return n, fallbacks
}

// The user said no (or turned WireGuide's notifications off): nothing is
// posted, through the service or around it, for the rest of the session.
func TestDeliverDeniedDropsWithoutFallback(t *testing.T) {
	b := &fakeBackend{granted: false}
	n, fallbacks := deliverNotifier(b)
	n.deliver("WireGuide", "one")
	n.deliver("WireGuide", "two")
	if *fallbacks != 0 {
		t.Fatalf("denied authorization must not fall back, fallbacks=%d", *fallbacks)
	}
	if b.sent != 0 {
		t.Fatalf("denied authorization must not send, sent=%d", b.sent)
	}
	if b.asked != 1 {
		t.Fatalf("authorization must be asked once, asked=%d", b.asked)
	}
}

func TestDeliverGrantedUsesService(t *testing.T) {
	b := &fakeBackend{granted: true}
	n, fallbacks := deliverNotifier(b)
	n.deliver("WireGuide", "one")
	n.deliver("WireGuide", "two")
	if b.sent != 2 || *fallbacks != 0 || b.asked != 1 {
		t.Fatalf("sent=%d fallbacks=%d asked=%d", b.sent, *fallbacks, b.asked)
	}
}

// A service that fails (cannot start, authorization or delivery errors)
// falls back.
func TestDeliverServiceFailureFallsBack(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]*fakeBackend{
		"start": {startErr: boom},
		"auth":  {authErr: boom},
		"send":  {granted: true, sendErr: boom},
	}
	for name, b := range cases {
		n, fallbacks := deliverNotifier(b)
		n.deliver("WireGuide", "one")
		if *fallbacks != 1 {
			t.Errorf("%s error: want 1 fallback, got %d", name, *fallbacks)
		}
	}
}

// Notifications arriving while the authorization prompt is open are
// dropped rather than posted around it.
func TestDeliverDuringPendingAuthDrops(t *testing.T) {
	b := &fakeBackend{granted: true}
	n, fallbacks := deliverNotifier(b)
	n.svcStarted, n.svcUsable, n.svc, n.authPending = true, true, b, true
	if got := n.sendViaService("WireGuide", "one"); got != serviceDrop {
		t.Fatalf("pending authorization: got %v, want serviceDrop", got)
	}
	n.deliver("WireGuide", "two")
	if *fallbacks != 0 || b.sent != 0 {
		t.Fatalf("fallbacks=%d sent=%d", *fallbacks, b.sent)
	}
}

// An authorization prompt left unanswered times out. That is not a
// failure of the service: nothing is posted around it, and the user's
// later "Don't Allow" is respected.
func TestDeliverAuthTimeoutThenDenialDropsWithoutFallback(t *testing.T) {
	timeout := fmt.Errorf("notification authorization timed out after 3 minutes: %w", context.DeadlineExceeded)
	b := &fakeBackend{authErr: timeout, checkOK: false}
	n, fallbacks := deliverNotifier(b)
	n.deliver("WireGuide", "one")
	n.deliver("WireGuide", "two")
	n.deliver("WireGuide", "three")
	if *fallbacks != 0 {
		t.Fatalf("a timed-out prompt must not fall back, fallbacks=%d", *fallbacks)
	}
	if b.sent != 0 {
		t.Fatalf("not authorized: must not send, sent=%d", b.sent)
	}
	if b.asked != 1 {
		t.Fatalf("authorization must be asked once, asked=%d", b.asked)
	}
	if b.checked != 2 {
		t.Fatalf("later sends must re-check, checked=%d", b.checked)
	}
}

// ...and a grant made after the timeout is honoured without another prompt.
func TestDeliverAuthTimeoutThenGrantSends(t *testing.T) {
	timeout := fmt.Errorf("timed out: %w", context.DeadlineExceeded)
	b := &fakeBackend{authErr: timeout}
	n, fallbacks := deliverNotifier(b)
	n.deliver("WireGuide", "one") // the request times out: dropped
	if b.sent != 0 {
		t.Fatalf("timeout must drop the first notification, sent=%d", b.sent)
	}
	b.checkOK = true
	n.deliver("WireGuide", "two")
	n.deliver("WireGuide", "three")
	if b.sent != 2 || *fallbacks != 0 || b.asked != 1 {
		t.Fatalf("sent=%d fallbacks=%d asked=%d", b.sent, *fallbacks, b.asked)
	}
	if b.checked != 1 {
		t.Fatalf("a granted check is remembered, checked=%d", b.checked)
	}
}

// A failed re-check drops; it is not a reason to bypass the service.
func TestDeliverAuthTimeoutThenCheckErrorDrops(t *testing.T) {
	b := &fakeBackend{authErr: context.DeadlineExceeded, checkErr: errors.New("boom")}
	n, fallbacks := deliverNotifier(b)
	n.deliver("WireGuide", "one")
	n.deliver("WireGuide", "two")
	if *fallbacks != 0 || b.sent != 0 {
		t.Fatalf("fallbacks=%d sent=%d", *fallbacks, b.sent)
	}
}
