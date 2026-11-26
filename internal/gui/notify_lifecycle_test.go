package gui

import "testing"

func TestNotifierQueuedWorkCannotStartAuthorizationAfterCancellation(t *testing.T) {
	for _, interruption := range []string{"disable", "stop", "reset", "disable-enable"} {
		t.Run(interruption, func(t *testing.T) {
			n, svc, _, b, fallbacks := cancelNotifier(t)
			var queued func()
			n.spawn = func(f func()) { queued = f }
			created := 0
			n.newBackend = func() notificationBackend { created++; return b }
			n.onCriticalError("test")
			if queued == nil {
				t.Fatal("expected queued notification work")
			}
			switch interruption {
			case "disable":
				setNotifyAutoChanges(t, svc, false)
			case "stop":
				n.stop()
			case "reset":
				n.reset()
			case "disable-enable":
				setNotifyAutoChanges(t, svc, false)
				setNotifyAutoChanges(t, svc, true)
			}
			queued()
			if created != 0 || b.asked != 0 || b.sentCount() != 0 || *fallbacks != 0 {
				t.Fatalf("canceled work reached backend: created=%d asked=%d sent=%d fallback=%d", created, b.asked, b.sentCount(), *fallbacks)
			}
		})
	}
}

type startupCancellationBackend struct {
	fakeBackend
	onStart func()
}

func (b *startupCancellationBackend) start() error {
	b.onStart()
	return nil
}

func TestNotifierCancellationDuringBackendStartupSkipsAuthorization(t *testing.T) {
	n, fallbacks := deliverNotifier(&fakeBackend{})
	b := &startupCancellationBackend{onStart: n.stop}
	n.newBackend = func() notificationBackend { return b }
	n.deliver(n.generation(), "WireGuide", "test")
	if b.asked != 0 || b.sentCount() != 0 || *fallbacks != 0 {
		t.Fatalf("canceled startup reached authorization: asked=%d sent=%d fallback=%d", b.asked, b.sentCount(), *fallbacks)
	}
}

func TestNotifierSupersededTimerCannotDeliver(t *testing.T) {
	n, _, clock, b, fallbacks := cancelNotifier(t)
	gen := n.generation()
	key := changeKey("home", true)
	n.schedule(key, msgUp, "home", gen)
	n.schedule(key, msgUp, "home", gen)
	clock.timers[0].f()
	if b.sentCount() != 0 || *fallbacks != 0 {
		t.Fatal("the replaced timer must not deliver after losing its pending slot")
	}
	clock.timers[1].f()
	if b.sentCount() != 1 {
		t.Fatalf("the current timer must still deliver once, got %d", b.sentCount())
	}
}
