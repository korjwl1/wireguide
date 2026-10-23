package gui

import (
	"sync"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type eventTransportWindow struct {
	application.Window
	deliver func(*application.CustomEvent)
}

func (w eventTransportWindow) DispatchWailsEvent(event *application.CustomEvent) { w.deliver(event) }

func TestEventTransportReleasesWindowLockBeforeNativeDispatch(t *testing.T) {
	var windowsLock sync.RWMutex
	var queued []func()
	delivered := false
	transport := newGUIEventTransport()
	transport.Ready()
	transport.dispatch = func(fn func()) { queued = append(queued, fn) }
	transport.windows = func() []application.Window {
		windowsLock.RLock()
		defer windowsLock.RUnlock()
		return []application.Window{eventTransportWindow{deliver: func(*application.CustomEvent) {
			if !windowsLock.TryLock() {
				t.Fatal("native delivery retained the lock needed by application shutdown")
			}
			windowsLock.Unlock()
			delivered = true
		}}}
	}
	transport.DispatchWailsEvent(&application.CustomEvent{Name: "status"})
	if delivered || len(queued) != 1 {
		t.Fatal("event delivery did not move onto the GUI queue")
	}
	queued[0]()
	if !delivered {
		t.Fatal("event was lost")
	}
}

func TestEventTransportDropsQueuedEventsOnShutdown(t *testing.T) {
	var queued []func()
	transport := newGUIEventTransport()
	transport.Ready()
	transport.dispatch = func(fn func()) { queued = append(queued, fn) }
	transport.windows = func() []application.Window {
		t.Fatal("shutdown event touched destroyed native windows")
		return nil
	}
	transport.DispatchWailsEvent(&application.CustomEvent{Name: "log"})
	if err := transport.Stop(); err != nil {
		t.Fatal(err)
	}
	queued[0]()
	transport.DispatchWailsEvent(&application.CustomEvent{Name: "status"})
	if len(queued) != 1 {
		t.Fatal("shutdown kept queuing events")
	}
}

func TestEventTransportDoesNotDispatchBeforeNativeRuntime(t *testing.T) {
	transport := newGUIEventTransport()
	transport.dispatch = func(func()) { t.Fatal("startup event touched the uninitialized native application") }
	transport.DispatchWailsEvent(&application.CustomEvent{Name: "log"})
}
