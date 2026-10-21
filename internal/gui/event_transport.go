package gui

import (
	"sync/atomic"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// Wails alpha.74 holds its window-map read lock while delivering events
// through InvokeSync. Native quit takes the write lock on the AppKit thread,
// so an event waiting for that thread can deadlock application cleanup.
// Keep the normal HTTP bindings transport, but deliver events on the GUI
// thread after releasing the window-map lock.
type guiEventTransport struct {
	*application.HTTPTransport
	windows  func() []application.Window
	dispatch func(func())
	ready    atomic.Bool
	stopped  atomic.Bool
}

func newGUIEventTransport() *guiEventTransport {
	return &guiEventTransport{
		HTTPTransport: application.NewHTTPTransport(),
		dispatch:      application.InvokeAsync,
	}
}

func (t *guiEventTransport) DispatchWailsEvent(event *application.CustomEvent) {
	// Startup logs can emit events before Wails has a native application.
	// InvokeAsync is only valid once the window runtime is ready.
	if !t.ready.Load() || t.stopped.Load() {
		return
	}
	t.dispatch(func() {
		if t.stopped.Load() || event.IsCancelled() || t.windows == nil {
			return
		}
		for _, window := range t.windows() {
			if event.IsCancelled() {
				return
			}
			window.DispatchWailsEvent(event)
		}
	})
}

func (t *guiEventTransport) Ready() { t.ready.Store(true) }

func (t *guiEventTransport) Stop() error {
	t.stopped.Store(true)
	return t.HTTPTransport.Stop()
}
