package gui

import (
	"sync"

	"github.com/korjwl1/wireguide/internal/guiinstance"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

func startInstanceActivation(instance *guiinstance.Instance, win *application.WebviewWindow) {
	if instance.Requests() == nil {
		return
	}
	ready := make(chan struct{})
	var once sync.Once
	win.OnWindowEvent(events.Common.WindowRuntimeReady, func(*application.WindowEvent) { once.Do(func() { close(ready) }) })
	go waitInstanceActivations(instance.Requests(), ready, instance.Done(), func() {
		if !appQuitting.Load() {
			showDock()
		}
	})
}

func waitInstanceActivations(requests, ready, done <-chan struct{}, activate func()) {
	select {
	case <-done:
		return
	case <-ready:
	}
	for {
		select {
		case <-done:
			return
		case <-requests:
			select {
			case <-done:
				return
			default:
			}
			activate()
		}
	}
}
