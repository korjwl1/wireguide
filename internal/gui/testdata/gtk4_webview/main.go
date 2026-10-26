//go:build linux

// GTK4/WebKitGTK runtime fixture: no VPN, helper, or user profile is opened.
package main

import (
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
)

const page = `<!doctype html><html><body><div id="probe">mounted</div>
<script type="module">
import { Events } from '/wails/runtime.js';
Events.On('gtk4:reply', async event => {
  await Events.Emit('gtk4:complete', document.querySelector('#probe').textContent + ':' + event.data);
});
await Events.Emit('gtk4:ready', 'mounted');
</script></body></html>`

func main() {
	var passed atomic.Bool
	app := application.New(application.Options{
		Name: "WireGuide GTK4 smoke",
		Assets: application.AssetOptions{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" && r.URL.Path != "/index.html" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, page)
		})},
	})
	app.Event.On("gtk4:ready", func(event *application.CustomEvent) {
		if event.Data == "mounted" {
			go app.Event.Emit("gtk4:reply", "pong")
		}
	})
	app.Event.On("gtk4:complete", func(event *application.CustomEvent) {
		passed.Store(event.Data == "mounted:pong")
		go app.Quit()
	})
	app.Window.NewWithOptions(application.WebviewWindowOptions{Title: "WireGuide GTK4 smoke", Width: 480, Height: 320, URL: "/"})
	timer := time.AfterFunc(45*time.Second, func() { app.Quit() })
	err := app.Run()
	timer.Stop()
	if err != nil || !passed.Load() {
		fmt.Fprintf(os.Stderr, "GTK4 webview event round trip failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: GTK4/WebKitGTK 6.0 DOM and JavaScript -> Go -> JavaScript events")
}
