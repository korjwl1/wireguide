//go:build linux

// GTK4/WebKitGTK runtime fixture: no VPN, helper, or user profile is opened.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/icons"
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
	var passed, clicked atomic.Bool
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
		webviewPassed := event.Data == "mounted:pong"
		go func() {
			defer app.Quit()
			conn, err := dbus.SessionBus()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			item := conn.Object(fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid()), "/StatusNotifierItem")
			for ctx.Err() == nil {
				err = item.CallWithContext(ctx, "org.kde.StatusNotifierItem.Activate", 0, int32(0), int32(0)).Err
				if err == nil && clicked.Load() {
					passed.Store(webviewPassed)
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
			fmt.Fprintf(os.Stderr, "D-Bus tray activation failed: %v\n", err)
		}()
	})
	tray := app.SystemTray.New()
	tray.SetIcon(icons.SystrayMacTemplate)
	tray.OnClick(func() { clicked.Store(true) })
	app.Window.NewWithOptions(application.WebviewWindowOptions{Title: "WireGuide GTK4 smoke", Width: 480, Height: 320, URL: "/"})
	timer := time.AfterFunc(45*time.Second, func() { app.Quit() })
	err := app.Run()
	timer.Stop()
	if err != nil || !passed.Load() {
		fmt.Fprintf(os.Stderr, "GTK4 webview event round trip failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: GTK4/WebKitGTK 6.0 DOM and JavaScript -> Go -> JavaScript events; D-Bus tray activation")
}
