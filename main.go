package main

import (
	"embed"
	"log"
	"log/slog"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Connect to daemon via gRPC
	client, err := ipc.NewClient()
	if err != nil {
		slog.Warn("daemon not running, some features may not work", "error", err)
	}

	tunnelService := wgapp.NewTunnelService(client)

	app := application.New(application.Options{
		Name:        "WireGuide",
		Description: "Cross-platform WireGuard desktop client",
		Services: []application.Service{
			application.NewService(tunnelService),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "WireGuide",
		Width:  900,
		Height: 600,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(26, 26, 46),
		URL:              "/",
	})

	// System tray
	tray := app.SystemTray.New()
	tray.SetTooltip("WireGuide - Disconnected")

	buildTrayMenu := func() {
		trayMenu := app.NewMenu()
		trayMenu.Add("WireGuide").SetEnabled(false)
		trayMenu.AddSeparator()

		if client != nil {
			tunnels, _ := tunnelService.ListTunnels()
			for _, t := range tunnels {
				tun := t
				label := "○ " + tun.Name
				if tun.IsConnected {
					label = "● " + tun.Name
				}
				trayMenu.Add(label).OnClick(func(ctx *application.Context) {
					if tun.IsConnected {
						tunnelService.Disconnect()
					} else {
						tunnelService.Connect(tun.Name, false)
					}
				})
			}
		} else {
			trayMenu.Add("Daemon not running").SetEnabled(false)
		}

		trayMenu.AddSeparator()
		trayMenu.Add("Show Window").OnClick(func(ctx *application.Context) {
			app.Show()
		})
		trayMenu.AddSeparator()
		trayMenu.Add("Quit").OnClick(func(ctx *application.Context) {
			if client != nil {
				client.Close()
			}
			app.Quit()
		})
		tray.SetMenu(trayMenu)
	}

	buildTrayMenu()
	go func() {
		for {
			time.Sleep(2 * time.Second)
			buildTrayMenu()
		}
	}()

	err = app.Run()
	if err != nil {
		log.Fatal(err)
	}
}
