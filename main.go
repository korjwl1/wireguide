package main

import (
	"embed"
	"log"
	"log/slog"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Initialize storage paths
	paths, err := storage.GetPaths()
	if err != nil {
		log.Fatal("failed to get paths:", err)
	}
	if err := paths.EnsureDirs(); err != nil {
		log.Fatal("failed to create directories:", err)
	}

	// Initialize stores and tunnel manager
	tunnelStore := storage.NewTunnelStore(paths.TunnelsDir)
	settingsStore := storage.NewSettingsStore(paths.ConfigDir)
	manager := tunnel.NewManager(paths.DataDir)

	// Check for crash recovery
	if recovered := tunnel.RecoverFromCrash(paths.DataDir); recovered != "" {
		slog.Warn("recovered from previous crash", "tunnel", recovered)
	}

	// Create service for Wails bindings
	tunnelService := wgapp.NewTunnelService(tunnelStore, settingsStore, manager)

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

	// Build tray menu with tunnel list
	buildTrayMenu := func() {
		trayMenu := app.NewMenu()
		trayMenu.Add("WireGuide").SetEnabled(false)
		trayMenu.AddSeparator()

		// Dynamic tunnel list
		names, _ := tunnelStore.List()
		activeName := manager.ActiveTunnel()
		for _, name := range names {
			tunnelName := name // capture for closure
			isActive := tunnelName == activeName
			label := "  " + tunnelName
			if isActive {
				label = "● " + tunnelName
			} else {
				label = "○ " + tunnelName
			}
			trayMenu.Add(label).OnClick(func(ctx *application.Context) {
				if isActive {
					manager.Disconnect()
				} else {
					if manager.IsConnected() {
						manager.Disconnect()
					}
					cfg, err := tunnelStore.Load(tunnelName)
					if err == nil {
						manager.Connect(cfg, false)
					}
				}
			})
		}

		trayMenu.AddSeparator()
		trayMenu.Add("Show Window").OnClick(func(ctx *application.Context) {
			app.Show()
		})
		trayMenu.AddSeparator()
		trayMenu.Add("Quit").OnClick(func(ctx *application.Context) {
			if manager.IsConnected() {
				manager.Disconnect()
			}
			app.Quit()
		})
		tray.SetMenu(trayMenu)

		// Update tooltip based on connection state
		if activeName != "" {
			tray.SetTooltip("WireGuide - " + activeName + " (Connected)")
		} else {
			tray.SetTooltip("WireGuide - Disconnected")
		}
	}

	buildTrayMenu()

	// Refresh tray menu periodically
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
