package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := application.New(application.Options{
		Name:        "WireGuide",
		Description: "Cross-platform WireGuard desktop client",
		Services: []application.Service{
			application.NewService(&GreetService{}),
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

	trayMenu := app.NewMenu()
	trayMenu.Add("WireGuide").SetEnabled(false)
	trayMenu.AddSeparator()
	trayMenu.Add("Show Window").OnClick(func(ctx *application.Context) {
		app.Show()
	})
	trayMenu.AddSeparator()
	trayMenu.Add("Quit").OnClick(func(ctx *application.Context) {
		app.Quit()
	})
	tray.SetMenu(trayMenu)

	err := app.Run()
	if err != nil {
		log.Fatal(err)
	}
}
