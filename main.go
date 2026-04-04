package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Ensure daemon is running, start it if needed
	client, err := ensureDaemon()
	if err != nil {
		slog.Error("failed to start daemon", "error", err)
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

// ensureDaemon checks if the daemon is running, and starts it if not.
func ensureDaemon() (*ipc.Client, error) {
	// Try connecting to existing daemon
	client, err := ipc.NewClient()
	if err == nil {
		// Daemon already running
		_, pingErr := client.Ping(context.Background())
		if pingErr == nil {
			slog.Info("connected to existing daemon")
			return client, nil
		}
		client.Close()
	}

	slog.Info("daemon not running, starting...")

	// Find daemon binary next to this executable
	daemonPath := findDaemonBinary()
	if daemonPath == "" {
		return nil, fmt.Errorf("wireguided binary not found")
	}

	// Start daemon with privilege escalation
	if err := startDaemonWithPrivilege(daemonPath); err != nil {
		return nil, fmt.Errorf("starting daemon: %w", err)
	}

	// Wait for daemon to be ready
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		client, err = ipc.NewClient()
		if err == nil {
			_, pingErr := client.Ping(context.Background())
			if pingErr == nil {
				slog.Info("daemon started successfully")
				return client, nil
			}
			client.Close()
		}
	}

	return nil, fmt.Errorf("daemon failed to start within 5 seconds")
}

// findDaemonBinary locates wireguided next to the GUI binary.
func findDaemonBinary() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)

	candidates := []string{
		filepath.Join(dir, "wireguided"),
		filepath.Join(dir, "..", "wireguided"), // for development
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// startDaemonWithPrivilege starts the daemon with root privileges.
func startDaemonWithPrivilege(daemonPath string) error {
	switch runtime.GOOS {
	case "darwin":
		// Use osascript to prompt for admin password
		script := fmt.Sprintf(
			`do shell script "%s &> /dev/null &" with administrator privileges`,
			daemonPath,
		)
		cmd := exec.Command("osascript", "-e", script)
		return cmd.Run()

	case "linux":
		// Use pkexec (PolicyKit)
		cmd := exec.Command("pkexec", daemonPath)
		return cmd.Start()

	case "windows":
		// On Windows, the daemon binary has requireAdministrator manifest
		cmd := exec.Command(daemonPath)
		return cmd.Start()

	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}
