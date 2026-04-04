package main

import (
	"embed"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/firewall"
	"github.com/korjwl1/wireguide/internal/reconnect"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/tunnel"
	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Step 1: Check privileges — relaunch with OS permission prompt if needed
	if !isElevated() {
		slog.Info("not running as root, requesting elevation...")
		if err := relaunchElevated(); err != nil {
			slog.Error("elevation failed", "error", err)
			// Continue without elevation — tunnel operations will fail but UI works
		} else {
			return // elevated process takes over
		}
	}

	// Step 2: Initialize everything directly (no IPC, no daemon)
	paths, err := storage.GetPaths()
	if err != nil {
		log.Fatal("failed to get paths:", err)
	}
	if err := paths.EnsureDirs(); err != nil {
		log.Fatal("failed to create directories:", err)
	}

	tunnelStore := storage.NewTunnelStore(paths.TunnelsDir)
	settingsStore := storage.NewSettingsStore(paths.ConfigDir)
	manager := tunnel.NewManager(paths.DataDir)
	fw := firewall.NewPlatformFirewall()

	// Crash recovery
	if recovered := tunnel.RecoverFromCrash(paths.DataDir); recovered != "" {
		slog.Warn("recovered from previous crash", "tunnel", recovered)
	}

	// Reconnect monitor
	monitor := reconnect.NewMonitor(manager, func() error {
		activeName := manager.ActiveTunnel()
		if activeName == "" {
			return fmt.Errorf("no tunnel to reconnect")
		}
		cfg, err := tunnelStore.Load(activeName)
		if err != nil {
			return err
		}
		return manager.Connect(cfg, false)
	}, func(state reconnect.State) {
		slog.Info("reconnect state", "reconnecting", state.Reconnecting, "attempt", state.Attempt)
	}, reconnect.DefaultConfig())
	monitor.Start()

	// Step 3: Create Wails service — direct access, no IPC
	tunnelService := wgapp.NewTunnelService(tunnelStore, settingsStore, manager, fw)

	// Step 4: Wails application
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

		trayMenu.AddSeparator()
		trayMenu.Add("Show Window").OnClick(func(ctx *application.Context) {
			app.Show()
		})
		trayMenu.AddSeparator()
		trayMenu.Add("Quit").OnClick(func(ctx *application.Context) {
			// Clean shutdown
			monitor.Stop()
			fw.Cleanup()
			if manager.IsConnected() {
				manager.Disconnect()
			}
			app.Quit()
		})
		tray.SetMenu(trayMenu)

		// Update tooltip
		if active := manager.ActiveTunnel(); active != "" {
			tray.SetTooltip("WireGuide - " + active + " (Connected)")
		} else {
			tray.SetTooltip("WireGuide - Disconnected")
		}
	}

	buildTrayMenu()
	go func() {
		for {
			time.Sleep(2 * time.Second)
			buildTrayMenu()
		}
	}()

	// Run app
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

// isElevated checks if the process has root/admin privileges.
func isElevated() bool {
	switch runtime.GOOS {
	case "darwin", "linux":
		return os.Geteuid() == 0
	case "windows":
		// On Windows, try writing to a privileged path
		f, err := os.CreateTemp(`C:\Windows\Temp`, "wireguide-check-*")
		if err != nil {
			return false
		}
		f.Close()
		os.Remove(f.Name())
		return true
	}
	return false
}

// relaunchElevated restarts this binary with OS-native privilege escalation.
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	switch runtime.GOOS {
	case "darwin":
		// macOS: osascript shows native password dialog
		script := fmt.Sprintf(`do shell script "open '%s'" with administrator privileges`, exe)
		cmd := exec.Command("osascript", "-e", script)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("osascript: %w (%s)", err, string(out))
		}
		return nil

	case "linux":
		// Linux: pkexec shows PolicyKit dialog
		cmd := exec.Command("pkexec", exe)
		return cmd.Start()

	case "windows":
		// Windows: runas triggers UAC dialog
		cmd := exec.Command("powershell", "-Command",
			fmt.Sprintf("Start-Process '%s' -Verb RunAs", exe))
		return cmd.Start()

	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}
