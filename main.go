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
	"github.com/wailsapp/wails/v3/pkg/icons"
)

//go:embed all:frontend/dist
var assets embed.FS

// StatusEvent is broadcast to the frontend whenever tunnel status changes.
type StatusEvent struct {
	State         string `json:"state"`
	TunnelName    string `json:"tunnel_name"`
	InterfaceName string `json:"interface_name"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	LastHandshake string `json:"last_handshake"`
	Duration      string `json:"duration"`
	Endpoint      string `json:"endpoint"`
}

// TunnelsEvent is broadcast when the tunnel list changes.
type TunnelsEvent struct {
	Tunnels []wgapp.TunnelInfo `json:"tunnels"`
}

func init() {
	application.RegisterEvent[StatusEvent]("status")
	application.RegisterEvent[TunnelsEvent]("tunnels")
}

func main() {
	// Step 1: Check privileges — relaunch with OS permission prompt if needed
	// --elevated flag prevents infinite re-elevation loop
	elevated := len(os.Args) > 1 && os.Args[1] == "--elevated"
	if !elevated && !isElevated() {
		slog.Info("not running as root, requesting elevation...")
		// This BLOCKS until the elevated process exits. The elevated
		// GUI app runs inside osascript's process tree, inheriting the
		// user's GUI session (so window server access works).
		if err := relaunchElevated(); err != nil {
			log.Fatal("elevation failed:", err)
		}
		return // elevated process has exited, we're done
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
	if runtime.GOOS == "darwin" {
		tray.SetTemplateIcon(icons.SystrayMacTemplate)
	} else {
		tray.SetLabel("WireGuide")
	}
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

	// Event emitter: push status + tunnel list changes to frontend.
	// Only emits when data actually changed (no spam).
	go func() {
		var lastStatusKey, lastTunnelsKey string
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			// Status event
			status := manager.Status()
			statusEvt := StatusEvent{
				State:         string(status.State),
				TunnelName:    status.TunnelName,
				InterfaceName: status.InterfaceName,
				RxBytes:       status.RxBytes,
				TxBytes:       status.TxBytes,
				LastHandshake: status.HandshakeAge,
				Duration:      status.Duration,
				Endpoint:      status.Endpoint,
			}
			statusKey := fmt.Sprintf("%s|%s|%d|%d|%s", statusEvt.State, statusEvt.TunnelName,
				statusEvt.RxBytes, statusEvt.TxBytes, statusEvt.LastHandshake)
			if statusKey != lastStatusKey {
				lastStatusKey = statusKey
				app.Event.Emit("status", statusEvt)
			}

			// Tunnels list event
			tunnels, err := tunnelService.ListTunnels()
			if err == nil {
				tunnelsKey := fmt.Sprintf("%d", len(tunnels))
				for _, t := range tunnels {
					tunnelsKey += "|" + t.Name + "|" + fmt.Sprintf("%v", t.IsConnected)
				}
				if tunnelsKey != lastTunnelsKey {
					lastTunnelsKey = tunnelsKey
					app.Event.Emit("tunnels", TunnelsEvent{Tunnels: tunnels})
					buildTrayMenu() // update tray when tunnels change
				}
			}
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
		// macOS: "do shell script ... with administrator privileges" shows
		// the native macOS padlock dialog. The binary runs inside osascript's
		// process tree, inheriting GUI session access. Blocks until app exits.
		script := fmt.Sprintf(
			`do shell script "'%s' --elevated" with administrator privileges with prompt "WireGuide needs administrator privileges to create VPN tunnels."`,
			exe,
		)
		cmd := exec.Command("osascript", "-e", script)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()

	case "linux":
		// Linux: pkexec shows PolicyKit dialog
		cmd := exec.Command("pkexec", exe, "--elevated")
		return cmd.Start()

	case "windows":
		// Windows: Start-Process -Verb RunAs triggers UAC dialog
		cmd := exec.Command("powershell", "-Command",
			fmt.Sprintf("Start-Process '%s' -ArgumentList '--elevated' -Verb RunAs", exe))
		return cmd.Start()

	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}
