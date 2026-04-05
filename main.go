package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/elevate"
	"github.com/korjwl1/wireguide/internal/helper"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/icons"
)

//go:embed all:frontend/dist
var assets embed.FS

// StatusEvent mirrors ipc.ConnectionStatusDTO for Wails event emission.
type StatusEvent struct {
	State         string `json:"state"`
	TunnelName    string `json:"tunnel_name"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	LastHandshake string `json:"last_handshake"`
	Duration      string `json:"duration"`
	Endpoint      string `json:"endpoint"`
}

type ReconnectEvent struct {
	Reconnecting bool   `json:"reconnecting"`
	Attempt      int    `json:"attempt"`
	MaxAttempts  int    `json:"max_attempts"`
}

func init() {
	application.RegisterEvent[StatusEvent]("status")
	application.RegisterEvent[ReconnectEvent]("reconnect")
	application.RegisterEvent[map[string]any]("files-dropped")
}

func main() {
	// Flags
	helperMode := flag.Bool("helper", false, "run as privileged helper")
	socketPath := flag.String("socket", "", "socket path for IPC")
	socketUID := flag.Int("uid", -1, "socket owner UID (Unix only)")
	dataDir := flag.String("data-dir", "", "data directory for crash recovery")
	flag.Parse()

	if *helperMode {
		// Helper mode: run as root, listen on socket
		if *socketPath == "" {
			log.Fatal("--socket required in helper mode")
		}
		if *dataDir == "" {
			*dataDir = defaultDataDir()
		}
		log.Println("WireGuide helper starting...")
		if err := helper.Run(*socketPath, *socketUID, *dataDir); err != nil {
			log.Fatal("helper error:", err)
		}
		return
	}

	// GUI mode
	runGUI()
}

func runGUI() {
	// Initialize storage
	paths, err := storage.GetPaths()
	if err != nil {
		log.Fatal("paths:", err)
	}
	if err := paths.EnsureDirs(); err != nil {
		log.Fatal("create dirs:", err)
	}
	tunnelStore := storage.NewTunnelStore(paths.TunnelsDir)
	settingsStore := storage.NewSettingsStore(paths.ConfigDir)

	// Connect to helper (spawn if needed)
	client, err := ensureHelper()
	if err != nil {
		log.Fatal("helper connection failed:", err)
	}
	defer client.Close()

	tunnelService := wgapp.NewTunnelService(tunnelStore, settingsStore, client)

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
	tunnelService.SetApp(app)

	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:          "WireGuide",
		Width:          900,
		Height:         600,
		EnableFileDrop: true,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(26, 26, 46),
		URL:              "/",
	})

	// Register native file drop handler — HTML5 drag-drop doesn't work in WebKit.
	win.OnWindowEvent(events.Common.WindowFilesDropped, func(event *application.WindowEvent) {
		files := event.Context().DroppedFiles()
		app.Event.Emit("files-dropped", map[string]any{
			"files": files,
		})
	})

	// System tray
	tray := app.SystemTray.New()
	if runtime.GOOS == "darwin" {
		tray.SetTemplateIcon(icons.SystrayMacTemplate)
	} else {
		tray.SetLabel("WireGuide")
	}
	tray.SetTooltip("WireGuide")

	// Unified shutdown — declared upfront so closures can reference it.
	var (
		shutdownOnce sync.Once
		doShutdown   func()
	)
	doShutdown = func() {
		shutdownOnce.Do(func() {
			slog.Info("shutting down GUI + helper")
			_ = client.Call(ipc.MethodDisconnect, nil, nil)
			_ = client.Call(ipc.MethodShutdown, nil, nil)
			time.Sleep(200 * time.Millisecond)
			client.Close()
		})
	}

	buildTrayMenu := func() {
		m := app.NewMenu()
		m.Add("WireGuide").SetEnabled(false)
		m.AddSeparator()
		tunnels, _ := tunnelService.ListTunnels()
		for _, t := range tunnels {
			tun := t
			label := "○ " + tun.Name
			if tun.IsConnected {
				label = "● " + tun.Name
			}
			m.Add(label).OnClick(func(ctx *application.Context) {
				if tun.IsConnected {
					tunnelService.Disconnect()
				} else {
					tunnelService.Connect(tun.Name, false)
				}
			})
		}
		m.AddSeparator()
		m.Add("Show Window").OnClick(func(ctx *application.Context) { app.Show() })
		m.AddSeparator()
		m.Add("Quit").OnClick(func(ctx *application.Context) {
			doShutdown()
			app.Quit()
		})
		tray.SetMenu(m)
	}

	buildTrayMenu()

	// Register shutdown handler for macOS Cmd+Q, Dock quit, etc.
	if runtime.GOOS == "darwin" {
		app.Event.OnApplicationEvent(events.Mac.ApplicationWillTerminate, func(_ *application.ApplicationEvent) {
			doShutdown()
		})
	}

	// Subscribe to helper events and forward to Wails
	if err := client.Subscribe(func(method string, params json.RawMessage) {
		switch method {
		case ipc.EventStatus:
			var dto ipc.ConnectionStatusDTO
			if json.Unmarshal(params, &dto) == nil {
				app.Event.Emit("status", StatusEvent{
					State:         dto.State,
					TunnelName:    dto.TunnelName,
					RxBytes:       dto.RxBytes,
					TxBytes:       dto.TxBytes,
					LastHandshake: dto.LastHandshake,
					Duration:      dto.Duration,
					Endpoint:      dto.Endpoint,
				})
			}
		case ipc.EventReconnect:
			var dto ipc.ReconnectStateDTO
			if json.Unmarshal(params, &dto) == nil {
				app.Event.Emit("reconnect", ReconnectEvent{
					Reconnecting: dto.Reconnecting,
					Attempt:      dto.Attempt,
					MaxAttempts:  dto.MaxAttempts,
				})
			}
		}
	}); err != nil {
		slog.Warn("event subscription failed", "error", err)
	}

	// Rebuild tray menu periodically to reflect tunnel list changes
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			buildTrayMenu()
		}
	}()

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

// ensureHelper connects to an existing helper or spawns one with elevation.
func ensureHelper() (*ipc.Client, error) {
	addr := ipc.DefaultSocketPath()

	// Try existing helper first
	if client, err := ipc.NewClient(addr); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = ctx
		var resp ipc.PingResponse
		if err := client.Call(ipc.MethodPing, nil, &resp); err == nil {
			slog.Info("connected to existing helper", "version", resp.Version)
			return client, nil
		}
		client.Close()
	}

	// Spawn new helper
	slog.Info("spawning helper with elevation...")
	dataDir := systemDataDir()
	args := elevate.Args{
		SocketPath: addr,
		SocketUID:  os.Getuid(),
		DataDir:    dataDir,
	}
	if err := elevate.SpawnHelper(args); err != nil {
		return nil, fmt.Errorf("spawn helper: %w", err)
	}

	// Poll for helper readiness (up to 30 seconds)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		client, err := ipc.NewClient(addr)
		if err != nil {
			continue
		}
		var resp ipc.PingResponse
		if err := client.Call(ipc.MethodPing, nil, &resp); err == nil {
			slog.Info("helper ready", "version", resp.Version)
			return client, nil
		}
		client.Close()
	}
	return nil, fmt.Errorf("helper did not become ready within 30s")
}

// systemDataDir returns the system-level data dir for helper state.
func systemDataDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/wireguide"
	case "linux":
		return "/var/lib/wireguide"
	case "windows":
		if pd := os.Getenv("PROGRAMDATA"); pd != "" {
			return pd + `\wireguide`
		}
		return `C:\ProgramData\wireguide`
	}
	return "/tmp/wireguide"
}

func defaultDataDir() string {
	return systemDataDir()
}
