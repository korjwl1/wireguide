// Package gui contains the GUI-mode runtime for the WireGuide app.
//
// The package is split so each file has a single reason to change:
//   - gui.go              (this file)  — Run() entry, Wails app + window setup
//   - tray.go                           — system tray menu (event-driven rebuild)
//   - event_bridge.go                   — IPC event forwarding + subscription
//   - helper_lifecycle.go               — helper spawn, health check, auto-reconnect
package gui

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/wifi"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

// ReconnectEvent mirrors ipc.ReconnectStateDTO for Wails event emission.
type ReconnectEvent struct {
	Reconnecting bool `json:"reconnecting"`
	Attempt      int  `json:"attempt"`
	MaxAttempts  int  `json:"max_attempts"`
}

// HelperEvent notifies the frontend about helper process health changes.
type HelperEvent struct {
	Alive   bool   `json:"alive"`
	Message string `json:"message"`
}

// Register Wails event payload types. Called once per process from init.
func init() {
	application.RegisterEvent[domain.ConnectionStatus]("status")
	application.RegisterEvent[ReconnectEvent]("reconnect")
	application.RegisterEvent[map[string]any]("files-dropped")
	application.RegisterEvent[HelperEvent]("helper")
	application.RegisterEvent[struct{}]("helper_reset")
}

// Run starts the GUI process. Blocks until the Wails app exits.
func Run(assetsHandler http.Handler, dataDir string) error {
	// 0. Install the slog handler that broadcasts to the LogViewer. Do this
	// first so every subsequent log call (path init, helper spawn, etc.) is
	// captured. The Wails app isn't built yet; bindAppToLogHandler wires
	// the app reference later once application.New returns.
	installGUILogHandler()
	// Expose the level mutator to the Wails-bound service layer so
	// Settings changes can reach us without an import cycle.
	wgapp.SetGUILogLevelSetter(setGUILogLevel)

	// 1. Local storage
	paths, err := storage.GetPaths()
	if err != nil {
		return fmt.Errorf("paths: %w", err)
	}
	if err := paths.EnsureDirs(); err != nil {
		return fmt.Errorf("create dirs: %w", err)
	}
	tunnelStore := storage.NewTunnelStore(paths.TunnelsDir)
	settingsStore := storage.NewSettingsStore(paths.ConfigDir)

	// Apply persisted log level to the GUI side immediately (helper-side
	// gets it after ensureHelper + the SaveSettings path).
	if s, err := settingsStore.Load(); err == nil && s != nil && s.LogLevel != "" {
		setGUILogLevel(s.LogLevel)
	}

	// 2. Helper process (spawn if needed).
	// If the user cancels the admin prompt, retry up to 3 times with a
	// user-visible dialog explaining why the helper is required.
	var initialClient *ipc.Client
	for attempt := 0; attempt < 3; attempt++ {
		helperCtx, helperCancel := context.WithTimeout(context.Background(), 30*time.Second)
		var err error
		initialClient, err = ensureHelper(helperCtx, dataDir)
		helperCancel()
		if err == nil {
			break
		}
		slog.Warn("helper connection failed", "attempt", attempt+1, "error", err)
		if attempt < 2 {
			// Show retry dialog via osascript (Wails app isn't running yet)
			retryCmd := `display dialog "WireGuide needs its helper service to manage VPN connections.\n\nPlease grant administrator access when prompted." buttons {"Quit", "Retry"} default button "Retry" with title "WireGuide" with icon caution`
			out, retryErr := exec.Command("osascript", "-e", retryCmd).Output()
			if retryErr != nil || strings.Contains(string(out), "Quit") {
				return fmt.Errorf("helper setup cancelled by user")
			}
			continue
		}
		return fmt.Errorf("helper connection failed after 3 attempts: %w", err)
	}
	clients := ipc.NewClientHolder(initialClient)

	// 3. Wails service
	tunnelService := wgapp.NewTunnelService(tunnelStore, settingsStore, clients)

	// 4. Wails app
	app := application.New(application.Options{
		Name:        "WireGuide",
		Description: "Cross-platform WireGuard desktop client",
		Services: []application.Service{
			application.NewService(tunnelService),
		},
		Assets: application.AssetOptions{
			Handler: assetsHandler,
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})
	tunnelService.SetApp(app)
	bindAppToLogHandler(app)

	// Trigger CLLocationManager authorization so this .app bundle appears in
	// System Settings → Location Services. Must run in the GUI process (not
	// the helper) because Location Services tracks the calling bundle ID.
	// cwRequestLocationAuthorization dispatches to the main thread internally.
	wifi.RequestLocationAuthorization()

	// On macOS 14+ the helper (root LaunchDaemon) cannot read SSID via
	// CoreWLAN because Location Services permission is bundle-scoped. Poll
	// here in the GUI process (which holds permission) and forward changes
	// to the helper via MethodReportSSID so auto-connect rules fire correctly.
	go startSSIDReporter(clients)

	// Register the log event shape so Wails knows how to marshal it.
	application.RegisterEvent[ipc.LogEntry]("log")

	// 5. Main window
	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:          "WireGuide",
		Width:          900,
		Height:         680,
		EnableFileDrop: true,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(30, 30, 30), // matches --bg-primary dark (#1E1E1E)
		URL:              "/",
	})

	// macOS standard: close button hides the window instead of destroying it.
	// The app stays alive in the tray; "Show Window" brings it back.
	//
	// CRITICAL: Must use RegisterHook, NOT OnWindowEvent. Wails registers
	// its own OnWindowEvent(WindowClosing) listener that calls markAsDestroyed
	// + close. Listeners run in separate goroutines, so Cancel() from our
	// listener races with Wails' listener — the window gets destroyed despite
	// Cancel. Hooks run sequentially BEFORE listeners, so Cancel() here
	// reliably prevents Wails' default close/destroy behavior.
	win.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		event.Cancel()
		win.Hide()
		hideDock()
	})

	// Wire the window reference so showDock() can retry showing it.
	dockWindow = win

	// Native file drop forwarded to frontend
	win.OnWindowEvent(events.Common.WindowFilesDropped, func(event *application.WindowEvent) {
		files := event.Context().DroppedFiles()
		app.Event.Emit("files-dropped", map[string]any{"files": files})
	})

	// 6. System tray — always use SetIcon (never SetTemplateIcon) to avoid
	// a Wails v3 bug where the isTemplateIcon sticky flag makes all
	// subsequent SetIcon calls render as monochrome template icons.
	tray := app.SystemTray.New()
	if runtime.GOOS == "darwin" {
		tray.SetIcon(trayOffIcon)
	} else {
		tray.SetLabel("WireGuide")
	}
	tray.SetTooltip("WireGuide")

	// 7. Shutdown coordination (declared upfront so closures can reference it)
	var (
		shutdownOnce sync.Once
		doShutdown   func()
	)
	doShutdown = func() {
		shutdownOnce.Do(func() {
			slog.Info("shutting down GUI + helper")
			c := clients.Get()
			if c != nil {
				_ = c.Call(ipc.MethodDisconnect, nil, nil)
				_ = c.Call(ipc.MethodShutdown, nil, nil)
			}
			// Close in a goroutine with a short delay so the helper has
			// time to process the shutdown command without blocking the
			// macOS main thread (AppKit requires the main thread to stay
			// responsive during termination).
			go func() {
				time.Sleep(50 * time.Millisecond)
				clients.Close()
			}()
		})
	}

	trayMgr := newTrayManager(app, win, tray, tunnelService, doShutdown)
	trayMgr.initialBuild()

	if runtime.GOOS == "darwin" {
		app.Event.OnApplicationEvent(events.Mac.ApplicationWillTerminate, func(_ *application.ApplicationEvent) {
			doShutdown()
			tray.Destroy()
		})
	}

	// 8. IPC event bridge + helper health monitor.
	// The bridge owns the subscription and re-subscribes when the helper
	// process restarts. The health monitor swaps the client in the holder.
	// Pass the tray's cheap icon-update hook — NOT the full menu rebuild —
	// so the 1 Hz status stream doesn't trigger IPC round-trips on every event.
	bridge := newEventBridge(app, clients, trayMgr.setIconState)
	bridge.start()

	// Push the persisted log level to the helper now that the event
	// subscription is live — ensures DEBUG from Settings takes effect
	// on helper-side records immediately after app launch, not only
	// after the user opens and saves Settings.
	if s, err := settingsStore.Load(); err == nil && s != nil && s.LogLevel != "" {
		if c := clients.Get(); c != nil {
			_ = c.Call(ipc.MethodSetLogLevel, ipc.SetLogLevelRequest{Level: s.LogLevel}, nil)
		}
	}

	healthDone := make(chan struct{})
	var healthWg sync.WaitGroup
	healthWg.Add(1)
	startHelperHealthMonitor(app, clients, dataDir, bridge, healthDone, &healthWg)

	// 9. Run (blocks)
	err = app.Run()
	close(healthDone)
	healthWg.Wait()
	return err
}
