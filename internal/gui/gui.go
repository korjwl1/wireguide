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
	"runtime"
	"sync"

	wgapp "github.com/korjwl1/wireguide/internal/app"
	"github.com/korjwl1/wireguide/internal/domain"
	"github.com/korjwl1/wireguide/internal/guiinstance"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/korjwl1/wireguide/internal/update"
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
	application.RegisterEvent[update.UpdateInfo]("update-available")
	application.RegisterEvent[map[string]any]("update_progress")
	application.RegisterEvent[ipc.SettingsChangedPayload]("settings_changed")
	application.RegisterEvent[struct{}]("config_changed")
	application.RegisterEvent[struct{}]("tunnels_changed")
	application.RegisterEvent[ipc.RecoveryWarningPayload]("recovery_warning")
}

// Run starts the GUI process. Blocks until the Wails app exits.
func Run(assetsHandler http.Handler, dataDir string) error {
	// Reserve the GUI before touching history, helper authorization or tray.
	instance, err := guiinstance.Acquire()
	if err != nil {
		return err
	}
	if instance == nil {
		return nil // Existing GUI accepted the activation.
	}
	defer instance.Close()

	// 0. Install the slog handler that broadcasts to the LogViewer. Do this
	// first so every subsequent log call (path init, helper spawn, etc.) is
	// captured. The Wails app isn't built yet; bindAppToLogHandler wires
	// the app reference later once application.New returns.
	installGUILogHandler()
	// Expose the level mutator to the Wails-bound service layer so
	// Settings changes can reach us without an import cycle.
	wgapp.SetGUILogLevelSetter(setGUILogLevel)

	// Pre-render the Windows tray icon variants now that main.go has
	// populated customTrayIconPNG via SetTrayIconPNG. macOS uses the
	// template path initialized here; the Windows builder
	// needs the embedded app icon.
	initializeTrayIcons()
	buildWindowsTrayIcons()

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
	historyStore := storage.NewHistoryStore(paths.ConfigDir)
	// Sweep up sessions left open by a previous crash before the UI has a
	// chance to read them. Mark "app_quit" so they aren't shown as still-
	// active in the timeline.
	historyStore.CloseOpenSessions("app_quit")

	// Apply persisted log level to the GUI side immediately (helper-side
	// gets it after ensureHelper + the UpdateSettings path).
	if s, err := settingsStore.Load(); err == nil && s != nil && s.LogLevel != "" {
		setGUILogLevel(s.LogLevel)
	}

	initialClient, err := connectInitialHelper(dataDir)
	if err != nil {
		return err
	}

	clients := ipc.NewClientHolder(initialClient)

	// 3. Wails service
	tunnelService := wgapp.NewTunnelService(tunnelStore, settingsStore, historyStore, clients)

	// 4. Wails app
	var win *application.WebviewWindow
	var connectionIndicator *connectionIcon
	if images, err := buildConnectionIconImages(customTrayIconPNG); err != nil {
		slog.Warn("cannot prepare application connection icons", "error", err)
	} else {
		connectionIndicator = newConnectionIcon(application.InvokeAsync, func(connected bool) error {
			return applyConnectionIcon(win.NativeWindow(), connected, images)
		})
		defer connectionIndicator.Close()
	}
	var shutdown *guiShutdown

	app := application.New(application.Options{
		Name:        "WireGuide",
		Description: "Cross-platform WireGuard desktop client",
		ShouldQuit: func() bool {
			if shutdown != nil {
				shutdown.run()
			}
			return true
		},
		Services: []application.Service{
			application.NewService(tunnelService),
		},
		Assets: application.AssetOptions{
			Handler: assetsHandler,
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
		Windows: application.WindowsOptions{
			WndProcInterceptor: connectionIconMessages(func() {
				if connectionIndicator != nil {
					connectionIndicator.Refresh()
				}
			}),
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
	// The reporter is wired into the same shutdown lifecycle as the helper
	// health monitor (declared further down) — both stop cleanly on app quit.

	// Register the log event shape so Wails knows how to marshal it.
	application.RegisterEvent[ipc.LogEntry]("log")

	// 5. Main window
	//
	// Default size: 1200 × 740 — width:height ≈ 1.62, the golden ratio.
	// Picked over the previous 900 × 680 (ratio 1.32) because that felt
	// squat after the notes section pushed the detail pane taller. The
	// extra width gives the 3-pane layout (sidebar 200 + list 240 +
	// detail flex) ~760 px for the detail pane, which is enough for the
	// stats grid + info rows + notes textarea + actions row to breathe.
	//
	// Min size pins the smallest pretty-looking shape (≈1.44 ratio) while
	// still leaving the detail pane wide enough that nothing wraps weirdly.
	win = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:          "WireGuide",
		Width:          1200,
		Height:         740,
		MinWidth:       920,
		MinHeight:      640,
		EnableFileDrop: true,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
		BackgroundColour: application.NewRGB(30, 30, 30), // matches --bg-primary dark (#1E1E1E)
		URL:              "/",
	})
	if connectionIndicator != nil {
		win.OnWindowEvent(events.Common.WindowRuntimeReady, func(*application.WindowEvent) { connectionIndicator.Ready() })
		win.OnWindowEvent(events.Common.WindowShow, func(*application.WindowEvent) { connectionIndicator.Refresh() })
	}

	// macOS standard: close button hides the window instead of destroying it.
	// The app stays alive in the tray; "Show Window" brings it back.
	//
	// CRITICAL: Must use RegisterHook, NOT OnWindowEvent. Wails registers
	// its own OnWindowEvent(WindowClosing) listener that calls markAsDestroyed
	// + close. Listeners run in separate goroutines, so Cancel() from our
	// listener races with Wails' listener — the window gets destroyed despite
	// Cancel. Hooks run sequentially BEFORE listeners, so Cancel() here
	// reliably prevents Wails' default close/destroy behavior.
	// Linux must intercept the native delete event itself. Wails maps
	// Linux.WindowDeleteEvent to Common.WindowClosing asynchronously; hooking
	// only the mapped event allows the default Common.WindowClosing listener to
	// destroy the window before close-to-tray can cancel it. Windows and macOS
	// expose a cancellable Common.WindowClosing event directly.
	closingEvent := events.Common.WindowClosing
	if runtime.GOOS == "linux" {
		closingEvent = events.Linux.WindowDeleteEvent
	}
	win.RegisterHook(closingEvent, func(event *application.WindowEvent) {
		event.Cancel()
		win.Hide()
		hideDock()
	})

	// Wire the window reference so showDock() can retry showing it.
	dockWindow = win
	// Activation can arrive during UAC or WebView startup. Do not call Show
	// before the native window/runtime exists, or Wails may create it twice.
	startInstanceActivation(instance, win)

	// Native file drop forwarded to frontend
	win.OnWindowEvent(events.Common.WindowFilesDropped, func(event *application.WindowEvent) {
		files := event.Context().DroppedFiles()
		app.Event.Emit("files-dropped", map[string]any{"files": files})
	})

	// macOS owns a native status item with a permanently attached menu.
	var tray *application.SystemTray
	if runtime.GOOS != "darwin" {
		tray = app.SystemTray.New()
		tray.SetLabel("WireGuide")
		if len(trayOffIconWindows) > 0 {
			tray.SetIcon(trayOffIconWindows)
		}
		if runtime.GOOS == "windows" {
			tray.OnClick(showDock)
		}
		tray.SetTooltip("WireGuide")
	}

	// Stop all socket probes before asking the helper to exit: a later dial
	// would activate it again through launchd.
	healthDone := make(chan struct{})
	var stopHealthOnce sync.Once
	stopHealth := func() { stopHealthOnce.Do(func() { close(healthDone) }) }
	shutdown = &guiShutdown{instance: instance, indicator: connectionIndicator, stopHealth: stopHealth, service: tunnelService, history: historyStore, clients: clients}
	defer shutdown.run()

	trayMgr := newTrayManager(app, win, tray, tunnelService, shutdown.run)
	trayMgr.connectionIcon = connectionIndicator
	wgapp.SetGUIPreferencesChanged(func() {
		if !appQuitting.Load() {
			trayMgr.scheduleRebuild()
		}
	})
	trayMgr.initialBuild()

	if runtime.GOOS == "darwin" {
		app.Event.OnApplicationEvent(events.Mac.ApplicationWillTerminate, func(_ *application.ApplicationEvent) {
			destroyNativeTray()
		})
	}

	// 8. IPC event bridge + helper health monitor.
	// The bridge owns the subscription and re-subscribes when the helper
	// process restarts. The health monitor swaps the client in the holder.
	// Pass the tray's cheap icon-update hook — NOT the full menu rebuild —
	// so the 1 Hz status stream doesn't trigger IPC round-trips on every event.
	bridge := newEventBridge(app, clients, trayMgr.setIconState, tunnelService.ReconcileHistoryFromStatus, trayMgr.quitApp)
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

	var healthWg sync.WaitGroup
	startGUIHangMonitor(paths.LogsDir, healthDone, &healthWg)
	healthWg.Add(1)
	startHelperHealthMonitor(app, clients, dataDir, bridge, healthDone, &healthWg)
	// SSID reporter shares the same shutdown channel + WaitGroup so app
	// quit waits for it to exit before returning, instead of leaking the
	// goroutine until process death.
	healthWg.Add(1)
	startSSIDReporter(clients, healthDone, &healthWg)

	// Watch config.json + the tunnels dir so external changes (the CLI)
	// reflect in a running GUI. Shares the shutdown channel/WaitGroup.
	healthWg.Add(1)
	startConfigWatcher(app, configFilePath(paths.ConfigDir), paths.TunnelsDir, healthDone, &healthWg)

	// Update scheduler — periodic GitHub Releases check. Lives in the GUI
	// process (not the helper) because update notifications are a pure UI
	// concern and the helper runs as root with minimum network surface by
	// design. Dev builds short-circuit inside Scheduler.Start, so this is
	// inert until a release-tagged binary runs it.
	updateStateStore, err := update.NewStateStore(paths.ConfigDir)
	if err != nil {
		slog.Warn("update scheduler: cannot create state store", "error", err)
	} else {
		schedulerCtx, schedulerCancel := context.WithCancel(context.Background())
		scheduler := update.NewScheduler(updateStateStore, func(info *update.UpdateInfo) {
			if info == nil {
				return
			}
			app.Event.Emit("update-available", *info)
		}, func() bool {
			// Settings toggle gate: respected at every tick boundary so
			// flipping the toggle off (or back on) takes effect without
			// restarting the app.
			s, err := settingsStore.Load()
			if err != nil || s == nil {
				return true // legacy / unreadable settings → default on
			}
			return s.AutoUpdateCheckEnabled()
		})
		scheduler.Start(schedulerCtx)
		tunnelService.SetUpdateScheduler(scheduler, updateStateStore)

		// Re-check when the window regains focus IF the cached check is
		// older than `focusRecheckThreshold` (the scheduler's Kick handles
		// the staleness gate). Covers the laptop-closed-for-a-week case.
		win.OnWindowEvent(events.Common.WindowFocus, func(_ *application.WindowEvent) {
			scheduler.Kick(false)
		})

		// Cancel scheduler on shutdown so its goroutine exits before
		// app.Run returns.
		go func() {
			<-healthDone
			schedulerCancel()
		}()
	}

	// 9. Run (blocks)
	err = app.Run()
	appQuitting.Store(true)
	instance.BeginShutdown()
	stopHealth()
	healthWg.Wait()
	return err
}
