package gui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/elevate"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/update"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// Contact budgets for the first dial/ping. On macOS the socket belongs to
// launchd: connect() succeeds at once and launchd then starts the helper, so
// the ping response can lag by launchd's ThrottleInterval (5 s) plus helper
// startup (crash recovery runs before Serve). When the socket file is absent
// there is nothing to wait for.
const (
	activatedContactBudget = 15 * time.Second
	plainContactBudget     = 2 * time.Second
	reconnectBudget        = 10 * time.Second
)

// plistNeedsReinstall is elevate.PlistNeedsReinstall, replaceable in tests
// (the real one reads /Library/LaunchDaemons).
var plistNeedsReinstall = elevate.PlistNeedsReinstall

// firstContactBudget is how long the first dial and ping may take.
func firstContactBudget(addr string) time.Duration {
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat(addr); err == nil {
			return activatedContactBudget
		}
	}
	return plainContactBudget
}

// ensureHelper connects to an existing helper (via socket) or spawns a new
// one with privilege elevation. Authorization time is excluded from the
// 30-second readiness timeout; ctx can still cancel recovery during shutdown.
func ensureHelper(ctx context.Context, dataDir string) (*ipc.Client, error) {
	args := elevate.Args{
		SocketPath: ipc.DefaultSocketPath(),
		// -1 on Windows — the SID below is the owner identity there.
		SocketUID: os.Getuid(),
		SocketSID: elevate.CurrentUserSID(),
		DataDir:   dataDir,
	}
	legacyAddr := ""
	if runtime.GOOS == "darwin" {
		legacyAddr = ipc.LegacyDarwinSocketPath
	}
	return ensureHelperWith(ctx, args, elevate.SpawnHelper, legacyAddr)
}

// ensureHelperWith is ensureHelper with the spawn function and the legacy
// socket path injectable. spawn is only called when no compatible helper is
// reachable: on macOS an up-to-date install is started by the dial itself
// (launchd socket activation), so a slow first response is waited for rather
// than answered with an administrator prompt.
func ensureHelperWith(ctx context.Context, args elevate.Args, spawn func(context.Context, elevate.Args) error, legacyAddr string) (*ipc.Client, error) {
	addr := args.SocketPath
	forceReinstall := false

	// Try an existing helper first (survives GUI restarts).
	budget := firstContactBudget(addr)
	connectCtx, connectCancel := context.WithTimeout(ctx, budget)
	client, connectErr := ipc.NewClientContext(connectCtx, addr)
	connectCancel()
	reachable := false
	if connectErr == nil {
		pingCtx, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		var resp ipc.PingResponse
		if err := client.CallWithContext(pingCtx, ipc.MethodPing, nil, &resp); err == nil {
			reachable = true
			guiVersion := update.CurrentVersion()
			helperAppVersion := resp.AppVersion
			if helperAppVersion == "" {
				// Old helper that doesn't have AppVersion field — force upgrade.
				helperAppVersion = "unknown"
			}
			// Two reinstall triggers:
			//  1. Helper binary version differs from GUI build (normal upgrade).
			//  2. LaunchDaemon plist on disk differs from what this build would
			//     write (e.g. KeepAlive policy change in the same version).
			// Without (2), a plist-only change would never reach existing users
			// because version-matched helpers are otherwise reused as-is.
			plistDrifted := plistNeedsReinstall(args)
			if helperAppVersion == guiVersion && !plistDrifted {
				slog.Info("connected to existing helper", "version", helperAppVersion)
				return client, nil
			}
			if plistDrifted {
				slog.Warn("LaunchDaemon plist drift detected, forcing reinstall",
					"helper", helperAppVersion, "gui", guiVersion)
			} else {
				slog.Warn("helper version mismatch, upgrading",
					"helper", helperAppVersion, "gui", guiVersion)
			}
			shutdownStaleHelper(client, resp.PID, addr)
			// Force reinstall so SpawnHelper skips the "already running"
			// check — KeepAlive may have restarted the old binary already.
			forceReinstall = true
		} else {
			client.Close()
		}
	}

	// Migration: before socket activation the helper listened on a different
	// path. An old helper (possibly with a tunnel up) may still be running
	// there; it must be stopped through its own graceful Shutdown before the
	// reinstall, or the installer's bootout would kill it.
	if !reachable && legacyAddr != "" && legacyAddr != addr {
		if shutdownLegacyHelper(ctx, legacyAddr) {
			forceReinstall = true
		}
	}

	// Spawn new helper with elevation
	slog.Info("spawning helper with elevation...")
	args.ForceReinstall = forceReinstall
	return spawnAndConnectHelper(ctx, args, spawn, 30*time.Second)
}

// shutdownLegacyHelper probes the pre-activation socket path and, if an old
// helper answers, shuts it down gracefully. Reports whether one was found.
func shutdownLegacyHelper(ctx context.Context, legacyAddr string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, plainContactBudget)
	defer cancel()
	client, err := ipc.NewClientContext(probeCtx, legacyAddr)
	if err != nil {
		return false
	}
	var resp ipc.PingResponse
	if err := client.CallWithContext(probeCtx, ipc.MethodPing, nil, &resp); err != nil {
		client.Close()
		return false
	}
	slog.Warn("found a helper on the legacy socket path, shutting it down before reinstall",
		"path", legacyAddr, "helper", resp.AppVersion, "pid", resp.PID)
	shutdownStaleHelper(client, resp.PID, legacyAddr)
	return true
}

// shutdownStaleHelper stops a running helper that must be replaced: graceful
// Shutdown first; if that fails, escalate to ForceShutdown, which the helper
// handles internally via os.Exit. Cross-privilege Kill from the GUI (normal
// user) to the helper (root/SYSTEM) doesn't work, so we ask the helper to
// terminate itself. Closes client.
func shutdownStaleHelper(client *ipc.Client, helperPID int, addr string) {
	shutdownErr := client.Call(ipc.MethodShutdown, nil, nil)
	if shutdownErr != nil {
		slog.Warn("helper Shutdown RPC failed, escalating to ForceShutdown",
			"error", shutdownErr)
		forceErr := client.Call(ipc.MethodForceShutdown, nil, nil)
		// ForceShutdown's handler does `time.Sleep(50ms); os.Exit`,
		// so the response may not reach us before the process
		// dies — Call returns "client closed" / EOF in that case.
		// That's actually a SUCCESS signal: helper is dead, which
		// is exactly what we wanted.
		if forceErr == nil || isHelperGoneErr(forceErr) {
			shutdownErr = nil
		} else {
			slog.Warn("helper ForceShutdown also failed",
				"error", forceErr, "pid", helperPID)
		}
	}
	client.Close()
	// Only attempt last-resort cross-privilege kill if the user is
	// running an un-elevated dev helper (same UID — proc.Kill
	// works). For LaunchDaemon/SYSTEM helpers this will fail with
	// EPERM, but logging it is still useful. We do NOT remove the
	// socket file when the helper might still be alive — that
	// would race a fresh listener.
	if shutdownErr != nil && helperPID > 0 {
		if killErr := elevate.KillProcess(helperPID); killErr != nil {
			slog.Warn("helper still up after Shutdown+ForceShutdown; cross-privilege kill failed",
				"pid", helperPID, "error", killErr,
				"hint", "the next helper spawn will fail until this PID is cleared")
		} else {
			// Same-UID kill succeeded; safe to clean up the socket.
			elevate.RemoveStaleSocket(addr)
		}
	}
	time.Sleep(300 * time.Millisecond)
}

// spawnAndConnectHelper keeps interactive authorization outside the readiness
// timeout. The spawn function also allows testing without an admin dialog.
func spawnAndConnectHelper(ctx context.Context, args elevate.Args, spawn func(context.Context, elevate.Args) error, readyTimeout time.Duration) (*ipc.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := spawn(ctx, args); err != nil {
		return nil, fmt.Errorf("spawn helper: %w", err)
	}

	// Start the readiness budget after the native authorization prompt closes.
	// Otherwise a password entered after 30s makes a successful install fail.
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		client, err := ipc.NewClientContext(ctx, args.SocketPath)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		var resp ipc.PingResponse
		if err := client.CallWithContext(ctx, ipc.MethodPing, nil, &resp); err == nil {
			// After force reinstall, verify we connected to the NEW helper.
			if args.ForceReinstall && resp.AppVersion != "" && resp.AppVersion != update.CurrentVersion() {
				slog.Debug("polling: still old helper version", "got", resp.AppVersion)
				client.Close()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(200 * time.Millisecond):
				}
				continue
			}
			slog.Info("helper ready", "app_version", resp.AppVersion)
			return client, nil
		}
		client.Close()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// startHelperHealthMonitor runs a background goroutine that pings the helper
// every 5 seconds. On failure it:
//  1. Emits a "helper" event to notify the frontend
//  2. Reconnects to launchd’s restarted helper on macOS, without authorization
//  3. Swaps the new connection into the ClientHolder
//  4. Asks the event bridge to re-subscribe
//  5. Emits "helper" (alive) once the connection is back
//
// This fixes the previous design where a helper crash left the app
// permanently unable to receive events (the bridge was still attached to a
// dead socket).
func startHelperHealthMonitor(app *application.App, clients *ipc.ClientHolder, dataDir string, bridge *eventBridge, done <-chan struct{}, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		wasAlive := true
		var outageStarted time.Time
		outageReported := false
		for {
			select {
			case <-done:
				slog.Info("helper health monitor stopped")
				return
			case <-ticker.C:
			}

			c := clients.Get()
			if c == nil {
				continue // client may be temporarily nil during swap; keep ticking
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			var resp ipc.PingResponse
			err := c.CallWithContext(ctx, ipc.MethodPing, nil, &resp)
			cancel()
			alive := err == nil

			// If a long-running RPC (Connect, Disconnect) is in-flight, the
			// server processes requests sequentially per connection, so our
			// ping won't be read until the RPC finishes. A timeout here does
			// NOT mean the helper is dead — it just means it's busy. Treating
			// this as a failure would trigger recoverHelper, which closes the
			// old client (killing the in-flight RPC), creates a new client,
			// and the server's onDisconnect fires the shutdown timer.
			// This was the root cause of the "helper dies 22-30s after connect" bug.
			if !alive && clients.HasInflight() {
				slog.Debug("health ping timed out but RPC in-flight, skipping")
				continue
			}

			switch {
			case !alive && wasAlive:
				slog.Warn("helper disconnected", "error", err)
				app.Event.Emit("helper", HelperEvent{
					Alive:   false,
					Message: "Helper process not responding: " + err.Error(),
				})
				wasAlive = false
				outageStarted = time.Now()
				outageReported = false

				// Try to recover immediately — don't wait for the next tick.
				if recoverHelper(clients, bridge, dataDir, done) {
					slog.Info("helper recovered")
					app.Event.Emit("helper", HelperEvent{Alive: true})
					wasAlive = true
				}

			case !alive && !wasAlive:
				// Retry recovery on subsequent ticks until it comes back.
				if recoverHelper(clients, bridge, dataDir, done) {
					slog.Info("helper recovered")
					app.Event.Emit("helper", HelperEvent{Alive: true})
					wasAlive = true
				}

			case alive && !wasAlive:
				// Unexpected: ping succeeded without a recoverHelper
				// call. Happens if a new helper accepted the old
				// socket somehow. Force a Resubscribe so we don't
				// silently miss status / log / wifi_ssid events from
				// the new helper — the previous Subscribe failed
				// during recovery and was never retried.
				slog.Info("helper reachable again")
				bridge.Resubscribe()
				app.Event.Emit("helper", HelperEvent{Alive: true})
				wasAlive = true
			}
			if !wasAlive && !outageReported && time.Since(outageStarted) >= 10*time.Second {
				app.Event.Emit("critical_error", ipc.CriticalErrorPayload{
					Where:  "Helper connection",
					Detail: "The VPN helper is unavailable. Quit and reopen WireGuide to retry helper setup.",
				})
				outageReported = true
			}
		}
	}()
}

// recoveryDial is how recoverHelper reaches the helper; a seam for tests.
var recoveryDial = func(ctx context.Context, dataDir string) (*ipc.Client, error) {
	if runtime.GOOS == "darwin" {
		return reconnectHelper(ctx, ipc.DefaultSocketPath())
	}
	return ensureHelper(ctx, dataDir)
}

// recoverHelper attempts to re-establish a working helper connection. Returns
// true if a new client is now in place. Best-effort — caller decides whether
// to retry on the next tick.
func recoverHelper(clients *ipc.ClientHolder, bridge *eventBridge, dataDir string, done <-chan struct{}) bool {
	// Quitting: never touch the helper socket again (on macOS a connect would
	// start the helper right after the user quit).
	select {
	case <-done:
		return false
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Allow early exit when shutdown is requested: cancel the context
	// so ensureHelper's polling loop terminates promptly.
	earlyExit := make(chan struct{})
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		case <-earlyExit:
		}
	}()
	defer close(earlyExit)

	// macOS launchd handles crash restarts. Background recovery must never
	// reopen administrator prompts after cancellation or a persistent failure.
	newClient, err := recoveryDial(ctx, dataDir)
	if err != nil {
		slog.Debug("helper recovery attempt failed", "error", err)
		return false
	}
	clients.Set(newClient)
	bridge.Resubscribe()
	// The restarted helper has no SSID (macOS: only the GUI can read it,
	// and the reporter is change-driven) — push the current one so SSID
	// automation rules resume immediately instead of after the next
	// Wi-Fi transition.
	ResendSSIDToHelper(clients)
	return true
}

// reconnectHelper is deliberately limited to RPC connection and version checks.
// It cannot install, shut down, or replace a helper during background recovery.
func reconnectHelper(ctx context.Context, addr string) (*ipc.Client, error) {
	// Covers launchd's ThrottleInterval plus helper startup: the connect
	// itself starts a launchd-activated helper, so this restarts one that
	// exited cleanly (e.g. after ForceShutdown) without a prompt.
	ctx, cancel := context.WithTimeout(ctx, reconnectBudget)
	defer cancel()
	client, err := ipc.NewClientContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	var ping ipc.PingResponse
	if err := client.CallWithContext(ctx, ipc.MethodPing, nil, &ping); err != nil {
		client.Close()
		return nil, err
	}
	if ping.AppVersion != update.CurrentVersion() {
		client.Close()
		return nil, fmt.Errorf("helper version %q does not match app %q; reopen WireGuide to update it", ping.AppVersion, update.CurrentVersion())
	}
	return client, nil
}

// isHelperGoneErr returns true when the error looks like "the helper
// closed the connection on us" — which is exactly what we expect when
// ForceShutdown succeeded. Used by the upgrade path to treat EOF as
// success rather than a failure.
//
// All four detection paths use typed/sentinel errors so wrapped errors
// (fmt.Errorf("…: %w", err)) still match. The previous substring-based
// check had false positives on normal RPC errors whose messages
// happened to contain "EOF" or "connection reset".
func isHelperGoneErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, ipc.ErrClientClosed)
}
