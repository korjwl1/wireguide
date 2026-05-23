package gui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/korjwl1/wireguide/internal/elevate"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/update"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// ensureHelper connects to an existing helper (via socket) or spawns a new
// one with privilege elevation. Polls for readiness until the context expires.
func ensureHelper(ctx context.Context, dataDir string) (*ipc.Client, error) {
	addr := ipc.DefaultSocketPath()
	forceReinstall := false
	args := elevate.Args{
		SocketPath: addr,
		SocketUID:  os.Getuid(),
		DataDir:    dataDir,
	}

	// Try an existing helper first (survives GUI restarts).
	if client, err := ipc.NewClient(addr); err == nil {
		pingCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		var resp ipc.PingResponse
		if err := client.CallWithContext(pingCtx, ipc.MethodPing, nil, &resp); err == nil {
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
			plistDrifted := elevate.PlistNeedsReinstall(args)
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
			// Graceful shutdown first; if it fails, escalate to
			// ForceShutdown which the helper handles internally via
			// os.Exit. Cross-privilege Kill from the GUI (normal user)
			// to the helper (root/SYSTEM) doesn't work, so we ask the
			// helper to terminate itself.
			helperPID := resp.PID
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
			// Force reinstall so SpawnHelper skips the "already running"
			// check — KeepAlive may have restarted the old binary already.
			forceReinstall = true
			time.Sleep(300 * time.Millisecond)
		} else {
			client.Close()
		}
	}

	// Spawn new helper with elevation
	slog.Info("spawning helper with elevation...")
	args.ForceReinstall = forceReinstall
	if err := elevate.SpawnHelper(ctx, args); err != nil {
		return nil, fmt.Errorf("spawn helper: %w", err)
	}

	// Poll for readiness until the context is cancelled.
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
		client, err := ipc.NewClient(addr)
		if err != nil {
			continue
		}
		var resp ipc.PingResponse
		if err := client.CallWithContext(ctx, ipc.MethodPing, nil, &resp); err == nil {
			// After force reinstall, verify we connected to the NEW helper.
			if forceReinstall && resp.AppVersion != "" && resp.AppVersion != update.CurrentVersion() {
				slog.Debug("polling: still old helper version", "got", resp.AppVersion)
				client.Close()
				continue
			}
			slog.Info("helper ready", "app_version", resp.AppVersion)
			return client, nil
		}
		client.Close()
	}
}

// startHelperHealthMonitor runs a background goroutine that pings the helper
// every 5 seconds. On failure it:
//  1. Emits a "helper" event to notify the frontend
//  2. Attempts to re-spawn the helper and establish a new connection
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
		}
	}()
}

// recoverHelper attempts to re-establish a working helper connection. Returns
// true if a new client is now in place. Best-effort — caller decides whether
// to retry on the next tick.
func recoverHelper(clients *ipc.ClientHolder, bridge *eventBridge, dataDir string, done <-chan struct{}) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	newClient, err := ensureHelper(ctx, dataDir)
	if err != nil {
		slog.Debug("helper recovery attempt failed", "error", err)
		return false
	}
	clients.Set(newClient)
	bridge.Resubscribe()
	return true
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
