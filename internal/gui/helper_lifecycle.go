package gui

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/korjwl1/wireguide/internal/elevate"
	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// ensureHelper connects to an existing helper (via socket) or spawns a new
// one with privilege elevation. Polls for readiness up to 30 seconds.
func ensureHelper(dataDir string) (*ipc.Client, error) {
	addr := ipc.DefaultSocketPath()

	// Try an existing helper first (survives GUI restarts).
	if client, err := ipc.NewClient(addr); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		var resp ipc.PingResponse
		if err := client.CallWithContext(ctx, ipc.MethodPing, nil, &resp); err == nil {
			slog.Info("connected to existing helper", "version", resp.Version)
			return client, nil
		}
		client.Close()
	}

	// Spawn new helper with elevation
	slog.Info("spawning helper with elevation...")
	args := elevate.Args{
		SocketPath: addr,
		SocketUID:  os.Getuid(),
		DataDir:    dataDir,
	}
	if err := elevate.SpawnHelper(args); err != nil {
		return nil, fmt.Errorf("spawn helper: %w", err)
	}

	// Poll for readiness (up to 30 seconds)
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
func startHelperHealthMonitor(app *application.App, clients *ipc.ClientHolder, dataDir string, bridge *eventBridge) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		wasAlive := true
		for range ticker.C {
			c := clients.Get()
			if c == nil {
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			var resp ipc.PingResponse
			err := c.CallWithContext(ctx, ipc.MethodPing, nil, &resp)
			cancel()
			alive := err == nil

			switch {
			case !alive && wasAlive:
				slog.Warn("helper disconnected", "error", err)
				app.Event.Emit("helper", HelperEvent{
					Alive:   false,
					Message: "Helper process not responding: " + err.Error(),
				})
				wasAlive = false

				// Try to recover immediately — don't wait for the next tick.
				if recoverHelper(clients, bridge, dataDir) {
					slog.Info("helper recovered")
					app.Event.Emit("helper", HelperEvent{Alive: true})
					wasAlive = true
				}

			case !alive && !wasAlive:
				// Retry recovery on subsequent ticks until it comes back.
				if recoverHelper(clients, bridge, dataDir) {
					slog.Info("helper recovered")
					app.Event.Emit("helper", HelperEvent{Alive: true})
					wasAlive = true
				}

			case alive && !wasAlive:
				// Unexpected: ping succeeded without a recoverHelper call.
				// Happens if a new helper accepted the old socket somehow.
				slog.Info("helper reachable again")
				app.Event.Emit("helper", HelperEvent{Alive: true})
				wasAlive = true
			}
		}
	}()
}

// recoverHelper attempts to re-establish a working helper connection. Returns
// true if a new client is now in place. Best-effort — caller decides whether
// to retry on the next tick.
func recoverHelper(clients *ipc.ClientHolder, bridge *eventBridge, dataDir string) bool {
	newClient, err := ensureHelper(dataDir)
	if err != nil {
		slog.Debug("helper recovery attempt failed", "error", err)
		return false
	}
	clients.Set(newClient)
	bridge.Resubscribe()
	return true
}
