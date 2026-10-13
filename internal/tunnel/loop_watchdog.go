package tunnel

import (
	"context"
	"log/slog"
	"time"
)

// The watchdog checks forwarding decisions, never traffic volume. A fast
// one-way upload is not a routing loop. Windows protects each outer socket
// directly; macOS supplies an endpoint-route checker as a fallback to its
// route monitor.
func loopWatchdogPoll(ctx context.Context, interval time.Duration, check func() (string, error), onTrip func(string)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		reason, err := check()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("loop watchdog: route check failed; will retry", "error", err)
			continue
		}
		if reason != "" {
			onTrip("routing loop detected: " + reason)
			return
		}
	}
}
