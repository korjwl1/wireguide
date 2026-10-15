package helper

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const signalShutdownTimeout = 3 * time.Second

// Register before startup recovery: a signal during initialization must also
// have a deadline. Readiness publishes only the shutdown callback, avoiding
// concurrent access to fields that Run is still initializing.
func watchHelperSignals(ready <-chan func(), finished <-chan struct{}, fallback ...func()) func() {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go superviseHelperSignals(signals, ready, finished, signalShutdownTimeout, os.Exit, fallback...)
	return func() { signal.Stop(signals) }
}

func superviseHelperSignals(signals <-chan os.Signal, ready <-chan func(), finished <-chan struct{}, timeout time.Duration, exit func(int), fallback ...func()) {
	select {
	case <-finished:
		return
	case sig := <-signals:
		slog.Info("helper termination requested", "signal", sig.String())
	}
	// Reserve the final third for independent best-effort firewall/DNS
	// cleanup even if monitor/tunnel teardown has stalled.
	grace := timeout
	if len(fallback) > 0 {
		grace = timeout * 2 / 3
	}
	deadline := time.NewTimer(grace)
	force := func() {
		go func() {
			for _, cleanup := range fallback {
				cleanup()
			}
		}()
		remaining := timeout - grace
		if remaining == 0 {
			remaining = time.Millisecond
		}
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		// A quick fallback does not prove that ordinary teardown completed.
		// Keep the remaining grace available to normal cleanup, and report
		// forced termination as a failure so launchd can run crash recovery.
		select {
		case <-finished:
			return
		case <-timer.C:
		}
		exit(1)
	}
	defer deadline.Stop()
	for {
		select {
		case <-finished:
			return
		case shutdown := <-ready:
			ready = nil
			// Shutdown may wait for handlers. Keep the deadline independent
			// of both that wait and Run's subsequent cleanup (including a
			// cleanup already in progress when the signal arrived).
			go shutdown()
		case <-deadline.C:
			slog.Warn("helper signal cleanup timed out; attempting bounded firewall/DNS fallback")
			force()
			return
		case <-signals:
			force()
			return
		}
	}
}
