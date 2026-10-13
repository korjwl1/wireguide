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
func watchHelperSignals(ready <-chan func(), finished <-chan struct{}) func() {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go superviseHelperSignals(signals, ready, finished, signalShutdownTimeout, os.Exit)
	return func() { signal.Stop(signals) }
}

func superviseHelperSignals(signals <-chan os.Signal, ready <-chan func(), finished <-chan struct{}, timeout time.Duration, exit func(int)) {
	select {
	case <-finished:
		return
	case sig := <-signals:
		slog.Info("helper termination requested", "signal", sig.String())
	}
	deadline := time.NewTimer(timeout)
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
			slog.Warn("helper signal cleanup timed out; exiting with unfinished cleanup")
			exit(0)
			return
		case <-signals:
			exit(0)
			return
		}
	}
}
