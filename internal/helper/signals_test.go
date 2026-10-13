package helper

import (
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestSignalShutdownBoundsStartupAndBlockedShutdown(t *testing.T) {
	for _, readyToShutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "during startup", true: "during cleanup"}[readyToShutdown], func(t *testing.T) {
			signals := make(chan os.Signal, 1)
			ready := make(chan func(), 1)
			finished := make(chan struct{})
			unblock := make(chan struct{})
			defer close(unblock)
			var called atomic.Bool
			if readyToShutdown {
				ready <- func() { called.Store(true); <-unblock }
			}
			exited := make(chan int, 1)
			signals <- syscall.SIGTERM
			go superviseHelperSignals(signals, ready, finished, 30*time.Millisecond, func(code int) { exited <- code })
			select {
			case code := <-exited:
				if code != 0 || called.Load() != readyToShutdown {
					t.Fatalf("exit=%d shutdown_called=%v", code, called.Load())
				}
			case <-time.After(time.Second):
				t.Fatal("signal shutdown exceeded its deadline")
			}
		})
	}
}

func TestSignalShutdownWaitsForCompletedCleanup(t *testing.T) {
	signals := make(chan os.Signal, 1)
	ready := make(chan func(), 1)
	finished := make(chan struct{})
	ready <- func() { close(finished) }
	signals <- os.Interrupt
	forced := false
	superviseHelperSignals(signals, ready, finished, time.Second, func(int) { forced = true })
	if forced {
		t.Fatal("completed cleanup forced a process exit")
	}
}
