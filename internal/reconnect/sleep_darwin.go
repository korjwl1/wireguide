//go:build darwin

package reconnect

import (
	"log/slog"
	"sync"
	"time"
)

// darwinSleepDetector detects sleep/wake on macOS by monitoring system uptime gaps.
// A more robust approach would use CGO with NSWorkspace notifications,
// but polling uptime is simpler and avoids CGO dependency.
//
// TODO(M6): Wall-clock polling is a known limitation. The ticker doesn't fire
// during sleep, so detection relies on observing a gap between wall-clock
// elapsed time and the expected tick interval after waking. This means there
// is always a delay of up to pollInterval before wake is detected. The proper
// fix is to use IOKit's IORegisterForSystemPower or NSWorkspace's
// NSWorkspaceDidWakeNotification via CGo, which would give immediate wake
// notifications. However, that adds a CGo dependency which complicates
// cross-compilation, so the polling approach is kept for now.
type darwinSleepDetector struct {
	mu     sync.Mutex
	wakeCh chan struct{}
	stopCh chan struct{}
}

func NewSleepDetector() SleepDetector {
	return &darwinSleepDetector{
		wakeCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
}

func (d *darwinSleepDetector) Start() {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Reinitialize stopCh so the detector is reusable after Stop().
	d.stopCh = make(chan struct{})
	go d.poll()
}

func (d *darwinSleepDetector) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.stopCh:
		// Already closed; nothing to do.
	default:
		close(d.stopCh)
	}
}

func (d *darwinSleepDetector) WakeChan() <-chan struct{} {
	return d.wakeCh
}

func (d *darwinSleepDetector) poll() {
	// Detect sleep by checking if wall clock advanced much more than expected
	// between iterations. If we sleep for 10s but wall clock shows 60s passed,
	// the system was asleep.
	lastCheck := time.Now()
	const pollInterval = 10 * time.Second
	const sleepThreshold = 30 * time.Second // if 30s+ gap, assume sleep

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(lastCheck)
			lastCheck = now

			if elapsed > pollInterval+sleepThreshold {
				slog.Info("sleep/wake detected",
					"expected", pollInterval,
					"actual", elapsed.Round(time.Second))
				select {
				case d.wakeCh <- struct{}{}:
				default:
				}
			}
		}
	}
}

