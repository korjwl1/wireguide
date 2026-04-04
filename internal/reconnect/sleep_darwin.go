//go:build darwin

package reconnect

import (
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// darwinSleepDetector detects sleep/wake on macOS by monitoring system uptime gaps.
// A more robust approach would use CGO with NSWorkspace notifications,
// but polling uptime is simpler and avoids CGO dependency.
type darwinSleepDetector struct {
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
	go d.poll()
}

func (d *darwinSleepDetector) Stop() {
	select {
	case <-d.stopCh:
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

	for {
		select {
		case <-d.stopCh:
			return
		case <-time.After(pollInterval):
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

// getSystemWakeTime returns the last wake time (unused but available for future use).
func getSystemWakeTime() string {
	out, err := exec.Command("pmset", "-g", "log").CombinedOutput()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "Wake from") {
			return strings.TrimSpace(lines[i])
		}
	}
	return ""
}
