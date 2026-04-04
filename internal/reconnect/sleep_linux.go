//go:build linux

package reconnect

import (
	"log/slog"
	"time"
)

// linuxSleepDetector detects sleep/wake on Linux using wall clock gap detection.
// A more robust approach would monitor systemd PrepareForSleep via D-Bus.
type linuxSleepDetector struct {
	wakeCh chan struct{}
	stopCh chan struct{}
}

func NewSleepDetector() SleepDetector {
	return &linuxSleepDetector{
		wakeCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
}

func (d *linuxSleepDetector) Start() {
	go d.poll()
}

func (d *linuxSleepDetector) Stop() {
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}
}

func (d *linuxSleepDetector) WakeChan() <-chan struct{} {
	return d.wakeCh
}

func (d *linuxSleepDetector) poll() {
	lastCheck := time.Now()
	const pollInterval = 10 * time.Second
	const sleepThreshold = 30 * time.Second

	for {
		select {
		case <-d.stopCh:
			return
		case <-time.After(pollInterval):
			now := time.Now()
			elapsed := now.Sub(lastCheck)
			lastCheck = now

			if elapsed > pollInterval+sleepThreshold {
				slog.Info("sleep/wake detected", "elapsed", elapsed.Round(time.Second))
				select {
				case d.wakeCh <- struct{}{}:
				default:
				}
			}
		}
	}
}
