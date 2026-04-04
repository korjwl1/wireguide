//go:build windows

package reconnect

import (
	"log/slog"
	"time"
)

// windowsSleepDetector detects sleep/wake on Windows using wall clock gap detection.
// A more robust approach would use WM_POWERBROADCAST via win32 API.
type windowsSleepDetector struct {
	wakeCh chan struct{}
	stopCh chan struct{}
}

func NewSleepDetector() SleepDetector {
	return &windowsSleepDetector{
		wakeCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
}

func (d *windowsSleepDetector) Start() {
	go d.poll()
}

func (d *windowsSleepDetector) Stop() {
	select {
	case <-d.stopCh:
	default:
		close(d.stopCh)
	}
}

func (d *windowsSleepDetector) WakeChan() <-chan struct{} {
	return d.wakeCh
}

func (d *windowsSleepDetector) poll() {
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
