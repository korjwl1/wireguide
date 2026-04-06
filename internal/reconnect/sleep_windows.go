//go:build windows

package reconnect

import (
	"log/slog"
	"sync"
	"time"
)

// windowsSleepDetector detects sleep/wake on Windows using wall clock gap detection.
// A more robust approach would use WM_POWERBROADCAST via win32 API.
//
// TODO(M13): Replace polling with RegisterPowerSettingNotification for instant
// wake detection. The current polling approach works but has up to a 30-second
// detection delay. RegisterPowerSettingNotification with GUID_CONSOLE_DISPLAY_STATE
// or GUID_MONITOR_POWER_ON would provide immediate notification. This requires
// creating a hidden message-only window and a message pump (win32 GetMessage loop),
// which is a non-trivial amount of platform-specific code.
type windowsSleepDetector struct {
	mu     sync.Mutex
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
	d.mu.Lock()
	defer d.mu.Unlock()
	// Reinitialize stopCh so the detector is reusable after Stop().
	d.stopCh = make(chan struct{})
	go d.poll()
}

func (d *windowsSleepDetector) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.stopCh:
		// Already closed; nothing to do.
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
				slog.Info("sleep/wake detected", "elapsed", elapsed.Round(time.Second))
				select {
				case d.wakeCh <- struct{}{}:
				default:
				}
			}
		}
	}
}
