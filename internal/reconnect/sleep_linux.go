//go:build linux

package reconnect

import (
	"bufio"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// linuxSleepDetector detects sleep/wake on Linux. It first tries monitoring
// systemd's PrepareForSleep signal via gdbus for instant wake detection.
// Falls back to wall clock gap polling if gdbus is not available.
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
	if _, err := exec.LookPath("gdbus"); err == nil {
		go d.monitorDBus()
	} else {
		slog.Info("gdbus not available, falling back to poll-based sleep detection")
		go d.poll()
	}
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

// monitorDBus monitors the systemd login1 PrepareForSleep signal.
// PrepareForSleep(true) means going to sleep, PrepareForSleep(false) means waking up.
func (d *linuxSleepDetector) monitorDBus() {
	for {
		select {
		case <-d.stopCh:
			return
		default:
		}

		cmd := exec.Command("gdbus", "monitor", "--system",
			"--dest", "org.freedesktop.login1",
			"--object-path", "/org/freedesktop/login1")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			slog.Warn("gdbus pipe failed, falling back to polling", "error", err)
			go d.poll()
			return
		}
		if err := cmd.Start(); err != nil {
			slog.Warn("gdbus start failed, falling back to polling", "error", err)
			go d.poll()
			return
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case <-d.stopCh:
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				return
			default:
			}
			line := scanner.Text()
			// Look for PrepareForSleep(false) which indicates wake
			if strings.Contains(line, "PrepareForSleep") && strings.Contains(line, "false") {
				slog.Info("sleep/wake detected via D-Bus PrepareForSleep")
				select {
				case d.wakeCh <- struct{}{}:
				default:
				}
			}
		}

		_ = cmd.Wait()

		// gdbus process exited — retry after a short delay unless stopped
		select {
		case <-d.stopCh:
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// poll detects sleep/wake via wall clock gap (fallback for non-systemd systems).
func (d *linuxSleepDetector) poll() {
	lastCheck := time.Now()
	const pollInterval = 5 * time.Second
	const sleepThreshold = 10 * time.Second

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
