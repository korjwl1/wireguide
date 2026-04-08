//go:build linux

package network

import (
	"bufio"
	"log/slog"
	"os/exec"
	"sync"
	"time"
)

// routeMonitor runs `ip monitor route` in the background and triggers
// re-application of DNS and MTU whenever a route change is detected.
// This mirrors the macOS routeMonitor (monitor_darwin.go) but uses
// Linux-specific tooling.
//
// On Linux with fwmark-based full-tunnel routing, bypass routes are not
// used (policy routing handles endpoint traffic), so the main purpose
// is DNS re-application and detecting gateway changes that may require
// MTU adjustment.
type routeMonitor struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	stopCh   chan struct{}
	running  bool
	reapply  func()
	debounce *time.Timer
	pending  sync.WaitGroup
}

func newRouteMonitor(reapply func()) *routeMonitor {
	return &routeMonitor{reapply: reapply}
}

// Start begins monitoring. Safe to call multiple times (no-op if already running).
func (rm *routeMonitor) Start() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.running {
		return
	}

	cmd := exec.Command("ip", "monitor", "route")
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		slog.Warn("route monitor pipe failed", "error", err)
		return
	}
	if err := cmd.Start(); err != nil {
		slog.Warn("route monitor start failed", "error", err)
		return
	}

	rm.cmd = cmd
	rm.stopCh = make(chan struct{})
	rm.running = true

	go rm.loop(stdout)
	slog.Info("route monitor started")
}

// Stop terminates the monitor goroutine, kills the subprocess, and waits
// for any in-flight debounce callback to finish before returning.
func (rm *routeMonitor) Stop() {
	rm.mu.Lock()
	if !rm.running {
		rm.mu.Unlock()
		return
	}
	close(rm.stopCh)
	if rm.cmd != nil && rm.cmd.Process != nil {
		_ = rm.cmd.Process.Kill()
		_ = rm.cmd.Wait()
	}
	if rm.debounce != nil {
		if rm.debounce.Stop() {
			rm.pending.Done()
		}
	}
	rm.running = false
	rm.mu.Unlock()

	rm.pending.Wait()
	slog.Info("route monitor stopped")
}

func (rm *routeMonitor) loop(stdout interface {
	Read(p []byte) (int, error)
}) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-rm.stopCh:
			return
		default:
		}
		// Every line from `ip monitor route` represents a route change.
		// No filtering needed — unlike macOS RTM_* events, ip monitor route
		// only emits actual route modifications.
		rm.trigger()
	}
}

// trigger debounces rapid events — only fires reapply once per 500ms burst.
func (rm *routeMonitor) trigger() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if !rm.running {
		return
	}
	if rm.debounce != nil {
		if rm.debounce.Stop() {
			rm.pending.Done()
		}
	}
	rm.pending.Add(1)
	rm.debounce = time.AfterFunc(500*time.Millisecond, func() {
		defer rm.pending.Done()

		rm.mu.Lock()
		running := rm.running
		rm.mu.Unlock()
		if !running {
			return
		}
		if rm.reapply != nil {
			rm.reapply()
		}
	})
}
