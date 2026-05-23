//go:build linux

package reconnect

import (
	"log/slog"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// linuxSleepDetector listens for systemd-logind's PrepareForSleep signal on
// the system DBus. The signal fires with arg `true` immediately before
// suspend/hibernate and `false` immediately after resume — far more reliable
// than wall-clock gap heuristics (which had up to a 40s detection delay).
//
// If the DBus connection fails (no systemd, e.g. inside a minimal container)
// we fall back to the wall-clock poller.
//
// IMPORTANT: dbus.SystemBus() is a process-singleton. We must NOT call
// conn.Close() on Stop — that would terminate the shared connection and
// break every other consumer (e.g. wifi.startLinuxDBusWatcher). Instead
// we remove our own signal channel and matcher, leaving the bus connection
// intact for the rest of the helper's lifetime.
type linuxSleepDetector struct {
	mu      sync.Mutex
	running bool

	// conn is shared with wifi/detect_linux.go via dbus.SystemBus(). We
	// keep a reference so Stop() can RemoveMatchSignal / Signal-remove
	// our subscription, but we never Close() it.
	conn      *dbus.Conn
	signalCh  chan *dbus.Signal // the channel we registered for our signal pump
	wakeCh    chan struct{}
	stopCh    chan struct{}
}

func NewSleepDetector() SleepDetector {
	return &linuxSleepDetector{
		wakeCh: make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
}

func (d *linuxSleepDetector) Start() {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	// Reinitialize stopCh in case Start is called after Stop.
	d.stopCh = make(chan struct{})
	d.mu.Unlock()

	conn, err := dbus.SystemBus()
	if err != nil {
		slog.Warn("dbus system bus unavailable; falling back to poll-based sleep detection", "error", err)
		go d.poll()
		return
	}
	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.login1.Manager"),
		dbus.WithMatchMember("PrepareForSleep"),
		dbus.WithMatchObjectPath("/org/freedesktop/login1"),
	); err != nil {
		slog.Warn("dbus AddMatchSignal failed; falling back to poll", "error", err)
		// Don't close the shared bus connection — other consumers (wifi
		// detector) need it. Just fall back to polling instead.
		go d.poll()
		return
	}
	ch := make(chan *dbus.Signal, 16)
	conn.Signal(ch)
	d.mu.Lock()
	d.conn = conn
	d.signalCh = ch
	d.mu.Unlock()
	go d.dbusLoop(ch)
	slog.Info("logind PrepareForSleep sleep detector started")
}

func (d *linuxSleepDetector) Stop() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	conn := d.conn
	ch := d.signalCh
	d.conn = nil
	d.signalCh = nil
	stop := d.stopCh
	d.mu.Unlock()
	select {
	case <-stop:
	default:
		close(stop)
	}
	// Unsubscribe from our signal channel + matcher but DO NOT close the
	// shared system bus — wifi detector still needs it. The connection is
	// torn down naturally when the helper process exits.
	if conn != nil && ch != nil {
		conn.RemoveSignal(ch)
		_ = conn.RemoveMatchSignal(
			dbus.WithMatchInterface("org.freedesktop.login1.Manager"),
			dbus.WithMatchMember("PrepareForSleep"),
			dbus.WithMatchObjectPath("/org/freedesktop/login1"),
		)
	}
}

func (d *linuxSleepDetector) WakeChan() <-chan struct{} {
	return d.wakeCh
}

// dbusLoop drains PrepareForSleep events. Signal body is a single bool: true
// = "about to sleep", false = "just resumed". We only care about the false
// case, since that's when reconnects need to fire.
//
// The channel + matcher are registered/unregistered by Start/Stop on the
// SHARED system bus connection. dbusLoop here is purely a consumer.
func (d *linuxSleepDetector) dbusLoop(ch <-chan *dbus.Signal) {
	for {
		select {
		case <-d.stopCh:
			return
		case sig, ok := <-ch:
			if !ok {
				slog.Info("dbus signal channel closed")
				return
			}
			if sig == nil || sig.Name != "org.freedesktop.login1.Manager.PrepareForSleep" {
				continue
			}
			if len(sig.Body) != 1 {
				continue
			}
			about, _ := sig.Body[0].(bool)
			if about {
				slog.Info("logind PrepareForSleep=true (about to suspend)")
				continue
			}
			slog.Info("logind PrepareForSleep=false (resumed)")
			select {
			case d.wakeCh <- struct{}{}:
			default:
			}
		}
	}
}

// poll is the legacy wall-clock gap detector — retained as a fallback for
// environments without systemd-logind (musl containers, minimal init).
//
// Lifecycle note: on this fallback path d.conn and d.signalCh remain nil.
// Stop() guards those reads with `if conn != nil && ch != nil` so the
// nil state is safe; only d.stopCh drives shutdown here.
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
				slog.Info("sleep/wake detected via wall-clock gap", "elapsed", elapsed.Round(time.Second))
				select {
				case d.wakeCh <- struct{}{}:
				default:
				}
			}
		}
	}
}
