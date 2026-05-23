//go:build linux

package wifi

import (
	"log/slog"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// startLinuxDBusWatcher launches a background goroutine that listens for
// NetworkManager's wireless `StateChanged` signal and pushes any resulting
// SSID change through the supplied callback. Returns a stop function.
//
// We narrow the matcher to org.freedesktop.NetworkManager.Device.Wireless
// (instead of the parent Device interface) so ethernet plug/unplug,
// modem state changes, loopback, etc. don't trigger onChange. nmcli is
// invoked from CurrentSSID() — re-running it for every ethernet flap
// would spawn unnecessary subprocesses.
//
// Falls back silently (does nothing, returns a no-op stop) on systems
// without NetworkManager / DBus — the wifi.Monitor's 5s nmcli poll still
// catches SSID changes there, just with up to 5s latency instead of being
// event-driven.
//
// IMPORTANT: dbus.SystemBus() is a process-singleton (see godbus docs).
// We must NOT call conn.Close() — that would terminate the connection
// shared with internal/reconnect/sleep_linux.go. We only unsubscribe our
// own matcher + signal channel on stop.
func startLinuxDBusWatcher(onChange func()) (stop func()) {
	noop := func() {}
	conn, err := dbus.SystemBus()
	if err != nil {
		slog.Debug("wifi: dbus unavailable, no event-driven SSID watcher", "error", err)
		return noop
	}

	matchOpts := []dbus.MatchOption{
		dbus.WithMatchInterface("org.freedesktop.NetworkManager.Device.Wireless"),
		dbus.WithMatchMember("StateChanged"),
	}
	if err := conn.AddMatchSignal(matchOpts...); err != nil {
		slog.Debug("wifi: NM AddMatchSignal failed", "error", err)
		return noop
	}

	ch := make(chan *dbus.Signal, 16)
	conn.Signal(ch)
	stopCh := make(chan struct{})
	var once sync.Once

	go func() {
		// Coalesce bursts: NM emits several state transitions per Wi-Fi
		// handover, but we only want to re-query the SSID once per burst.
		var debounce *time.Timer
		fire := func() {
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(300*time.Millisecond, func() {
				onChange()
			})
		}
		for {
			select {
			case <-stopCh:
				if debounce != nil {
					debounce.Stop()
				}
				// Unsubscribe but DO NOT close the shared connection —
				// other consumers (logind sleep detector) still need it.
				conn.RemoveSignal(ch)
				_ = conn.RemoveMatchSignal(matchOpts...)
				return
			case sig, ok := <-ch:
				if !ok {
					return
				}
				if sig == nil {
					continue
				}
				fire()
			}
		}
	}()

	slog.Info("wifi: NetworkManager DBus watcher started (Wireless.StateChanged only)")
	return func() {
		once.Do(func() { close(stopCh) })
	}
}
