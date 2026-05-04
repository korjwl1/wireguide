package gui

import (
	"log/slog"
	"runtime"
	"time"

	"github.com/korjwl1/wireguide/internal/ipc"
	"github.com/korjwl1/wireguide/internal/wifi"
)

// startSSIDReporter polls the current SSID every 5 seconds and forwards
// changes to the helper via MethodReportSSID. This is required on macOS 14+
// because the helper (root LaunchDaemon) cannot read SSID via CoreWLAN —
// Location Services permission is scoped to the GUI .app bundle.
// On non-darwin platforms this is a no-op since the helper can read SSID directly.
func startSSIDReporter(clients *ipc.ClientHolder) {
	if runtime.GOOS != "darwin" {
		return
	}
	last := wifi.CurrentSSID()
	// Send the initial SSID immediately so the helper starts with the right state.
	reportSSID(clients, last)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		current := wifi.CurrentSSID()
		if current == last {
			continue
		}
		last = current
		reportSSID(clients, current)
	}
}

func reportSSID(clients *ipc.ClientHolder, ssid string) {
	c := clients.Get()
	if c == nil {
		return
	}
	if err := c.Call(ipc.MethodReportSSID, ipc.ReportSSIDRequest{SSID: ssid}, nil); err != nil {
		slog.Debug("SSID report to helper failed", "error", err)
	}
}
