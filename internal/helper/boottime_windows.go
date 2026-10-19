//go:build windows

package helper

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// procGetTickCount64 is kernel32.GetTickCount64 — milliseconds since boot.
// x/sys/windows wraps it only as an unexported getTickCount64, so declare
// the lazy proc directly (same pattern as internal/firewall's iphlpapi
// procs). The tick counter resets on reboot, which is exactly the identity
// desired-state restore needs: a desired-state file whose mtime predates
// this instant belongs to a previous power cycle.
var procGetTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

// systemBootTime returns the time of the last Windows boot, derived from
// GetTickCount64 (64-bit, so no 49.7-day wrap). A Fast Startup "shutdown"
// hibernates the kernel instead of rebooting, so this carries over it; the
// helper (a plain elevated process, not a service) still dies at logoff, so
// restore on Windows is additionally gated on the GUI's --restore-desired.
func systemBootTime() (time.Time, error) {
	tick, _, err := procGetTickCount64.Call()
	if tick == 0 {
		return time.Time{}, fmt.Errorf("GetTickCount64 failed: %w", err)
	}
	uptime := time.Duration(tick) * time.Millisecond
	return time.Now().Add(-uptime), nil
}
