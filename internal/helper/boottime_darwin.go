//go:build darwin

package helper

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// systemBootTime returns the time of the last macOS boot via kern.boottime.
// launchd sets this at power-on and it does not change across sleep/wake
// cycles — precisely the distinction desired-state restore depends on: a
// helper crash during sleep is a same-boot event (restore), a reboot is not.
func systemBootTime() (time.Time, error) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return time.Time{}, fmt.Errorf("sysctl kern.boottime: %w", err)
	}
	// Explicit casts: Sec/Usec widths differ across the BSD variants this
	// file's siblings serve, and darwin can't be compile-checked from a
	// Windows host.
	return time.Unix(int64(tv.Sec), int64(tv.Usec)*1000), nil
}
