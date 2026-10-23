//go:build !darwin && !linux && !windows

package helper

import (
	"errors"
	"time"
)

var errBootTimeUnsupported = errors.New("boot time not supported on this platform")

// systemBootTime is unavailable on other platforms. Callers treat an error as
// "unknown" and proceed with desired-state restore without the reboot check —
// see restoreDesiredTunnels for why that is the acceptable default.
func systemBootTime() (time.Time, error) {
	return time.Time{}, errBootTimeUnsupported
}
