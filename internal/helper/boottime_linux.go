//go:build linux

package helper

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// systemBootTime returns the time of the last Linux boot, derived from
// /proc/uptime. Sleep/suspend does not advance wall time relative to this
// measure's anchor, so a crash-during-suspend is still a same-boot event.
func systemBootTime() (time.Time, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, fmt.Errorf("read /proc/uptime: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return time.Time{}, fmt.Errorf("parse /proc/uptime: empty file")
	}
	uptimeSeconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse /proc/uptime %q: %w", fields[0], err)
	}
	return time.Now().Add(-time.Duration(uptimeSeconds * float64(time.Second))), nil
}
