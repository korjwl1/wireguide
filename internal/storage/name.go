package storage

import (
	"fmt"
	"strings"
)

// reservedDeviceNames are Windows reserved device names that cannot be used
// as a file's base name regardless of extension (CON.conf still resolves to
// the console device). Rejected on every platform for portability — a config
// synced from macOS/Linux to Windows must not become unusable.
var reservedDeviceNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// ValidateTunnelName ensures a tunnel name is safe for use as a filesystem
// path (preventing traversal) and consistent across all entry points —
// both on first save and on rename. Allowed: letters, digits, '-', '_', spaces.
// Leading/trailing spaces are rejected to avoid confusing filenames.
// Length limit guards against filesystem limits on some platforms.
func ValidateTunnelName(name string) error {
	if name == "" {
		return fmt.Errorf("tunnel name is empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("tunnel name too long (max 64 characters)")
	}
	if name[0] == ' ' || name[len(name)-1] == ' ' {
		return fmt.Errorf("tunnel name cannot start or end with a space")
	}
	for _, r := range name {
		valid := (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == ' '
		if !valid {
			return fmt.Errorf("invalid character in tunnel name %q (letters, digits, '-', '_' and spaces only)", name)
		}
	}
	if reservedDeviceNames[strings.ToUpper(name)] {
		return fmt.Errorf("tunnel name %q is a reserved device name and cannot be used", name)
	}
	return nil
}
