//go:build windows

package helper

import (
	"fmt"
	"os"
	"path/filepath"
)

// deriveUserAppSupport returns the user's %APPDATA%\wireguide directory.
// On Windows the helper runs as SYSTEM via the named-pipe service, so we
// can't read os.UserHomeDir() — that returns the SYSTEM profile path. The
// uid arg is ignored on Windows; the GUI passes its own %APPDATA% via
// SocketUID==-1 but the path semantics are derived from environment.
//
// In practice the helper inherits the GUI's environment because UAC spawn
// passes env through; APPDATA points at the elevated user's roaming dir.
// If APPDATA is missing we fall back to LOCALAPPDATA or ProgramData so the
// helper at least has a writable directory.
func deriveUserAppSupport(uid int) (string, error) {
	_ = uid
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		return filepath.Join(appdata, "wireguide"), nil
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		return filepath.Join(local, "wireguide"), nil
	}
	if pd := os.Getenv("PROGRAMDATA"); pd != "" {
		return filepath.Join(pd, "wireguide"), nil
	}
	return "", fmt.Errorf("no APPDATA/LOCALAPPDATA/PROGRAMDATA env available")
}
