//go:build linux

package helper

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// deriveUserAppSupport returns the user's config directory on Linux.
// XDG_CONFIG_HOME wins when set; otherwise $HOME/.config/wireguide.
// The helper runs as root via pkexec, so we look up the invoking
// user's home by their uid rather than os.UserHomeDir() (which would
// give /root or similar).
func deriveUserAppSupport(uid int) (string, error) {
	if uid < 0 {
		return "", fmt.Errorf("invalid uid %d", uid)
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", fmt.Errorf("user.LookupId %d: %w", uid, err)
	}
	// Respect XDG_CONFIG_HOME if it was passed through the environment
	// when the GUI launched pkexec (pkexec preserves a subset of env).
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "wireguide"), nil
	}
	return filepath.Join(u.HomeDir, ".config", "wireguide"), nil
}
