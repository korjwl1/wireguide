//go:build darwin

package helper

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
)

// deriveUserAppSupport returns the user's macOS Application Support
// directory for WireGuide given the uid passed to the helper at
// launch (`--uid` from the LaunchDaemon plist). The helper itself
// runs as root, so we can't read os.UserHomeDir() — that returns
// /var/root. Looking the user up by uid recovers their actual home.
func deriveUserAppSupport(uid int) (string, error) {
	if uid < 0 {
		return "", fmt.Errorf("invalid uid %d", uid)
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", fmt.Errorf("user.LookupId %d: %w", uid, err)
	}
	return filepath.Join(u.HomeDir, "Library", "Application Support", "wireguide"), nil
}
