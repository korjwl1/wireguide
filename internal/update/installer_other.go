//go:build !windows && !darwin

package update

import (
	"context"
	"fmt"
	"runtime"
)

// Linux releases ship as a .deb that installs /usr/local/bin/wireguide
// through dpkg. Replacing a package-owned file behind dpkg's back would
// desync the package database, and driving `pkexec dpkg -i` from the GUI
// depends on a polkit agent being present and leaves the restart to
// guesswork — the distro package manager (or the Releases page) is the
// honest update path. Other OSes have no release assets at all.
func platformSelfUpdateSupport() error {
	return fmt.Errorf("%w: %s installs are updated through the package manager", ErrSelfUpdateUnsupported, runtime.GOOS)
}

func platformInstall(ctx context.Context, path string, info *UpdateInfo) (*InstallResult, error) {
	_, _, _ = ctx, path, info
	return nil, platformSelfUpdateSupport()
}
