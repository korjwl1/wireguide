//go:build !windows && !darwin

package update

import (
	"context"
	"fmt"
	"runtime"
)

// Linux DEB/RPM installs are updated through the package manager or Releases
// page. Replacing package-owned files would desync the package database;
// this remains unsupported even when a matching release asset is available.
// Other OSes have no release assets.
func platformSelfUpdateSupport() error {
	return fmt.Errorf("%w: %s installs are updated through the package manager", ErrSelfUpdateUnsupported, runtime.GOOS)
}

func platformInstall(ctx context.Context, path string, info *UpdateInfo) (*InstallResult, error) {
	_, _, _ = ctx, path, info
	return nil, platformSelfUpdateSupport()
}

func platformCleanupPreviousUpdate() {}
