package update

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// Prefer the installed package's format: either distribution can have both
// package managers available. Queries only read package metadata and share
// a deadline so an unavailable package database cannot stall update checks.
func linuxPackageFormat() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return detectLinuxPackageFormat(ctx)
}

func detectLinuxPackageFormat(ctx context.Context) string {
	rpm := exec.CommandContext(ctx, "rpm", "-q", "wireguide")
	rpm.WaitDelay = 100 * time.Millisecond
	if rpm.Run() == nil {
		return "rpm"
	}
	dpkg := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Status}", "wireguide")
	dpkg.WaitDelay = 100 * time.Millisecond
	if out, err := dpkg.Output(); err == nil && strings.TrimSpace(string(out)) == "install ok installed" {
		return "deb"
	}
	// Unpackaged installs have no receipt. Use the available tool, retaining
	// the existing DEB preference when both or neither are available.
	_, dpkgErr := exec.LookPath("dpkg")
	_, rpmErr := exec.LookPath("rpm")
	if dpkgErr != nil && rpmErr == nil {
		return "rpm"
	}
	return "deb"
}
