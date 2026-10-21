//go:build !darwin && !windows

package app

import "fmt"

// Linux never self-updates (package-managed; RunUpdate opens the Releases
// page), so there is nothing to restart.
func (s *TunnelService) restartAfterUpdate(appPath string) error {
	_ = appPath
	return fmt.Errorf("in-app update restart is not available on this platform")
}
