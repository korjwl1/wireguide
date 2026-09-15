//go:build !darwin

package app

import "fmt"

func (s *TunnelService) restartAfterUpdate() error {
	return fmt.Errorf("Homebrew update restart is only available on macOS")
}
