//go:build darwin && !cgo

package guiinstance

import (
	"os"
	"path/filepath"
)

func activateLegacyApplication() (bool, error) { return false, nil }

func darwinReservationDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wireguide-gui"), nil
}
