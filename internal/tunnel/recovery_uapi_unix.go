//go:build !windows

package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
)

func cleanupStaleUAPI(interfaceName string) error {
	if interfaceName == "" || filepath.Base(interfaceName) != interfaceName {
		return fmt.Errorf("unsafe interface name %q", interfaceName)
	}
	path := filepath.Join("/var/run/wireguard", interfaceName+".sock")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
