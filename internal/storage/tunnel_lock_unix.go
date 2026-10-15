//go:build !windows

package storage

import (
	"fmt"
	"os"
	"syscall"
)

func setTunnelLockOwner(f *os.File, root *os.Root) error {
	if os.Geteuid() != 0 {
		return nil
	}
	info, err := root.Stat(".")
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine tunnel directory owner")
	}
	return f.Chown(int(owner.Uid), int(owner.Gid))
}
