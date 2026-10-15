//go:build !windows

package storage

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func verifyProfileDirectory(info os.FileInfo, uid int, final bool) error {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect directory owner")
	}
	if final && int(owner.Uid) != uid {
		return fmt.Errorf("profile directory belongs to uid %d, expected %d", owner.Uid, uid)
	}
	if int(owner.Uid) != uid && owner.Uid != 0 {
		return fmt.Errorf("untrusted directory owner uid %d", owner.Uid)
	}
	if info.Mode()&os.ModeSymlink != 0 && owner.Uid != 0 {
		return fmt.Errorf("user-controlled directory symlink")
	}
	return nil
}

func verifyProfileFile(info os.FileInfo, uid int) error {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != uid || !info.Mode().IsRegular() {
		return fmt.Errorf("profile is not a regular file owned by uid %d", uid)
	}
	return nil
}

func verifyProfileRoot(root *os.Root, uid int, sid string) error {
	info, err := root.Stat(".")
	if err != nil {
		return err
	}
	return verifyProfileDirectory(info, uid, true)
}
func verifyProfileHandle(f *os.File, uid int, sid string) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	return verifyProfileFile(info, uid)
}
func openProfileRead(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
}
