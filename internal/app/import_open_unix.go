//go:build !windows

package app

import (
	"os"

	"golang.org/x/sys/unix"
)

// NONBLOCK makes FIFO imports rejectable by f.Stat instead of hanging in open.
func openImportFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
