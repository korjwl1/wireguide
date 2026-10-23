//go:build !windows

package storage

import (
	"errors"
	"golang.org/x/sys/unix"
)

// flockExclusive / flockUnlock wrap advisory whole-file locks so a
// read-modify-write of config.json is atomic ACROSS processes (the GUI
// and the `wireguide ctl` CLI both write it). An in-process mutex alone
// can't do this — they're separate processes.
func tryFlock(fd int, shared bool) (bool, error) {
	mode := unix.LOCK_EX
	if shared {
		mode = unix.LOCK_SH
	}
	err := unix.Flock(fd, mode|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	return err == nil, err
}
func flockUnlock(fd int) error { return unix.Flock(fd, unix.LOCK_UN) }
