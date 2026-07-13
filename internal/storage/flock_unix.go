//go:build !windows

package storage

import "golang.org/x/sys/unix"

// flockExclusive / flockUnlock wrap advisory whole-file locks so a
// read-modify-write of config.json is atomic ACROSS processes (the GUI
// and the `wireguide ctl` CLI both write it). An in-process mutex alone
// can't do this — they're separate processes.
func flockExclusive(fd int) error { return unix.Flock(fd, unix.LOCK_EX) }
func flockUnlock(fd int) error     { return unix.Flock(fd, unix.LOCK_UN) }
