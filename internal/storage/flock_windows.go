//go:build windows

package storage

import "golang.org/x/sys/windows"

// flockExclusive / flockUnlock provide the same cross-process advisory
// lock as the unix build via LockFileEx on a lock-file handle. A single
// byte range is locked; the range is arbitrary but must match between
// lock and unlock.
func flockExclusive(fd int) error {
	ol := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(fd), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol)
}

func flockUnlock(fd int) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(fd), 0, 1, 0, ol)
}
