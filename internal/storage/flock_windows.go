//go:build windows

package storage

import "golang.org/x/sys/windows"

// flockExclusive / flockUnlock provide the same cross-process advisory
// lock as the unix build via LockFileEx on a lock-file handle. A single
// byte range is locked; the range is arbitrary but must match between
// lock and unlock.
func tryFlock(fd int, shared bool) (bool, error) {
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if !shared {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	err := windows.LockFileEx(windows.Handle(fd), flags, 0, 1, 0, new(windows.Overlapped))
	if err == windows.ERROR_LOCK_VIOLATION {
		return false, nil
	}
	return err == nil, err
}

func flockUnlock(fd int) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(fd), 0, 1, 0, ol)
}
