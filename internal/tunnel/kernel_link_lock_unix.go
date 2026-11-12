//go:build unix

package tunnel

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// kernelIntentLock is an flock on a lock file that is never renamed or
// removed, so it is a different inode from the atomically replaced intent.
// The kernel drops it when the process dies.
type kernelIntentLock struct{ f *os.File }

func tryLockKernelIntent(path string) (*kernelIntentLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening kernel link lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errKernelLinkBusy
		}
		return nil, fmt.Errorf("locking kernel link intent: %w", err)
	}
	return &kernelIntentLock{f: f}, nil
}

func (l *kernelIntentLock) unlock() {
	if l == nil || l.f == nil {
		return
	}
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}
