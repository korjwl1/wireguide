package guiinstance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// The OS private per-user directory keeps app copies and launch methods on
// the same reservation, independently of their bundle path or TMPDIR.
func Acquire() (*Instance, error) {
	dir, err := darwinReservationDir()
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Getuid() || st.Mode&0777 != 0700 {
		return nil, fmt.Errorf("unsafe GUI reservation directory: %s", dir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), contactTimeout)
	defer cancel()
	return acquireDarwinAt(ctx, dir, func() (bool, error) {
		// An already running pre-migration binary keeps its old reservation
		// even when an updater has replaced its bundle's Info.plist on disk.
		oldDir := filepath.Join("/private/tmp", fmt.Sprintf("wireguide-gui-%d", os.Getuid()))
		if active, err := activateOldReservation(ctx, oldDir); active || err != nil {
			return active, err
		}
		return activateLegacyApplication()
	})
}

func activateOldReservation(ctx context.Context, dir string) (bool, error) {
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Getuid() || st.Mode&0777 != 0700 {
		// An untrusted directory cannot belong to this user's old GUI.
		return false, nil
	}
	fd, err := unix.Open(filepath.Join(dir, "gui.lock"), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	if err := unix.Fstat(fd, &st); err != nil {
		return false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Getuid() || st.Mode&0777 != 0600 || st.Nlink != 1 {
		return false, nil
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
		return false, nil
	} else if !errors.Is(err, unix.EWOULDBLOCK) {
		return false, err
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "gui.sock"))
	if err != nil {
		return false, err
	}
	if err := notify(ctx, c, func(net.Conn) error { return nil }); err != nil {
		return false, err
	}
	return true, nil
}

func acquireDarwinAt(ctx context.Context, dir string, legacy func() (bool, error)) (*Instance, error) {
	path := filepath.Join(dir, "gui.sock")
	return acquire(ctx, func() (net.Listener, error) {
		fd, err := unix.Open(filepath.Join(dir, "gui.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return nil, err
		}
		lock := os.NewFile(uintptr(fd), "gui.lock")
		keep := false
		defer func() {
			if !keep {
				lock.Close()
			}
		}()
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return nil, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Getuid() || st.Mode&0777 != 0600 || st.Nlink != 1 {
			return nil, fmt.Errorf("unsafe GUI reservation lock")
		}
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return nil, err
		}
		if activated, err := legacy(); err != nil {
			return nil, err
		} else if activated {
			return nil, errActivated
		}
		// Only the lock holder may remove a socket left behind by SIGKILL.
		if info, err := os.Lstat(path); err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, fmt.Errorf("GUI activation path is not a socket")
			}
			if err := os.Remove(path); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		l, err := net.Listen("unix", path)
		if err != nil {
			return nil, err
		}
		keep = true
		return &darwinListener{Listener: l, lock: lock}, nil
	}, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}, func(net.Conn) error { return nil })
}

type darwinListener struct {
	net.Listener
	lock *os.File
	once sync.Once
	err  error
}

func (l *darwinListener) Close() error {
	l.once.Do(func() {
		l.err = errors.Join(l.Listener.Close(), l.lock.Close())
	})
	return l.err
}
