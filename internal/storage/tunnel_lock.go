package storage

import (
	"os"
	"path/filepath"
)

// lockWrite serializes complete config/metadata mutations across store
// instances and processes. Keep the existing import lock path so current
// clients also serialize with an import performed by an older binary.
func (s *TunnelStore) lockWrite() (func(), error) {
	s.mu.Lock()
	f, err := openTunnelLock(filepath.Join(s.dir, ".imports.lock"))
	if err == nil {
		err = flockExclusive(int(f.Fd()))
	}
	if err != nil {
		if f != nil {
			f.Close()
		}
		s.mu.Unlock()
		return nil, err
	}
	return func() {
		_ = flockUnlock(int(f.Fd()))
		f.Close()
		s.mu.Unlock()
	}, nil
}

func openTunnelLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if os.IsExist(err) {
		return os.OpenFile(path, os.O_RDWR, 0600)
	}
	if err != nil {
		return nil, err
	}
	// The privileged helper may be the first writer for an existing user
	// profile directory. Its new private lock must remain usable by the GUI.
	if err := setTunnelLockOwner(f, filepath.Dir(path)); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
