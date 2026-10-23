package storage

import (
	"os"
)

// lockWrite serializes complete config/metadata mutations across store
// instances and processes. Keep the existing import lock path so current
// clients also serialize with an import performed by an older binary.
func (s *TunnelStore) lockWrite() (func(), error) { return s.lockProfiles(false) }
func (s *TunnelStore) lockRead() (func(), error)  { return s.lockProfiles(true) }

func (s *TunnelStore) lockProfiles(shared bool) (func(), error) {
	s.mu.Lock()
	root, err := s.openRoot()
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.root = root
	f, err := openTunnelLock(root)
	if err == nil {
		err = flockAcquire(int(f.Fd()), shared)
	}
	if err != nil {
		if f != nil {
			f.Close()
		}
		s.root = nil
		root.Close()
		s.mu.Unlock()
		return nil, err
	}
	return func() {
		_ = flockUnlock(int(f.Fd()))
		f.Close()
		s.root = nil
		root.Close()
		s.mu.Unlock()
	}, nil
}

func openTunnelLock(root *os.Root) (*os.File, error) {
	f, err := root.OpenFile(".imports.lock", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if os.IsExist(err) {
		return root.OpenFile(".imports.lock", os.O_RDWR, 0600)
	}
	if err != nil {
		return nil, err
	}
	// The privileged helper may be the first writer for an existing user
	// profile directory. Its new private lock must remain usable by the GUI.
	if err := setTunnelLockOwner(f, root); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
