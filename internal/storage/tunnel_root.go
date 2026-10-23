package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// NewUserTunnelStore is for the privileged helper's access to user files.
// The owner is the authenticated GUI user, not the helper's effective user.
func NewUserTunnelStore(dir string, ownerUID int, ownerSID ...string) *TunnelStore {
	s := NewTunnelStore(dir)
	s.ownerUID = &ownerUID
	if len(ownerSID) > 0 {
		s.ownerSID = ownerSID[0]
	}
	return s
}

// openRoot verifies each directory as it is opened, retaining handles rather
// than checking a pathname and using that pathname again after an attacker can
// replace it. Administrative OS links (such as macOS /var) remain usable.
func (s *TunnelStore) openRoot() (*os.Root, error) {
	if s.ownerUID == nil {
		return os.OpenRoot(s.dir)
	}
	abs, err := filepath.Abs(s.dir)
	if err != nil {
		return nil, err
	}
	base := filepath.VolumeName(abs) + string(filepath.Separator)
	r, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(abs, base), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		info, err := r.Lstat(part)
		if err == nil {
			err = verifyProfileDirectory(info, *s.ownerUID, false)
		}
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("unsafe profile directory: %w", err)
		}
		next, err := r.OpenRoot(part)
		r.Close()
		if err != nil {
			return nil, err
		}
		r = next
	}
	err = verifyProfileRoot(r, *s.ownerUID, s.ownerSID)
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// borrowRoot is called under s.mu. Write operations reuse the directory held
// throughout lock acquisition and publication; standalone reads own a handle.
func (s *TunnelStore) borrowRoot() (*os.Root, func(), error) {
	if s.root != nil {
		return s.root, func() {}, nil
	}
	r, err := s.openRoot()
	if err != nil {
		return nil, func() {}, err
	}
	return r, func() { r.Close() }, nil
}

func (s *TunnelStore) openProfileFile(root *os.Root, name string) (*os.File, error) {
	f, err := openProfileRead(root, name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("profile is not a regular file")
	}
	if err == nil && s.ownerUID != nil {
		err = verifyProfileHandle(f, *s.ownerUID, s.ownerSID)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// ReadUserFile is the helper's bounded, owner-checked settings read.
func ReadUserFile(dir, name string, uid int, sid string, limit int64) ([]byte, error) {
	s := NewUserTunnelStore(dir, uid, sid)
	root, err := s.openRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := s.openProfileFile(root, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = fmt.Errorf("user file exceeds %d bytes", limit)
	}
	return data, err
}
