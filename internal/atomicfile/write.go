// Package atomicfile publishes complete file snapshots with private temporary
// files in the destination directory. Callers own directory creation and locking.
package atomicfile

import (
	"os"
	"path/filepath"
)

// WriteFile replaces path with data and perm, without modifying the existing
// file in place or following a destination symlink. A failure before replacement
// leaves the previous snapshot intact. The temporary file is synced before
// publication; directory syncing is best effort where supported.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".wireguide-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return replace(f.Name(), path)
}
