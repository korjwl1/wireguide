//go:build !windows

package atomicfile

import (
	"os"
	"path/filepath"
)

func replaceInRoot(root *os.Root, src, dst string) error { return root.Rename(src, dst) }

func replace(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	// Some filesystems do not support directory fsync. The snapshot has
	// already been published, so an unsupported sync is not a save failure.
	if d, err := os.Open(filepath.Dir(dst)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
