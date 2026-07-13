package storage

import (
	"os"
	"path/filepath"
	"runtime"
)

// atomicRename moves src to dst. On modern Go (1.21+), os.Rename uses
// MoveFileEx with MOVEFILE_REPLACE_EXISTING on Windows, so it handles
// overwriting the destination atomically on all platforms.
func atomicRename(src, dst string) error {
	return os.Rename(src, dst)
}

// atomicRenameDurable renames src→dst and then fsyncs the containing
// directory so the rename's directory entry survives a power loss. The
// per-file fsync in the writers makes the CONTENT durable, but the
// rename itself isn't durable until the directory metadata is flushed —
// without this a save can report success and then vanish on reboot.
// Best-effort on the directory sync: not all filesystems/platforms
// support directory fsync (notably Windows, where opening a directory as
// a file fails), so a sync error there is not treated as a save failure.
func atomicRenameDurable(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	syncDir(filepath.Dir(dst))
	return nil
}

// syncDir best-effort fsyncs a directory. No-op on Windows (directory
// handles can't be opened as files there) and silently ignores errors on
// filesystems that don't support it.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
