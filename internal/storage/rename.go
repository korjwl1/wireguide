package storage

import "os"

// atomicRename moves src to dst. On modern Go (1.21+), os.Rename uses
// MoveFileEx with MOVEFILE_REPLACE_EXISTING on Windows, so it handles
// overwriting the destination atomically on all platforms.
func atomicRename(src, dst string) error {
	return os.Rename(src, dst)
}
