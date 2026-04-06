//go:build windows

package ipc

// verifyDirOwnership is a no-op on Windows. The Windows IPC transport uses
// named pipes with SDDL-based access control, not filesystem directories.
func verifyDirOwnership(_ string, _ int) error {
	return nil
}
