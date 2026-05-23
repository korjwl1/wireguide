//go:build darwin || linux || freebsd

package ipc

import (
	"fmt"
	"os"
	"syscall"
)

// verifyDirOwnership checks that the directory at path is owned by the
// expected UID. This prevents an attacker from pre-creating a directory
// (e.g. under /tmp) and tricking the application into using it.
func verifyDirOwnership(path string, expectedUID int) error {
	// Guard negative expectedUID up front: a -1 here would wrap to
	// 0xFFFFFFFF on the cast below and could mask a misconfigured call
	// site. Caller is expected to pass a real UID (>=0).
	if expectedUID < 0 {
		return fmt.Errorf("verifyDirOwnership: negative expectedUID %d", expectedUID)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	if st.Uid != uint32(expectedUID) { //nolint:gosec // G115: expectedUID >= 0 checked above
		return fmt.Errorf("directory %s owned by UID %d, expected %d — possible attack", path, st.Uid, expectedUID)
	}
	return nil
}
