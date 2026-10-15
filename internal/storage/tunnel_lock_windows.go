package storage

import "os"

// The lock inherits the user's tunnel directory ACL on Windows.
func setTunnelLockOwner(*os.File, *os.Root) error { return nil }
