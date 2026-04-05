// Package elevate spawns a child process with elevated privileges.
package elevate

import "os"

// Args holds arguments for spawning the helper.
type Args struct {
	// SocketPath is passed to the helper as --socket=PATH
	SocketPath string
	// SocketUID is the UID to chown the socket to (Unix only). On Windows, 0.
	SocketUID int
	// DataDir for crash recovery state
	DataDir string
}

// SelfPath returns the absolute path of the current executable.
func SelfPath() (string, error) {
	return os.Executable()
}
