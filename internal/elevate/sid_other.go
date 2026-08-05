//go:build !windows

package elevate

// CurrentUserSID is Windows-only; Unix platforms identify the socket
// owner by UID instead.
func CurrentUserSID() string { return "" }
