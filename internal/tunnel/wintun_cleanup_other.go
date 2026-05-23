//go:build !windows

package tunnel

// cleanupStaleWintunAdapter is a no-op on non-Windows platforms (wintun
// is Windows-only). Kept here so engine.go can call it unconditionally.
func cleanupStaleWintunAdapter(name string) {}
