//go:build !windows

package guiinstance

// Acquire leaves other platforms' existing lifecycle unchanged.
func Acquire() (*Instance, error) { return newInstance(nil), nil }
