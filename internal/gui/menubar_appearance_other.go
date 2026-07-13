//go:build !darwin

package gui

// menuBarIsDark is only meaningful on macOS; other platforms never
// reach the appearance-dependent icon paths.
func menuBarIsDark() bool { return false }
